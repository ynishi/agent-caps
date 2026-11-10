//! The transaction of a claim: whether what someone states takes effect, judged by the
//! difference it makes, as a whole or not at all.
//!
//! An event is an act or a claim by its kind's [`Nature`]. An act is what rules judge, and it is
//! folded as it is. A claim (a temporary adjustment or its cancel, a mode switch, a record a rule
//! reads) may change how the rules take effect, so it is applied to a copy of the state, and the
//! difference is judged from several points of view before it is kept.
//!
//! ```text
//! Catalog::apply_with(state, event, &TxPolicy)
//!   carried = state.carry(event)                 what the past and the time bring; an act
//!                                                  advances the clock, a claim does not; kept
//!   act   → carried.step(event)                  not judged
//!   claim → carried.admits(event)                  an adjustment or a cancel that cannot take
//!                                                  effect: carried, Abort, TxReport::inadmissible
//!           after   = carried.clone().step(event)  applied to a copy
//!           changes = State::changes(carried, after)
//!           each check.judge(input) → Vec<CheckFinding>     the domain's checks, then the extra ones
//!           floor   = every Loosens finding: Authority::may_loosen(by, authors) is Ok
//!           policy  = TxPolicy.combine(findings)
//!           after when the floor and the policy both commit, carried otherwise
//! ```
//!
//! The domain holds only the steps and the floor. What a point of view sees is an
//! [`AdjustmentCheck`]: the domain's own ([`checks`]) are applied to every claim, and a
//! [`TxPolicy`] adds checks of its own and the [`Combine`] that merges the findings. A check
//! says which way a difference moves the rules and, when it loosens, whose rules; it never
//! decides who may. That is [`Authority::may_loosen`](super::authority::Authority::may_loosen),
//! asked here and nowhere else at run time.
//!
//! # A spawn
//!
//! A spawn ([`Body::Spawn`](super::event::Body::Spawn)) is a claim: the platform observed that an
//! agent started, but where its child sits in the hierarchy of actors is its spawner's choice,
//! and the rules that read the actor (`ActorUnder`, and a selector or a scope that chooses
//! events by actor, [`By::Under`](super::predicate::By::Under)) take effect by it, as does a
//! temporary adjustment whose lifetime lasts within a scope that chooses by actor: placing a
//! child under the principal it names lets the child's acts end it. The fold keeps only its
//! shape ([`super::state`]); [`checks::SpawnCheck`] judges the placement, for every [`Reader`].
//!
//! The difference of a spawn is not "before the child existed and after": the child, before, is an
//! unknown actor, and every rule that reads the actor would be loosened by anything. The place it
//! is judged against is directly under its spawner, which is the delegation of RFC 8693: the work
//! of a child is its spawner's work. Against that, a placement that moves the child into a
//! principal that a policy reads as "applies inside" tightens, and one that moves it out of a
//! principal, or in or out where the direction of the reading cannot be told, loosens, by the
//! author of that policy. The check reads the spawner (`Event::by`) to make that place, not to
//! decide who may loosen: that is still the floor's alone, so the rule above holds.
//!
//! # Invariants
//!
//! - The floor is fixed. However the findings are combined, and whatever a policy adds, a claim
//!   with a loosening finding whose authors its author does not cover is aborted: a combination
//!   can turn a commit into an abort, never an abort into a commit. Nobody asks of a tightening
//!   finding: it is open to anyone. A finding whose direction cannot be read is a loosening one.
//! - The domain's checks are always applied, so no policy can leave one out to get past the
//!   floor. The move of a state atom is looked at by one check ([`checks::ModeCheck`] the mode
//!   as rules read it with `ModeIs`, [`checks::SlotCheck`] a slot, [`checks::SpawnCheck`] the
//!   actor); how the rules take effect, their strength (with the temporary adjustments,
//!   [`Catalog::effective_in`](super::catalog::Catalog::effective_in)), the bindings suspended
//!   and the exemptions, is [`checks::RuleCheck`]'s, read from the whole state before and after,
//!   whichever [`StateChange`] moved it: a mode switch, an adjustment added, used up, cancelled,
//!   or ended because the claim closes the scope it lasts within (compared with the state after
//!   as the next event finds it). So a cancel is judged by its result alone. An adjustment that
//!   runs out by time, and a window that starts again by time, are not judged: they happen in
//!   the carry, by the clock, which only acts advance; the lifetime is its maker's choice, and
//!   the time of an act the adapter's to give ([`super::state`]). A claim's time never ends what
//!   loosens when it ends, so no claim brings about such an end without its transaction. A check
//!   never decides who may loosen.
//!   (The spawn check reads `Event::by` to make the place a spawn is compared with, which is a
//!   fact of the claim and not a question of trust.)
//! - One function decides every claim: [`Catalog::apply`], [`Catalog::apply_with`],
//!   [`Catalog::fold`], [`Catalog::fold_with`], [`Catalog::admit`] and the check of the fixtures
//!   in [`Catalog::accept`] all go through it, so an example is folded as a run is.
//! - Within one catalog, the hierarchy and the authors do not change, so a claim comes to the
//!   same wherever in a fold it is seen, under the same [`TxPolicy`]. After
//!   [`Catalog::change`], folding the same events again may give a past claim another result:
//!   that is intended, since the rules it is judged by are the new ones.

pub mod checks;

use std::fmt;

use checks::RuleMove;

use super::adjust::Inadmissible;
use super::authority::{Authority, NotCovered, Principal};
use super::catalog::{AcceptError, Catalog, Rejected};
use super::event::Event;
use super::name::{AdjustmentId, PolicyId};
use super::policy::{Expect, Finding};
use super::schema::Nature;
use super::set::Sources;
use super::state::{SlotId, State, StateChange};

/// One point of view on the difference a claim makes. The domain's own checks and the ones a
/// [`TxPolicy`] adds both implement it.
pub trait AdjustmentCheck {
    /// What this point of view finds of the claim: one finding per difference it looks at, or
    /// none when there is nothing for it to see.
    fn judge(&self, input: &TxInput<'_>) -> Vec<CheckFinding>;
}

/// What a check is given: the claim, and the state before and after it.
#[derive(Debug, Clone, Copy)]
pub struct TxInput<'a> {
    /// The catalog the claim is judged by.
    pub catalog: &'a Catalog,
    /// The claim.
    pub event: &'a Event,
    /// The state carried to the claim, before it.
    pub before: &'a State,
    /// The state with the claim applied, on a copy.
    pub after: &'a State,
    /// The differences between the two.
    pub changes: &'a [StateChange],
}

/// The name of a check, as it appears in its findings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CheckName(String);

impl CheckName {
    /// The name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The text of the name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CheckName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What one check found.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckFinding {
    /// The check.
    pub check: CheckName,
    /// What it found.
    pub verdict: Verdict,
}

/// How sure a check is that a difference only tightens.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Confidence {
    /// It is sure.
    Certain,
    /// It is not sure; the value is how likely it takes itself to be right, from 0 to 1. Only a
    /// [`Combine`] reads it.
    Uncertain(f64),
}

/// Which way a difference moves the rules, with what matters only for that way. A difference
/// whose direction cannot be read is [`Verdict::Loosens`]; the floor reads only the variant.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// The rules hold the same.
    Neutral,
    /// The rules hold more.
    Tightens(Confidence),
    /// The rules hold less, or the direction cannot be read.
    Loosens {
        /// The authors of the rules it loosens: the claim's author must cover each of them.
        authors: Vec<Principal>,
        /// What it loosens, for the one who reads why a claim did not take effect.
        detail: FindingDetail,
    },
}

/// What a loosening finding is about.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum FindingDetail {
    /// The rules take effect otherwise: how each policy moves (see [`checks::RuleCheck`]), and
    /// the policies loosened because they read the judgments of one that moves.
    Rules {
        /// How the policies move, those that tighten included.
        moves: Vec<RuleMove>,
        /// The policies that read the judgments of one that moves, loosened by that.
        reading: Vec<PolicyId>,
    },
    /// The mode changes, and these policies are loosened by the mode they read with `ModeIs`
    /// (see [`checks`]).
    Mode {
        /// The policies loosened by reading the mode: one that applies inside a mode it sees
        /// left, one that reads a mode in a direction that cannot be told, entered or left, and
        /// one that reads the judgments of a policy that the switch moves.
        reading: Vec<PolicyId>,
    },
    /// The slot changes, and these policies read it.
    Slot {
        /// The slot.
        slot: SlotId,
        /// The policies that read it.
        reading: Vec<PolicyId>,
    },
    /// A spawn places a child where these readers of the actor take effect less strongly or in a
    /// direction that cannot be read, against a place directly under the spawner: policies, and
    /// temporary adjustments whose lifetime ends at the acts of the actors under a principal.
    /// Policies that read the judgments of a policy that the placement moves are among them.
    Spawn {
        /// The new actor.
        child: Principal,
        /// The actor it is placed under.
        under: Principal,
        /// The readers it loosens.
        loosened: Vec<Reader>,
    },
    /// What a check from outside the domain says, in its own words.
    Described(String),
}

/// What reads where an actor sits in the hierarchy of actors, so that a spawn can move it: a
/// policy (`ActorUnder`, or a selector or a scope that chooses by actor), or a temporary
/// adjustment in effect whose lifetime lasts within a scope that chooses by actor. A loosening of
/// a policy asks its author, and one of an adjustment asks the one who made it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reader {
    /// The policy.
    Policy(PolicyId),
    /// The temporary adjustment in effect.
    Adjustment(AdjustmentId),
}

impl Reader {
    /// The policy, when the reader is one.
    fn policy(self) -> Option<PolicyId> {
        match self {
            Self::Policy(id) => Some(id),
            Self::Adjustment(_) => None,
        }
    }
}

/// Whether a claim takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TxDecision {
    /// It takes effect: the state after it is kept.
    Commit,
    /// It does not: the state before it is kept.
    Abort,
}

/// How the findings of the checks are merged into one decision: all must agree, a weighted or a
/// probabilistic merge. Given from outside; the floor applies whatever it returns.
pub trait Combine {
    /// The decision the findings come to.
    fn combine(&self, findings: &[CheckFinding]) -> TxDecision;
}

/// What a caller adds to the transaction: checks of its own, and the way to combine the
/// findings. The domain's checks are not in it: they are always applied.
pub struct TxPolicy {
    /// The checks added to the domain's own.
    pub extra: Vec<Box<dyn AdjustmentCheck>>,
    /// How the findings are combined.
    pub combine: Box<dyn Combine>,
}

impl TxPolicy {
    /// No check added, and [`checks::AllOk`]: the policy [`Catalog::apply`] and
    /// [`Catalog::fold`] use.
    pub fn standard() -> Self {
        Self {
            extra: Vec::new(),
            combine: Box::new(checks::AllOk),
        }
    }
}

impl Default for TxPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

/// The transaction of one event, as [`Catalog::admit`] reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct TxReport {
    /// Whether it takes effect. An act always does.
    pub decision: TxDecision,
    /// Every finding of every check, the domain's first. None for an act.
    pub findings: Vec<CheckFinding>,
    /// What the floor found: for each loosening finding whose authors the claim's author does
    /// not cover, why. Empty when the floor commits.
    pub uncovered: Vec<NotCovered>,
    /// Why the claim, an adjustment or a cancel, cannot take effect whoever makes it, when it
    /// cannot ([`State`]'s one answer). Such a claim is aborted with no finding: it changes
    /// nothing, and saying it committed would tell its maker it took effect.
    pub inadmissible: Option<Inadmissible>,
}

impl Catalog {
    /// The catalog of the sets `sources` under the hierarchy `authority`, when it keeps every
    /// invariant of [`super::catalog`]. The structure is checked first: every item of a set is by
    /// its owner or one below ([`Authority::within`]), the sets compose
    /// ([`Sources::compose`](super::set::Sources::compose)), and the composed graph holds. The
    /// fixtures, only of a graph whose structure holds, are then folded by [`Catalog::fold`], the
    /// same transaction as a run. The catalog keeps the sources and the hierarchy.
    ///
    /// A single graph is accepted as one set:
    /// `Sources::new(vec![Source { id, name, owner, graph }])`, with an owner every author of the graph
    /// is below or is.
    pub fn accept(sources: Sources, authority: Authority) -> Result<Self, Rejected> {
        let catalog = Self::accept_structure(sources, authority)?;
        let errors = fixture_errors(&catalog);
        if errors.is_empty() {
            Ok(catalog)
        } else {
            Err(Rejected(errors))
        }
    }

    /// The state after `event`, with [`TxPolicy::standard`]. A temporary adjustment or a cancel
    /// that cannot take effect ([`Inadmissible`]: a duplicate id, a policy or binding the catalog
    /// lacks or of the meta layer, a cover or filter that does not type-check, a temporary
    /// binding stronger than its policy may be bound or by one not within its author's work, a
    /// rebinding for the next judgment or one that changes nothing, a cancel of an id not held)
    /// is aborted, and [`Catalog::admit`] reports why.
    pub fn apply(&self, state: State, event: &Event) -> State {
        self.apply_with(state, event, &TxPolicy::standard())
    }

    /// The state after `event`, a claim judged with `policy`.
    pub fn apply_with(&self, state: State, event: &Event, policy: &TxPolicy) -> State {
        transact(self, state, event, policy).0
    }

    /// The state after `events`, from the start, with [`TxPolicy::standard`].
    pub fn fold<'e>(&self, events: impl IntoIterator<Item = &'e Event>) -> State {
        self.fold_with(events, &TxPolicy::standard())
    }

    /// The state after `events`, from the start, each claim judged with `policy`.
    pub fn fold_with<'e>(
        &self,
        events: impl IntoIterator<Item = &'e Event>,
        policy: &TxPolicy,
    ) -> State {
        events.into_iter().fold(self.start(), |state, event| {
            self.apply_with(state, event, policy)
        })
    }

    /// The transaction of `event` after `state`, as a decision and every finding, by the same
    /// function that [`Catalog::apply_with`] folds with: what an adapter shows when a claim did
    /// not take effect.
    pub fn admit(&self, state: &State, event: &Event, policy: &TxPolicy) -> TxReport {
        transact(self, state.clone(), event, policy).1
    }
}

/// The one function that decides whether an event takes effect: the state after it, and the
/// report of its transaction. See the module doc for the steps.
fn transact(
    catalog: &Catalog,
    state: State,
    event: &Event,
    policy: &TxPolicy,
) -> (State, TxReport) {
    let table = catalog.slots();
    let carried = state.carry(table, event);
    if event.body.kind().nature() == Nature::Act {
        let report = TxReport {
            decision: TxDecision::Commit,
            findings: Vec::new(),
            uncovered: Vec::new(),
            inadmissible: None,
        };
        let kept = carried.step(table, event, catalog.index(), catalog.authority());
        return (kept, report);
    }
    if let Err(reason) = carried.admits(event, catalog.index(), catalog.authority()) {
        let report = TxReport {
            decision: TxDecision::Abort,
            findings: Vec::new(),
            uncovered: Vec::new(),
            inadmissible: Some(reason),
        };
        return (carried, report);
    }
    let after = carried
        .clone()
        .step(table, event, catalog.index(), catalog.authority());
    let changes = State::changes(table, &carried, &after);
    let input = TxInput {
        catalog,
        event,
        before: &carried,
        after: &after,
        changes: &changes,
    };
    let mut findings = Vec::new();
    for check in checks::domain() {
        findings.extend(check.judge(&input));
    }
    for check in &policy.extra {
        findings.extend(check.judge(&input));
    }
    // The floor: a loosening finding takes effect only from one who covers its authors.
    let uncovered: Vec<NotCovered> = findings
        .iter()
        .filter_map(|finding| match &finding.verdict {
            Verdict::Loosens { authors, .. } => {
                catalog.authority().may_loosen(&event.by, authors).err()
            }
            Verdict::Neutral | Verdict::Tightens(_) => None,
        })
        .collect();
    let combined = policy.combine.combine(&findings);
    let decision = if uncovered.is_empty() && combined == TxDecision::Commit {
        TxDecision::Commit
    } else {
        TxDecision::Abort
    };
    let report = TxReport {
        decision,
        findings,
        uncovered,
        inadmissible: None,
    };
    match decision {
        TxDecision::Commit => (after, report),
        TxDecision::Abort => (carried, report),
    }
}

/// Every fixture of the catalog that does not give the finding it expects (a known gap aside),
/// and every one with no event. Each is folded by [`Catalog::fold`].
fn fixture_errors(catalog: &Catalog) -> Vec<AcceptError> {
    let mut errors = Vec::new();
    for policy in catalog.policies() {
        for fixture in policy.fixtures() {
            let Some(judged) = fixture.events.last() else {
                errors.push(AcceptError::EmptyFixture {
                    policy: policy.id(),
                    fixture: fixture.name.clone(),
                });
                continue;
            };
            let state = catalog.fold(&fixture.events);
            let found = match policy.evaluate(catalog.slots(), catalog.authority(), &state, judged)
            {
                Finding::Violated => Expect::Violated,
                Finding::Satisfied => Expect::Satisfied,
                Finding::NotApplicable | Finding::Exempted => Expect::NotApplicable,
                Finding::Unknown => Expect::Unknown,
            };
            if found != fixture.expect && !fixture.known_gap {
                errors.push(AcceptError::FixtureFailed {
                    policy: policy.id(),
                    fixture: fixture.name.clone(),
                    expected: fixture.expect,
                    found,
                });
            }
        }
    }
    errors
}
