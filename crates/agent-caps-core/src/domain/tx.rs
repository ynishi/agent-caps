//! The transaction of a claim: whether what someone states takes effect, judged by the
//! difference it makes, as a whole or not at all.
//!
//! An event is an act or a claim by its kind's [`Nature`]. An act is what rules judge, and it is
//! folded as it is. A claim (an exemption, a mode switch, a record a rule reads) may change how
//! the rules take effect, so it is applied to a copy of the state, and the difference is judged
//! from several points of view before it is kept.
//!
//! ```text
//! Catalog::apply_with(state, event, &TxPolicy)
//!   carried = state.carry(event.at)              what the past brings; always kept
//!   act   → carried.step(event)                  not judged
//!   claim → after   = carried.clone().step(event)  applied to a copy
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
//! and the rules that read the actor (`ActorUnder`) take effect by it. The fold keeps only its
//! shape ([`super::state`]); [`checks::SpawnCheck`] judges the placement.
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
//!   floor; each looks at one kind of [`StateChange`], and no two look at the same. A check
//!   never decides who may loosen. (The spawn check reads `Event::by` to make the place a spawn is
//!   compared with, which is a fact of the claim and not a question of trust.)
//! - One function decides every claim: [`Catalog::apply`], [`Catalog::apply_with`],
//!   [`Catalog::fold`], [`Catalog::fold_with`], [`Catalog::admit`] and the check of the fixtures
//!   in [`Catalog::accept`] all go through it, so an example is folded as a run is.
//! - Within one catalog, the hierarchy and the authors do not change, so a claim comes to the
//!   same wherever in a fold it is seen, under the same [`TxPolicy`]. After
//!   [`Catalog::change`], folding the same events again may give a past claim another result:
//!   that is intended, since the rules it is judged by are the new ones.

pub mod checks;

use std::fmt;

use super::authority::{Authority, NotCovered, Principal};
use super::catalog::{AcceptError, Catalog, Lowered, Rejected};
use super::event::Event;
use super::name::PolicyId;
use super::policy::{Expect, Finding, PolicyGraph};
use super::schema::Nature;
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
    /// An exemption of the guard is added.
    ExemptionAdded(PolicyId),
    /// The mode changes: these policies take effect less strongly, and these read a mode it
    /// changes from or to.
    Mode {
        /// The policies that take effect less strongly.
        lowered: Vec<Lowered>,
        /// The policies that read the mode before or after.
        reading: Vec<PolicyId>,
    },
    /// The slot changes, and these policies read it.
    Slot {
        /// The slot.
        slot: SlotId,
        /// The policies that read it.
        reading: Vec<PolicyId>,
    },
    /// A spawn places a child where these policies, which read the actor, take effect less
    /// strongly or in a direction that cannot be read, against a place directly under the
    /// spawner.
    Spawn {
        /// The new actor.
        child: Principal,
        /// The actor it is placed under.
        under: Principal,
        /// The policies it loosens.
        loosened: Vec<PolicyId>,
    },
    /// What a check from outside the domain says, in its own words.
    Described(String),
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
}

impl Catalog {
    /// The catalog of `graph` under the hierarchy `authority`, when it keeps every invariant of
    /// [`super::catalog`]. The structure is checked first; the fixtures, only of a graph whose
    /// structure holds, are then folded by [`Catalog::fold`], the same transaction as a run.
    /// The catalog keeps the hierarchy.
    pub fn accept(graph: PolicyGraph, authority: Authority) -> Result<Self, Rejected> {
        let catalog = Self::accept_structure(graph, authority)?;
        let errors = fixture_errors(&catalog);
        if errors.is_empty() {
            Ok(catalog)
        } else {
            Err(Rejected(errors))
        }
    }

    /// The state after `event`, with [`TxPolicy::standard`]. An exemption that does not
    /// type-check against the guard it names (its target is read from the guard's subject, and
    /// the filter of a `Within(Since(..))` from its own kind), or that names no guard outside the
    /// meta layer, takes no effect.
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
    let carried = state.carry(table, event.at);
    if event.body.kind().nature() == Nature::Act {
        let report = TxReport {
            decision: TxDecision::Commit,
            findings: Vec::new(),
            uncovered: Vec::new(),
        };
        let kept = carried.step(table, event, catalog.guards(), catalog.authority());
        return (kept, report);
    }
    let after = carried
        .clone()
        .step(table, event, catalog.guards(), catalog.authority());
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
