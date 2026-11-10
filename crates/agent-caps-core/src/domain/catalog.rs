//! The aggregate of the rules: the policies, the overrides of the layers above them, the slots
//! their predicates need, and what each policy reads.
//!
//! The catalog is accepted whole, every time: [`Catalog::accept`] is the only way to make one,
//! and a catalog that exists keeps every invariant below. There is no operation that changes one
//! policy of an accepted catalog; a changed graph is accepted again, and
//! [`Catalog::change`] (see [`super::change`]) accepts it and judges whether the one who made
//! the change may.
//!
//! ```text
//! Catalog::accept (super::tx)
//!   accept_structure        every invariant but the fixtures: authors, types, rewards,
//!                           overrides, and what each policy reads (`Reads`)
//!   the fixtures            folded by the same transaction as a run (Catalog::fold)
//! ```
//!
//! This module holds the structure and the layering; folding events, and the transaction a claim
//! goes through, are [`super::tx`]'s, so the fixtures are checked by the same function that
//! decides at run time.
//!
//! The catalog keeps the [`Authority`] it was accepted with, and so the hierarchy one change is
//! judged by is always the catalog's own. To change the hierarchy, accept the graph again with
//! the new one; whether that loosens anything is a question for whoever keeps the hierarchy,
//! not one this module judges.
//!
//! # Layers
//!
//! ```text
//! Mode      the overrides of the mode in effect       (one mode at a time)
//! Project   the overrides of the project
//! Base      the policies as defined
//! ───────────────────────────────────────────────
//! Meta      fixed: no override, no exemption
//! ```
//!
//! The effective level of a policy is its base level with the project's override and then the
//! mode's applied over it. The order of the overrides within a layer never matters: a layer
//! holds at most one override per policy. When the mode is unknown, every mode's overrides are
//! tried to the end and each policy takes the strictest effect any mode gives, so not knowing
//! the mode never loosens a rule, and never gives a value no mode gives.
//! [`Catalog::effective`] gives that result for every policy, off ones included.
//!
//! # Invariants
//!
//! - Ids and names are unique.
//! - Every author of a policy and of an override is a principal of the catalog's [`Authority`]
//!   ([`AcceptError::UnknownAuthor`]), so [`Authority::covers`] is total on the authors.
//! - The author of a meta policy is a root of the hierarchy ([`AcceptError::MetaAuthorNotRoot`]):
//!   only the top places what nothing changes.
//! - A principal that `ActorUnder` names is a principal of the hierarchy
//!   ([`AcceptError::UnknownActor`]): the leaves that spawns add are new at every start, so a rule
//!   cannot name one. How a policy reads each such principal, in a direction a spawn's
//!   transaction can use, is part of what it reads ([`super::tx`]).
//! - An item refers only to items whose author is its own or above it
//!   ([`AcceptError::ReferencesBelow`]): a reward's `bound_by`, the policy an override
//!   targets, and every policy whose judgments a predicate of the policy reads. What is above
//!   never depends on what is below, so taking away one principal's work and everyone's below it
//!   leaves a graph that is still accepted.
//! - Which judgments a predicate reads is read from the filters of its temporal operators and of
//!   their `Since` scopes, one value per policy that the run-time checks read too, made from the
//!   predicates the catalog uses (see below). A filter of judgments narrows to the policies it
//!   names with `policy == id` or `policy in {ids}` (alone, within an `all`, or in an `any` every
//!   branch of which does), and then reads those. Every policy a filter names, wherever in the
//!   filter, is read as named: a policy named below is [`AcceptError::ReferencesBelow`], whatever
//!   the shape of the filter. A `last` of a judgment's field has no filter to narrow, so it reads
//!   every policy, and is not accepted beside a policy below.
//! - A filter of judgments that narrows to no policy sees the judgments of the policies of the
//!   catalog whose authors cover the author of its policy, its own and those above, and no
//!   others: a rule counts what it may trust. Who is visible is decided here, once, from the
//!   catalog's [`Authority`], and written into the predicate the catalog keeps for the policy
//!   (`policy in {the visible}`, all of the filter's own condition beside it, in the catalog's
//!   order, so two policies of one author share their slots). The policy as written is kept as
//!   it is: [`Catalog::graph`] and [`super::change::classify`] read it, so a difference between
//!   graphs is a difference of what was written. State and the transaction of a claim know
//!   nothing of who: they run the predicate they are given. A judgment of a policy that is not in
//!   the catalog is not seen by such a filter.
//! - What the predicate of a policy is, is decided only by the policy as written, the catalog's
//!   hierarchy and the policies of authors that cover its author. A policy of one below or beside
//!   an author does not change what that author's rules see, and a policy of one above or of the
//!   author itself cannot be made by one who does not cover it ([`super::change`]); so a change
//!   that [`super::change::classify`] reads from the written policies alone cannot loosen a rule
//!   through the predicates it does not read. A meta policy never changes, so it does not depend
//!   on a set that grows: it reads no judgment without naming the policies, neither in a filter
//!   that narrows to none nor in a `last` of a judgment's field
//!   ([`AcceptError::MetaReadsUnscoped`]). So a genuine record of a judgment, written in the name of
//!   the judged policy's author, is always one its reader may count ([`super::tx`]): what is
//!   checked here is what is used there.
//! - A reward is bound by a guard that exists, and is not stronger than it as defined. After the
//!   overrides, a reward stronger than its guard is lowered to the guard's level, and a reward
//!   whose guard is off is off; both are reported as [`Degraded`], never done silently.
//! - Every predicate reads each field from its own kind of event, with an operand of its type;
//!   so does the filter of a `Since` scope.
//! - An exemption that arrives as an event takes effect only if it names a guard of the catalog
//!   and reads its target and the filter of a `Within(Since(..))` as a predicate would
//!   ([`Catalog::apply`]).
//! - No override reaches a meta policy, and no override gives a reward Force.
//! - A guard that is Force, as defined or through any override of any layer, has at
//!   least one fixture it fails on and one it holds on: an override cannot make a stopping guard
//!   that was never checked on an example.
//! - Every fixture of a structural policy gives the finding it expects, except those marked as
//!   known gaps. A fixture is folded as a run is, so a claim in it takes effect, or not, as it
//!   would at run time.
//!
//! # Errors
//!
//! [`Catalog::accept`] returns every [`AcceptError`] it finds at once, in [`Rejected`], so a
//! policy graph can be fixed in one pass.

use std::collections::{HashMap, HashSet};
use std::fmt;

use super::authority::{Authority, Principal};
use super::name::{Mode, PolicyId, PolicyName};
use super::policy::{
    Change, DefLayer, Expect, Level, Override, OverrideLayer, Polarity, Policy, PolicyDef,
    PolicyGraph, Rule,
};
use super::predicate::{
    JudgedRead, PredError, Reading, Scope, Site, StateAtom, Temporal, judged_read, note_reading,
    state_readings,
};
use super::schema::EventKind;
use super::state::{GuardIndex, Known, SlotId, SlotTable, State};

/// One item of a policy graph: a policy, or the override of a layer on a policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    /// The policy.
    Policy(PolicyId),
    /// The override of the layer on the policy.
    Override(OverrideLayer, PolicyId),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(id) => write!(f, "policy {id}"),
            Self::Override(OverrideLayer::Project, id) => {
                write!(f, "the project's override of {id}")
            }
            Self::Override(OverrideLayer::Mode(mode), id) => {
                write!(f, "mode {mode}'s override of {id}")
            }
        }
    }
}

/// One reason a policy graph was not accepted.
#[derive(Debug, Clone, PartialEq)]
pub enum AcceptError {
    /// The author of the item is not a principal of the hierarchy.
    UnknownAuthor {
        /// The item.
        item: Target,
        /// The author it names.
        author: Principal,
    },
    /// The author of the meta policy is not a root of the hierarchy.
    MetaAuthorNotRoot {
        /// The meta policy.
        policy: PolicyId,
        /// Its author.
        author: Principal,
    },
    /// The item refers to a policy whose author is below its own, or beside it: a reward bound
    /// by it, an override that targets it, or a policy whose predicate names it in a filter of
    /// judgments (`policy == id`, `policy in {ids}`, wherever in the filter), or reads every
    /// policy's judgments with a `last` of a judgment's field. A filter of judgments that narrows
    /// to no policy (names none, or names one only where it does not narrow, as in
    /// `any(policy == id, judgment == denied)`) is not this for what it does not name: it sees
    /// only the policies its author may count. To fix a predicate, name only the policies of its
    /// own author or of one above.
    ReferencesBelow {
        /// The item.
        item: Target,
        /// The policy it refers to.
        referenced: PolicyId,
    },
    /// A predicate of the policy reads `ActorUnder` of a principal that is not in the
    /// hierarchy. The leaves that spawns add have names that are new at every start, so a rule
    /// can name only a principal of the hierarchy.
    UnknownActor {
        /// The policy.
        policy: PolicyId,
        /// The principal it names.
        principal: Principal,
    },
    /// The meta policy reads judgments without naming the policies: a filter of judgments that
    /// narrows to no policy, or a `last` of a judgment's field. What such a read sees grows with
    /// the policies of the catalog, and a meta policy depends on nothing that changes. To fix
    /// it, name the policies whose judgments it reads.
    MetaReadsUnscoped(PolicyId),
    /// Two policies have the id.
    DuplicateId(PolicyId),
    /// Two policies have the name.
    DuplicateName(PolicyName),
    /// A predicate of the policy reads a field it cannot.
    Predicate {
        /// The policy.
        policy: PolicyId,
        /// What is wrong.
        error: PredError,
    },
    /// The reward is bound by a policy that does not exist.
    UnknownBound {
        /// The reward.
        reward: PolicyId,
        /// The id it names.
        bound_by: PolicyId,
    },
    /// The reward is bound by another reward, not by a guard.
    BoundByReward {
        /// The reward.
        reward: PolicyId,
        /// The reward it names.
        bound_by: PolicyId,
    },
    /// The reward is defined stronger than its guard.
    RewardAboveGuard {
        /// The reward.
        reward: PolicyId,
        /// Its guard.
        guard: PolicyId,
    },
    /// The Force guard lacks a fixture it fails on, or one it holds on.
    MissingFixtures(PolicyId),
    /// The override raises the guard to Force, and the guard lacks a fixture it fails
    /// on, or one it holds on.
    RaisedWithoutFixtures {
        /// The guard.
        policy: PolicyId,
        /// The layer of the override that raises it.
        layer: OverrideLayer,
        /// The level it is raised to.
        level: Level,
    },
    /// The fixture has no event to judge.
    EmptyFixture {
        /// The policy.
        policy: PolicyId,
        /// The fixture.
        fixture: String,
    },
    /// The fixture's last event was not found as expected.
    FixtureFailed {
        /// The policy.
        policy: PolicyId,
        /// The fixture.
        fixture: String,
        /// What it expects.
        expected: Expect,
        /// What the policy found.
        found: Expect,
    },
    /// The override names a policy that does not exist.
    UnknownOverride(PolicyId),
    /// The override names a meta policy.
    MetaOverride(PolicyId),
    /// The override gives a reward a level it cannot have.
    RewardOverrideLevel {
        /// The reward.
        policy: PolicyId,
        /// The level.
        level: Level,
    },
    /// The layer has two overrides of the policy.
    DuplicateOverride(PolicyId),
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownAuthor { item, author } => {
                write!(f, "{item} is by {author}, who is not in the hierarchy")
            }
            Self::MetaAuthorNotRoot { policy, author } => write!(
                f,
                "meta policy {policy} is by {author}, who is not a root of the hierarchy"
            ),
            Self::ReferencesBelow { item, referenced } => write!(
                f,
                "{item} refers to {referenced}, whose author is not its own or above it"
            ),
            Self::UnknownActor { policy, principal } => write!(
                f,
                "policy {policy} reads the actor {principal}, who is not in the hierarchy"
            ),
            Self::MetaReadsUnscoped(policy) => write!(
                f,
                "meta policy {policy} reads judgments without naming the policies"
            ),
            Self::DuplicateId(id) => write!(f, "two policies have the id {id}"),
            Self::DuplicateName(name) => write!(f, "two policies have the name {name}"),
            Self::Predicate { policy, error } => write!(f, "policy {policy}: {error}"),
            Self::UnknownBound { reward, bound_by } => {
                write!(
                    f,
                    "reward {reward} is bound by {bound_by}, which does not exist"
                )
            }
            Self::BoundByReward { reward, bound_by } => {
                write!(
                    f,
                    "reward {reward} is bound by {bound_by}, which is not a guard"
                )
            }
            Self::RewardAboveGuard { reward, guard } => {
                write!(f, "reward {reward} is stronger than its guard {guard}")
            }
            Self::MissingFixtures(id) => write!(
                f,
                "guard {id} stops events but lacks a fixture it fails on or one it holds on"
            ),
            Self::RaisedWithoutFixtures {
                policy,
                layer,
                level,
            } => {
                let layer = match layer {
                    OverrideLayer::Project => "the project".to_owned(),
                    OverrideLayer::Mode(mode) => format!("mode {mode}"),
                };
                write!(
                    f,
                    "an override of {layer} raises guard {policy} to {level:?}, but the guard \
                     lacks a fixture it fails on or one it holds on"
                )
            }
            Self::EmptyFixture { policy, fixture } => {
                write!(f, "fixture `{fixture}` of {policy} has no event")
            }
            Self::FixtureFailed {
                policy,
                fixture,
                expected,
                found,
            } => write!(
                f,
                "fixture `{fixture}` of {policy} expects {expected:?} and found {found:?}"
            ),
            Self::UnknownOverride(id) => write!(f, "an override names {id}, which does not exist"),
            Self::MetaOverride(id) => write!(f, "an override names the meta policy {id}"),
            Self::RewardOverrideLevel { policy, level } => {
                write!(
                    f,
                    "an override gives the reward {policy} the level {level:?}"
                )
            }
            Self::DuplicateOverride(id) => write!(f, "a layer overrides {id} twice"),
        }
    }
}

/// Why a policy graph was not accepted: every reason found.
#[derive(Debug, Clone, PartialEq)]
pub struct Rejected(pub Vec<AcceptError>);

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the policy graph was not accepted:")?;
        for error in &self.0 {
            write!(f, "\n- {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Rejected {}

/// A level the platform or the layers could not keep as written, and what was done instead.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Degraded {
    /// The reward was stronger than its guard after the overrides, and was lowered to it.
    RewardLowered {
        /// The reward.
        reward: PolicyId,
        /// Its guard.
        guard: PolicyId,
        /// The level it is lowered to.
        to: Level,
    },
    /// The reward's guard is off, so the reward is off.
    RewardWithoutGuard {
        /// The reward.
        reward: PolicyId,
        /// Its guard.
        guard: PolicyId,
    },
}

/// Whether a policy takes effect under a mode, after the overrides and the binding of rewards to
/// their guards.
///
/// Ordered by how much it holds, least first: `Off < On(Inform) < On(Advise) < On(Force)`. This
/// order is the one comparison of effects: what is "at least as strict" anywhere is `>=` here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effect {
    /// It does not take effect: turned off by a layer, or a reward whose guard is off.
    Off,
    /// It takes effect, at this level.
    On(Level),
}

/// One policy and its effect under a mode.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PolicyEffect<'a> {
    /// The policy.
    pub policy: &'a Policy,
    /// Its effect.
    pub effect: Effect,
}

/// What the catalog comes to under one mode: every policy with its effect, and what the layers
/// could not keep as written. This is what a platform adapter turns into hooks, instructions and
/// text; [`super::judge::judge`] reads the same value, so the two never disagree.
#[derive(Debug, Clone, PartialEq)]
pub struct Effective<'a> {
    /// Every policy of the catalog, in the catalog's order, with its effect.
    pub policies: Vec<PolicyEffect<'a>>,
    /// What had to be degraded.
    pub degraded: Vec<Degraded>,
}

impl<'a> Effective<'a> {
    /// The policies that take effect, each with its level.
    pub fn on(&self) -> impl Iterator<Item = (&'a Policy, Level)> + '_ {
        self.policies.iter().filter_map(|p| match p.effect {
            Effect::On(level) => Some((p.policy, level)),
            Effect::Off => None,
        })
    }
}

/// One policy that takes effect less strongly in one effective list than in another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Lowered {
    /// The policy.
    pub policy: PolicyId,
    /// What it comes to in the first list.
    pub before: Effect,
    /// What it comes to in the second, below `before`.
    pub after: Effect,
}

/// The policies that take effect less strongly in `after` than in `before`, in the order of
/// `before`: the one answer to "does the effect of a policy go down", by the order of [`Effect`].
/// A policy missing from either list is not compared; its removal is a question of its own.
pub fn lowered(before: &Effective<'_>, after: &Effective<'_>) -> Vec<Lowered> {
    let after_of: HashMap<PolicyId, Effect> = after
        .policies
        .iter()
        .map(|a| (a.policy.id(), a.effect))
        .collect();
    before
        .policies
        .iter()
        .filter_map(|b| {
            let id = b.policy.id();
            let after = *after_of.get(&id)?;
            (after < b.effect).then_some(Lowered {
                policy: id,
                before: b.effect,
                after,
            })
        })
        .collect()
}

/// What one policy reads, from its predicates (`when` and `rule`) as the catalog uses them: the
/// one value the run-time checks of a claim ([`super::tx`]) read (its slots and modes), and the
/// check of references here reads (the judgments it reads).
#[derive(Debug, Clone, PartialEq, Default)]
pub(super) struct Reads {
    /// The slots of its temporal operators (`once`, `count`, `last`), each with its scope.
    slots: Vec<SlotId>,
    /// The judgments those operators and the filters of their `Since` scopes read.
    judged: Vec<JudgedRead>,
    /// The modes it reads with `ModeIs`. The mode's scope is read through `slots`.
    modes: Vec<Mode>,
    /// The principals it reads with `ActorUnder`, each with the direction it reads it in. A
    /// principal read in two directions is `Unreadable`.
    actors: Vec<(Principal, Reading)>,
}

impl Reads {
    /// What `policy` reads, with the slots of `table`.
    fn of(policy: &Policy, table: &SlotTable) -> Self {
        let mut reads = Self::default();
        for pred in policy.preds() {
            for temporal in pred.temporals() {
                if let Some(slot) = table.id_of(&temporal)
                    && !reads.slots.contains(&slot)
                {
                    reads.slots.push(slot);
                }
                let (judged, scope) = match &temporal {
                    Temporal::Once(filter, scope) | Temporal::Count(filter, scope) => {
                        (judged_read(filter), scope)
                    }
                    Temporal::Last(field, scope) => (
                        (field.kind() == EventKind::Judged).then(JudgedRead::every),
                        scope,
                    ),
                };
                let since = match scope {
                    Scope::Since(filter) => judged_read(filter),
                    _ => None,
                };
                for read in judged.into_iter().chain(since) {
                    if !reads.judged.contains(&read) {
                        reads.judged.push(read);
                    }
                }
            }
        }
        let sites = if policy.is_guard() {
            (Site::GuardWhen, Site::GuardRule)
        } else {
            (Site::Reward, Site::Reward)
        };
        let when = policy.when().map(|when| (when, sites.0));
        for (pred, site) in when.into_iter().chain([(policy.rule(), sites.1)]) {
            for (atom, reading) in state_readings(pred, site) {
                match atom {
                    StateAtom::Mode(mode) => {
                        if !reads.modes.contains(mode) {
                            reads.modes.push(mode.clone());
                        }
                    }
                    StateAtom::Actor(principal) => {
                        note_reading(&mut reads.actors, principal.clone(), reading);
                    }
                }
            }
        }
        reads
    }

    /// The principals the policy reads with `ActorUnder`, each with the direction it reads it in.
    pub(super) fn actors(&self) -> &[(Principal, Reading)] {
        &self.actors
    }

    /// Whether the policy reads the slot.
    pub(super) fn reads_slot(&self, slot: SlotId) -> bool {
        self.slots.contains(&slot)
    }

    /// The modes the policy reads with `ModeIs`.
    pub(super) fn modes(&self) -> &[Mode] {
        &self.modes
    }
}

/// The accepted rules.
#[derive(Debug, Clone, PartialEq)]
pub struct Catalog {
    policies: Vec<Policy>,
    overrides: Vec<Override>,
    slots: SlotTable,
    /// What each policy reads, in the order of `policies`.
    reads: Vec<Reads>,
    guards: GuardIndex,
    authority: Authority,
}

impl Catalog {
    /// The catalog of `graph` under the hierarchy `authority`, when it keeps every invariant of
    /// the module doc but the one on fixtures, which [`Catalog::accept`] checks after it. The
    /// catalog keeps the hierarchy.
    pub(super) fn accept_structure(
        graph: PolicyGraph,
        authority: Authority,
    ) -> Result<Self, Rejected> {
        let mut errors = Vec::new();
        check_authors(&graph, &authority, &mut errors);
        check_policies(&graph, &mut errors);
        check_overrides(&graph, &mut errors);
        let policies = compile_policies(graph.policies, &authority);
        let slots = SlotTable::of(policies.iter().flat_map(Policy::preds));
        let reads: Vec<Reads> = policies.iter().map(|p| Reads::of(p, &slots)).collect();
        check_reads(&policies, &reads, &authority, &mut errors);
        check_actors(&policies, &reads, &authority, &mut errors);
        let guards = GuardIndex::new(
            policies
                .iter()
                .filter(|p| p.is_guard() && p.layer() != DefLayer::Meta)
                .map(|p| (p.id(), p.subject())),
        );
        if errors.is_empty() {
            Ok(Self {
                policies,
                overrides: graph.overrides,
                slots,
                reads,
                guards,
                authority,
            })
        } else {
            Err(Rejected(errors))
        }
    }

    /// The hierarchy the catalog was accepted with.
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// The graph the catalog was accepted from.
    pub fn graph(&self) -> PolicyGraph {
        PolicyGraph {
            policies: self.policies.iter().map(|p| p.def().clone()).collect(),
            overrides: self.overrides.clone(),
        }
    }

    /// The overrides, in the order they were given.
    pub(super) fn overrides(&self) -> &[Override] {
        &self.overrides
    }

    /// The policies, as defined.
    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    /// The policy with the id.
    pub fn policy(&self, id: PolicyId) -> Option<&Policy> {
        self.policies.iter().find(|p| p.id() == id)
    }

    /// The state before any event.
    pub fn start(&self) -> State {
        State::start(&self.slots)
    }

    pub(super) fn slots(&self) -> &SlotTable {
        &self.slots
    }

    /// The guards an exemption may name.
    pub(super) fn guards(&self) -> &GuardIndex {
        &self.guards
    }

    /// Each policy with what it reads, in the catalog's order.
    pub(super) fn reads(&self) -> impl Iterator<Item = (&Policy, &Reads)> {
        self.policies.iter().zip(&self.reads)
    }

    /// What the catalog comes to under `mode`: every policy with its effect, and what had to be
    /// degraded. When the mode is unknown, every mode is computed to the end (rewards bound to
    /// their guards) and each policy takes the strictest effect any of them gives; what was
    /// degraded is what a mode degraded and the strictest effect still shows. No event is
    /// judged; this is the catalog alone.
    pub fn effective(&self, mode: &Known<Option<Mode>>) -> Effective<'_> {
        effective_in(&self.policies, &self.overrides, mode)
    }

    /// Every mode an override names.
    pub(super) fn modes(&self) -> Vec<&Mode> {
        modes_of(&self.overrides)
    }
}

/// What `policies` come to under `mode` with `overrides` over them: the one implementation of
/// the layering, of the modes and of the binding of rewards to guards. [`Catalog::effective`]
/// reads it for the catalog, and a change reads it for a graph narrowed to what one does not
/// cover, which is never made a catalog.
pub(super) fn effective_in<'a>(
    policies: &'a [Policy],
    overrides: &[Override],
    mode: &Known<Option<Mode>>,
) -> Effective<'a> {
    match mode {
        Known::Known(mode) => effective_under(policies, overrides, mode.as_ref()),
        Known::Unknown => {
            // Each candidate mode is computed to the end, rewards bound; then each policy takes
            // the strictest effect any of them gives. Not knowing the mode is never a value of
            // its own: it is the strictest of the modes it may be.
            let mut strictest = effective_under(policies, overrides, None);
            for mode in modes_of(overrides) {
                let candidate = effective_under(policies, overrides, Some(mode));
                // Both list every policy in the order of `policies`.
                for (kept, other) in strictest.policies.iter_mut().zip(candidate.policies) {
                    kept.effect = kept.effect.max(other.effect);
                }
                for d in candidate.degraded {
                    if !strictest.degraded.contains(&d) {
                        strictest.degraded.push(d);
                    }
                }
            }
            // Of what the modes degraded, only what the strictest effect still shows: a reward
            // lowered or turned off under one mode may stand under another.
            let effect_of = |id: PolicyId| {
                strictest
                    .policies
                    .iter()
                    .find(|p| p.policy.id() == id)
                    .map(|p| p.effect)
            };
            let degraded = strictest
                .degraded
                .iter()
                .filter(|d| match d {
                    Degraded::RewardLowered { reward, to, .. } => {
                        effect_of(*reward) == Some(Effect::On(*to))
                    }
                    Degraded::RewardWithoutGuard { reward, .. } => {
                        effect_of(*reward) == Some(Effect::Off)
                    }
                })
                .cloned()
                .collect();
            strictest.degraded = degraded;
            strictest
        }
    }
}

/// What `policies` come to under one known mode.
fn effective_under<'a>(
    policies: &'a [Policy],
    overrides: &[Override],
    mode: Option<&Mode>,
) -> Effective<'a> {
    let mut in_effect: Vec<(&Policy, Option<Level>)> = policies
        .iter()
        .map(|policy| (policy, level_under(policy, overrides, mode)))
        .collect();
    let degraded = bind_rewards(&mut in_effect);
    let policies = in_effect
        .into_iter()
        .map(|(policy, level)| PolicyEffect {
            policy,
            effect: level.map_or(Effect::Off, Effect::On),
        })
        .collect();
    Effective { policies, degraded }
}

/// Every mode an override names.
pub(super) fn modes_of(overrides: &[Override]) -> Vec<&Mode> {
    let mut modes: Vec<&Mode> = Vec::new();
    for o in overrides {
        if let OverrideLayer::Mode(mode) = &o.layer
            && !modes.contains(&mode)
        {
            modes.push(mode);
        }
    }
    modes
}

/// The level of `policy` under `mode`, or `None` when it is off.
fn level_under(policy: &Policy, overrides: &[Override], mode: Option<&Mode>) -> Option<Level> {
    let mut enabled = policy.enabled();
    let mut level = policy.base_level();
    if policy.layer() == DefLayer::Base {
        let project = override_of(overrides, policy.id(), &OverrideLayer::Project);
        let by_mode =
            mode.and_then(|m| override_of(overrides, policy.id(), &OverrideLayer::Mode(m.clone())));
        for change in project.into_iter().chain(by_mode) {
            match change {
                Change::Level(new) => level = new,
                Change::Off => enabled = false,
                Change::On => enabled = true,
            }
        }
    }
    enabled.then_some(level)
}

fn override_of(overrides: &[Override], policy: PolicyId, layer: &OverrideLayer) -> Option<Change> {
    overrides
        .iter()
        .find(|o| o.policy == policy && o.layer == *layer)
        .map(|o| o.change)
}

/// Keeps each reward within its guard: off when the guard is off, no stronger than it.
fn bind_rewards(in_effect: &mut [(&Policy, Option<Level>)]) -> Vec<Degraded> {
    let guard_levels: Vec<(PolicyId, Option<Level>)> = in_effect
        .iter()
        .map(|(policy, level)| (policy.id(), *level))
        .collect();
    let mut degraded = Vec::new();
    for (policy, level) in in_effect.iter_mut() {
        let (Polarity::Reward { bound_by, .. }, Some(current)) = (policy.polarity(), *level) else {
            continue;
        };
        let guard_level = guard_levels
            .iter()
            .find(|(id, _)| id == bound_by)
            .and_then(|(_, level)| *level);
        match guard_level {
            None => {
                *level = None;
                degraded.push(Degraded::RewardWithoutGuard {
                    reward: policy.id(),
                    guard: *bound_by,
                });
            }
            Some(guard) if current > guard => {
                *level = Some(guard);
                degraded.push(Degraded::RewardLowered {
                    reward: policy.id(),
                    guard: *bound_by,
                    to: guard,
                });
            }
            Some(_) => {}
        }
    }
    degraded
}

/// The authors are of the hierarchy, a meta policy is by a root, and nothing refers below its
/// author. A reference is checked only when both authors are of the hierarchy.
fn check_authors(graph: &PolicyGraph, authority: &Authority, errors: &mut Vec<AcceptError>) {
    let author_of = |id: PolicyId| {
        graph
            .policies
            .iter()
            .find(|p| p.id == id)
            .map(|p| &p.author)
            .filter(|author| authority.contains(author))
    };
    for def in &graph.policies {
        if !authority.contains(&def.author) {
            errors.push(AcceptError::UnknownAuthor {
                item: Target::Policy(def.id),
                author: def.author.clone(),
            });
            continue;
        }
        if def.layer == DefLayer::Meta && !authority.is_root(&def.author) {
            errors.push(AcceptError::MetaAuthorNotRoot {
                policy: def.id,
                author: def.author.clone(),
            });
        }
        if let Polarity::Reward { bound_by, .. } = &def.polarity
            && let Some(above) = author_of(*bound_by)
            && !authority.covers(above, &def.author)
        {
            errors.push(AcceptError::ReferencesBelow {
                item: Target::Policy(def.id),
                referenced: *bound_by,
            });
        }
    }
    for o in &graph.overrides {
        let item = || Target::Override(o.layer.clone(), o.policy);
        if !authority.contains(&o.author) {
            errors.push(AcceptError::UnknownAuthor {
                item: item(),
                author: o.author.clone(),
            });
        } else if let Some(above) = author_of(o.policy)
            && !authority.covers(above, &o.author)
        {
            errors.push(AcceptError::ReferencesBelow {
                item: item(),
                referenced: o.policy,
            });
        }
    }
}

/// The policies of the catalog, each with the predicates the catalog uses: the one place that
/// decides which judgments a filter that narrows to no policy sees. A policy sees the judgments of the
/// policies, in the order given, whose authors cover its own ([`Authority::covers`]: its own
/// author and those above). A meta policy is not given this, as it reads no judgment unnarrowed
/// ([`AcceptError::MetaReadsUnscoped`]); nor is one whose author is not of the hierarchy, which
/// [`check_authors`] rejects. Every other policy is, whether or not it has such a filter, so that
/// its predicates are decided by the same three things always.
fn compile_policies(defs: Vec<PolicyDef>, authority: &Authority) -> Vec<Policy> {
    let in_hierarchy = |def: &PolicyDef| authority.contains(&def.author);
    let visible_to = |reader: &PolicyDef| -> Vec<PolicyId> {
        defs.iter()
            .filter(|def| in_hierarchy(def) && authority.covers(&def.author, &reader.author))
            .map(|def| def.id)
            .collect()
    };
    defs.iter()
        .map(|def| {
            if def.layer == DefLayer::Meta || !in_hierarchy(def) {
                Policy::new(def.clone())
            } else {
                Policy::scoped(def.clone(), &visible_to(def))
            }
        })
        .collect()
}

/// No policy reads the judgments of a policy whose author does not cover its own, and no meta
/// policy reads judgments without naming the policies. A reference is checked only when both
/// authors are of the hierarchy, as in [`check_authors`].
///
/// What is read is [`Reads`], made from the predicates the catalog uses. A filter that narrows to
/// no policy has been narrowed to the policies its author may count, so it reads none below; a
/// policy named, in any shape of filter, and a `last` of a judgment's field, which reads every
/// policy, are what can be below. A meta policy's reads are made from its predicates as
/// written, so a read of every policy is the one thing its check looks for; the policies it
/// names are checked as any other's, and it is not also told off for every policy below that a
/// read of every policy would reach.
fn check_reads(
    policies: &[Policy],
    reads: &[Reads],
    authority: &Authority,
    errors: &mut Vec<AcceptError>,
) {
    for (reader, reads) in policies.iter().zip(reads) {
        if !authority.contains(reader.author()) {
            continue;
        }
        let meta = reader.layer() == DefLayer::Meta;
        if meta && reads.judged.iter().any(|read| read.narrowed.is_none()) {
            let error = AcceptError::MetaReadsUnscoped(reader.id());
            if !errors.contains(&error) {
                errors.push(error);
            }
        }
        // Only a policy below can be an error, so that is asked first: what a compiled filter
        // names holds every policy its author may count, none of which is below.
        let below = |target: &&Policy| {
            authority.contains(target.author())
                && !authority.covers(target.author(), reader.author())
        };
        for read in &reads.judged {
            let every = read.narrowed.is_none() && !meta;
            for target in policies
                .iter()
                .filter(below)
                .filter(|p| every || read.names(p.id()))
            {
                let error = AcceptError::ReferencesBelow {
                    item: Target::Policy(reader.id()),
                    referenced: target.id(),
                };
                if !errors.contains(&error) {
                    errors.push(error);
                }
            }
        }
    }
}

/// Every principal a policy reads with `ActorUnder` is a principal of the hierarchy: what a
/// policy reads is [`Reads`], the value the transaction of a spawn reads too.
fn check_actors(
    policies: &[Policy],
    reads: &[Reads],
    authority: &Authority,
    errors: &mut Vec<AcceptError>,
) {
    for (policy, reads) in policies.iter().zip(reads) {
        for (principal, _) in reads.actors() {
            if !authority.contains(principal) {
                errors.push(AcceptError::UnknownActor {
                    policy: policy.id(),
                    principal: principal.clone(),
                });
            }
        }
    }
}

fn check_policies(graph: &PolicyGraph, errors: &mut Vec<AcceptError>) {
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for def in &graph.policies {
        if !ids.insert(def.id) {
            errors.push(AcceptError::DuplicateId(def.id));
        }
        if !names.insert(&def.name) {
            errors.push(AcceptError::DuplicateName(def.name.clone()));
        }
        let Rule::Structural(rule) = &def.rule;
        for pred in def.when.iter().chain(std::iter::once(rule)) {
            for error in pred.check(def.subject) {
                errors.push(AcceptError::Predicate {
                    policy: def.id,
                    error,
                });
            }
        }
        match &def.polarity {
            Polarity::Reward { level, bound_by } => {
                match graph.policies.iter().find(|p| p.id == *bound_by) {
                    None => errors.push(AcceptError::UnknownBound {
                        reward: def.id,
                        bound_by: *bound_by,
                    }),
                    Some(guard) => match guard.polarity {
                        Polarity::Reward { .. } => errors.push(AcceptError::BoundByReward {
                            reward: def.id,
                            bound_by: *bound_by,
                        }),
                        Polarity::Guard { level: guard_level } => {
                            if Level::from(*level) > guard_level {
                                errors.push(AcceptError::RewardAboveGuard {
                                    reward: def.id,
                                    guard: *bound_by,
                                });
                            }
                        }
                    },
                }
            }
            Polarity::Guard { level } if level.stops() => {
                if !has_stopping_fixtures(def) {
                    errors.push(AcceptError::MissingFixtures(def.id));
                }
            }
            Polarity::Guard { .. } => {}
        }
    }
}

fn check_overrides(graph: &PolicyGraph, errors: &mut Vec<AcceptError>) {
    let mut seen = HashSet::new();
    for o in &graph.overrides {
        if !seen.insert((&o.layer, o.policy)) {
            errors.push(AcceptError::DuplicateOverride(o.policy));
        }
        let Some(def) = graph.policies.iter().find(|p| p.id == o.policy) else {
            errors.push(AcceptError::UnknownOverride(o.policy));
            continue;
        };
        if def.layer == DefLayer::Meta {
            errors.push(AcceptError::MetaOverride(o.policy));
        }
        match (&def.polarity, o.change) {
            (Polarity::Reward { .. }, Change::Level(level)) if level.stops() => {
                errors.push(AcceptError::RewardOverrideLevel {
                    policy: o.policy,
                    level,
                });
            }
            // A guard that already stops as defined is reported once, by `check_policies`; an
            // override of a meta policy never applies, and is reported as `MetaOverride`.
            (Polarity::Guard { level: defined }, Change::Level(level))
                if def.layer == DefLayer::Base
                    && level.stops()
                    && !defined.stops()
                    && !has_stopping_fixtures(def) =>
            {
                errors.push(AcceptError::RaisedWithoutFixtures {
                    policy: o.policy,
                    layer: o.layer.clone(),
                    level,
                });
            }
            _ => {}
        }
    }
}

/// Whether the guard has, besides its known gaps, a fixture it fails on and one it holds on: what
/// a stopping guard needs, whichever layer makes it stop.
fn has_stopping_fixtures(def: &PolicyDef) -> bool {
    let real = || def.fixtures.iter().filter(|f| !f.known_gap);
    let fails = real().any(|f| f.expect == Expect::Violated);
    let holds = real().any(|f| f.expect == Expect::Satisfied);
    fails && holds
}
