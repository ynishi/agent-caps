//! The aggregate of the rules: the policies, the bindings that put them into effect, the slots
//! their predicates need, and what each policy reads.
//!
//! The catalog is accepted whole, every time: [`Catalog::accept`] is the only way to make one,
//! and a catalog that exists keeps every invariant below. It is accepted from its sets of
//! policies, [`Sources`], and keeps them: the graph it reads is the one they compose to
//! ([`Sources::compose`], [`super::set`]). There is no operation that changes one policy of an
//! accepted catalog; changed sources are accepted again, and [`Catalog::change`] (see
//! [`super::change`]) accepts them and judges whether the one who made the change may. A catalog
//! of one set is sources of one set, `Sources::new(vec![Source { id, name, owner, graph }])`.
//!
//! ```text
//! Catalog::accept(sources, authority) (super::tx)
//!   accept_structure        the owners: every item of a set is by its owner or one below
//!                           (Authority::within); the composition (Sources::compose); then
//!                           every invariant but the fixtures, of the composed graph: authors,
//!                           types, rewards, bindings, and what each policy reads (`Reads`)
//!   the fixtures            folded by the same transaction as a run (Catalog::fold)
//! ```
//!
//! This module holds the structure and the bindings; folding events, and the transaction a claim
//! goes through, are [`super::tx`]'s, so the fixtures are checked by the same function that
//! decides at run time.
//!
//! The catalog keeps the [`Authority`] it was accepted with, and so the hierarchy one change is
//! judged by is always the catalog's own. To change the hierarchy, accept the sources again with
//! the new one; whether that loosens anything is a question for whoever keeps the hierarchy,
//! not one this module judges.
//!
//! # Bindings
//!
//! ```text
//! Binding { policy, level, mode: ModeScope, author }    a policy, at a level, where the scope holds
//!   effect of a policy under a mode = the strongest level of its bindings whose scope
//!                                      does not fail to hold, or Off with none
//!   then a guard at Force that reads a classifier whose record falls short of its bound
//!   is lowered to Advise (Degraded::Uncalibrated)
//!   then each reward is held to its guard (Degraded)
//! + a state's temporary adjustments (Catalog::effective_in)
//!   bindings of the catalog a held adjustment suspends do not hold; each binding one adds holds
//!   under every mode, by the one who made it; the strongest still wins
//! ───────────────────────────────────────────────
//! Meta      fixed: one binding, by its author, under every mode; no adjustment
//! ```
//!
//! The strongest binding wins, whatever the order of the bindings and whoever wrote them, so
//! adding a binding never lowers a policy: a policy goes down only when a binding that carried
//! its strength is removed, weakened, or stops holding. Whether a binding holds under a mode is
//! [`ModeScope::holds`]. When the mode is unknown, each mode it may be is computed, rewards held
//! to their guards in each, and each policy takes the strongest effect any of them gives (so a
//! guard the strongest level any of its bindings gives), and not knowing the mode never loosens a
//! rule. That is decided in one place, [`Catalog::effective`], which
//! gives the result for every policy, off ones included.
//!
//! # Capabilities
//!
//! ```text
//! bindings and mode    ─▶ Effective   the strength as written (`Effective::degraded`)
//! + Capabilities       ─▶ Enforced    the strength the platform holds (`Enforced::lowered`)
//!      each policy held to the cap of its own subject; each reward held to its guard
//! ```
//!
//! What a platform can enforce is data, in the words of an event filter ([`Capabilities`]), and is
//! supplied with each judgment; the catalog is the same on every platform. The written strength
//! ([`Effective`]) and the enforced strength ([`Enforced`]) are separate types, so one is not
//! taken for the other: [`Catalog::change`], the checks of a claim and the fixtures read only the
//! written strength, which does not depend on the platform (a platform that squashes Force to
//! Advise does not make a change that lowers the guard to Advise harmless), and a stop is decided
//! by the enforced one. Lowering is a report of a fact of the platform, not a loosening that
//! someone made: no transaction and no `may_loosen` is asked, and each lowering is reported
//! ([`Lowering`]) apart from what the bindings degraded ([`Degraded`]).
//!
//! The cap is the lowest level among the possible worlds ([`Capabilities::cap`]), as an unknown
//! mode is the strictest of the modes it may be, turned round. How a judgment and a list lower,
//! and how a reward follows its guard, is stated at [`Catalog::enforced`].
//! [`Catalog::check_capabilities`] lists, mode by mode, what a platform cannot hold of this
//! catalog, for a caller that refuses such a catalog when it loads it.
//!
//! # Invariants
//!
//! - Ids and names of policies are unique, and so are the ids of bindings: the
//!   [`PolicyGraph`] of a set cannot hold a duplicate ([`PolicyGraph::parse`],
//!   [`super::policy::Clash`]), and two sets compose only when they hold the same item under
//!   each id they share, and no two policies of one name ([`AcceptError::Conflict`]). A binding
//!   names a policy of the composed graph ([`AcceptError::UnknownBindingPolicy`]), whichever set
//!   holds it.
//! - The owner of every set is a principal of the hierarchy ([`AcceptError::UnknownOwner`]), and
//!   every item of a set is by its owner or one below it ([`AcceptError::NotWithinOwner`]), so a
//!   set holds only what its owner may loosen ([`super::set`]).
//! - Every author of a policy and of a binding is a principal of the catalog's [`Authority`]
//!   ([`AcceptError::UnknownAuthor`]), so [`Authority::covers`] is total on the authors.
//! - The author of a meta policy is a root of the hierarchy ([`AcceptError::MetaAuthorNotRoot`]):
//!   only the top places what nothing changes.
//! - A principal that `ActorUnder` names, or that a selector or a scope chooses events by
//!   (`By::Under`, `By::Only`), is a principal of the hierarchy ([`AcceptError::UnknownActor`]):
//!   the leaves that spawns add are new at every start, so a rule cannot name one. How a policy
//!   reads each `ActorUnder` and `By::Under` principal, in a direction a spawn's transaction can
//!   use, is part of what it reads ([`super::tx`]); a spawn cannot move a `By::Only`.
//! - An item refers only to items whose author is its own or above it
//!   ([`AcceptError::ReferencesBelow`]): a reward's `bound_by`, the policy a binding puts into
//!   effect, and every policy whose judgments a predicate of the policy reads. What is above
//!   never depends on what is below, so taking away one principal's work and everyone's below it
//!   leaves a graph that is still accepted.
//! - Which judgments a predicate reads is read from the filters of its temporal operators and of
//!   their `Since` scopes, one value per policy that the run-time checks read too, made from the
//!   predicates the catalog uses (see below). A filter of judgments narrows to the policies it
//!   names with `policy == id` or `policy in {ids}` (alone, within an `all`, or in an `any` every
//!   branch of which does), and then reads those. Every policy a filter names, wherever in the
//!   filter, is read as named: a policy named below is [`AcceptError::ReferencesBelow`], whatever
//!   the shape of the filter. A `last` has a filter as `once` and `count` do, and is read the same
//!   way; a policy named in its test (`policy == id`, which it reads from the last event the
//!   filter takes) is named as one in its filter is.
//! - A filter of judgments that narrows to no policy sees the judgments of the policies of the
//!   catalog whose authors cover the author of its policy, its own and those above, and no
//!   others: a rule counts what it may trust. Who is visible is decided here, once, from the
//!   catalog's [`Authority`], and written into the predicate the catalog keeps for the policy
//!   (`policy in {the visible}`, all of the filter's own condition beside it, in id order, so
//!   two policies of one author share their slots). The policy as written is kept as
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
//!   on a set that grows: it reads no judgment without naming the policies, in no filter that
//!   narrows to none, that of a `last` included ([`AcceptError::MetaReadsUnscoped`]). So a
//!   genuine record of a judgment, written in the name of the judged policy's author, is always
//!   one its reader may count ([`super::tx`]): what is checked here is what is used there.
//! - A reward is bound by a guard that exists. Under a mode, a reward whose bindings make it
//!   stronger than its guard is lowered to the guard's level, and a reward whose guard is off is
//!   off; both are reported as [`Degraded`], never done silently.
//! - A classifier is declared once, by name ([`super::policy::Classifier`], FR52), by its owner's
//!   set or one below it, and a policy reads it only by a filter of `Classified` events that
//!   narrows to its name (`classifier == name`, [`AcceptError::UnnamedClassifier`]; a policy that
//!   judges `Classified` events reads the one its `when` narrows to), a name that
//!   is declared ([`AcceptError::UndeclaredClassifier`]) by its own author or one above
//!   ([`AcceptError::ReferencesBelow`]); a meta policy reads none
//!   ([`AcceptError::MetaReadsClassifier`]). What a policy reads of them is in `Reads`, and a
//!   guard that reads one takes effect at Force only while the calibration record of each
//!   admits it ([`super::policy::Calibration::admit`]), decided in [`Catalog::effective`] and
//!   nowhere else (FR26): otherwise it is Advise, and reported as [`Degraded::Uncalibrated`].
//! - Every predicate reads each field from its own kind of event, with an operand of its type;
//!   so does the filter of a `Since` scope.
//! - A temporary adjustment that arrives as an event takes effect only if the catalog's index
//!   admits it ([`super::adjust`]): it names policies and bindings of the catalog outside the
//!   meta layer, an exemption names a guard and reads its cover as a predicate would, a
//!   temporary binding is no stronger than its policy may be bound (no Force for a reward or for
//!   a guard without the fixtures of a stopping guard) and is made by one within the work of the
//!   policy's author, as a binding of the catalog is ([`Authority::within`]), and so on. One
//!   that is not is aborted, with the reason ([`super::adjust::Inadmissible`]).
//! - A meta policy has exactly one binding, written by its own author under every mode
//!   ([`ModeScope::Any`]), and no other ([`AcceptError::MetaBinding`]): nothing can lower it,
//!   raise it, or make it depend on the mode.
//! - No binding of a reward is Force ([`AcceptError::RewardForce`]).
//! - A guard with a Force binding, under any mode, has at least one fixture it fails on and one
//!   it holds on ([`AcceptError::MissingFixtures`]): a binding cannot make a stopping guard that
//!   was never checked on an example.
//! - Every fixture of a structural policy gives the finding it expects, except those marked as
//!   known gaps. A fixture is folded as a run is, so a claim in it takes effect, or not, as it
//!   would at run time.
//!
//! # Order
//!
//! A catalog has one order, the order of its [`PolicyGraph`]: by id, whatever order the
//! policies and bindings were written in. It is decided there, once, and read everywhere: the
//! policies of the catalog ([`Catalog::policies`]), the policies a filter of judgments sees
//! (and so which slots two policies share), the lists of what takes effect ([`Effective`],
//! [`Enforced`]), and what a judgment reports ([`super::judge::Outcome`]: the causes of a
//! verdict, the rewards, what was degraded and lowered). No decision depends on it: the
//! strongest binding and the strongest result win whatever the order.
//!
//! # Errors
//!
//! [`Catalog::accept`] returns every [`AcceptError`] it finds at once, in [`Rejected`], so a
//! policy graph can be fixed in one pass. A graph with a duplicate id or name is refused before,
//! when it is made ([`PolicyGraph::parse`]), with every clash at once. What each set says of its
//! own items needs no composition, and is checked of every set before the sets are composed: an
//! owner or an author outside the hierarchy, and an item not within its set's owner. So sets
//! that do not compose are reported in one pass with those errors; the rest is checked on the
//! composed graph, which then does not exist.

use std::collections::HashMap;
use std::collections::btree_map;
use std::fmt;

use super::adjust::{AdjustIndex, BoundKind, Reach, TooStrong, may_bind_at};
use super::authority::{Authority, NotWithin, Principal};
use super::event::Event;
use super::name::{BindingId, ClassifierName, Mode, PolicyId};
use super::policy::{
    Binding, DefLayer, Expect, Level, ModeScope, Polarity, Policy, PolicyDef, PolicyGraph, Rule,
    Shortfall,
};
use super::predicate::{
    ClassifiedRead, EventFilter, JudgedRead, PredError, Reading, Site, StateAtom, Truth,
    classified_subject_read, note_reading, state_readings,
};
use super::schema::EventKind;
use super::set::{JoinConflict, SetId, Sources};
use super::state::{Known, SlotId, SlotTable, State, matched};

/// One item of a catalog: a policy, a binding of one, a classifier, or a set of them
/// ([`super::set`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Target {
    /// The policy.
    Policy(PolicyId),
    /// The binding.
    Binding(BindingId),
    /// The classifier's declaration, by name ([`super::policy::Classifier`]).
    Classifier(ClassifierName),
    /// The set of policies, as a whole: its graph, its name and its owner.
    Set(SetId),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(id) => write!(f, "policy {id}"),
            Self::Binding(id) => write!(f, "binding {id}"),
            Self::Classifier(name) => write!(f, "classifier {name}"),
            Self::Set(id) => write!(f, "set {id}"),
        }
    }
}

/// One reason a policy graph was not accepted.
#[derive(Debug, Clone, PartialEq)]
pub enum AcceptError {
    /// Two sets hold different items under one id, or two policies of one name
    /// ([`Sources::compose`]). To fix it, make the two items equal, give them their own ids and
    /// names, or leave one out.
    Conflict(JoinConflict),
    /// The owner of the set is not a principal of the hierarchy. Its items are not checked
    /// against it.
    UnknownOwner {
        /// The set.
        set: SetId,
        /// The owner it names.
        owner: Principal,
    },
    /// An item of the set is by a principal that is neither the set's owner nor below it
    /// ([`Authority::within`]). To fix it, move the item to a set of its author or of one above,
    /// or name the owner the application says the set belongs to.
    NotWithinOwner {
        /// The set.
        set: SetId,
        /// The item.
        item: Target,
        /// The owner of the set.
        owner: Principal,
    },
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
    /// The item refers to a policy or a classifier whose author is below its own, or beside it:
    /// a reward bound by it, a binding that puts it into effect, a policy whose predicate names
    /// it in a filter of judgments (`policy == id`, `policy in {ids}`, wherever in the filter; the
    /// filter of a `last` included), or a policy whose predicate reads the classifier. A filter
    /// of judgments that narrows to no policy (names none, or names one only where it does not
    /// narrow, as in `any(policy == id, judgment == denied)`) is not this for what it does not
    /// name: it sees only the policies its author may count. To fix a predicate, name only the
    /// policies and the classifiers of its own author or of one above.
    ReferencesBelow {
        /// The item.
        item: Target,
        /// The policy ([`Target::Policy`]) or the classifier ([`Target::Classifier`]) it refers
        /// to.
        referenced: Target,
    },
    /// A filter of `Classified` events of the policy narrows to no one classifier: it has no
    /// `classifier == name` (alone or in an `all`), or names a text that is no classifier name.
    /// To fix it, narrow the filter to the classifier it reads.
    UnnamedClassifier {
        /// The policy.
        policy: PolicyId,
    },
    /// The policy reads a classifier that no set declares. To fix it, declare the classifier in
    /// a set, or name one that is declared.
    UndeclaredClassifier {
        /// The policy.
        policy: PolicyId,
        /// The classifier it names.
        classifier: ClassifierName,
    },
    /// The meta policy reads a classifier. A meta policy is lowered by nothing, and a guard that
    /// reads a classifier is lowered while the classifier is not calibrated, so the two do not go
    /// together. To fix it, read the classifier from a policy that is not meta.
    MetaReadsClassifier {
        /// The meta policy.
        policy: PolicyId,
        /// The classifier it names.
        classifier: ClassifierName,
    },
    /// A predicate of the policy reads `ActorUnder` of a principal that is not in the
    /// hierarchy, or chooses events by one (`By::Under` or `By::Only` of a selector or a
    /// scope). The leaves
    /// that spawns add have names that are new at every start, so a rule can name only a
    /// principal of the hierarchy.
    UnknownActor {
        /// The policy.
        policy: PolicyId,
        /// The principal it names.
        principal: Principal,
    },
    /// The meta policy reads judgments without naming the policies: a filter of judgments that
    /// narrows to no policy, that of a `last` included. What such a read sees grows with the
    /// policies of the catalog, and a meta policy depends on nothing that changes. To fix it,
    /// name the policies whose judgments it reads.
    MetaReadsUnscoped(PolicyId),
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
    /// The binding puts the guard into effect at Force, and the guard lacks a fixture it fails
    /// on, or one it holds on.
    MissingFixtures {
        /// The guard.
        policy: PolicyId,
        /// The binding.
        binding: BindingId,
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
    /// The binding names a policy that does not exist.
    UnknownBindingPolicy {
        /// The binding.
        binding: BindingId,
        /// The id it names.
        policy: PolicyId,
    },
    /// The binding puts a reward into effect at Force, which a recommendation cannot have.
    RewardForce {
        /// The reward.
        policy: PolicyId,
        /// The binding.
        binding: BindingId,
    },
    /// The meta policy does not have exactly one binding, by its own author, under every mode
    /// ([`ModeScope::Any`]): it has none, more than one, or one by another or under a mode scope.
    MetaBinding(PolicyId),
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict(conflict) => write!(f, "{conflict}"),
            Self::UnknownOwner { set, owner } => {
                write!(
                    f,
                    "set {set} is owned by {owner}, who is not in the hierarchy"
                )
            }
            Self::NotWithinOwner { set, item, owner } => write!(
                f,
                "{item} of set {set} is by one who is neither its owner {owner} nor below it"
            ),
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
            Self::UnnamedClassifier { policy } => write!(
                f,
                "policy {policy} reads classified events without narrowing to one classifier"
            ),
            Self::UndeclaredClassifier { policy, classifier } => write!(
                f,
                "policy {policy} reads the classifier {classifier}, which no set declares"
            ),
            Self::MetaReadsClassifier { policy, classifier } => {
                write!(f, "meta policy {policy} reads the classifier {classifier}")
            }
            Self::UnknownActor { policy, principal } => write!(
                f,
                "policy {policy} reads the actor {principal}, who is not in the hierarchy"
            ),
            Self::MetaReadsUnscoped(policy) => write!(
                f,
                "meta policy {policy} reads judgments without naming the policies"
            ),
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
            Self::MissingFixtures { policy, binding } => write!(
                f,
                "binding {binding} makes guard {policy} stop events, but the guard lacks a \
                 fixture it fails on or one it holds on"
            ),
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
            Self::UnknownBindingPolicy { binding, policy } => {
                write!(f, "binding {binding} names {policy}, which does not exist")
            }
            Self::RewardForce { policy, binding } => {
                write!(f, "binding {binding} gives the reward {policy} Force")
            }
            Self::MetaBinding(id) => write!(
                f,
                "meta policy {id} needs exactly one binding, by its author, under every mode"
            ),
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

/// A level that the catalog did not let a policy keep as its bindings give it, and what was done
/// instead: a reward held to its guard, or a guard that reads an uncalibrated classifier held
/// to Advise. Reported, never done silently.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Degraded {
    /// The reward's bindings made it stronger than its guard, and it was lowered to it.
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
    /// The guard's bindings made it Force, and it reads a classifier whose calibration record does
    /// not meet the bound of its declaration ([`super::policy::Calibration::admit`]), so it was
    /// lowered. One is reported for each classifier it reads that falls short; a reward bound to
    /// the guard follows it as to any lowered guard.
    Uncalibrated {
        /// The guard.
        guard: PolicyId,
        /// The classifier that falls short.
        classifier: ClassifierName,
        /// How it falls short.
        shortfall: Shortfall,
        /// The level the guard is lowered to.
        to: Level,
    },
}

/// Whether a policy takes effect under a mode, from its bindings and the holding of rewards to
/// their guards.
///
/// Ordered by how much it holds, least first: `Off < On(Inform) < On(Advise) < On(Force)`. This
/// order is the one comparison of effects: what is "at least as strict" anywhere is `>=` here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effect {
    /// It does not take effect: no binding of it holds, or it is a reward whose guard is off.
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

/// What the catalog comes to under one mode, as written: every policy with its effect, and what
/// could not be kept as the bindings give it ([`Degraded`]). This is the written strength, which does not depend on
/// the platform: [`Catalog::change`], the checks of a claim and the fixtures read it. What a
/// platform can enforce of it is [`Enforced`], made by [`Catalog::enforced`] (which states how)
/// and, event by event, by [`super::judge::judge`].
#[derive(Debug, Clone, PartialEq)]
pub struct Effective<'a> {
    /// Every policy of the catalog, by id, with its effect.
    pub policies: Vec<PolicyEffect<'a>>,
    /// What had to be degraded: a reward held to its guard, a guard held to Advise for want of a
    /// classifier's calibration.
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

/// A level that is the same on every event of a kind, or that depends on the event.
///
/// It is the answer of [`Capabilities::cap_kind`] (the highest level the platform enforces on
/// events of a kind), and the level a policy is enforced at in the list [`Catalog::enforced`]
/// makes, where no event is judged. In [`Outcome::lowered`](super::judge::Outcome::lowered), where
/// an event is judged, it is always [`Cap::Fixed`], the value for that event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cap {
    /// The same on every event of the kind.
    Fixed(Level),
    /// It depends on the event. It is never below `at_least` on any event, and never above
    /// `at_most`; `at_least` is below `at_most`.
    ByEvent {
        /// The level that holds on every event of the kind.
        at_least: Level,
        /// The level on the best event of the kind. The conditions of the capabilities are not
        /// solved, so no event may reach it.
        at_most: Level,
    },
}

impl Cap {
    /// The two ends as a cap: [`Cap::Fixed`] when they are the same.
    fn between(at_least: Level, at_most: Level) -> Self {
        if at_least == at_most {
            Self::Fixed(at_least)
        } else {
            Self::ByEvent { at_least, at_most }
        }
    }

    /// The level that holds on every event: the value of a [`Cap::Fixed`].
    pub fn at_least(self) -> Level {
        match self {
            Self::Fixed(level)
            | Self::ByEvent {
                at_least: level, ..
            } => level,
        }
    }

    /// This cap with no level above `level`.
    fn under(self, level: Level) -> Self {
        match self {
            Self::Fixed(fixed) => Self::Fixed(fixed.min(level)),
            Self::ByEvent { at_least, at_most } => {
                Self::between(at_least.min(level), at_most.min(level))
            }
        }
    }
}

/// The highest level the platform can enforce on an event, given as data in the words of an event
/// filter: the facts of the platform, supplied with each judgment. The catalog is the same on
/// every platform; what a platform cannot hold is lowered when the catalog is judged
/// ([`super::judge::judge`]) or listed ([`Catalog::enforced`], which states how), and reported
/// ([`Lowering`]).
///
/// The cap of an event is the lowest level among the possible worlds. A filter of the capabilities
/// that matches the event gives its level; a filter that cannot tell (the event's value is not
/// known yet, as `ok` of a tool call that has not returned) gives its level too, since the
/// platform may or may not hold the event; and when no filter surely matches, the `otherwise`
/// level counts as well. This is the direction of not knowing the mode ([`Catalog::effective`]),
/// turned round: there the strictest of the candidates is taken, here the weakest.
///
/// Filters that overlap, and match one event, give the lowest of their levels. So to make only
/// some events stoppable, list those with the higher level and set `otherwise` to the lower:
/// `[(tool == Bash, Force)]` with `otherwise` Advise stops a Bash call and warns on any other
/// tool.
///
/// These are a fact the adapter reads from the platform. They go through no transaction and no
/// `may_loosen`: a value that lowers everything to Inform makes every Force guard stop nothing,
/// and every judgment then reports it as [`Lowering::BeyondCapability`]. Whoever supplies them
/// is trusted with what the platform holds, as the caller is trusted with the [`Authority`].
#[derive(Debug, Clone, PartialEq)]
pub struct Capabilities {
    caps: Vec<(EventFilter, Level)>,
    otherwise: Level,
}

impl Capabilities {
    /// The capabilities of a platform that enforces everything: nothing is lowered.
    pub fn full() -> Self {
        Self {
            caps: Vec::new(),
            otherwise: Level::Force,
        }
    }

    /// The capabilities that hold `level` on an event that meets the filter, and `otherwise` on
    /// one that meets none. Each filter is type-checked ([`EventFilter::check`]), and every
    /// error is returned.
    pub fn new(caps: Vec<(EventFilter, Level)>, otherwise: Level) -> Result<Self, Vec<PredError>> {
        let errors: Vec<PredError> = caps.iter().flat_map(|(filter, _)| filter.check()).collect();
        if errors.is_empty() {
            Ok(Self { caps, otherwise })
        } else {
            Err(errors)
        }
    }

    /// The highest level the platform enforces on `event`: the lowest among the possible worlds.
    /// Whether a filter matches is decided by the one matcher the state uses.
    pub fn cap(&self, event: &Event) -> Level {
        let kind = event.body.kind();
        let mut lowest: Option<Level> = None;
        let mut surely = false;
        for (filter, level) in self.caps.iter().filter(|(f, _)| f.kind == kind) {
            match matched(filter, &event.body) {
                Truth::True => surely = true,
                Truth::Unknown => {}
                Truth::False => continue,
            }
            lowest = Some(lowest.map_or(*level, |lowest| lowest.min(*level)));
        }
        if surely {
            lowest.unwrap_or(self.otherwise)
        } else {
            lowest.map_or(self.otherwise, |lowest| lowest.min(self.otherwise))
        }
    }

    /// The highest level the platform enforces on events of `kind`, when no event is at hand:
    /// [`Cap::Fixed`] when every event of the kind has the same, else [`Cap::ByEvent`], whose
    /// `at_least` is never above [`Capabilities::cap`] of any event of the kind (see
    /// [`Catalog::enforced`]).
    pub fn cap_kind(&self, kind: EventKind) -> Cap {
        let of_kind = || self.caps.iter().filter(|(f, _)| f.kind == kind);
        // A filter with no condition matches every event of the kind: the otherwise never counts.
        let always = of_kind()
            .filter(|(f, _)| f.cond.is_none())
            .map(|(_, level)| *level)
            .min();
        let conditional = of_kind()
            .filter(|(f, _)| f.cond.is_some())
            .map(|(_, level)| *level);
        match always {
            Some(always) => Cap::between(conditional.fold(always, Level::min), always),
            None => {
                let (least, most) = conditional
                    .fold((self.otherwise, self.otherwise), |(l, m), x| {
                        (l.min(x), m.max(x))
                    });
                Cap::between(least, most)
            }
        }
    }
}

/// Why a policy is enforced less strongly than it is written, by what the platform can hold.
/// This is the report of the stage of the platform's capabilities; the stage before it, the
/// bindings, reports as [`Degraded`], and the two are kept apart.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Lowering {
    /// The platform cannot enforce the level the policy is written at on the events it judges.
    /// This states a fact of the platform and is not a loosening of the rule: no one changed it.
    BeyondCapability {
        /// The policy.
        policy: PolicyId,
        /// The level it comes to as written.
        written: Level,
        /// The level it is enforced at. In a judgment ([`super::judge::Outcome::lowered`]) this
        /// is [`Cap::Fixed`], the value for that event; in a list ([`Enforced::lowered`]) it is
        /// the cap of the policy's kind, where [`Cap::ByEvent`] says it differs by event.
        enforced: Cap,
    },
    /// The reward is bound by a guard that is enforced less strongly than the reward would be, so
    /// the reward follows it (see [`Catalog::enforced`] for the level it is held to).
    RewardFollowsGuard {
        /// The reward.
        reward: PolicyId,
        /// Its guard.
        guard: PolicyId,
        /// The level it is lowered to.
        to: Level,
    },
}

impl Lowering {
    /// The policy whose strength is lowered: the policy, or the reward that followed its guard.
    pub fn policy(&self) -> PolicyId {
        match self {
            Self::BeyondCapability { policy, .. } => *policy,
            Self::RewardFollowsGuard { reward, .. } => *reward,
        }
    }
}

/// How strongly a policy is enforced under a mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnforcedEffect {
    /// It does not take effect.
    Off,
    /// It takes effect at this level, on the events it judges.
    On(Cap),
}

/// One policy with the strength it is written at and the strength it is enforced at.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EnforcedPolicy<'a> {
    /// The policy.
    pub policy: &'a Policy,
    /// Its effect as written ([`Effective`]).
    pub written: Effect,
    /// Its effect as the platform enforces it.
    pub enforced: EnforcedEffect,
}

/// What the catalog is enforced at: [`Effective`] with the platform's capabilities applied. The
/// written strength and the enforced strength are separate types, so the one cannot be taken for
/// the other: a change of the rules is judged by the written ([`Effective`]), and a stop is made
/// by the enforced.
#[derive(Debug, Clone, PartialEq)]
pub struct Enforced<'a> {
    /// Every policy of the catalog, by id.
    pub policies: Vec<EnforcedPolicy<'a>>,
    /// What the capabilities lowered, and the rewards that followed. What the bindings degraded
    /// is in [`Effective::degraded`] and is not repeated here.
    pub lowered: Vec<Lowering>,
}

impl<'a> Enforced<'a> {
    /// The policies that take effect, each with the level it is written at and the strength it is
    /// enforced at.
    pub fn on(&self) -> impl Iterator<Item = (&'a Policy, Level, Cap)> + '_ {
        self.policies
            .iter()
            .filter_map(|p| match (p.written, p.enforced) {
                (Effect::On(written), EnforcedEffect::On(cap)) => Some((p.policy, written, cap)),
                _ => None,
            })
    }
}

/// `effective` with the capabilities applied, read by [`super::judge::judge`] and by
/// [`Catalog::enforced`], which differ only in how the cap of a policy is found (`own`; `None`
/// leaves the policy as written). The rule is stated at [`Catalog::enforced`].
///
/// ```text
/// Effective (as written)
///   → each policy, held to the cap of its own subject          (`own`; BeyondCapability)
///   → each reward, held to its guard as the guard is enforced   (RewardFollowsGuard)
///   → Enforced
/// ```
pub(super) fn enforce_in<'a>(
    effective: &Effective<'a>,
    caps: &Capabilities,
    own: impl Fn(&Policy) -> Option<Cap>,
) -> Enforced<'a> {
    let mut lowered = Vec::new();
    let mut policies: Vec<EnforcedPolicy<'a>> = effective
        .policies
        .iter()
        .map(|p| {
            let enforced = match p.effect {
                Effect::Off => EnforcedEffect::Off,
                Effect::On(written) => {
                    let cap = own(p.policy).map_or(Cap::Fixed(written), |cap| cap.under(written));
                    if cap != Cap::Fixed(written) {
                        lowered.push(Lowering::BeyondCapability {
                            policy: p.policy.id(),
                            written,
                            enforced: cap,
                        });
                    }
                    EnforcedEffect::On(cap)
                }
            };
            EnforcedPolicy {
                policy: p.policy,
                written: p.effect,
                enforced,
            }
        })
        .collect();
    // A guard that is off has turned its reward off already, so only guards that are on count.
    let guards_on: HashMap<PolicyId, (&Policy, Level)> = effective
        .policies
        .iter()
        .filter_map(|g| match g.effect {
            Effect::On(level) => Some((g.policy.id(), (g.policy, level))),
            Effect::Off => None,
        })
        .collect();
    for entry in &mut policies {
        let (Polarity::Reward { bound_by, .. }, EnforcedEffect::On(cap)) =
            (entry.policy.polarity(), entry.enforced)
        else {
            continue;
        };
        let Some(&(guard, written)) = guards_on.get(bound_by) else {
            continue;
        };
        // On a kind the reward shares with its guard, an event being judged has one cap for both.
        let guard_cap = if guard.subject() == entry.policy.subject() {
            own(guard).unwrap_or_else(|| caps.cap_kind(guard.subject()))
        } else {
            caps.cap_kind(guard.subject())
        };
        let to = written.min(guard_cap.at_least());
        let bound = cap.under(to);
        if bound != cap {
            lowered.push(Lowering::RewardFollowsGuard {
                reward: entry.policy.id(),
                guard: *bound_by,
                to,
            });
            entry.enforced = EnforcedEffect::On(bound);
        }
    }
    Enforced { policies, lowered }
}

/// `effective` held to the capabilities by kind of event, where no event is judged: the one rule
/// of [`Catalog::enforced`] and [`Catalog::enforced_in`].
fn enforce_by_kind<'a>(effective: &Effective<'a>, caps: &Capabilities) -> Enforced<'a> {
    enforce_in(effective, caps, |policy| {
        Some(caps.cap_kind(policy.subject()))
    })
}

/// What one policy reads, from its predicates (`when` and `rule`) as the catalog uses them: the
/// one value the run-time checks of a claim ([`super::tx`]) read (its slots and modes), and the
/// check of references here reads (the judgments it reads).
#[derive(Debug, Clone, PartialEq, Default)]
pub(super) struct Reads {
    /// The slots of its temporal operators (`once`, `count`, `last`, `spent`), each with its
    /// scope.
    slots: Vec<SlotId>,
    /// The judgments those operators and the filters of their `Since` scopes read.
    judged: Vec<JudgedRead>,
    /// The modes it reads with `ModeIs`, each with the direction it reads it in. A mode read in
    /// two directions is `Unreadable`. The mode's scope is read through `slots`.
    modes: Vec<(Mode, Reading)>,
    /// The principals it reads with `ActorUnder`, and those its selectors and scopes choose
    /// events by (`By::Under`, always `Unreadable`), each with the direction it reads it in. A
    /// principal read in two directions is `Unreadable`.
    actors: Vec<(Principal, Reading)>,
    /// The classifiers those operators and the filters of their `Since` scopes read, each named
    /// by a filter that narrows to it ([`ClassifiedRead::Named`]): the one set that the
    /// acceptance of a policy checks against the declarations and that its effect is lowered by.
    classifiers: Vec<ClassifierName>,
    /// Whether a filter of `Classified` events it holds narrows to no one classifier
    /// ([`ClassifiedRead::Unnamed`]), which is not accepted.
    unnamed_classifier: bool,
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
            }
            for read in pred.classified_reads() {
                reads.note_classified(read);
            }
            for read in pred.judged_reads() {
                if !reads.judged.contains(&read) {
                    reads.judged.push(read);
                }
            }
        }
        // A policy that judges the answers reads the classifier its `when` narrows to, as a
        // filter of `Classified` events does: the judged event is the answer.
        if policy.subject() == EventKind::Classified {
            reads.note_classified(classified_subject_read(policy.when()));
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
                    StateAtom::Mode(mode) => note_reading(&mut reads.modes, mode.clone(), reading),
                    StateAtom::Actor(principal) => {
                        note_reading(&mut reads.actors, principal.clone(), reading);
                    }
                }
            }
        }
        reads
    }

    /// Notes a classifier read: the set of classifiers, or that a read names none.
    fn note_classified(&mut self, read: ClassifiedRead) {
        match read {
            ClassifiedRead::Named(name) if !self.classifiers.contains(&name) => {
                self.classifiers.push(name);
            }
            ClassifiedRead::Named(_) => {}
            ClassifiedRead::Unnamed => self.unnamed_classifier = true,
        }
    }

    /// The principals the policy reads in the hierarchy of actors, with `ActorUnder` or a
    /// `By::Under`, each with the direction it reads it in.
    pub(super) fn actors(&self) -> &[(Principal, Reading)] {
        &self.actors
    }

    /// Whether the policy reads the judgments of `id`: a filter of judgments that narrows to no
    /// policy reads every one it may count, and one that narrows or names reads those. The
    /// transaction of a claim asks this to find the rules that read what a policy's wider reach
    /// would write.
    pub(super) fn reads_judgments_of(&self, id: PolicyId) -> bool {
        self.judged.iter().any(|read| {
            read.names(id)
                || read
                    .narrowed
                    .as_ref()
                    .is_none_or(|narrowed| narrowed.contains(&id))
        })
    }

    /// The classifiers the policy reads, each once, in the order they first appear.
    pub(super) fn classifiers(&self) -> &[ClassifierName] {
        &self.classifiers
    }

    /// Whether the policy reads the slot.
    pub(super) fn reads_slot(&self, slot: SlotId) -> bool {
        self.slots.contains(&slot)
    }

    /// The modes the policy reads with `ModeIs`, each with the direction it reads it in.
    pub(super) fn modes(&self) -> &[(Mode, Reading)] {
        &self.modes
    }
}

/// The accepted rules.
#[derive(Debug, Clone, PartialEq)]
pub struct Catalog {
    /// The sets it was accepted from, as given: what a change is made to.
    sources: Sources,
    /// The graph `sources` compose to, as written: the one order of the catalog (by id).
    graph: PolicyGraph,
    /// The policies of `graph`, in its order, with the predicates the catalog uses.
    policies: Vec<Policy>,
    slots: SlotTable,
    /// What each policy reads, in the order of `policies`.
    reads: Vec<Reads>,
    index: AdjustIndex,
    authority: Authority,
}

/// The scope of a binding that a temporary adjustment adds, and of what a lost record of one may
/// have added: every mode.
static ANY_MODE: ModeScope = ModeScope::Any;

/// One binding as the effect reads it: a binding of the catalog, or one a temporary adjustment
/// adds, with its author (for a temporary one, who made the adjustment).
#[derive(Debug, Clone, Copy)]
pub(super) struct InEffect<'a> {
    /// The policy it puts into effect.
    pub(super) policy: PolicyId,
    /// The level.
    pub(super) level: Level,
    /// Where it holds, as to the mode.
    pub(super) mode: &'a ModeScope,
    /// Its author.
    pub(super) author: &'a Principal,
}

impl<'a> InEffect<'a> {
    /// The binding of the catalog as the effect reads it.
    pub(super) fn of(binding: &'a Binding) -> Self {
        Self {
            policy: binding.policy,
            level: binding.level,
            mode: &binding.mode,
            author: &binding.author,
        }
    }
}

impl Catalog {
    /// The catalog of `sources` under the hierarchy `authority`, when they compose
    /// ([`Sources::compose`]), every item of a set is within the set's owner, and the composed
    /// graph keeps every invariant of the module doc but the one on fixtures, which
    /// [`Catalog::accept`] checks after it. The catalog keeps the sources and the hierarchy.
    pub(super) fn accept_structure(
        sources: Sources,
        authority: Authority,
    ) -> Result<Self, Rejected> {
        let mut errors = Vec::new();
        check_owners(&sources, &authority, &mut errors);
        let graph = match sources.compose() {
            Ok(graph) => graph,
            Err(conflicts) => {
                errors.extend(conflicts.into_iter().map(AcceptError::Conflict));
                return Err(Rejected(errors));
            }
        };
        check_authors(&graph, &authority, &mut errors);
        check_policies(&graph, &mut errors);
        check_bindings(&graph, &mut errors);
        let policies = compile_policies(&graph, &authority);
        let slots = SlotTable::of(policies.iter().flat_map(Policy::preds));
        let reads: Vec<Reads> = policies.iter().map(|p| Reads::of(p, &slots)).collect();
        check_reads(&graph, &policies, &reads, &authority, &mut errors);
        check_actors(&policies, &authority, &mut errors);
        let index = AdjustIndex::new(
            policies.iter().map(|p| {
                let reach = match p.polarity() {
                    _ if p.layer() == DefLayer::Meta => Reach::Meta,
                    Polarity::Guard => Reach::Guard {
                        subject: p.subject(),
                        stops: has_stopping_fixtures(p.def()),
                    },
                    Polarity::Reward { .. } => Reach::Reward,
                };
                (p.id(), reach, p.author().clone())
            }),
            graph.bindings().map(|b| (b.id, b.policy)),
        );
        if errors.is_empty() {
            Ok(Self {
                sources,
                graph,
                policies,
                slots,
                reads,
                index,
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

    /// The sets the catalog was accepted from, as given: what a change starts from
    /// ([`Sources::with`], [`Sources::without`], [`Sources::replaced`]).
    pub fn sources(&self) -> &Sources {
        &self.sources
    }

    /// The graph the sets compose to, as written ([`Sources::compose`]).
    pub fn graph(&self) -> &PolicyGraph {
        &self.graph
    }

    /// The bindings, by id.
    pub(super) fn bindings(&self) -> btree_map::Values<'_, BindingId, Binding> {
        self.graph.bindings()
    }

    /// The policies, as defined, by id.
    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    /// The policy with the id. The policies are in id order (the graph's), so it is a search.
    pub fn policy(&self, id: PolicyId) -> Option<&Policy> {
        self.policies
            .binary_search_by_key(&id, Policy::id)
            .ok()
            .map(|at| &self.policies[at])
    }

    /// The state before any event.
    pub fn start(&self) -> State {
        State::start(&self.slots)
    }

    pub(super) fn slots(&self) -> &SlotTable {
        &self.slots
    }

    /// Each policy with what it reads, by id.
    pub(super) fn reads(&self) -> impl Iterator<Item = (&Policy, &Reads)> {
        self.policies.iter().zip(&self.reads)
    }

    /// The index of what an adjustment may name, which decides whether one may take effect.
    pub(super) fn index(&self) -> &AdjustIndex {
        &self.index
    }

    /// The bindings in effect in `state`: those of the catalog but the ones a held adjustment
    /// suspends, then those the held adjustments add, each under every mode and by the one who
    /// made it. When the state has lost a record that may have been an adjustment or a cancel,
    /// no suspension is taken to hold, since one may have been cancelled. The one list both the
    /// effect ([`Catalog::effective_in`]) and the authors of a lowering read.
    pub(super) fn bindings_in<'a>(&'a self, state: &'a State) -> Vec<InEffect<'a>> {
        // Each held adjustment is read as `HeldAdjustment::effect` says: one that may have ended
        // still adds its bindings and suspends none.
        let suspended: Vec<BindingId> = if state.adjustments_lost() {
            Vec::new()
        } else {
            state
                .adjustments()
                .iter()
                .flat_map(|held| held.effect().suspended)
                .copied()
                .collect()
        };
        let temporary = state.adjustments().iter().flat_map(|held| {
            held.effect().added.iter().map(|t| InEffect {
                policy: t.policy,
                level: t.level,
                mode: &ANY_MODE,
                author: &held.by,
            })
        });
        self.bindings()
            .filter(|b| !suspended.contains(&b.id))
            .map(InEffect::of)
            .chain(temporary)
            .collect()
    }

    /// What the catalog comes to under `mode`: every policy with its effect, and what had to be
    /// degraded. A policy takes effect at the strongest level of its bindings that hold under
    /// `mode` ([`ModeScope::holds`]), and is off with none; then each reward is held to its
    /// guard. No event is judged; this is the catalog alone, with no temporary adjustment (see
    /// [`Catalog::effective_in`]).
    ///
    /// When the mode is not known, each mode it may be (no mode, and every mode a binding's scope
    /// names) is computed to the end, rewards bound to their guards, and each policy takes the
    /// strongest effect any of them gives; what was degraded is what the strongest effect still
    /// shows. This is the one place where not knowing the mode is decided, so it never loosens a
    /// rule, and never gives a value no mode gives; [`Catalog::effective_in`] goes through it.
    pub fn effective(&self, mode: &Known<Option<Mode>>) -> Effective<'_> {
        let bindings: Vec<InEffect<'_>> = self.bindings().map(InEffect::of).collect();
        self.effective_with(&bindings, mode)
    }

    /// What the catalog comes to in `state`: [`Catalog::effective`] under the state's mode, with
    /// the state's temporary adjustments. The bindings of the catalog that a held adjustment
    /// suspends do not hold, and each binding a held adjustment adds holds under every mode, by
    /// the one who made it; the strongest wins and a policy with none is off, as in the catalog.
    /// This is the one place that adds the temporary adjustments to what takes effect, and what a
    /// judgment and the transaction of a claim read.
    ///
    /// When a record that may have been an adjustment or a cancel was lost
    /// ([`State::adjustments_lost`]), what is held is not all there is: no suspension is taken to
    /// hold, and every policy outside the meta layer takes effect at least as strongly as a
    /// temporary binding could make it (a guard with the fixtures of a stopping guard at Force, any
    /// other guard and a reward at Advise), with rewards then held to their guards as always. That
    /// is decided here and nowhere else, apart from the choice of the strongest mode, which
    /// [`Catalog::effective`] makes. A meta policy is never touched.
    pub fn effective_in(&self, state: &State) -> Effective<'_> {
        self.effective_in_with(&self.bindings_in(state), state)
    }

    /// [`Catalog::effective_in`] with the bindings in effect in `state` already made
    /// ([`Catalog::bindings_in`]), for a caller that reads them too.
    pub(super) fn effective_in_with(
        &self,
        bindings: &[InEffect<'_>],
        state: &State,
    ) -> Effective<'_> {
        if !state.adjustments_lost() {
            return self.effective_with(bindings, state.mode());
        }
        // The strength under the mark: what a temporary binding could give each policy.
        let mut possible = bindings.to_vec();
        possible.extend(
            self.index
                .ceilings()
                .map(|(policy, level, author)| InEffect {
                    policy,
                    level,
                    mode: &ANY_MODE,
                    author,
                }),
        );
        self.effective_with(&possible, state.mode())
    }

    /// What the catalog comes to under `mode` with `bindings` in effect: the rule of
    /// [`Catalog::effective`], an unknown mode included.
    pub(super) fn effective_with(
        &self,
        bindings: &[InEffect<'_>],
        mode: &Known<Option<Mode>>,
    ) -> Effective<'_> {
        let Known::Unknown = mode else {
            return self.effective_under(bindings, mode);
        };
        // Each mode it may be is computed to the end, rewards bound to their guards; then each
        // policy takes the strongest effect any of them gives. So the answer is never a value no
        // mode gives (a reward is never held to a guard level of another mode). A temporary
        // binding holds under every mode, so it names none.
        let mut strongest = self.effective_under(bindings, &Known::Known(None));
        for candidate in compared_modes([self]).into_iter().skip(1) {
            let other = self.effective_under(bindings, &Known::Known(candidate));
            // Both list every policy by id.
            for (kept, o) in strongest.policies.iter_mut().zip(other.policies) {
                kept.effect = kept.effect.max(o.effect);
            }
            for d in other.degraded {
                if !strongest.degraded.contains(&d) {
                    strongest.degraded.push(d);
                }
            }
        }
        // Of what the modes degraded, only what the strongest effect still shows.
        let effect_of = |id: PolicyId| {
            strongest
                .policies
                .iter()
                .find(|p| p.policy.id() == id)
                .map(|p| p.effect)
        };
        let degraded = strongest
            .degraded
            .iter()
            .filter(|d| match d {
                Degraded::RewardLowered { reward, to, .. } => {
                    effect_of(*reward) == Some(Effect::On(*to))
                }
                Degraded::RewardWithoutGuard { reward, .. } => {
                    effect_of(*reward) == Some(Effect::Off)
                }
                Degraded::Uncalibrated { guard, to, .. } => {
                    effect_of(*guard) == Some(Effect::On(*to))
                }
            })
            .cloned()
            .collect();
        strongest.degraded = degraded;
        strongest
    }

    /// What the catalog comes to under one known mode, read binding by binding. It is called with
    /// a known mode only ([`Catalog::effective`] decides an unknown one), so a scope never reads
    /// as unknown here.
    ///
    /// This is the one place that decides whether Force takes effect, whatever the way in
    /// ([`Catalog::effective`], [`Catalog::effective_in`] and so everything that reads them).
    /// Per mode, the strongest level of the bindings that hold comes first; then a guard at Force
    /// that reads a classifier is lowered to Advise when the classifier's declaration does not
    /// admit its calibration record ([`Calibration::admit`](super::policy::Calibration::admit)),
    /// one [`Degraded::Uncalibrated`] for each classifier that falls short; then each reward is
    /// held to its guard as that guard now comes to ([`bind_rewards`]).
    fn effective_under(
        &self,
        bindings: &[InEffect<'_>],
        mode: &Known<Option<Mode>>,
    ) -> Effective<'_> {
        let mut in_effect: Vec<(&Policy, Option<Level>)> = self
            .policies
            .iter()
            .map(|policy| {
                let strongest = bindings
                    .iter()
                    .filter(|b| b.policy == policy.id() && b.mode.holds(mode) != Truth::False)
                    .map(|b| b.level)
                    .max();
                (policy, strongest)
            })
            .collect();
        let mut degraded = self.lower_uncalibrated(&mut in_effect);
        degraded.extend(bind_rewards(&mut in_effect));
        let policies = in_effect
            .into_iter()
            .map(|(policy, level)| PolicyEffect {
                policy,
                effect: level.map_or(Effect::Off, Effect::On),
            })
            .collect();
        Effective { policies, degraded }
    }

    /// Lowers to Advise each policy at Force that reads a classifier whose declaration does not
    /// admit its record, and reports each such classifier. `in_effect` is in the order of the
    /// policies, as `self.reads` is. A reward is never at Force, so only a guard is lowered.
    fn lower_uncalibrated(&self, in_effect: &mut [(&Policy, Option<Level>)]) -> Vec<Degraded> {
        let mut degraded = Vec::new();
        for ((policy, level), reads) in in_effect.iter_mut().zip(&self.reads) {
            if *level != Some(Level::Force) {
                continue;
            }
            let short: Vec<(ClassifierName, Shortfall)> = reads
                .classifiers()
                .iter()
                .filter_map(|name| {
                    // Acceptance refuses a read of an undeclared classifier; were one to get
                    // here, it has no record to admit, so the guard does not stay at Force.
                    let shortfall = match self.graph.classifier(name) {
                        Some(declared) => declared.bound.admit(declared.record.as_ref()).err()?,
                        None => Shortfall::Missing,
                    };
                    Some((name.clone(), shortfall))
                })
                .collect();
            if short.is_empty() {
                continue;
            }
            *level = Some(Level::Advise);
            degraded.extend(short.into_iter().map(|(classifier, shortfall)| {
                Degraded::Uncalibrated {
                    guard: policy.id(),
                    classifier,
                    shortfall,
                    to: Level::Advise,
                }
            }));
        }
        degraded
    }

    /// What the catalog is enforced at under `mode` on a platform with `caps`: [`Catalog::effective`]
    /// with the capabilities applied by kind of event, since no event is judged. This is what an
    /// adapter turns into hooks and instructions, and what shows what was lowered.
    ///
    /// This is where the rule of lowering is stated. [`super::judge::judge`] and this list lower a
    /// written strength through one function, which differs only in the cap it holds a policy to:
    /// the cap of the event in a judgment, and here, where no event is judged, the cap of the
    /// kind ([`Capabilities::cap_kind`]), never above the cap of an event of it. So the list never
    /// says more than a judgment does.
    ///
    /// A reward is held to the level its guard is enforced at. When the reward and its guard judge
    /// different kinds of event, that is the level the guard holds on every event of its kind
    /// (`cap_kind(..).at_least()`), the same in a judgment and in the list. When they judge the
    /// same kind and an event is being judged, it is the guard's level on that event, so a guard
    /// that was not lowered on it does not lower its reward ([`Lowering::RewardFollowsGuard`]).
    ///
    /// This is the catalog as written, with no temporary adjustment; what a state comes to, its
    /// adjustments included, is [`Catalog::enforced_in`].
    pub fn enforced(&self, mode: &Known<Option<Mode>>, caps: &Capabilities) -> Enforced<'_> {
        enforce_by_kind(&self.effective(mode), caps)
    }

    /// What the catalog is enforced at in `state` on a platform with `caps`:
    /// [`Catalog::enforced`] from [`Catalog::effective_in`], so with the state's temporary
    /// adjustments and its mode. The list an adapter shows while adjustments are in effect.
    pub fn enforced_in(&self, state: &State, caps: &Capabilities) -> Enforced<'_> {
        enforce_by_kind(&self.effective_in(state), caps)
    }

    /// What `caps` lower, mode by mode: [`Enforced::lowered`] under each compared mode (no mode,
    /// and every mode a binding's scope names, counted as [`Catalog::change`] counts them), with the
    /// mode. It compares nothing itself. When it is empty, this catalog is enforced as written on
    /// a platform with these capabilities.
    ///
    /// Whether to refuse a catalog that is not is the caller's choice, made when it loads the
    /// catalog: it may reject it (strict), or accept it and let every judgment report the
    /// lowering. The core does the second at run time, always.
    pub fn check_capabilities(&self, caps: &Capabilities) -> Vec<(Option<Mode>, Lowering)> {
        compared_modes([self])
            .into_iter()
            .flat_map(|mode| {
                let lowered = self.enforced(&Known::Known(mode.clone()), caps).lowered;
                lowered.into_iter().map(move |l| (mode.clone(), l))
            })
            .collect()
    }

    /// Every mode a binding's scope names (`In` and `Outside`), each once.
    fn modes(&self) -> Vec<&Mode> {
        let mut modes: Vec<&Mode> = Vec::new();
        for mode in self.bindings().flat_map(|b| b.mode.modes()) {
            if !modes.contains(&mode) {
                modes.push(mode);
            }
        }
        modes
    }
}

/// The modes catalogs are compared under: no mode, then each mode a scope of any of their bindings
/// names. A mode that no scope names behaves as no mode. An unknown mode is not compared: it is
/// the strongest of these ([`Catalog::effective`]), so a policy that goes down under it goes down
/// under one of them. The one count of modes, the same one [`Catalog::effective`] reads,
/// read by [`Catalog::change`] (two catalogs) and by [`Catalog::check_capabilities`] (one).
pub(super) fn compared_modes<'a>(
    catalogs: impl IntoIterator<Item = &'a Catalog>,
) -> Vec<Option<Mode>> {
    let mut modes = vec![None];
    for mode in catalogs.into_iter().flat_map(Catalog::modes) {
        let mode = Some(mode.clone());
        if !modes.contains(&mode) {
            modes.push(mode);
        }
    }
    modes
}

/// Keeps each reward within its guard: off when the guard is off, no stronger than it.
fn bind_rewards(in_effect: &mut [(&Policy, Option<Level>)]) -> Vec<Degraded> {
    let guard_levels: Vec<(PolicyId, Option<Level>)> = in_effect
        .iter()
        .map(|(policy, level)| (policy.id(), *level))
        .collect();
    let mut degraded = Vec::new();
    for (policy, level) in in_effect.iter_mut() {
        let (Polarity::Reward { bound_by }, Some(current)) = (policy.polarity(), *level) else {
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

/// Every owner and every author is of the hierarchy, and every item of a set, policy, binding and
/// classifier, is by its owner or one below ([`Authority::within`], the one answer, which a binding and a
/// temporary binding are held to as well). Checked of each set's own graph, so it needs no
/// composition and is reported with any conflict of the sets.
fn check_owners(sources: &Sources, authority: &Authority, errors: &mut Vec<AcceptError>) {
    for source in sources.iter() {
        let known_owner = authority.contains(&source.owner);
        if !known_owner {
            errors.push(AcceptError::UnknownOwner {
                set: source.id,
                owner: source.owner.clone(),
            });
        }
        let policies = source
            .graph
            .policies()
            .map(|p| (Target::Policy(p.id), &p.author));
        let bindings = source
            .graph
            .bindings()
            .map(|b| (Target::Binding(b.id), &b.author));
        let classifiers = source
            .graph
            .classifiers()
            .map(|c| (Target::Classifier(c.name.clone()), &c.author));
        for (item, author) in policies.chain(bindings).chain(classifiers) {
            let error = match authority.within(author, &source.owner) {
                Ok(()) => continue,
                Err(NotWithin::UnknownPrincipal(_)) => AcceptError::UnknownAuthor {
                    item,
                    author: author.clone(),
                },
                // An owner the hierarchy lacks is reported once, above, not for each item.
                Err(NotWithin::NotBelow { .. }) if !known_owner => continue,
                Err(NotWithin::NotBelow { .. }) => AcceptError::NotWithinOwner {
                    set: source.id,
                    item,
                    owner: source.owner.clone(),
                },
            };
            // An item two sets hold the same is reported once.
            if !errors.contains(&error) {
                errors.push(error);
            }
        }
    }
}

/// A meta policy is by a root, and nothing refers below its author. An author that is not of the
/// hierarchy is reported by [`check_owners`], before the sets are composed; a reference is checked
/// only when both authors are of the hierarchy.
fn check_authors(graph: &PolicyGraph, authority: &Authority, errors: &mut Vec<AcceptError>) {
    let author_of = |id: PolicyId| {
        graph
            .policy(id)
            .map(|p| &p.author)
            .filter(|author| authority.contains(author))
    };
    for def in graph.policies() {
        if !authority.contains(&def.author) {
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
                referenced: Target::Policy(*bound_by),
            });
        }
    }
    for b in graph.bindings() {
        // The same answer a temporary binding is held to ([`Authority::within`]).
        // An unknown author of the binding is reported by `check_owners`; a policy missing or of
        // an unknown author, on its own.
        if let Some(owner) = author_of(b.policy)
            && let Err(NotWithin::NotBelow { .. }) = authority.within(&b.author, owner)
        {
            errors.push(AcceptError::ReferencesBelow {
                item: Target::Binding(b.id),
                referenced: Target::Policy(b.policy),
            });
        }
    }
}

/// The policies of the catalog, each with the predicates the catalog uses: the one place that
/// decides which judgments a filter that narrows to no policy sees. A policy sees the judgments of the
/// policies, by id, whose authors cover its own ([`Authority::covers`]: its own
/// author and those above). A meta policy is not given this, as it reads no judgment unnarrowed
/// ([`AcceptError::MetaReadsUnscoped`]); nor is one whose author is not of the hierarchy, which
/// [`check_authors`] rejects. Every other policy is, whether or not it has such a filter, so that
/// its predicates are decided by the same three things always. The policies come out in the
/// order of the graph, by id.
fn compile_policies(graph: &PolicyGraph, authority: &Authority) -> Vec<Policy> {
    let in_hierarchy = |def: &PolicyDef| authority.contains(&def.author);
    let visible_to = |reader: &PolicyDef| -> Vec<PolicyId> {
        graph
            .policies()
            .filter(|def| in_hierarchy(def) && authority.covers(&def.author, &reader.author))
            .map(|def| def.id)
            .collect()
    };
    graph
        .policies()
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
/// policy named, in any shape of filter (a `last`'s included), is what can be below. A meta
/// policy's reads are made from its predicates as written, so a read of every policy is the one
/// thing its check looks for; the policies it names are checked as any other's, and it is not
/// also told off for every policy below that a read of every policy would reach.
///
/// The classifiers a policy reads are checked here too, from the same [`Reads`]: a filter that
/// narrows to none ([`AcceptError::UnnamedClassifier`]), a classifier no set declares
/// ([`AcceptError::UndeclaredClassifier`]), a declaration whose author is below the reader's
/// ([`AcceptError::ReferencesBelow`] with [`Target::Classifier`]), and any classifier read by a
/// meta policy ([`AcceptError::MetaReadsClassifier`]).
fn check_reads(
    graph: &PolicyGraph,
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
        check_classifier_reads(graph, reader, reads, authority, errors);
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
                    referenced: Target::Policy(target.id()),
                };
                if !errors.contains(&error) {
                    errors.push(error);
                }
            }
        }
    }
}

/// The classifiers `reader` reads, against the declarations of the graph: see [`check_reads`].
fn check_classifier_reads(
    graph: &PolicyGraph,
    reader: &Policy,
    reads: &Reads,
    authority: &Authority,
    errors: &mut Vec<AcceptError>,
) {
    let mut found = Vec::new();
    if reads.unnamed_classifier {
        found.push(AcceptError::UnnamedClassifier {
            policy: reader.id(),
        });
    }
    for name in reads.classifiers() {
        if reader.layer() == DefLayer::Meta {
            found.push(AcceptError::MetaReadsClassifier {
                policy: reader.id(),
                classifier: name.clone(),
            });
            continue;
        }
        match graph.classifier(name) {
            None => found.push(AcceptError::UndeclaredClassifier {
                policy: reader.id(),
                classifier: name.clone(),
            }),
            Some(declared)
                if authority.contains(&declared.author)
                    && !authority.covers(&declared.author, reader.author()) =>
            {
                found.push(AcceptError::ReferencesBelow {
                    item: Target::Policy(reader.id()),
                    referenced: Target::Classifier(name.clone()),
                });
            }
            Some(_) => {}
        }
    }
    for error in found {
        if !errors.contains(&error) {
            errors.push(error);
        }
    }
}

/// Every principal a policy reads with `ActorUnder` or chooses events by (`By::Under` or
/// `By::Only`) is a principal of the hierarchy, each reported once per policy. The principals
/// are those its predicates name (`Pred::named_actors_into`), a superset of what [`Reads`] keeps
/// for the transaction of a spawn: an `Only` is no reading a spawn can move, and is checked here
/// all the same.
fn check_actors(policies: &[Policy], authority: &Authority, errors: &mut Vec<AcceptError>) {
    for policy in policies {
        let mut named: Vec<&Principal> = Vec::new();
        for pred in policy.preds() {
            pred.named_actors_into(&mut named);
        }
        for principal in named.into_iter().filter(|p| !authority.contains(p)) {
            errors.push(AcceptError::UnknownActor {
                policy: policy.id(),
                principal: principal.clone(),
            });
        }
    }
}

/// Every predicate type-checks, and every reward is bound by a guard of the graph.
fn check_policies(graph: &PolicyGraph, errors: &mut Vec<AcceptError>) {
    for def in graph.policies() {
        let Rule::Structural(rule) = &def.rule;
        for pred in def.when.iter().chain(std::iter::once(rule)) {
            for error in pred.check(def.subject) {
                errors.push(AcceptError::Predicate {
                    policy: def.id,
                    error,
                });
            }
        }
        if let Polarity::Reward { bound_by } = &def.polarity {
            match graph.policy(*bound_by) {
                None => errors.push(AcceptError::UnknownBound {
                    reward: def.id,
                    bound_by: *bound_by,
                }),
                Some(guard) if guard.polarity != Polarity::Guard => {
                    errors.push(AcceptError::BoundByReward {
                        reward: def.id,
                        bound_by: *bound_by,
                    });
                }
                Some(_) => {}
            }
        }
    }
}

/// Each binding names a policy, no reward is bound at Force, a guard bound at Force has its
/// fixtures, and a meta policy has exactly its one binding.
fn check_bindings(graph: &PolicyGraph, errors: &mut Vec<AcceptError>) {
    for b in graph.bindings() {
        let Some(def) = graph.policy(b.policy) else {
            errors.push(AcceptError::UnknownBindingPolicy {
                binding: b.id,
                policy: b.policy,
            });
            continue;
        };
        // The rule a temporary binding keeps too. A meta guard is held to it as any guard is.
        let kind = match def.polarity {
            Polarity::Reward { .. } => BoundKind::Reward,
            Polarity::Guard => BoundKind::Guard {
                stops: has_stopping_fixtures(def),
            },
        };
        if let Err(too_strong) = may_bind_at(kind, b.level) {
            errors.push(match too_strong {
                TooStrong::RewardForce => AcceptError::RewardForce {
                    policy: def.id,
                    binding: b.id,
                },
                TooStrong::MissingFixtures => AcceptError::MissingFixtures {
                    policy: def.id,
                    binding: b.id,
                },
            });
        }
    }
    for def in graph.policies().filter(|p| p.layer == DefLayer::Meta) {
        let mut bindings = graph.bindings().filter(|b| b.policy == def.id);
        let fixed = match (bindings.next(), bindings.next()) {
            (Some(only), None) => only.author == def.author && only.mode == ModeScope::Any,
            _ => false,
        };
        if !fixed {
            errors.push(AcceptError::MetaBinding(def.id));
        }
    }
}

/// Whether the guard has, besides its known gaps, a fixture it fails on and one it holds on: what
/// a stopping guard needs, whichever binding makes it stop.
fn has_stopping_fixtures(def: &PolicyDef) -> bool {
    let real = || def.fixtures.iter().filter(|f| !f.known_gap);
    let fails = real().any(|f| f.expect == Expect::Violated);
    let holds = real().any(|f| f.expect == Expect::Satisfied);
    fails && holds
}
