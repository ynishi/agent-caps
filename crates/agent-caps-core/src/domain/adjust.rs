//! A temporary adjustment: what it changes, for how long, and whether it may take effect.
//!
//! ```text
//! Adjustment { id, change: Temporary, lifetime, ends_by, reason }
//!   Temporary::Exempt { guard, cover }   the guard does not judge the events the cover covers
//!   Temporary::Rebind { add, suspend }   bindings added (under every mode) and bindings of the
//!                                        catalog suspended, on every event
//! Body::Adjust(Adjustment)               held from then on, while its lifetime lasts
//! Body::Cancel { id }                    the adjustment in effect with that id ends
//! ```
//!
//! An adjustment has two axes and no list of grains: what it changes and how long it lasts
//! ([`Lifetime`], and the time it ends by). Every adjustment has an end: the claim states the
//! time it ends by ([`Adjustment::ends_by`]), the one end by time, and a lifetime may end it
//! sooner, by the next judgment or a scope starting again. A session's start is not such an end:
//! it ends only an adjustment that lasts within a span its starter chooses, so an adjustment
//! within a mode, a `since` scope, or a task only the user starts can outlast a session, up to
//! the time it ends by. How far ahead that time may lie is the catalog's [`TemporaryBound`]
//! (below); one meant to last longer is a permanent binding in the catalog, so a lasting
//! exception is a visible change to the rules. A raise for a while is a Force binding added; a
//! lowering for a while is a Force binding suspended with an Advise binding added, in one
//! adjustment.
//!
//! An adjustment that lasts within a scope ends when the scope starts again or closes. When that
//! cannot be told (an actor of unknown place, a condition not known yet), it is kept as possibly
//! ended ([`super::state::Holding`]) and read in the direction that tightens, part by part: an
//! exemption covers nothing, a binding it adds still holds, and a binding it suspends is not
//! suspended. What cannot be told never loosens a rule; a later known start or close ends it.
//!
//! # Time
//!
//! The time an adjustment ends by, and a lifetime within a window of `Every`, are read with the
//! state's clock ([`super::state`]), which only acts advance. A claim's time never ends what
//! loosens when it ends; it may end an exemption's cover. So a raise or a suspension ends, and
//! an adjustment is refused as [`Inadmissible::Expired`], only by the time of an act, while
//! whether an exemption covers the judged event is read with the later of the clock and that
//! event's time: an exemption that ends sooner only tightens. `Adjustment::lasts_at` is the one
//! place that reads the time an adjustment ends by.
//!
//! # The bound
//!
//! The longest period a temporary adjustment may have is the catalog's [`TemporaryBound`]. A root
//! declares it in a set it owns, and the catalog decides it once, when it is accepted
//! ([`super::catalog::AcceptError::NoTemporaryBound`]), so a period nobody chose is never
//! assumed. It refuses and never rounds: an adjustment that ends further ahead of the clock than
//! the bound, or that lasts within a window of `Every` longer than the bound, is refused
//! ([`Inadmissible::EndsTooLate`], [`Inadmissible::WindowTooLong`]). Before the first act there is
//! no clock, and nothing has ended by time ([`super::state`]), so the adjustment is held, and
//! every adjustment held then is checked against the time of the first act, where it ends if it
//! lies too far ahead. Both checks are `AdjustIndex::bounds`.
//!
//! An adjustment and a cancel are claims, judged by their result alone ([`super::tx`]): what
//! lowers a policy asks the authors of the bindings that carried what it lost (a temporary binding
//! by the one who made the adjustment), an exemption that starts asks the guard's author and the
//! author of every binding of it in the catalog, and a binding suspended asks its author whether
//! or not the policy goes down. So cancelling a raise is a loosening, of the one who raised;
//! cancelling a lowering or an exemption tightens, and is open to anyone. A temporary binding is
//! by the guard's author or one below it (see below), so whoever covers the guard's author covers
//! it too, and need not be asked of it.
//!
//! # Whether an adjustment may take effect
//!
//! Whether one may take effect at all, whoever makes it, is decided in one place, the index the
//! catalog builds (`AdjustIndex::admits`), which the state's fold and the transaction both read
//! through [`super::state`]. One that it refuses takes no effect: its transaction is aborted and
//! reports why ([`Inadmissible`]). It refuses an adjustment
//!
//! - whose id is held by an adjustment in effect;
//! - that names a policy or a binding the catalog does not have;
//! - that names a meta policy or a binding of one: a meta policy is the target of no adjustment;
//! - an exemption of a policy that is not a guard, or whose cover does not read as a predicate on
//!   the guard's event would;
//! - that ends by the clock, the latest time an act has carried (the time of the claim itself is
//!   not read), or ends further ahead of it than the bound allows, or lasts within a window
//!   longer than the bound (see above);
//! - with a temporary binding stronger than one can be (see below), by the rule a binding of the
//!   catalog keeps too (`may_bind_at`);
//! - with a temporary binding whose maker is not within the work of the policy's author: one of
//!   the hierarchy, the author or below it ([`Authority::within`], the same answer a binding of
//!   the catalog is held to). One outside the hierarchy, a leaf a spawn added, one beside the
//!   author or above it cannot bind the policy, so nobody is left with a binding that its
//!   author's superiors cannot loosen;
//! - a rebinding that lasts for the next judgment: a policy that a rebinding turns off writes no
//!   record of a judgment, so the lifetime would never end;
//! - a rebinding that neither adds nor suspends anything;
//! - whose lifetime lasts within a `Since` scope whose filter does not read as a predicate would;
//! - whose lifetime lasts within a scope that chooses by a principal outside the hierarchy
//!   (`By::Under` or `By::Only`), as a rule may not.
//!
//! A cancel of an id that no adjustment in effect has is refused too
//! ([`Inadmissible::NotHeld`]).
//!
//! The strongest a temporary binding can make a policy is one value per policy, decided here
//! (`Reach::ceiling`): Force for a guard with a fixture it fails on and one it holds on (so a
//! stopping guard is always one that was checked on an example), Advise for any other guard and
//! for a reward, and nothing for a meta policy. The same value is what a lost record of an
//! adjustment makes each policy ([`super::catalog::Catalog::effective_in`]).

use std::fmt;

use super::authority::{Authority, NotWithin, Principal};
use super::name::{AdjustmentId, BindingId, PolicyId, Reason};
use super::predicate::{By, Cond, PredError, Reading, Scope, Window, by_reading};
use super::schema::{At, EventKind, Level};
use super::state::Clock;

/// What ends an adjustment by an event, if anything does. The time it ends by is the
/// adjustment's own ([`Adjustment::ends_by`]), the only end by time, so every lifetime ends by it
/// at the latest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub enum Lifetime {
    /// The next judgment it covers, and no more: the record of the
    /// [`super::schema::Judgment::Exempted`] judgment, or of the
    /// [`super::schema::Judgment::Uncertain`] one it let through, uses it up. An exemption only.
    Next,
    /// Until the scope starts again. Within [`Scope::Since`], until the event after the one the
    /// selector chose: that event is judged with the adjustment still in effect. A scope that
    /// chooses by actor ([`super::predicate::By::Under`]) ends the adjustment only at the acts of
    /// the actors it chooses, so a spawn that places a child under its principal changes who
    /// ends it, and is asked of the one who made the adjustment ([`super::tx`]). A window of
    /// [`Scope::Every`] is no longer than the catalog's bound ([`Inadmissible::WindowTooLong`]).
    Within(Scope),
    /// No event ends it: it lasts until the time it ends by, or a cancel.
    Timed,
}

impl Lifetime {
    /// The principal the lifetime reads in the hierarchy of actors, with the direction it reads
    /// it in: the `By::Under` of the scope it lasts within, read as a predicate's scope is
    /// ([`by_reading`]). None for any other lifetime.
    pub(super) fn reading(&self) -> Option<(&Principal, Reading)> {
        match self {
            Self::Within(scope) => scope.by().and_then(by_reading),
            Self::Next | Self::Timed => None,
        }
    }
}

/// The longest period a temporary adjustment may have, in milliseconds, more than zero: how far
/// ahead of the clock the time it ends by may lie, and the longest window of [`Scope::Every`] it
/// may last within. A root declares it in a set it owns
/// ([`super::policy::PolicyGraph::parse_with`]), and the catalog decides it once
/// ([`super::catalog::Catalog::temporary_bound`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "i64", into = "i64"))]
pub struct TemporaryBound(i64);

/// The encoded form of a bound is its milliseconds, read back through
/// [`TemporaryBound::from_millis`].
#[cfg(feature = "serde")]
impl TryFrom<i64> for TemporaryBound {
    type Error = BoundError;

    fn try_from(millis: i64) -> Result<Self, Self::Error> {
        Self::from_millis(millis)
    }
}

#[cfg(feature = "serde")]
impl From<TemporaryBound> for i64 {
    fn from(bound: TemporaryBound) -> Self {
        bound.millis()
    }
}

impl TemporaryBound {
    /// The bound of `millis` milliseconds; zero and negative lengths are refused.
    pub const fn from_millis(millis: i64) -> Result<Self, BoundError> {
        if millis > 0 {
            Ok(Self(millis))
        } else {
            Err(BoundError::NotPositive(millis))
        }
    }

    /// The length in milliseconds.
    pub const fn millis(self) -> i64 {
        self.0
    }

    /// The instant the bound after `at`: the latest time an adjustment made at `at` may end by.
    /// It stops at the latest instant and does not wrap.
    pub(super) const fn after(self, at: At) -> At {
        At::from_millis(at.millis().saturating_add(self.0))
    }
}

/// Why a length is not a bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundError {
    /// The length, in milliseconds, is zero or negative.
    NotPositive(i64),
}

impl fmt::Display for BoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPositive(millis) => write!(f, "a bound of {millis} ms is not positive"),
        }
    }
}

impl std::error::Error for BoundError {}

/// A binding added for a while: the policy takes effect at least at the level, under every mode,
/// by the one who made the adjustment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct TemporaryBinding {
    /// The policy it puts into effect.
    pub policy: PolicyId,
    /// The level.
    pub level: Level,
}

/// What a temporary adjustment changes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub enum Temporary {
    /// The guard does not judge the events the cover covers. It does not change the strength the
    /// guard takes effect at.
    Exempt {
        /// The guard it exempts from.
        guard: PolicyId,
        /// The events it covers, read on the judged event; `None` covers every event the guard
        /// judges. A cover that reads as unknown does not cover the event.
        #[cfg_attr(feature = "serde", serde(deserialize_with = "Option::deserialize"))]
        cover: Option<Cond>,
    },
    /// Bindings added and bindings of the catalog suspended, on every event (there is no cover).
    Rebind {
        /// The bindings added, each under every mode.
        add: Vec<TemporaryBinding>,
        /// The bindings of the catalog that do not hold while it lasts.
        suspend: Vec<BindingId>,
    },
}

/// One temporary adjustment, as a claim states it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct Adjustment {
    /// Its id, which a cancel names.
    pub id: AdjustmentId,
    /// What it changes.
    pub change: Temporary,
    /// What ends it by an event, if anything does.
    pub lifetime: Lifetime,
    /// The time it ends by, compared with the state's clock, which only acts advance: it ends at
    /// the first act at or after the instant, whatever its lifetime. The cover of an exemption is
    /// read with the later of the clock and the time of the judged event, so it covers no event at
    /// or after the instant. No further ahead of the clock than the catalog's bound
    /// ([`Inadmissible::EndsTooLate`]).
    pub ends_by: At,
    /// Why it was made.
    pub reason: Reason,
}

impl Adjustment {
    /// Whether the adjustment has not run out by time as of `clock`: the one place that reads the
    /// time it ends by, read by the fold, by the cover of an exemption and by whether an
    /// adjustment may take effect. Before the first act there is no time yet, and nothing has run
    /// out. That an event has ended it (`Next` used, a scope started again) is the fold's, which
    /// drops it. It takes a [`Clock`], never the time of an event, so a claim's time cannot end
    /// what loosens when it ends.
    pub(super) fn lasts_at(&self, clock: &Clock) -> bool {
        clock.at().is_none_or(|now| now < self.ends_by)
    }

    /// The guard it exempts from, when it is an exemption.
    pub(super) fn exempted(&self) -> Option<PolicyId> {
        match &self.change {
            Temporary::Exempt { guard, .. } => Some(*guard),
            Temporary::Rebind { .. } => None,
        }
    }

    /// The bindings it adds, none for an exemption.
    pub(super) fn added(&self) -> &[TemporaryBinding] {
        match &self.change {
            Temporary::Rebind { add, .. } => add,
            Temporary::Exempt { .. } => &[],
        }
    }

    /// The bindings it suspends, none for an exemption.
    pub(super) fn suspended(&self) -> &[BindingId] {
        match &self.change {
            Temporary::Rebind { suspend, .. } => suspend,
            Temporary::Exempt { .. } => &[],
        }
    }
}

/// What an adjustment may do to a policy, by what the policy is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reach {
    /// A meta policy: nothing.
    Meta,
    /// A guard, with the kind of event it judges and whether it has a fixture it fails on and one
    /// it holds on.
    Guard {
        /// The kind of event it judges, which an exemption's cover is read from.
        subject: EventKind,
        /// Whether it has the fixtures a stopping guard needs.
        stops: bool,
    },
    /// A reward.
    Reward,
}

/// What a policy is, as to the level a binding of it may have: the one fact the rule of
/// [`may_bind_at`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BoundKind {
    /// A guard, and whether it has a fixture it fails on and one it holds on.
    Guard {
        /// Whether it has the fixtures a stopping guard needs.
        stops: bool,
    },
    /// A reward.
    Reward,
}

/// Why a binding of a policy may not be at a level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TooStrong {
    /// A reward at Force: a recommendation cannot stop.
    RewardForce,
    /// A guard at Force that lacks a fixture it fails on or one it holds on.
    MissingFixtures,
}

/// Whether a binding of a policy of `kind` may be at `level`: no reward at Force, and a guard at
/// Force only with the fixtures of a stopping guard (so a stopping guard was always checked on an
/// example). The one answer, read by `Catalog::accept` for a binding of the catalog and by
/// [`AdjustIndex::admits`] for a temporary one; whether the policy may be bound at all (a meta
/// policy) is each caller's own question.
pub(super) fn may_bind_at(kind: BoundKind, level: Level) -> Result<(), TooStrong> {
    match kind {
        _ if !level.stops() => Ok(()),
        BoundKind::Reward => Err(TooStrong::RewardForce),
        BoundKind::Guard { stops: false } => Err(TooStrong::MissingFixtures),
        BoundKind::Guard { stops: true } => Ok(()),
    }
}

impl Reach {
    /// The strongest level a temporary binding can give a policy of this reach: Force for a guard
    /// with the fixtures a stopping guard needs, Advise for any other guard and for a reward, and
    /// `None` for a meta policy.
    fn ceiling(self) -> Option<Level> {
        match self {
            Self::Meta => None,
            Self::Guard { stops: true, .. } => Some(Level::Force),
            Self::Guard { stops: false, .. } | Self::Reward => Some(Level::Advise),
        }
    }
}

/// Why a claimed adjustment, a cancel, or a record of a judgment cannot take effect, whoever
/// makes it. Its transaction is aborted and reports this
/// ([`super::tx::TxReport::inadmissible`]), so the one who claimed it learns that it did not take
/// effect, and why.
#[derive(Debug, Clone, PartialEq)]
pub enum Inadmissible {
    /// An adjustment in effect has the id.
    DuplicateId(AdjustmentId),
    /// The time it ends by has passed by the clock: it is at or before the latest time an act has
    /// carried. The time of the claim itself is not read.
    Expired,
    /// The time it ends by lies further ahead of the clock than the catalog's bound allows. To fix
    /// it, end it by `latest` or sooner, or ask the root for a longer bound.
    EndsTooLate {
        /// The time it ends by.
        ends_by: At,
        /// The latest time it may end by: the clock and the bound.
        latest: At,
        /// The bound.
        bound: TemporaryBound,
    },
    /// The window of `Every` that the lifetime lasts within is longer than the catalog's bound
    /// allows. To fix it, use a window no longer than the bound.
    WindowTooLong {
        /// The window.
        window: Window,
        /// The bound.
        bound: TemporaryBound,
    },
    /// The catalog has no policy with the id.
    UnknownPolicy(PolicyId),
    /// The catalog has no binding with the id.
    UnknownBinding(BindingId),
    /// The policy, or the policy of a suspended binding, is of the meta layer.
    Meta(PolicyId),
    /// The exemption names a policy that is not a guard.
    NotAGuard(PolicyId),
    /// The exemption's cover does not read as a predicate on the guard's event would.
    ExemptionError(Vec<PredError>),
    /// A temporary binding puts the reward into effect at Force.
    RewardForce(PolicyId),
    /// A temporary binding puts the guard into effect at Force, and the guard lacks a fixture it
    /// fails on or one it holds on.
    MissingFixtures(PolicyId),
    /// A rebinding lasts for the next judgment, which a policy it turns off would never record.
    NextOnRebind,
    /// The filter of a `Within(Since(..))` lifetime does not read as a predicate would.
    SinceFilterError(Vec<PredError>),
    /// A rebinding adds nothing and suspends nothing.
    Empty,
    /// The scope of a `Within` lifetime chooses by a principal that is not in the hierarchy
    /// (`By::Under` or `By::Only`), as a rule may not ([`super::catalog::AcceptError::UnknownActor`]).
    UnknownActor(Principal),
    /// The one who makes a temporary binding is not in the hierarchy (one outside it, or a leaf a
    /// spawn added).
    AuthorUnknown(Principal),
    /// The one who makes a temporary binding is neither the policy's author nor below it.
    AuthorAbove {
        /// The policy.
        policy: PolicyId,
        /// The one who makes the binding.
        author: Principal,
    },
    /// A cancel names an id that no adjustment in effect has.
    NotHeld(AdjustmentId),
    /// A record of a judgment is not in the name of the judged policy's author. A record of a
    /// judgment is written in that name ([`super::judge::Outcome::evidence`]), so one in another
    /// name is no judgment any rule made (FR59). A record of a policy the catalog has not is
    /// [`Inadmissible::UnknownPolicy`].
    NotTheAuthor {
        /// The judged policy.
        policy: PolicyId,
        /// Its author, in whose name the record is written.
        author: Principal,
        /// The one the record is in the name of.
        by: Principal,
    },
}

impl fmt::Display for Inadmissible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let errors = |f: &mut fmt::Formatter<'_>, errors: &[PredError]| {
            errors.iter().try_for_each(|e| write!(f, "; {e}"))
        };
        match self {
            Self::DuplicateId(id) => write!(f, "an adjustment in effect has the id {id}"),
            Self::Expired => {
                f.write_str("the time it ends by has passed by the time of the last act")
            }
            Self::EndsTooLate {
                ends_by,
                latest,
                bound,
            } => write!(
                f,
                "it ends by {} ms, later than {} ms, the latest the bound of {} ms allows",
                ends_by.millis(),
                latest.millis(),
                bound.millis()
            ),
            Self::WindowTooLong { window, bound } => write!(
                f,
                "its window of {} ms is longer than the bound of {} ms",
                window.millis(),
                bound.millis()
            ),
            Self::UnknownPolicy(id) => write!(f, "no policy {id}"),
            Self::UnknownBinding(id) => write!(f, "no binding {id}"),
            Self::Meta(id) => write!(f, "{id} is a meta policy"),
            Self::NotAGuard(id) => write!(f, "{id} is not a guard"),
            Self::ExemptionError(e) => {
                f.write_str("the cover does not type-check")?;
                errors(f, e)
            }
            Self::RewardForce(id) => write!(f, "a temporary binding gives the reward {id} Force"),
            Self::MissingFixtures(id) => write!(
                f,
                "a temporary binding makes {id} stop, and it lacks the fixtures of a stopping guard"
            ),
            Self::NextOnRebind => f.write_str("a rebinding cannot last for the next judgment"),
            Self::SinceFilterError(e) => {
                f.write_str("the filter of the lifetime does not type-check")?;
                errors(f, e)
            }
            Self::Empty => f.write_str("the rebinding adds and suspends nothing"),
            Self::UnknownActor(p) => write!(
                f,
                "the lifetime chooses by {p}, who is not in the hierarchy"
            ),
            Self::AuthorUnknown(p) => write!(f, "{p} is not in the hierarchy"),
            Self::AuthorAbove { policy, author } => {
                write!(f, "{author} is neither the author of {policy} nor below it")
            }
            Self::NotHeld(id) => write!(f, "no adjustment in effect has the id {id}"),
            Self::NotTheAuthor { policy, author, by } => write!(
                f,
                "the record of a judgment of {policy} is in the name of {by}, not of its author {author}"
            ),
        }
    }
}

impl std::error::Error for Inadmissible {}

/// What the catalog tells about its policies and bindings for adjustments: the one place that
/// decides whether an adjustment may take effect, and the strongest a temporary binding can make
/// each policy. Built by the catalog when it is accepted.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct AdjustIndex {
    /// Each policy with its reach and its author.
    policies: Vec<(PolicyId, Reach, Principal)>,
    /// Each binding of the catalog, with its policy.
    bindings: Vec<(BindingId, PolicyId)>,
    /// The longest period of an adjustment, as the catalog decided it when it was accepted.
    bound: TemporaryBound,
}

impl AdjustIndex {
    /// The index of the policies, each with its reach and author, and of the bindings, each with
    /// its policy, under the bound the catalog decided.
    pub(super) fn new(
        policies: impl IntoIterator<Item = (PolicyId, Reach, Principal)>,
        bindings: impl IntoIterator<Item = (BindingId, PolicyId)>,
        bound: TemporaryBound,
    ) -> Self {
        Self {
            policies: policies.into_iter().collect(),
            bindings: bindings.into_iter().collect(),
            bound,
        }
    }

    /// The catalog's bound.
    pub(super) fn bound(&self) -> TemporaryBound {
        self.bound
    }

    /// Whether a record of a judgment of `policy` in the name of `by` may be kept: the one check
    /// of who a judgment's record belongs to. It is in the name of the policy's author, or it is
    /// no record of any judgment the catalog's rules made.
    pub(super) fn admits_judged(
        &self,
        policy: PolicyId,
        by: &Principal,
    ) -> Result<(), Inadmissible> {
        match self.policy(policy) {
            None => Err(Inadmissible::UnknownPolicy(policy)),
            Some((_, author)) if author != by => Err(Inadmissible::NotTheAuthor {
                policy,
                author: author.clone(),
                by: by.clone(),
            }),
            Some(_) => Ok(()),
        }
    }

    /// Whether `adjustment` exceeds the bound: the one check of it, read when an adjustment is
    /// admitted (`at` is the clock) and when the carry reaches the first act with an adjustment
    /// admitted before it (`at` is that act). A window of `Every` longer than the bound is refused
    /// whatever `at` is; with a time, so is a time it ends by further ahead than the bound.
    pub(super) fn bounds(
        &self,
        adjustment: &Adjustment,
        at: Option<At>,
    ) -> Result<(), Inadmissible> {
        if let Lifetime::Within(Scope::Every(window)) = &adjustment.lifetime
            && window.millis() > self.bound.millis()
        {
            return Err(Inadmissible::WindowTooLong {
                window: *window,
                bound: self.bound,
            });
        }
        if let Some(at) = at {
            let latest = self.bound.after(at);
            if adjustment.ends_by > latest {
                return Err(Inadmissible::EndsTooLate {
                    ends_by: adjustment.ends_by,
                    latest,
                    bound: self.bound,
                });
            }
        }
        Ok(())
    }

    fn policy(&self, policy: PolicyId) -> Option<(Reach, &Principal)> {
        self.policies
            .iter()
            .find(|(id, _, _)| *id == policy)
            .map(|(_, reach, author)| (*reach, author))
    }

    fn reach(&self, policy: PolicyId) -> Option<Reach> {
        self.policy(policy).map(|(reach, _)| reach)
    }

    /// Each policy outside the meta layer with the strongest level a temporary binding can give it
    /// ([`Reach::ceiling`]) and its author, by id (the catalog's order): what a lost record of an
    /// adjustment may have bound.
    pub(super) fn ceilings(&self) -> impl Iterator<Item = (PolicyId, Level, &Principal)> {
        self.policies
            .iter()
            .filter_map(|(id, reach, author)| reach.ceiling().map(|level| (*id, level, author)))
    }

    /// Whether `adjustment`, made by `by`, may take effect, while `held` says which ids the
    /// adjustments in effect have: see the module doc. `by` is read only as the author of the
    /// bindings it adds, which must be within the policy's author's work by `authority`
    /// ([`Authority::within`], the answer a binding of the catalog is held to); who may loosen
    /// what is the transaction's floor, not this.
    ///
    /// With no clock the time it ends by cannot be checked against the bound; every adjustment
    /// held before the first act is checked by the carry to it ([`AdjustIndex::bounds`]).
    pub(super) fn admits(
        &self,
        adjustment: &Adjustment,
        by: &Principal,
        clock: &Clock,
        authority: &Authority,
        held: impl Fn(AdjustmentId) -> bool,
    ) -> Result<(), Inadmissible> {
        if held(adjustment.id) {
            return Err(Inadmissible::DuplicateId(adjustment.id));
        }
        // One that has run out by the clock would be dropped in the same step. The claim's own
        // time is not read: it does not move the clock.
        if !adjustment.lasts_at(clock) {
            return Err(Inadmissible::Expired);
        }
        self.bounds(adjustment, clock.at())?;
        // A rule's `By` is held to the hierarchy when the catalog is accepted; a lifetime's here.
        if let Lifetime::Within(scope) = &adjustment.lifetime
            && let Some(principal) = scope.by().and_then(By::principal)
            && !authority.contains(principal)
        {
            return Err(Inadmissible::UnknownActor(principal.clone()));
        }
        if let Lifetime::Within(Scope::Since(selector)) = &adjustment.lifetime {
            let errors = selector.filter.check();
            if !errors.is_empty() {
                return Err(Inadmissible::SinceFilterError(errors));
            }
        }
        match &adjustment.change {
            Temporary::Exempt { guard, cover } => match self.reach(*guard) {
                None => Err(Inadmissible::UnknownPolicy(*guard)),
                Some(Reach::Meta) => Err(Inadmissible::Meta(*guard)),
                Some(Reach::Reward) => Err(Inadmissible::NotAGuard(*guard)),
                Some(Reach::Guard { subject, .. }) => {
                    let errors = cover
                        .as_ref()
                        .map_or_else(Vec::new, |cover| cover.check(subject));
                    if errors.is_empty() {
                        Ok(())
                    } else {
                        Err(Inadmissible::ExemptionError(errors))
                    }
                }
            },
            Temporary::Rebind { add, suspend } => {
                if add.is_empty() && suspend.is_empty() {
                    return Err(Inadmissible::Empty);
                }
                if adjustment.lifetime == Lifetime::Next {
                    return Err(Inadmissible::NextOnRebind);
                }
                for binding in add {
                    self.bindable(binding, by, authority)?;
                }
                for id in suspend {
                    let Some((_, policy)) = self.bindings.iter().find(|(b, _)| b == id) else {
                        return Err(Inadmissible::UnknownBinding(*id));
                    };
                    if self.reach(*policy) == Some(Reach::Meta) {
                        return Err(Inadmissible::Meta(*policy));
                    }
                }
                Ok(())
            }
        }
    }

    /// Whether `by` may add the temporary binding: its policy is of the catalog and not of the
    /// meta layer, its level is no stronger than [`Reach::ceiling`], and `by` is within the
    /// work of the policy's author.
    fn bindable(
        &self,
        binding: &TemporaryBinding,
        by: &Principal,
        authority: &Authority,
    ) -> Result<(), Inadmissible> {
        let policy = binding.policy;
        let Some((reach, owner)) = self.policy(policy) else {
            return Err(Inadmissible::UnknownPolicy(policy));
        };
        let kind = match reach {
            Reach::Meta => return Err(Inadmissible::Meta(policy)),
            Reach::Guard { stops, .. } => BoundKind::Guard { stops },
            Reach::Reward => BoundKind::Reward,
        };
        may_bind_at(kind, binding.level).map_err(|e| match e {
            TooStrong::RewardForce => Inadmissible::RewardForce(policy),
            TooStrong::MissingFixtures => Inadmissible::MissingFixtures(policy),
        })?;
        authority.within(by, owner).map_err(|e| match e {
            NotWithin::UnknownPrincipal(p) => Inadmissible::AuthorUnknown(p),
            NotWithin::NotBelow { principal, .. } => Inadmissible::AuthorAbove {
                policy,
                author: principal,
            },
        })
    }
}
