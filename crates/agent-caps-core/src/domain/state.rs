//! The state a judgment reads: a fold of the events, never stored.
//!
//! ```text
//! transcript ─ platform adapter ─▶ events ─┐
//! evidence (appended by the caller) ───────┤
//!                                          ▼
//!                       State = fold(Catalog::apply, initial, events)
//! ```
//!
//! The same events always give the same state, so a judgment can be repeated. A cache of the
//! state is the caller's affair: it is the fold up to a point, continued with the events after.
//!
//! The fold history holds only events that happened. An act judged before it runs is judged on a
//! copy of the state with the act folded over it, and enters the history when it is read back
//! from the transcript. An act that was stopped never runs, so it is not in the history and
//! closes no interval; the same act is never folded twice.
//!
//! # How an event is folded
//!
//! Folding one event is two steps, and the module decides nothing of trust by who an event comes
//! from: [`Event::by`] is read only for whether an adjustment may take effect at all, where the
//! maker of a temporary binding must be within the work of its policy's author, the rule a binding
//! of the catalog keeps ([`super::adjust`]). A temporary adjustment that is held keeps who made it
//! ([`HeldAdjustment::by`]), since a binding it adds is that one's, and the transaction asks that
//! one when the binding is lost; keeping it is a record, not a decision. (Evaluating `ActorUnder`
//! reads the `by` of the event being judged, and a selector or a scope that chooses by actor
//! ([`super::predicate::By`]) reads the `by` of each event it looks at, through
//! `Selector::selects`: facts the rule asks for, not decisions about trust.) Whether the step of a
//! claim is kept is decided by its transaction
//! ([`super::tx`]), which compares the state before and after the step as a list of
//! [`StateChange`]s.
//!
//! ```text
//! carry(event)   what the past and the time bring; of the event it reads only whether it is an
//!                act and when
//!   1. the scopes the previous event closed (kept in the state as `closing`): on true, start
//!      again (slots to their start values, the adjustments that last within the scope end); on
//!      unknown, make the slots of the scope unknown (a `once` that was true too) and mark the
//!      adjustments that last within it as possibly ended (`Holding::MaybeEnded`)
//!   1b. an act advances the clock to max(clock, at); a claim leaves it. `Scope::rolls(before,
//!      after)`, for the scopes of the slots and of the adjustments in effect: a window of
//!      `Every` whose boundary the clock crossed starts again, as in 1
//!   2. the adjustments whose lifetime ran out by the clock end
//! step(event)    what the event itself does
//!   3. `starts_at(event, actors)`, for the scopes of the slots and of the adjustments in effect:
//!      true starts it again, unknown is handled as in 1
//!   4. the event steps every slot (`Selector::selects`), and updates the mode and the
//!      adjustments; what a record that could not be read may have changed is settled here (see
//!      the invariants); an adjustment whose lifetime has run out by the clock as carried is
//!      not added (`State::admits`)
//!   5. `ends_at(event, actors)`, for the scopes of the slots and of the adjustments in effect: a
//!      scope that is not false is kept in `closing` with its truth
//! ```
//!
//! Steps 3 to 5 read the event and the hierarchy of actors, and nothing of time: whether an
//! event is chosen, starts a scope or closes one is `Selector::selects`, which reads the actor
//! with `Actors::is_under`. Everything that happens by time happens in the carry and reads the
//! clock alone: a window that starts again (1b), a lifetime that ends (2), and an adjustment
//! refused as expired (`State::admits`, on the state as carried).
//!
//! # Time
//!
//! The clock is advanced by acts alone, to the latest time an act has carried; before the first
//! act it has no time, and nothing has ended by time: an `Until` lasts, nothing is expired, and
//! no window starts again. A claim's time never ends what loosens when it ends; it may end an
//! exemption's cover. So a raise or a suspension ends by time, a window starts again and an
//! adjustment is refused as expired only by the clock, while whether an exemption covers the
//! judged event is read at the later of the clock and that event's time
//! (`Clock::no_earlier_than`, read and never kept): an exemption that ends sooner only tightens.
//! A claim dated in the future ends no raise, and a guard that judges a claim is not exempted by
//! an exemption whose `Until` the claim's own time has passed. The time of an act is the
//! adapter's to give, as its origin is; an act dated earlier than the clock does not move it
//! back. A record that could not be read advances the clock only when it may have been an act
//! (a kind of [`super::schema::Nature::Act`] among what it may have been); one that may have
//! been only claims carries a claim's time, and moves nothing.
//!
//! Limits of reading time this way:
//!
//! - The clock moves only when an act comes, so a window does not start again and a lifetime
//!   does not end between acts: the carry of the next act does it. A judgment happens only at an
//!   event, and every read of time that loosens waits for an act, so this is never read wrongly
//!   in the loosening direction.
//! - A suspension (or a raise) past its `Until` lasts until the next act's time, as it does when
//!   only claims come, a record that may have been only claims included.
//!
//! An adjustment ([`Body::Adjust`]) is held when the catalog's index admits it
//! ([`super::adjust`]), with the principal of its event; a cancel ([`Body::Cancel`]) ends the
//! held adjustment with its id, and one with no such adjustment does nothing; the record of an
//! [`Judgment::Exempted`] judgment uses up one exemption for the next judgment of that guard.
//! Whether one may take effect, and why not, is one entry point the transaction reads too
//! (`State::admits`).
//!
//! An adjustment that runs out by time (`Lifetime::Until`, or `Within` a window of `Every`) ends
//! in the carry, and no transaction judges that end: the lifetime is what the one who made the
//! adjustment chose, and the time is the clock, which only the acts advance, whose time is the
//! adapter's to give, as the origin of an act is. The domain takes both as given. An
//! end that a claim brings about, a cancel or a claim that closes the scope an adjustment lasts
//! within, is judged by its result.
//!
//! Each [`Scope`] answers the two questions of 3 and 5 about an event, each a [`Truth`], and the
//! question of 1b about the clock, and every scope is folded by this one rule. A claim and an
//! act are stepped by the same rule; a switch to the mode already in effect starts the mode's
//! scope again, as any switch does.
//!
//! The event is judged on the state after the step, so a closing event is judged as the last
//! event of the interval it closes.
//!
//! # What the state holds
//!
//! - The clock: no time before the first act, then the latest time an act has carried
//!   (see Time). Only the carry advances it.
//! - The mode in effect: the mode of the last switch that took effect.
//! - One slot per temporal operator of the catalog's predicates. Each is updated
//!   from its last value and the new event alone, and goes back to its start value when its
//!   scope starts again. The slot of a `spent` is a sum of amounts that starts at zero; a
//!   `Used` it chooses whose amount could not be read makes it unknown until its scope starts
//!   again.
//! - The temporary adjustments in effect, each with who made it and whether it is known to be
//!   held ([`State::adjustments`], [`Holding`]). Each lasts only for its lifetime or until it is
//!   cancelled, and only one the catalog's index admits is kept. When it cannot be told whether
//!   the scope an adjustment lasts within started again or closed, the adjustment is kept as
//!   possibly ended, and what it may have ended is read in the direction that tightens, part by
//!   part (`HeldAdjustment::effect`, the one place that reads it): an exemption covers nothing,
//!   a binding it adds still holds, a binding it suspends is not suspended. So not knowing never
//!   loosens a rule, and never ends a raise without a transaction. A later known start or close
//!   of the scope ends it, as a cancel does.
//! - Whether a record that may have been an adjustment or a cancel was lost. It is kept for the
//!   whole fold, as the mark of a lost spawn is, and how the rules take effect under it is
//!   [`super::catalog::Catalog::effective_in`]'s.
//! - The scopes the last event closed, and whether that is known, until the next event.
//! - The leaves that spawns added to the hierarchy of actors, each with its place and whether
//!   that place is known, and whether a record that may have been a spawn was lost.
//!
//! # Actors
//!
//! Who acts is read from the event ([`Event::by`]); where the actor sits is read from the
//! hierarchy of actors: the catalog's [`Authority`], plus the leaves that spawns added to it.
//! The two are apart: a leaf is in the hierarchy of actors only, so it is no author, and what
//! it claims loosens nothing ([`Authority::may_loosen`] knows it not).
//!
//! - Folding a [`Body::Spawn`] keeps its shape and nothing else: the child is new to the
//!   hierarchy of actors, the place it is put under is in it, and a leaf is added once and never
//!   moved. A spawn that does not meet that adds nothing. Whether the spawn takes effect at all
//!   is its transaction's ([`super::tx`]); the fold does not read who made it.
//! - `Actors::ancestry` is the one place that walks the ancestors of an actor. Whether an actor
//!   is under a principal (`Actors::is_under`) and where a spawn places its child (the
//!   transaction's check) both come from it. An actor the hierarchy does not know, and a leaf
//!   whose place is unknown, make the walk stop with what it has: unknown is never "not under".
//! - A record that could not be read and may have been a spawn may have added a leaf, possibly
//!   with the name of one added after it. So every leaf added after such a record has an unknown
//!   place; those added before it stay as they are. The child of the lost spawn itself is in
//!   neither part of the hierarchy, so it is an unknown actor like any other.
//! - The leaves and the mark of a lost spawn are kept for the whole fold, and a
//!   [`Body::SessionStart`] does not clear them. The name of a leaf is new at every start, so a
//!   leaf of an earlier session changes no judgment of the next, and a mark that stays can only
//!   leave a later leaf unknown, which stops what stops on unknown.
//!
//! # Invariants
//!
//! - Each slot is [`Known`] or unknown.
//! - A record that could not be read changes, for each kind it may have been, what an event of
//!   that kind may have changed, and nothing else: a slot that reads the kind becomes unknown (a
//!   `once` that has seen its event stays known); a `Since` scope whose filter is of the kind
//!   may have closed, so its slots become unknown before the next event; a mode switch makes the
//!   mode unknown and the start of the mode's scope unknown; a judgment ends every exemption for
//!   the next judgment, which it may have used up; an adjustment or a cancel sets the mark that
//!   the temporary adjustments are not known, and a cancel also ends every exemption held, which
//!   it may have cancelled. Losing a record never loosens a rule.
//! - The start of a session, a task or a turn is assumed not to be lost (a known gap, see
//!   [`Scope`]).
//! - An actor whose place in the hierarchy is not known makes a selector or a scope that chooses
//!   by actor unknown on its event, never "not chosen": a slot becomes unknown, and a scope that
//!   may have started again or closed is handled as one that may have.

use std::borrow::Cow;

use super::adjust::{AdjustIndex, Adjustment, Inadmissible, Lifetime, Temporary, TemporaryBinding};
use super::authority::{Authority, Principal};
use super::event::{Body, Event};
use super::name::{AdjustmentId, BindingId, Mode, PolicyId};
use super::policy::ModeScope;
use super::predicate::{Amount, By, Cond, EventFilter, Pred, Scope, Selector, Temporal, Truth};
use super::schema::{At, EventKind, Judgment, Nature};

/// A value that was seen, or could not be.
#[derive(Debug, Clone, PartialEq)]
pub enum Known<T> {
    /// The value.
    Known(T),
    /// What would have told the value could not be read.
    Unknown,
}

/// One slot of a state: what one temporal operator of the catalog remembers. The id is
/// meaningful only within the catalog whose state it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotId(usize);

/// The temporal operators of a catalog, in a fixed order: slot `i` of a state holds what
/// operator `i` remembers.
#[derive(Debug, Clone, PartialEq, Default)]
pub(super) struct SlotTable(Vec<Temporal>);

impl SlotTable {
    /// The table of every temporal operator of `preds`, each once.
    pub(super) fn of<'a>(preds: impl IntoIterator<Item = &'a Pred>) -> Self {
        let mut table: Vec<Temporal> = Vec::new();
        for temporal in preds.into_iter().flat_map(Pred::temporals) {
            if !table.contains(&temporal) {
                table.push(temporal);
            }
        }
        Self(table)
    }

    /// The slot of the temporal operator, when it is one of the table.
    pub(super) fn id_of(&self, temporal: &Temporal) -> Option<SlotId> {
        self.find(temporal).map(SlotId)
    }

    fn find(&self, temporal: &Temporal) -> Option<usize> {
        self.0.iter().position(|t| t == temporal)
    }

    fn scopes(&self) -> impl Iterator<Item = &Scope> {
        self.0.iter().map(Temporal::scope)
    }
}

/// A temporary adjustment in effect, with the principal whose claim made it: the author of the
/// bindings it adds.
#[derive(Debug, Clone, PartialEq)]
pub struct HeldAdjustment {
    /// Who made it.
    pub by: Principal,
    /// The adjustment.
    pub adjustment: Adjustment,
    /// Whether it is known to be held, or may have ended.
    pub holding: Holding,
}

/// Whether a held adjustment is known to be in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Holding {
    /// It is in effect.
    Held,
    /// The scope it lasts within may or may not have started again or closed: an actor of
    /// unknown place, or a condition not known yet. It is kept, and each part of it is read in
    /// the direction that tightens (`HeldAdjustment::effect`), until a known start or close of
    /// the scope ends it, or a cancel does.
    MaybeEnded,
}

/// What a held adjustment does, part by part, as it is read: the one reading of [`Holding`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct HeldEffect<'a> {
    /// The guard it exempts from, with the cover, when it exempts.
    pub(super) exemption: Option<(PolicyId, Option<&'a Cond>)>,
    /// The bindings it adds.
    pub(super) added: &'a [TemporaryBinding],
    /// The bindings of the catalog it suspends.
    pub(super) suspended: &'a [BindingId],
}

impl HeldAdjustment {
    /// What the adjustment does: all of it while it is held. One that may have ended is read in
    /// the direction that tightens, part by part, since what cannot be told never loosens: an
    /// exemption covers nothing (read as ended), a binding it adds still holds (read as held),
    /// and a binding it suspends is not suspended (read as ended). The one place that reads
    /// [`Holding`]; the effect of the rules, the cover of an exemption and the transaction's
    /// comparison all read it here.
    pub(super) fn effect(&self) -> HeldEffect<'_> {
        let held = self.holding == Holding::Held;
        let exemption = match &self.adjustment.change {
            Temporary::Exempt { guard, cover } if held => Some((*guard, cover.as_ref())),
            Temporary::Exempt { .. } | Temporary::Rebind { .. } => None,
        };
        let suspended = if held {
            self.adjustment.suspended()
        } else {
            &[]
        };
        HeldEffect {
            exemption,
            added: self.adjustment.added(),
            suspended,
        }
    }
}

/// One difference between a state and the state after one step: what the transaction of a claim
/// judges ([`super::tx`]).
#[derive(Debug, Clone, PartialEq)]
pub enum StateChange {
    /// The slot's value changed, or whether its scope closes on the event did.
    Slot(SlotId),
    /// The temporary adjustment was added.
    AdjustmentAdded(AdjustmentId),
    /// The temporary adjustment ended: cancelled, used up, or at the end of its lifetime.
    AdjustmentEnded(AdjustmentId),
    /// The mode in effect changed.
    Mode {
        /// The mode before.
        before: Known<Option<Mode>>,
        /// The mode after.
        after: Known<Option<Mode>>,
    },
    /// A leaf was added to the hierarchy of actors.
    ActorAdded {
        /// The new actor.
        child: Principal,
        /// The actor it was placed under.
        under: Principal,
    },
}

/// One leaf the spawns added to the hierarchy of actors.
#[derive(Debug, Clone, PartialEq)]
struct Leaf {
    child: Principal,
    under: Principal,
    /// `Unknown` when the leaf was added after a record that may have been a spawn.
    placed: Known<()>,
}

/// The principals above an actor, itself first, as far as they can be told.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Ancestry {
    /// The whole chain, up to the root of the authority.
    Known(Vec<Principal>),
    /// The walk met an actor the hierarchy does not know, or a leaf whose place is unknown. These
    /// are the principals it passed (the one it stopped at included); what is above is not known.
    Unknown { known: Vec<Principal> },
}

/// The hierarchy of actors beyond the authority's: the leaves that spawns added, in the order
/// they were added. Together with the [`Authority`] it is the hierarchy `ActorUnder` reads.
#[derive(Debug, Clone, PartialEq, Default)]
pub(super) struct Actors {
    leaves: Vec<Leaf>,
    /// Whether a record that may have been a spawn was lost. It is kept for the whole fold.
    lost: bool,
}

impl Actors {
    fn leaf(&self, actor: &Principal) -> Option<&Leaf> {
        self.leaves.iter().find(|leaf| leaf.child == *actor)
    }

    /// Whether the actor is in the hierarchy of actors: a principal of the authority, or a leaf.
    fn has(&self, actor: &Principal, authority: &Authority) -> bool {
        authority.contains(actor) || self.leaf(actor).is_some()
    }

    /// Adds the leaf, when `child` is new to the hierarchy of actors and `under` is in it: the
    /// shape of a spawn, and nothing about who made it. A leaf added after a lost record that
    /// may have been a spawn is of unknown place.
    fn add(&mut self, child: &Principal, under: &Principal, authority: &Authority) {
        if self.has(child, authority) || !self.has(under, authority) {
            return;
        }
        let placed = if self.lost {
            Known::Unknown
        } else {
            Known::Known(())
        };
        self.leaves.push(Leaf {
            child: child.clone(),
            under: under.clone(),
            placed,
        });
    }

    /// The principals above `actor`, itself first: the one place that walks the ancestors. From
    /// `actor` it follows the leaves to a principal of the authority, then the authority's
    /// parents. It stops with what it has at an actor that is in neither, and at a leaf whose
    /// place is unknown.
    pub(super) fn ancestry(&self, actor: &Principal, authority: &Authority) -> Ancestry {
        let mut chain: Vec<Principal> = Vec::new();
        let mut at = actor;
        loop {
            if let Some(leaf) = self.leaf(at) {
                chain.push(at.clone());
                match leaf.placed {
                    Known::Known(()) => at = &leaf.under,
                    Known::Unknown => return Ancestry::Unknown { known: chain },
                }
            } else if authority.contains(at) {
                let mut above = Some(at);
                while let Some(principal) = above {
                    chain.push(principal.clone());
                    above = authority.parent(principal);
                }
                return Ancestry::Known(chain);
            } else {
                chain.push(at.clone());
                return Ancestry::Unknown { known: chain };
            }
        }
    }

    /// Whether `actor` is `ancestor` or below it, from [`Actors::ancestry`]: true or false when the
    /// walk is whole, and when it stopped, true if it passed `ancestor` and unknown otherwise.
    /// (The words and the direction differ from [`Authority::covers`], which is about whose
    /// rules one may loosen.)
    pub(super) fn is_under(
        &self,
        actor: &Principal,
        ancestor: &Principal,
        authority: &Authority,
    ) -> Truth {
        match self.ancestry(actor, authority) {
            Ancestry::Known(chain) => Truth::of(chain.contains(ancestor)),
            Ancestry::Unknown { known } if known.contains(ancestor) => Truth::True,
            Ancestry::Unknown { .. } => Truth::Unknown,
        }
    }

    /// The leaves `self` has that `before` does not, in the order they were added. `self` is
    /// `before` folded further, and leaves are only ever appended, so they are the tail.
    fn added_since<'a>(&'a self, before: &Self) -> impl Iterator<Item = &'a Leaf> {
        self.leaves.iter().skip(before.leaves.len())
    }
}

/// What one temporal operator remembers.
#[derive(Debug, Clone, PartialEq)]
enum Slot {
    Once(Known<bool>),
    Count(Known<u32>),
    /// The last event that matched the filter within the scope; `Known(None)`: there was none.
    Last(Known<Option<Body>>),
    /// The sum of the amounts of the `Used` events chosen within the scope.
    Spent(Known<Amount>),
}

impl Slot {
    fn start(temporal: &Temporal) -> Self {
        match temporal {
            Temporal::Once(..) => Self::Once(Known::Known(false)),
            Temporal::Count(..) => Self::Count(Known::Known(0)),
            Temporal::Last(..) => Self::Last(Known::Known(None)),
            Temporal::Spent(..) => Self::Spent(Known::Known(Amount::ZERO)),
        }
    }

    /// The slot after a record that could not be read, and may have been an event it reads.
    fn unread(self) -> Self {
        match self {
            Self::Once(Known::Known(true)) => self,
            Self::Once(_) => Self::Once(Known::Unknown),
            Self::Count(_) => Self::Count(Known::Unknown),
            Self::Last(_) => Self::Last(Known::Unknown),
            Self::Spent(_) => Self::Spent(Known::Unknown),
        }
    }

    /// The slot when the interval it counts in may or may not have closed: nothing is known of
    /// it, a `once` that was true included.
    fn lost(&self) -> Self {
        match self {
            Self::Once(_) => Self::Once(Known::Unknown),
            Self::Count(_) => Self::Count(Known::Unknown),
            Self::Last(_) => Self::Last(Known::Unknown),
            Self::Spent(_) => Self::Spent(Known::Unknown),
        }
    }

    /// The slot after `event`, which is not an unreadable record, with the hierarchy of actors
    /// its selector reads the actor in.
    fn step(
        self,
        temporal: &Temporal,
        event: &Event,
        actors: &Actors,
        authority: &Authority,
    ) -> Self {
        let chosen = temporal.selector().selects(event, actors, authority);
        match (self, temporal) {
            (Self::Once(seen), Temporal::Once(..)) => Self::Once(match (seen, chosen) {
                (_, Truth::True) | (Known::Known(true), _) => Known::Known(true),
                (_, Truth::Unknown) | (Known::Unknown, Truth::False) => Known::Unknown,
                (Known::Known(false), Truth::False) => Known::Known(false),
            }),
            (Self::Count(count), Temporal::Count(..)) => Self::Count(match (count, chosen) {
                (Known::Known(n), Truth::True) => Known::Known(n.saturating_add(1)),
                (Known::Known(n), Truth::False) => Known::Known(n),
                (_, _) => Known::Unknown,
            }),
            (Self::Last(last), Temporal::Last(..)) => match chosen {
                Truth::True => Self::Last(Known::Known(Some(event.body.clone()))),
                Truth::False => Self::Last(last),
                Truth::Unknown => Self::Last(Known::Unknown),
            },
            // The one place that reads the amount a `Used` adds. One whose amount could not be
            // read makes the sum unknown; the event is still chosen, so a `count` of it and a
            // `Since` it closes read it as known.
            (Self::Spent(sum), Temporal::Spent(..)) => Self::Spent(match (sum, chosen) {
                (Known::Known(total), Truth::True) => match &event.body {
                    Body::Used {
                        amount: Some(amount),
                        ..
                    } => Known::Known(total.saturating_add(*amount)),
                    _ => Known::Unknown,
                },
                (Known::Known(total), Truth::False) => Known::Known(total),
                (_, _) => Known::Unknown,
            }),
            // A slot always has the shape of its operator: both come from the same table.
            (slot, _) => slot,
        }
    }
}

/// Whether the temporal operator reads events of `kind`: the kind it looks for.
fn reads(temporal: &Temporal, kind: EventKind) -> bool {
    temporal.selector().filter.kind == kind
}

/// The time as the acts tell it: no time before the first act, then the latest time an act has
/// carried. Only [`State::carry`] advances it, and only for an act; a claim's time never moves it,
/// and an act dated earlier never moves it back. Every read of time that ends what loosens when
/// it ends (a lifetime, the window of [`Scope::Every`], an adjustment refused as expired) reads
/// it; the one read that may take a claim's time is [`Clock::no_earlier_than`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Clock(Option<At>);

impl Clock {
    /// The time, once an act has carried one.
    pub(super) fn at(&self) -> Option<At> {
        self.0
    }

    /// The later of the clock and `at`: the clock an act at `at` advances it to in the carry, and,
    /// read and never kept, the time an exemption's cover is read at on an event at `at`. A
    /// claim's time may end an exemption sooner, since that only tightens; it is the one place a
    /// claim's time is read.
    pub(super) fn no_earlier_than(&self, at: At) -> Self {
        Self(Some(self.0.map_or(at, |now| now.max(at))))
    }
}

/// The state a judgment reads. Made by folding events from [`super::catalog::Catalog::start`]
/// with [`super::catalog::Catalog::apply`].
#[derive(Debug, Clone, PartialEq)]
pub struct State {
    /// The time as the acts tell it.
    clock: Clock,
    mode: Known<Option<Mode>>,
    slots: Vec<Slot>,
    /// The temporary adjustments in effect, in the order they were made.
    adjustments: Vec<HeldAdjustment>,
    /// Whether a record that may have been an adjustment or a cancel was lost. Kept for the
    /// whole fold.
    adjustments_lost: bool,
    /// The scopes the last event closed, with whether it did: they start again (or become
    /// unknown) before the next event.
    closing: Vec<(Scope, Truth)>,
    /// The leaves spawns added to the hierarchy of actors. Kept for the whole fold.
    actors: Actors,
}

/// The start event of a task scope, of any actor: what `Task(by)` chooses with its `by`.
const TASK_START: EventFilter = EventFilter {
    kind: EventKind::TaskStart,
    cond: None,
};

/// The start event of a turn scope, of any actor: what `Turn(by)` chooses with its `by`.
const PROMPT_SUBMIT: EventFilter = EventFilter {
    kind: EventKind::PromptSubmit,
    cond: None,
};

impl Scope {
    /// Whether the scope starts again by time, as the clock moved from `before` to `after` in the
    /// carry to an event (step 1b of the module doc): only `Every`, when the clock's window
    /// changed. False when either clock has no time yet. The one answer to "does time start this
    /// scope again"; it reads the clock, and nothing of the event.
    pub(super) fn rolls(&self, before: &Clock, after: &Clock) -> Truth {
        let Self::Every(window) = self else {
            return Truth::False;
        };
        match (before.at(), after.at()) {
            (Some(was), Some(is)) => Truth::of(window.index(was) != window.index(is)),
            _ => Truth::False,
        }
    }

    /// Whether the scope starts again before `event`, with the hierarchy of actors a `By` reads
    /// the actor in. Every scope bounded by events starts again at a session's start; `Every` is
    /// bounded by time and never starts again here ([`Scope::rolls`]). `Task` and `Turn` start
    /// again at their start event when their `By` chooses its actor (`chosen`, unknown when its
    /// place is). Any mode switch starts the mode's scope again, and a record that may have been
    /// one leaves it unknown. It reads the event, and nothing of time.
    pub(super) fn starts_at(&self, event: &Event, actors: &Actors, authority: &Authority) -> Truth {
        let at_session = matches!(event.body, Body::SessionStart);
        let started_by = |start: &EventFilter, by: &By| {
            if at_session {
                Truth::True
            } else {
                chosen(start, by, event, actors, authority)
            }
        };
        match self {
            Self::Session | Self::Since(_) => Truth::of(at_session),
            Self::Every(_) => Truth::False,
            Self::Task(by) => started_by(&TASK_START, by),
            Self::Turn(by) => started_by(&PROMPT_SUBMIT, by),
            Self::Mode => match &event.body {
                Body::SessionStart | Body::ModeSwitch { .. } => Truth::True,
                Body::Unreadable { may_have_been }
                    if may_have_been.contains(EventKind::ModeSwitch) =>
                {
                    Truth::Unknown
                }
                _ => Truth::False,
            },
        }
    }

    /// Whether the scope closes on `event`, which then belongs to the interval it closes. Only
    /// `Since` closes on an event: one its selector chooses ([`Selector::selects`]). A record
    /// that could not be read may have been the event it looks for only when the filter's kind
    /// is one it may have been.
    pub(super) fn ends_at(&self, event: &Event, actors: &Actors, authority: &Authority) -> Truth {
        let Self::Since(selector) = self else {
            return Truth::False;
        };
        match &event.body {
            body if body.kind() == selector.filter.kind => {
                selector.selects(event, actors, authority)
            }
            Body::Unreadable { may_have_been } if may_have_been.contains(selector.filter.kind) => {
                Truth::Unknown
            }
            _ => Truth::False,
        }
    }
}

/// Whether `body`, an event of the filter's kind, meets the filter's condition: the one answer to
/// "does this filter match this event", read by the selectors, the scopes and
/// [`super::catalog::Capabilities`]. It reads nothing of who acted.
pub(super) fn matched(filter: &EventFilter, body: &Body) -> Truth {
    filter
        .cond
        .as_ref()
        .map_or(Truth::True, |cond| body.holds(cond))
}

/// Ends the adjustments that last within a scope `of` takes, as `truth` says it started again or
/// closed: true ends them, unknown marks them [`Holding::MaybeEnded`] (what may have ended is
/// read in the direction that tightens), false does nothing. The one rule for ending an
/// adjustment by its scope, read by the fold and by the state as the next event finds it.
fn end_within(adjustments: &mut Vec<HeldAdjustment>, of: impl Fn(&Scope) -> bool, truth: Truth) {
    let within = |held: &HeldAdjustment| matches!(&held.adjustment.lifetime, Lifetime::Within(scope) if of(scope));
    match truth {
        Truth::False => {}
        Truth::True => adjustments.retain(|held| !within(held)),
        Truth::Unknown => {
            for held in adjustments.iter_mut().filter(|held| within(held)) {
                held.holding = Holding::MaybeEnded;
            }
        }
    }
}

impl Selector {
    /// Whether the selector chooses `event`, which is not an unreadable record: the event is of
    /// the filter's kind and meets it ([`matched`]), and its actor is one `by` chooses
    /// ([`Actors::is_under`] for `Under`, the event's `by` itself for `Only`). The one answer to
    /// "is this event chosen", read by the slots, by a `Since` that closes and by a task or a
    /// turn that starts again. Under `Under`, an actor whose place is not known gives unknown,
    /// unless the filter alone says no; `Only` reads no hierarchy and is never unknown.
    pub(super) fn selects(&self, event: &Event, actors: &Actors, authority: &Authority) -> Truth {
        chosen(&self.filter, &self.by, event, actors, authority)
    }
}

/// [`Selector::selects`], of a filter and a `By` held apart: the start event of a task or a turn
/// scope is a filter with no condition, and its `By` is the scope's.
fn chosen(
    filter: &EventFilter,
    by: &By,
    event: &Event,
    actors: &Actors,
    authority: &Authority,
) -> Truth {
    if event.body.kind() != filter.kind {
        return Truth::False;
    }
    // The filter alone may say no; then the hierarchy is not walked.
    let what = matched(filter, &event.body);
    if what == Truth::False {
        return Truth::False;
    }
    let actor = match by {
        By::Anyone => Truth::True,
        By::Under(principal) => actors.is_under(&event.by, principal, authority),
        By::Only(principal) => Truth::of(event.by == *principal),
    };
    Truth::all([what, actor])
}

impl State {
    /// The state before any event: no time, no mode, every slot at its start value, no
    /// adjustment.
    pub(super) fn start(table: &SlotTable) -> Self {
        Self {
            clock: Clock(None),
            mode: Known::Known(None),
            slots: table.0.iter().map(Slot::start).collect(),
            adjustments: Vec::new(),
            adjustments_lost: false,
            closing: Vec::new(),
            actors: Actors::default(),
        }
    }

    /// The mode in effect.
    pub fn mode(&self) -> &Known<Option<Mode>> {
        &self.mode
    }

    /// The temporary adjustments in effect, in the order they were made, each with who made it:
    /// what can be seen and cancelled. After a record that may have been an adjustment or a
    /// cancel was lost, this is what is known of them ([`State::adjustments_lost`]).
    pub fn adjustments(&self) -> &[HeldAdjustment] {
        &self.adjustments
    }

    /// Whether a record that may have been an adjustment or a cancel was lost in the fold, so the
    /// adjustments in effect are not known. Every rule then takes effect as strongly as a
    /// temporary binding could make it ([`super::catalog::Catalog::effective_in`]).
    pub fn adjustments_lost(&self) -> bool {
        self.adjustments_lost
    }

    /// Whether an adjustment in effect has the id: the one answer, read by the fold, by whether
    /// an adjustment or a cancel may take effect, and by the transaction's comparison.
    pub(super) fn holds_adjustment(&self, id: AdjustmentId) -> bool {
        self.adjustments.iter().any(|h| h.adjustment.id == id)
    }

    /// Whether `event` may take effect on this state as an adjustment or a cancel, whoever makes
    /// it: an adjustment as `index` admits it, made by the event's principal, and a cancel when an
    /// adjustment in effect has its id. Any other event is not one, and is `Ok`. The one entry
    /// point the fold and the transaction both read.
    pub(super) fn admits(
        &self,
        event: &Event,
        index: &AdjustIndex,
        authority: &Authority,
    ) -> Result<(), Inadmissible> {
        match &event.body {
            Body::Adjust(adjustment) => {
                index.admits(adjustment, &event.by, &self.clock, authority, |id| {
                    self.holds_adjustment(id)
                })
            }
            Body::Cancel { id } if !self.holds_adjustment(*id) => Err(Inadmissible::NotHeld(*id)),
            _ => Ok(()),
        }
    }

    /// The leaves that spawns added to the hierarchy of actors.
    pub(super) fn actors(&self) -> &Actors {
        &self.actors
    }

    /// The state carried to `event`: steps 1, 1b and 2 of the module doc. It reads of the event
    /// only whether it is an act and its time, never its actor, so it is the same whoever the
    /// event comes from, and it is always kept. The one place that advances the clock: to the
    /// later of the clock and the event's time, for an act alone.
    pub(super) fn carry(mut self, table: &SlotTable, event: &Event) -> Self {
        // 1. The scopes the previous event closed.
        for (scope, truth) in std::mem::take(&mut self.closing) {
            self.settle(table, &scope, truth);
        }
        // 1b. The clock, and the scopes it starts again.
        let before = self.clock;
        // A record that could not be read is an act only when it may have been one: one that
        // may have been only claims carries a claim's time, which moves no clock.
        let act = match &event.body {
            Body::Unreadable { may_have_been } => may_have_been
                .iter()
                .any(|kind| kind.nature() == Nature::Act),
            body => body.kind().nature() == Nature::Act,
        };
        if act {
            self.clock = before.no_earlier_than(event.at);
        }
        // A clock that did not move starts no window again.
        if self.clock != before {
            let rolling: Vec<(Scope, Truth)> = self
                .scopes_in_use(table)
                .filter_map(|scope| match scope.rolls(&before, &self.clock) {
                    Truth::False => None,
                    truth => Some((scope.clone(), truth)),
                })
                .collect();
            for (scope, truth) in rolling {
                self.settle(table, &scope, truth);
            }
        }
        // 2. The lifetimes that ran out by the clock.
        let clock = self.clock;
        self.adjustments
            .retain(|held| held.adjustment.lifetime.lasts_at(&clock));
        self
    }

    /// The state after `event`, from a state carried to it: steps 3 to 5 of the module doc.
    /// `index` is the catalog's: an adjustment is held only when it admits it. `authority` is the
    /// hierarchy the catalog was accepted with: a spawn's shape is checked against it, and so is
    /// the maker of a temporary binding (`AdjustIndex::admits`); nothing else of it is read here.
    pub(super) fn step(
        mut self,
        table: &SlotTable,
        event: &Event,
        index: &AdjustIndex,
        authority: &Authority,
    ) -> Self {
        let body = &event.body;
        // 3. The scopes that start again before this event: those of the slots and of the
        // adjustments in effect, the only ones whose start changes anything. Settling is
        // idempotent, so a scope listed twice does no harm; only the few that start are cloned.
        let starting: Vec<(Scope, Truth)> = self
            .scopes_in_use(table)
            .filter_map(
                |scope| match scope.starts_at(event, &self.actors, authority) {
                    Truth::False => None,
                    truth => Some((scope.clone(), truth)),
                },
            )
            .collect();
        for (scope, truth) in starting {
            self.settle(table, &scope, truth);
        }
        // 4. The event itself.
        match body {
            Body::Unreadable { may_have_been } => {
                // What an event of each kind it may have been may have changed. Whether it may
                // have closed a scope is answered by `ends_at`, and whether it may have started
                // the mode's scope again by `starts_at`.
                self.slots = self
                    .slots
                    .into_iter()
                    .zip(&table.0)
                    .map(|(slot, temporal)| {
                        if may_have_been.iter().any(|kind| reads(temporal, kind)) {
                            slot.unread()
                        } else {
                            slot
                        }
                    })
                    .collect();
                if may_have_been.contains(EventKind::ModeSwitch) {
                    self.mode = Known::Unknown;
                }
                if may_have_been.contains(EventKind::Judged) {
                    self.adjustments
                        .retain(|held| held.adjustment.lifetime != Lifetime::Next);
                }
                // It may have cancelled an exemption: ending one only stops a guard from being
                // skipped. What it may have done to bindings is the mark's.
                if may_have_been.contains(EventKind::Cancel) {
                    self.adjustments
                        .retain(|held| held.adjustment.exempted().is_none());
                }
                if may_have_been.contains(EventKind::Adjust)
                    || may_have_been.contains(EventKind::Cancel)
                {
                    self.adjustments_lost = true;
                }
                // It may have added a leaf, so the leaves added from now on are of unknown place.
                if may_have_been.contains(EventKind::Spawn) {
                    self.actors.lost = true;
                }
            }
            _ => {
                let actors = &self.actors;
                self.slots = std::mem::take(&mut self.slots)
                    .into_iter()
                    .zip(&table.0)
                    .map(|(slot, temporal)| slot.step(temporal, event, actors, authority))
                    .collect();
            }
        }
        match body {
            Body::ModeSwitch { to } => self.mode = Known::Known(Some(to.clone())),
            Body::Spawn { child, under } => self.actors.add(child, under, authority),
            Body::Adjust(adjustment) if self.admits(event, index, authority).is_ok() => {
                self.adjustments.push(HeldAdjustment {
                    by: event.by.clone(),
                    adjustment: adjustment.clone(),
                    holding: Holding::Held,
                });
            }
            Body::Cancel { id } => self.adjustments.retain(|held| held.adjustment.id != *id),
            Body::Judged {
                policy,
                judgment: Judgment::Exempted,
                ..
            } => {
                let used = self.adjustments.iter().position(|held| {
                    held.adjustment.exempted() == Some(*policy)
                        && held.adjustment.lifetime == Lifetime::Next
                });
                if let Some(at) = used {
                    self.adjustments.remove(at);
                }
            }
            _ => {}
        }
        // Nothing here ends by time: the step does not move the clock, the carry dropped what had
        // run out by it, and `admits` refuses as expired one this event would add.
        // 5. The scopes this event closes, each once.
        let mut closing: Vec<(Scope, Truth)> = Vec::new();
        for scope in self.scopes_in_use(table) {
            let truth = scope.ends_at(event, &self.actors, authority);
            if truth != Truth::False && !closing.iter().any(|(seen, _)| seen == scope) {
                closing.push((scope.clone(), truth));
            }
        }
        self.closing = closing;
        self
    }

    /// The differences between `before` and `after`, two states of the catalog whose table is
    /// `table`: each slot whose value, or whose scope's closing, differs; each adjustment added or
    /// ended, by its id; the mode, when it differs; and each leaf added to the hierarchy of
    /// actors.
    pub(super) fn changes(table: &SlotTable, before: &State, after: &State) -> Vec<StateChange> {
        let closing_of = |state: &State, scope: &Scope| {
            state
                .closing
                .iter()
                .find(|(closed, _)| closed == scope)
                .map(|(_, truth)| *truth)
        };
        let mut changes = Vec::new();
        for (at, temporal) in table.0.iter().enumerate() {
            let scope = temporal.scope();
            // The score of an event a slot holds is compared with NaN equal to NaN (see `Body`),
            // so a NaN that was not touched is not taken for a change.
            let same = before.slots.get(at) == after.slots.get(at);
            if !same || closing_of(before, scope) != closing_of(after, scope) {
                changes.push(StateChange::Slot(SlotId(at)));
            }
        }
        let ids = |state: &State| -> Vec<AdjustmentId> {
            state.adjustments.iter().map(|h| h.adjustment.id).collect()
        };
        let (was, is) = (ids(before), ids(after));
        changes.extend(
            is.iter()
                .filter(|id| !was.contains(id))
                .map(|id| StateChange::AdjustmentAdded(*id)),
        );
        changes.extend(
            was.iter()
                .filter(|id| !is.contains(id))
                .map(|id| StateChange::AdjustmentEnded(*id)),
        );
        if before.mode != after.mode {
            changes.push(StateChange::Mode {
                before: before.mode.clone(),
                after: after.mode.clone(),
            });
        }
        changes.extend(after.actors.added_since(&before.actors).map(|leaf| {
            StateChange::ActorAdded {
                child: leaf.child.clone(),
                under: leaf.under.clone(),
            }
        }));
        changes
    }

    /// The scopes of the slots and of the adjustments in effect, possibly with repeats: every
    /// scope whose start or close changes the state, a scope an adjustment lasts within and no
    /// slot counts in included.
    fn scopes_in_use<'a>(&'a self, table: &'a SlotTable) -> impl Iterator<Item = &'a Scope> {
        let within = self
            .adjustments
            .iter()
            .filter_map(|h| match &h.adjustment.lifetime {
                Lifetime::Within(scope) => Some(scope),
                Lifetime::Next | Lifetime::Until(_) => None,
            });
        table.scopes().chain(within)
    }

    /// Acts on `scope` as `truth` says it started again (or closed): true puts its slots back to
    /// their start values and ends the adjustments that last within it; unknown makes the slots
    /// unknown and marks those adjustments as possibly ended (`end_within`).
    fn settle(&mut self, table: &SlotTable, scope: &Scope, truth: Truth) {
        if truth == Truth::False {
            return;
        }
        for (slot, temporal) in self.slots.iter_mut().zip(&table.0) {
            if temporal.scope() == scope {
                *slot = match truth {
                    Truth::True => Slot::start(temporal),
                    _ => slot.lost(),
                };
            }
        }
        end_within(&mut self.adjustments, |within| within == scope, truth);
    }

    /// The state as the event after this one will find it, as to the adjustments: those that
    /// last within a scope this event closed, which are still held until the next carry (so that
    /// the closing event is judged with them), taken out. A claim that closes such a scope ends
    /// them, and its transaction compares the state before it with this one, so the end is judged
    /// as the claim's result. Borrowed as it is when no adjustment lasts within a scope this
    /// event closed, as for most claims, so nothing is cloned for them.
    pub(super) fn with_closed_scopes_ended(&self) -> Cow<'_, Self> {
        let closed = |held: &HeldAdjustment| {
            matches!(&held.adjustment.lifetime, Lifetime::Within(within)
                if self.closing.iter().any(|(scope, truth)| *truth != Truth::False && scope == within))
        };
        if !self.adjustments.iter().any(closed) {
            return Cow::Borrowed(self);
        }
        let mut ended = self.clone();
        for (scope, truth) in &self.closing {
            end_within(&mut ended.adjustments, |within| within == scope, *truth);
        }
        Cow::Owned(ended)
    }

    /// Whether an exemption in effect covers the guard `guard` on `event`: the one place that
    /// reads an exemption's cover on an event. A cover that reads as unknown does not cover it.
    /// Its lifetime is read at the later of the clock and the event's time
    /// ([`Clock::no_earlier_than`]): an exemption that ends sooner only tightens, so a claim
    /// judged after an exemption's `Until`, or past the boundary of the window of `Every` it lasts
    /// within, is not covered, with no act in between.
    pub(super) fn exempts(&self, guard: PolicyId, event: &Event) -> bool {
        let now = self.clock.no_earlier_than(event.at);
        self.adjustments.iter().any(|h| {
            // One that may have ended covers nothing (`HeldAdjustment::effect`).
            let Some((of, cover)) = h.effect().exemption else {
                return false;
            };
            // Held on the clock, so it was made in the clock's window: a window the event's time
            // has left is one it no longer lasts within.
            let window_left = matches!(&h.adjustment.lifetime,
                Lifetime::Within(scope) if scope.rolls(&self.clock, &now) != Truth::False);
            let in_time = h.adjustment.lifetime.lasts_at(&now) && !window_left;
            let covers = cover.is_none_or(|cover| event.body.holds(cover) == Truth::True);
            of == guard && in_time && covers
        })
    }

    /// Whether `pred` holds of `event`, with the state already folded over it. `authority` is the
    /// hierarchy the catalog was accepted with, which `ActorUnder` reads with the leaves.
    pub(super) fn holds(
        &self,
        table: &SlotTable,
        authority: &Authority,
        pred: &Pred,
        event: &Event,
    ) -> Truth {
        let slot = |temporal: Temporal| table.find(&temporal).and_then(|at| self.slots.get(at));
        let holds = |pred: &Pred| self.holds(table, authority, pred, event);
        match pred {
            Pred::Now(cond) => event.body.holds(cond),
            Pred::ModeIs(mode) => ModeScope::In(mode.clone()).holds(&self.mode),
            Pred::ActorUnder(principal) => self.actors.is_under(&event.by, principal, authority),
            Pred::Once { select, scope } => {
                match slot(Temporal::Once(select.clone(), scope.clone())) {
                    Some(Slot::Once(Known::Known(seen))) => Truth::of(*seen),
                    _ => Truth::Unknown,
                }
            }
            Pred::Count {
                select,
                scope,
                cmp,
                n,
            } => match slot(Temporal::Count(select.clone(), scope.clone())) {
                Some(Slot::Count(Known::Known(count))) => {
                    cmp.holds(*count, *n).map_or(Truth::Unknown, Truth::of)
                }
                _ => Truth::Unknown,
            },
            Pred::Last {
                select,
                scope,
                test,
            } => match slot(Temporal::Last(select.clone(), scope.clone())) {
                Some(Slot::Last(Known::Known(Some(last)))) => last.holds(test),
                Some(Slot::Last(Known::Known(None))) => Truth::False,
                _ => Truth::Unknown,
            },
            Pred::Spent {
                meter,
                by,
                scope,
                order,
                n,
            } => match slot(Temporal::Spent(
                Pred::spent_selector(meter, by),
                scope.clone(),
            )) {
                Some(Slot::Spent(Known::Known(sum))) => Truth::of(order.holds(*sum, *n)),
                _ => Truth::Unknown,
            },
            Pred::All(preds) => Truth::all(preds.iter().map(holds)),
            Pred::Any(preds) => Truth::any(preds.iter().map(holds)),
            Pred::Not(pred) => !holds(pred),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(key: &str) -> Principal {
        Principal::new(key)
    }

    /// `user` above `agent`.
    fn authority() -> Authority {
        Authority::new([(p("user"), None), (p("agent"), Some(p("user")))]).unwrap()
    }

    #[test]
    fn the_ancestry_follows_the_leaves_then_the_authority() {
        let authority = authority();
        let mut actors = Actors::default();
        actors.add(&p("a"), &p("agent"), &authority);
        actors.add(&p("b"), &p("a"), &authority);
        assert_eq!(
            actors.ancestry(&p("b"), &authority),
            Ancestry::Known(vec![p("b"), p("a"), p("agent"), p("user")])
        );
        assert_eq!(
            actors.is_under(&p("b"), &p("agent"), &authority),
            Truth::True
        );
        assert_eq!(
            actors.is_under(&p("agent"), &p("b"), &authority),
            Truth::False
        );
    }

    #[test]
    fn an_actor_the_hierarchy_does_not_know_is_unknown_not_outside() {
        let authority = authority();
        let actors = Actors::default();
        assert_eq!(
            actors.ancestry(&p("x"), &authority),
            Ancestry::Unknown {
                known: vec![p("x")]
            }
        );
        assert_eq!(
            actors.is_under(&p("x"), &p("agent"), &authority),
            Truth::Unknown
        );
        assert_eq!(actors.is_under(&p("x"), &p("x"), &authority), Truth::True);
    }

    #[test]
    fn a_leaf_added_after_a_lost_spawn_stops_the_walk_at_itself() {
        let authority = authority();
        let mut actors = Actors::default();
        actors.add(&p("before"), &p("agent"), &authority);
        actors.lost = true;
        actors.add(&p("after"), &p("agent"), &authority);
        assert_eq!(
            actors.is_under(&p("before"), &p("user"), &authority),
            Truth::True
        );
        assert_eq!(
            actors.ancestry(&p("after"), &authority),
            Ancestry::Unknown {
                known: vec![p("after")]
            }
        );
        assert_eq!(
            actors.is_under(&p("after"), &p("agent"), &authority),
            Truth::Unknown
        );
    }

    #[test]
    fn a_leaf_is_added_once_under_a_place_that_is_there() {
        let authority = authority();
        let mut actors = Actors::default();
        actors.add(&p("a"), &p("agent"), &authority);
        // Already there, as a leaf or as a principal of the authority; and a place that is not.
        actors.add(&p("a"), &p("user"), &authority);
        actors.add(&p("agent"), &p("user"), &authority);
        actors.add(&p("b"), &p("nowhere"), &authority);
        assert_eq!(actors.leaves.len(), 1);
        assert_eq!(actors.leaves[0].under, p("agent"));
    }
}
