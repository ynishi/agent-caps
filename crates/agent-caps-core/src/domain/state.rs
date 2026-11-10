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
//! Folding one event is two steps, and the module knows nothing of who an event comes from:
//! neither step reads [`Event::by`]. (Evaluating `ActorUnder` reads the `by` of the event being
//! judged, which is a fact the rule asks for, not a decision about trust.) Whether the step of a
//! claim is kept is decided by its transaction ([`super::tx`]), which compares the state before
//! and after the step as a list of [`StateChange`]s.
//!
//! ```text
//! carry(at)      what the past brings, whatever the event is
//!   1. the scopes the previous event closed (kept in the state as `closing`): on true, start
//!      again (slots to their start values, the exemptions that last within the scope end); on
//!      unknown, make the slots of the scope unknown (a `once` that was true too) and end the
//!      exemptions that last within it
//!   2. the exemptions whose lifetime ran out by `at` end
//! step(event)    what the event itself does
//!   3. `starts_at(event)`, for every scope: true starts it again, unknown is handled as in 1
//!   4. the event steps every slot, and updates the mode and the exemptions; what a record that
//!      could not be read may have changed is settled here (see the invariants); an exemption
//!      whose lifetime has run out by the time of the event is dropped
//!   5. `ends_at(event)`, for the scopes of the slots and of the exemptions in effect: a scope
//!      that is not false is kept in `closing` with its truth
//! ```
//!
//! Each [`Scope`] answers the two questions of 3 and 5 about an event, each a [`Truth`], and
//! every scope is folded by this one rule. A claim and an act are stepped by the same rule; a
//! switch to the mode already in effect starts the mode's scope again, as any switch does.
//!
//! The event is judged on the state after the step, so a closing event is judged as the last
//! event of the interval it closes.
//!
//! # What the state holds
//!
//! - The mode in effect: the mode of the last switch that took effect.
//! - One slot per temporal operator of the catalog's predicates. Each is updated
//!   from its last value and the new event alone, and goes back to its start value when its
//!   scope starts again.
//! - The exemptions in effect. Each lasts only for its lifetime, and only one that names a guard
//!   of the catalog outside the meta layer, and type-checks against it, is kept.
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
//!   the next judgment, which it may have used up; an exemption changes nothing, since one that
//!   was lost can only have loosened. Losing a record never loosens a rule.
//! - The start of a session or a task is assumed not to be lost (a known gap, see [`Scope`]).

use super::authority::{Authority, Principal};
use super::event::{Body, Event};
use super::exempt::{Exempt, Lifetime};
use super::name::{Mode, PolicyId};
use super::policy::ModeScope;
use super::predicate::{EventFilter, Pred, Scope, Temporal, Truth};
use super::schema::{At, EventKind, Judgment};

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

/// The guards an exemption may name, each with the kind of event it judges: the guards of the
/// catalog outside the meta layer.
#[derive(Debug, Clone, PartialEq, Default)]
pub(super) struct GuardIndex(Vec<(PolicyId, EventKind)>);

impl GuardIndex {
    /// The index of the guards, each with its subject.
    pub(super) fn new(guards: impl IntoIterator<Item = (PolicyId, EventKind)>) -> Self {
        Self(guards.into_iter().collect())
    }

    /// The subject of the guard, or `None` when an exemption may not name it.
    fn subject(&self, guard: PolicyId) -> Option<EventKind> {
        self.0
            .iter()
            .find(|(id, _)| *id == guard)
            .map(|(_, subject)| *subject)
    }
}

/// One difference between a state and the state after one step: what the transaction of a claim
/// judges ([`super::tx`]).
#[derive(Debug, Clone, PartialEq)]
pub enum StateChange {
    /// The slot's value changed, or whether its scope closes on the event did.
    Slot(SlotId),
    /// An exemption of the guard was added.
    ExemptionAdded(PolicyId),
    /// An exemption of the guard ended.
    ExemptionEnded(PolicyId),
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
}

impl Slot {
    fn start(temporal: &Temporal) -> Self {
        match temporal {
            Temporal::Once(..) => Self::Once(Known::Known(false)),
            Temporal::Count(..) => Self::Count(Known::Known(0)),
            Temporal::Last(..) => Self::Last(Known::Known(None)),
        }
    }

    /// The slot after a record that could not be read, and may have been an event it reads.
    fn unread(self) -> Self {
        match self {
            Self::Once(Known::Known(true)) => self,
            Self::Once(_) => Self::Once(Known::Unknown),
            Self::Count(_) => Self::Count(Known::Unknown),
            Self::Last(_) => Self::Last(Known::Unknown),
        }
    }

    /// The slot when the interval it counts in may or may not have closed: nothing is known of
    /// it, a `once` that was true included.
    fn lost(&self) -> Self {
        match self {
            Self::Once(_) => Self::Once(Known::Unknown),
            Self::Count(_) => Self::Count(Known::Unknown),
            Self::Last(_) => Self::Last(Known::Unknown),
        }
    }

    /// Whether two values of a slot are the same. The score of an event it holds is compared by
    /// its bits ([`Body::same_as`]), so a NaN that was not touched is not taken for a change.
    fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Last(Known::Known(Some(a))), Self::Last(Known::Known(Some(b)))) => a.same_as(b),
            _ => self == other,
        }
    }

    /// The slot after `body`, which is not an unreadable record.
    fn step(self, temporal: &Temporal, body: &Body) -> Self {
        match (self, temporal) {
            (Self::Once(seen), Temporal::Once(filter, _)) => {
                if body.kind() != filter.kind {
                    return Self::Once(seen);
                }
                Self::Once(match (seen, matched(filter, body)) {
                    (_, Truth::True) | (Known::Known(true), _) => Known::Known(true),
                    (_, Truth::Unknown) | (Known::Unknown, Truth::False) => Known::Unknown,
                    (Known::Known(false), Truth::False) => Known::Known(false),
                })
            }
            (Self::Count(count), Temporal::Count(filter, _)) => {
                if body.kind() != filter.kind {
                    return Self::Count(count);
                }
                Self::Count(match (count, matched(filter, body)) {
                    (Known::Known(n), Truth::True) => Known::Known(n.saturating_add(1)),
                    (Known::Known(n), Truth::False) => Known::Known(n),
                    (_, _) => Known::Unknown,
                })
            }
            (Self::Last(last), Temporal::Last(filter, _)) => {
                if body.kind() != filter.kind {
                    return Self::Last(last);
                }
                match matched(filter, body) {
                    Truth::True => Self::Last(Known::Known(Some(body.clone()))),
                    Truth::False => Self::Last(last),
                    Truth::Unknown => Self::Last(Known::Unknown),
                }
            }
            // A slot always has the shape of its operator: both come from the same table.
            (slot, _) => slot,
        }
    }
}

/// Whether the temporal operator reads events of `kind`: the kind it looks for.
fn reads(temporal: &Temporal, kind: EventKind) -> bool {
    match temporal {
        Temporal::Once(filter, _) | Temporal::Count(filter, _) | Temporal::Last(filter, _) => {
            filter.kind == kind
        }
    }
}

/// The state a judgment reads. Made by folding events from [`super::catalog::Catalog::start`]
/// with [`super::catalog::Catalog::apply`].
#[derive(Debug, Clone, PartialEq)]
pub struct State {
    mode: Known<Option<Mode>>,
    slots: Vec<Slot>,
    exempts: Vec<Exempt>,
    /// The scopes the last event closed, with whether it did: they start again (or become
    /// unknown) before the next event.
    closing: Vec<(Scope, Truth)>,
    /// The leaves spawns added to the hierarchy of actors. Kept for the whole fold.
    actors: Actors,
}

impl Scope {
    /// Whether the scope starts again before an event of `body`. Any mode switch starts the
    /// mode's scope again, and a record that may have been one leaves it unknown.
    pub(super) fn starts_at(&self, body: &Body) -> Truth {
        let at_session = matches!(body, Body::SessionStart);
        match self {
            Self::Session | Self::Since(_) => Truth::of(at_session),
            Self::Task => Truth::of(at_session || matches!(body, Body::TaskStart)),
            Self::Mode => match body {
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

    /// Whether the scope closes on an event of `body`, which then belongs to the interval it
    /// closes. Only `Since` closes on an event. A record that could not be read may have been the
    /// event it looks for only when the filter's kind is one it may have been.
    pub(super) fn ends_at(&self, body: &Body) -> Truth {
        let Self::Since(filter) = self else {
            return Truth::False;
        };
        match body {
            body if body.kind() == filter.kind => matched(filter, body),
            Body::Unreadable { may_have_been } if may_have_been.contains(filter.kind) => {
                Truth::Unknown
            }
            _ => Truth::False,
        }
    }
}

/// Whether `body`, an event of the filter's kind, meets the filter's condition: the one answer to
/// "does this filter match this event", read by the slots, the scopes and
/// [`super::catalog::Capabilities`].
pub(super) fn matched(filter: &EventFilter, body: &Body) -> Truth {
    filter
        .cond
        .as_ref()
        .map_or(Truth::True, |cond| body.holds(cond))
}

/// The scopes with a fixed start event, which an exemption may last within whether or not a slot
/// counts in them.
static FIXED_SCOPES: [Scope; 3] = [Scope::Session, Scope::Mode, Scope::Task];

impl State {
    /// The state before any event: no mode, every slot at its start value, no exemption.
    pub(super) fn start(table: &SlotTable) -> Self {
        Self {
            mode: Known::Known(None),
            slots: table.0.iter().map(Slot::start).collect(),
            exempts: Vec::new(),
            closing: Vec::new(),
            actors: Actors::default(),
        }
    }

    /// The mode in effect.
    pub fn mode(&self) -> &Known<Option<Mode>> {
        &self.mode
    }

    /// The exemptions in effect, each one as many times as it is held.
    pub(super) fn exemptions(&self) -> &[Exempt] {
        &self.exempts
    }

    /// The leaves that spawns added to the hierarchy of actors.
    pub(super) fn actors(&self) -> &Actors {
        &self.actors
    }

    /// The state carried to an event at `at`: steps 1 and 2 of the module doc. It depends on the
    /// past and the time alone, so it is the same whatever the event is and whoever it comes
    /// from, and it is always kept.
    pub(super) fn carry(mut self, table: &SlotTable, at: At) -> Self {
        for (scope, truth) in std::mem::take(&mut self.closing) {
            self.settle(table, &scope, truth);
        }
        self.exempts.retain(|e| e.lifetime.lasts_at(at));
        self
    }

    /// The state after `event`, from a state carried to it: steps 3 to 5 of the module doc.
    /// `guards` holds the guards an exemption may name: one takes effect only if its guard is
    /// there and [`Exempt::check`] finds nothing wrong with it. `authority` is the hierarchy the
    /// catalog was accepted with: a spawn's shape is checked against it, and nothing else of it
    /// is read here.
    pub(super) fn step(
        mut self,
        table: &SlotTable,
        event: &Event,
        guards: &GuardIndex,
        authority: &Authority,
    ) -> Self {
        let body = &event.body;
        // 3. The scopes that start again before this event. Settling is idempotent, so a scope
        // listed twice does no harm; only the few that start are cloned.
        let starting: Vec<(Scope, Truth)> = FIXED_SCOPES
            .iter()
            .chain(self.scopes_in_use(table))
            .filter_map(|scope| match scope.starts_at(body) {
                Truth::False => None,
                truth => Some((scope.clone(), truth)),
            })
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
                    self.exempts.retain(|e| e.lifetime != Lifetime::Next);
                }
                // It may have added a leaf, so the leaves added from now on are of unknown place.
                if may_have_been.contains(EventKind::Spawn) {
                    self.actors.lost = true;
                }
            }
            _ => {
                self.slots = self
                    .slots
                    .into_iter()
                    .zip(&table.0)
                    .map(|(slot, temporal)| slot.step(temporal, body))
                    .collect();
            }
        }
        match body {
            Body::ModeSwitch { to } => self.mode = Known::Known(Some(to.clone())),
            Body::Spawn { child, under } => self.actors.add(child, under, authority),
            Body::Exempt(exempt)
                if guards
                    .subject(exempt.guard)
                    .is_some_and(|subject| exempt.check(subject).is_empty()) =>
            {
                self.exempts.push(exempt.clone());
            }
            Body::Judged {
                policy,
                judgment: Judgment::Exempted,
                ..
            } => {
                let used = self
                    .exempts
                    .iter()
                    .position(|e| e.guard == *policy && e.lifetime == Lifetime::Next);
                if let Some(at) = used {
                    self.exempts.remove(at);
                }
            }
            _ => {}
        }
        // An exemption that has run out by the time of the event, one this event added
        // included, is not in effect on it.
        self.exempts.retain(|e| e.lifetime.lasts_at(event.at));
        // 5. The scopes this event closes, each once.
        let mut closing: Vec<(Scope, Truth)> = Vec::new();
        for scope in self.scopes_in_use(table) {
            let truth = scope.ends_at(body);
            if truth != Truth::False && !closing.iter().any(|(seen, _)| seen == scope) {
                closing.push((scope.clone(), truth));
            }
        }
        self.closing = closing;
        self
    }

    /// The differences between `before` and `after`, two states of the catalog whose table is
    /// `table`: each slot whose value, or whose scope's closing, differs; each exemption added or
    /// ended (an exemption held twice counts twice); the mode, when it differs; and each leaf
    /// added to the hierarchy of actors.
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
            let same = match (before.slots.get(at), after.slots.get(at)) {
                (Some(b), Some(a)) => b.same(a),
                (b, a) => b == a,
            };
            if !same || closing_of(before, scope) != closing_of(after, scope) {
                changes.push(StateChange::Slot(SlotId(at)));
            }
        }
        let mut remaining: Vec<&Exempt> = before.exempts.iter().collect();
        for exempt in &after.exempts {
            match remaining.iter().position(|kept| *kept == exempt) {
                Some(at) => {
                    remaining.remove(at);
                }
                None => changes.push(StateChange::ExemptionAdded(exempt.guard)),
            }
        }
        changes.extend(
            remaining
                .into_iter()
                .map(|ended| StateChange::ExemptionEnded(ended.guard)),
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

    /// The scopes of the slots and of the exemptions in effect, possibly with repeats.
    fn scopes_in_use<'a>(&'a self, table: &'a SlotTable) -> impl Iterator<Item = &'a Scope> {
        let within = self.exempts.iter().filter_map(|e| match &e.lifetime {
            Lifetime::Within(scope) => Some(scope),
            Lifetime::Next | Lifetime::Until(_) => None,
        });
        table.scopes().chain(within)
    }

    /// Acts on `scope` as `truth` says it started again (or closed): true puts its slots back to
    /// their start values; unknown makes them unknown; either ends the exemptions that last
    /// within it.
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
        self.exempts
            .retain(|e| !matches!(&e.lifetime, Lifetime::Within(within) if within == scope));
    }

    /// Whether an exemption in effect covers the guard `guard` on `event`.
    pub(super) fn exempts(&self, guard: PolicyId, event: &Event) -> bool {
        self.exempts.iter().any(|e| {
            let in_time = e.lifetime.lasts_at(event.at);
            let covers = e
                .target
                .as_ref()
                .is_none_or(|target| event.body.holds(target) == Truth::True);
            e.guard == guard && in_time && covers
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
            Pred::Once {
                event: filter,
                scope,
            } => match slot(Temporal::Once(filter.clone(), scope.clone())) {
                Some(Slot::Once(Known::Known(seen))) => Truth::of(*seen),
                _ => Truth::Unknown,
            },
            Pred::Count {
                event: filter,
                scope,
                cmp,
                n,
            } => match slot(Temporal::Count(filter.clone(), scope.clone())) {
                Some(Slot::Count(Known::Known(count))) => {
                    cmp.holds(*count, *n).map_or(Truth::Unknown, Truth::of)
                }
                _ => Truth::Unknown,
            },
            Pred::Last {
                event: filter,
                scope,
                test,
            } => match slot(Temporal::Last(filter.clone(), scope.clone())) {
                Some(Slot::Last(Known::Known(Some(last)))) => last.holds(test),
                Some(Slot::Last(Known::Known(None))) => Truth::False,
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
