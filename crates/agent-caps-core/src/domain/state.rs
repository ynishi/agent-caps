//! The state a judgment reads: a fold of the events, never stored.
//!
//! ```text
//! transcript ─ platform adapter ─▶ events ─┐
//! evidence (appended by caps) ─────────────┤
//!                                          ▼
//!                       State = fold(apply, initial, events)
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
//! # How a scope is folded
//!
//! Each [`Scope`] answers two questions about an event: does the scope start again before it
//! (`starts_at`), and does the scope close on it (`ends_at`), each a [`Truth`]. `apply` folds
//! every scope by one rule, in this order:
//!
//! 1. The scopes the previous event closed (kept in the state as `closing`): on true, start
//!    again (slots to their start values, the exemptions that last within the scope end); on
//!    unknown, make the slots of the scope unknown (a `once` that was true too) and end the
//!    exemptions that last within it.
//! 2. `starts_at(event)`: true starts the scope again, unknown is handled as in 1.
//! 3. The event steps every slot, and updates the mode and the exemptions. What an unreadable
//!    record may have changed in the content of a slot, the mode and the exemptions is settled
//!    here (see the invariants).
//! 4. `ends_at(event)`, for the scopes of the slots and of the exemptions in effect: a scope
//!    that is not false is kept in `closing` with its truth.
//!
//! The event is judged on the state after step 3, so a closing event is judged as the last event
//! of the interval it closes.
//!
//! # What the state holds
//!
//! - The mode in effect. Only a mode switch from the user or caps takes effect.
//! - One slot per temporal operator of the catalog's predicates. Each is updated
//!   from its last value and the new event alone, and goes back to its start value when its
//!   scope starts again.
//! - The exemptions in effect. Only an exemption from the user takes effect, and each lasts
//!   only for its lifetime.
//! - The scopes the last event closed, and whether that is known, until the next event.
//!
//! # Invariants
//!
//! - Each slot is [`Known`] or unknown. An unreadable record makes a slot unknown when the
//!   record may have changed it: a `once` that has not yet seen its event, any count, any last
//!   value. A `once` that has seen its event stays known, unless the record may have closed the
//!   `Since` scope it counts in: then it becomes unknown before the next event.
//! - An unreadable record of the evidence makes the mode unknown and ends every exemption, since
//!   it may have been a mode switch or the use of an exemption. Losing a record never loosens a
//!   rule.

use super::event::{Body, Event, Read, Value};
use super::exempt::{Exempt, Lifetime};
use super::name::{Mode, PolicyId};
use super::predicate::{EventFilter, Pred, Scope, Temporal, Truth};
use super::schema::{EventKind, Judgment, Origin, Source};

/// A value that was seen, or could not be.
#[derive(Debug, Clone, PartialEq)]
pub enum Known<T> {
    /// The value.
    Known(T),
    /// What would have told the value could not be read.
    Unknown,
}

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

    fn find(&self, temporal: &Temporal) -> Option<usize> {
        self.0.iter().position(|t| t == temporal)
    }

    fn scopes(&self) -> impl Iterator<Item = &Scope> {
        self.0.iter().map(Temporal::scope)
    }
}

/// What one temporal operator remembers.
#[derive(Debug, Clone, PartialEq)]
enum Slot {
    Once(Known<bool>),
    Count(Known<u32>),
    /// `Known(None)`: no event of the field's kind within the scope.
    Last(Known<Option<Value>>),
}

impl Slot {
    fn start(temporal: &Temporal) -> Self {
        match temporal {
            Temporal::Once(..) => Self::Once(Known::Known(false)),
            Temporal::Count(..) => Self::Count(Known::Known(0)),
            Temporal::Last(..) => Self::Last(Known::Known(None)),
        }
    }

    /// The slot after a record that could not be read.
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
            (Self::Last(last), Temporal::Last(field, _)) => match body.read(*field) {
                Read::OtherKind => Self::Last(last),
                Read::Unknown => Self::Last(Known::Unknown),
                // No value to compare with: the same as no event, every comparison is false.
                Read::Absent => Self::Last(Known::Known(None)),
                Read::Found(value) => Self::Last(Known::Known(Some(value))),
            },
            // A slot always has the shape of its operator: both come from the same table.
            (slot, _) => slot,
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
}

impl Scope {
    /// Whether the scope starts again before `event`. A mode switch takes effect, and so starts
    /// the mode again, only from the user or from caps.
    pub(super) fn starts_at(&self, event: &Event) -> Truth {
        let body = &event.body;
        let starts = match self {
            Self::Session | Self::Since(_) => matches!(body, Body::SessionStart),
            Self::Agent => matches!(body, Body::SessionStart | Body::AgentStart { .. }),
            Self::Mode => {
                matches!(body, Body::SessionStart)
                    || (matches!(body, Body::ModeSwitch { .. }) && event.origin != Origin::Agent)
            }
            Self::Task => matches!(body, Body::SessionStart | Body::TaskStart),
        };
        Truth::of(starts)
    }

    /// Whether the scope closes on `event`, which then belongs to the interval it closes. Only
    /// `Since` closes on an event. A record that could not be read may have been the event it
    /// looks for only when events of that kind are recorded where the record was.
    pub(super) fn ends_at(&self, event: &Event) -> Truth {
        let Self::Since(filter) = self else {
            return Truth::False;
        };
        match &event.body {
            body if body.kind() == filter.kind => matched(filter, body),
            Body::Unreadable { source } if filter.kind.may_be_lost_in(*source) => Truth::Unknown,
            _ => Truth::False,
        }
    }
}

/// Whether `body`, an event of the filter's kind, meets the filter's condition.
fn matched(filter: &EventFilter, body: &Body) -> Truth {
    filter
        .cond
        .as_ref()
        .map_or(Truth::True, |cond| body.holds(cond))
}

/// The scopes with a fixed start event, which an exemption may last within whether or not a slot
/// counts in them.
static FIXED_SCOPES: [Scope; 4] = [Scope::Session, Scope::Agent, Scope::Mode, Scope::Task];

impl State {
    /// The state before any event: no mode, every slot at its start value, no exemption.
    pub(super) fn start(table: &SlotTable) -> Self {
        Self {
            mode: Known::Known(None),
            slots: table.0.iter().map(Slot::start).collect(),
            exempts: Vec::new(),
            closing: Vec::new(),
        }
    }

    /// The mode in effect.
    pub fn mode(&self) -> &Known<Option<Mode>> {
        &self.mode
    }

    /// The state after `event`, by the rule in the module doc. `guard_subject` gives the kind
    /// of event a guard judges, `None` for a guard that does not exist: an exemption takes
    /// effect only if its guard exists and [`Exempt::check`] finds nothing wrong with it.
    pub(super) fn apply(
        mut self,
        table: &SlotTable,
        event: &Event,
        guard_subject: impl Fn(PolicyId) -> Option<EventKind>,
    ) -> Self {
        let body = &event.body;
        let loosening_allowed = event.origin != Origin::Agent;
        // 1. The scopes the previous event closed.
        for (scope, truth) in std::mem::take(&mut self.closing) {
            self.settle(table, &scope, truth);
        }
        // 2. The scopes that start again before this event. Settling is idempotent, so a scope
        // listed twice does no harm; only the few that start are cloned.
        let starting: Vec<(Scope, Truth)> = FIXED_SCOPES
            .iter()
            .chain(self.scopes_in_use(table))
            .filter_map(|scope| match scope.starts_at(event) {
                Truth::False => None,
                truth => Some((scope.clone(), truth)),
            })
            .collect();
        for (scope, truth) in starting {
            self.settle(table, &scope, truth);
        }
        // 3. The event itself.
        match body {
            Body::Unreadable { source } => {
                self.slots = self.slots.into_iter().map(Slot::unread).collect();
                // What a lost record may have done to the mode and the exemptions. Only records
                // that take effect matter here: a mode switch or an exemption from the agent,
                // which a transcript record could be, never takes effect, so only a lost record
                // of the evidence (caps's own) can have changed them. Whether a lost record may
                // have closed a scope is a different question, answered by `ends_at` through
                // `EventKind::may_be_lost_in`, where an agent's record still counts.
                if *source == Source::Evidence {
                    self.mode = Known::Unknown;
                    self.exempts.clear();
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
            Body::ModeSwitch { to } if loosening_allowed => {
                self.mode = Known::Known(Some(to.clone()))
            }
            Body::Exempt(exempt)
                if event.origin == Origin::User
                    && guard_subject(exempt.guard)
                        .is_some_and(|subject| exempt.check(subject).is_empty()) =>
            {
                self.exempts.push(exempt.clone());
            }
            Body::Judged {
                policy,
                judgment: Judgment::Exempted,
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
        self.exempts.retain(|e| e.lifetime.lasts_at(event.at));
        // 4. The scopes this event closes, each once.
        let mut closing: Vec<(Scope, Truth)> = Vec::new();
        for scope in self.scopes_in_use(table) {
            let truth = scope.ends_at(event);
            if truth != Truth::False && !closing.iter().any(|(seen, _)| seen == scope) {
                closing.push((scope.clone(), truth));
            }
        }
        self.closing = closing;
        self
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

    /// Whether `pred` holds of `event`, with the state already folded over it.
    pub(super) fn holds(&self, table: &SlotTable, pred: &Pred, event: &Event) -> Truth {
        let slot = |temporal: Temporal| table.find(&temporal).and_then(|at| self.slots.get(at));
        match pred {
            Pred::Now(cond) => event.body.holds(cond),
            Pred::ModeIs(mode) => match &self.mode {
                Known::Known(Some(current)) => Truth::of(current == mode),
                Known::Known(None) => Truth::False,
                Known::Unknown => Truth::Unknown,
            },
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
                field,
                scope,
                value,
            } => match slot(Temporal::Last(*field, scope.clone())) {
                Some(Slot::Last(Known::Known(Some(last)))) => last.equals(value),
                Some(Slot::Last(Known::Known(None))) => Truth::False,
                _ => Truth::Unknown,
            },
            Pred::All(preds) => Truth::all(preds.iter().map(|p| self.holds(table, p, event))),
            Pred::Any(preds) => Truth::any(preds.iter().map(|p| self.holds(table, p, event))),
            Pred::Not(pred) => !self.holds(table, pred, event),
        }
    }
}
