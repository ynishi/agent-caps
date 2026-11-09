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
//! # What the state holds
//!
//! - The mode in effect. Only a mode switch from the user or caps takes effect.
//! - One slot per temporal operator of the catalog's predicates. Each is updated
//!   from its last value and the new event alone, and goes back to its start value when its
//!   scope starts again.
//! - The exemptions in effect. Only an exemption from the user takes effect, and each lasts
//!   only for its lifetime.
//!
//! # Invariants
//!
//! - Each slot is [`Known`] or unknown. An unreadable record makes a slot unknown when the
//!   record may have changed it: a `once` that has not yet seen its event, any count, any last
//!   value. A `once` that has seen its event stays known.
//! - An unreadable record of the evidence makes the mode unknown and ends every exemption, since
//!   it may have been a mode switch or the use of an exemption. Losing a record never loosens a
//!   rule.

use super::event::{Body, Event, Read, Value};
use super::exempt::{Exempt, Lifetime};
use super::name::{Mode, PolicyId};
use super::predicate::{Pred, Temporal, Truth};
use super::schema::{Judgment, Origin, Scope, Source};

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

    /// The slot after `body`, which is not an unreadable record.
    fn step(self, temporal: &Temporal, body: &Body) -> Self {
        match (self, temporal) {
            (Self::Once(seen), Temporal::Once(filter, _)) => {
                if body.kind() != filter.kind {
                    return Self::Once(seen);
                }
                let matched = filter
                    .cond
                    .as_ref()
                    .map_or(Truth::True, |cond| body.holds(cond));
                Self::Once(match (seen, matched) {
                    (_, Truth::True) | (Known::Known(true), _) => Known::Known(true),
                    (_, Truth::Unknown) | (Known::Unknown, Truth::False) => Known::Unknown,
                    (Known::Known(false), Truth::False) => Known::Known(false),
                })
            }
            (Self::Count(count), Temporal::Count(filter, _)) => {
                if body.kind() != filter.kind {
                    return Self::Count(count);
                }
                let matched = filter
                    .cond
                    .as_ref()
                    .map_or(Truth::True, |cond| body.holds(cond));
                Self::Count(match (count, matched) {
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
}

/// The scopes an event starts again, if it takes effect.
fn starts(body: &Body) -> &'static [Scope] {
    match body {
        Body::SessionStart => &[Scope::Session, Scope::Agent, Scope::Mode, Scope::Task],
        Body::AgentStart { .. } => &[Scope::Agent],
        Body::TaskStart => &[Scope::Task],
        Body::ModeSwitch { .. } => &[Scope::Mode],
        _ => &[],
    }
}

impl State {
    /// The state before any event: no mode, every slot at its start value, no exemption.
    pub(super) fn start(table: &SlotTable) -> Self {
        Self {
            mode: Known::Known(None),
            slots: table.0.iter().map(Slot::start).collect(),
            exempts: Vec::new(),
        }
    }

    /// The mode in effect.
    pub fn mode(&self) -> &Known<Option<Mode>> {
        &self.mode
    }

    /// The state after `event`.
    pub(super) fn apply(mut self, table: &SlotTable, event: &Event) -> Self {
        let body = &event.body;
        let loosening_allowed = event.origin != Origin::Agent;
        let switch = matches!(body, Body::ModeSwitch { .. });
        if !switch || loosening_allowed {
            for scope in starts(body) {
                self.start_again(table, *scope);
            }
        }
        match body {
            Body::Unreadable { source } => {
                self.slots = self.slots.into_iter().map(Slot::unread).collect();
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
            Body::Exempt(exempt) if event.origin == Origin::User => {
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
        self.exempts.retain(|e| match e.lifetime {
            Lifetime::Until(until) => event.at < until,
            Lifetime::Next | Lifetime::Within(_) => true,
        });
        self
    }

    /// Puts the slots of `scope` back to their start values and ends the exemptions that last
    /// within it.
    fn start_again(&mut self, table: &SlotTable, scope: Scope) {
        for (slot, temporal) in self.slots.iter_mut().zip(&table.0) {
            if temporal.scope() == scope {
                *slot = Slot::start(temporal);
            }
        }
        self.exempts
            .retain(|e| e.lifetime != Lifetime::Within(scope));
    }

    /// Whether an exemption in effect covers the guard `guard` on `event`.
    pub(super) fn exempts(&self, guard: PolicyId, event: &Event) -> bool {
        self.exempts.iter().any(|e| {
            let in_time = match e.lifetime {
                Lifetime::Until(until) => event.at < until,
                Lifetime::Next | Lifetime::Within(_) => true,
            };
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
            } => match slot(Temporal::Once(filter.clone(), *scope)) {
                Some(Slot::Once(Known::Known(seen))) => Truth::of(*seen),
                _ => Truth::Unknown,
            },
            Pred::Count {
                event: filter,
                scope,
                cmp,
                n,
            } => match slot(Temporal::Count(filter.clone(), *scope)) {
                Some(Slot::Count(Known::Known(count))) => {
                    cmp.holds(*count, *n).map_or(Truth::Unknown, Truth::of)
                }
                _ => Truth::Unknown,
            },
            Pred::Last {
                field,
                scope,
                value,
            } => match slot(Temporal::Last(*field, *scope)) {
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
