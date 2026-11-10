//! The structural rule language: what a policy says about an event and the events before it.
//!
//! ```text
//! Pred := Now(Cond) | ModeIs(mode)
//!       | Once(filter, scope) | Count(filter, scope) cmp n | Last(field, scope) == lit
//!       | All[Pred…] | Any[Pred…] | Not Pred
//! Cond := field == lit | field in {lit…} | glob(field, pattern) | words(field, words)
//!       | num(field) cmp n | All[Cond…] | Any[Cond…] | Not Cond
//! filter := kind [where Cond]
//! scope  := Session | Agent | Mode | Task | Since(filter)
//! ```
//!
//! # Invariants
//!
//! - Every predicate stops, in time linear in its size per event: there is no loop, recursion,
//!   user-defined function or regex. Shell patterns are matched without backtracking.
//! - The past is read only through the three temporal operators, each one level deep: the
//!   condition inside a [`Pred::Once`] or [`Pred::Count`] is a [`Cond`], which cannot hold one.
//!   The type, not a check, keeps them from nesting. Each temporal operator becomes one slot of
//!   the state, updated from its last value and the new event alone.
//! - A predicate is evaluated in three values ([`Truth`]). A value the event has but did not
//!   show (a result not yet back, a record not read) is [`Truth::Unknown`], never false, so `not`
//!   cannot turn it into a pass. A value the event has no place for (the command of an edit) is
//!   absent, and a comparison with it is false.
//! - A field is read only from its own kind of event, with an operand of its type. The catalog
//!   checks this ([`Pred::check`]) before it accepts a policy.

use super::name::{CommandWords, GlobPattern, Mode};
use super::schema::{EventKind, Field, FieldType};

/// A truth value of Kleene's three-valued logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Truth {
    /// It holds.
    True,
    /// It does not hold.
    False,
    /// What it depends on could not be read.
    Unknown,
}

impl Truth {
    /// The truth of a known `bool`.
    pub fn of(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }

    /// All of `truths` hold: false when one is false, else unknown when one is unknown.
    pub fn all(truths: impl IntoIterator<Item = Self>) -> Self {
        truths
            .into_iter()
            .fold(Self::True, |acc, truth| match (acc, truth) {
                (Self::False, _) | (_, Self::False) => Self::False,
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                _ => Self::True,
            })
    }

    /// One of `truths` holds: true when one is true, else unknown when one is unknown.
    pub fn any(truths: impl IntoIterator<Item = Self>) -> Self {
        truths
            .into_iter()
            .fold(Self::False, |acc, truth| match (acc, truth) {
                (Self::True, _) | (_, Self::True) => Self::True,
                (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
                _ => Self::False,
            })
    }
}

impl std::ops::Not for Truth {
    type Output = Self;

    /// The negation; unknown stays unknown.
    fn not(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }
}

/// A literal a field is compared with.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Lit {
    /// Text, for a text field.
    Text(String),
    /// True or false, for a bool field.
    Bool(bool),
}

/// A comparison of numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cmp {
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `==`
    Eq,
    /// `>=`
    Ge,
    /// `>`
    Gt,
}

impl Cmp {
    /// Whether `left` compares to `right` this way. `None` when they cannot be ordered (a NaN).
    pub(super) fn holds<T: PartialOrd>(self, left: T, right: T) -> Option<bool> {
        let order = left.partial_cmp(&right)?;
        Some(match self {
            Self::Lt => order.is_lt(),
            Self::Le => order.is_le(),
            Self::Eq => order.is_eq(),
            Self::Ge => order.is_ge(),
            Self::Gt => order.is_gt(),
        })
    }
}

/// A condition on one event, with no reference to the past.
#[derive(Debug, Clone, PartialEq)]
pub enum Cond {
    /// The field equals the literal.
    Eq(Field, Lit),
    /// The field equals one of the literals.
    In(Field, Vec<Lit>),
    /// The text field matches the shell pattern as a whole.
    Glob(Field, GlobPattern),
    /// The words field starts with the words: `cargo test -p a` starts with `cargo test`.
    Words(Field, CommandWords),
    /// The number field compares to the number.
    Num(Field, Cmp, f64),
    /// All of them hold (true when there are none).
    All(Vec<Cond>),
    /// One of them holds (false when there are none).
    Any(Vec<Cond>),
    /// It does not hold.
    Not(Box<Cond>),
}

/// An event a temporal operator looks for: a kind, and a condition on the event when only some
/// events of that kind count.
#[derive(Debug, Clone, PartialEq)]
pub struct EventFilter {
    /// The kind of event.
    pub kind: EventKind,
    /// The condition the event must meet; `None` takes every event of the kind.
    pub cond: Option<Cond>,
}

/// The span a temporal operator counts within, and that an exemption may last for. Each starts
/// again at its own boundary; a new session starts all of them again.
///
/// A scope has two boundaries, both read from the event being folded: the event before which it
/// starts again, and the event on which it closes (the closing event belongs to the interval it
/// closes, and the interval starts again before the next event). The state folds both in one
/// place, so every scope, the four fixed ones and [`Scope::Since`], is handled by one rule.
///
/// `Session`, `Agent` and `Task` assume their start events are not lost to an unreadable record
/// (a known gap: a lost start leaves the scope looking as if it had not started again).
/// [`Scope::Mode`] and [`Scope::Since`] do not: when a lost record may have been a mode switch,
/// or the event a `Since` looks for, the scope's slots become unknown.
///
/// # `Since`
///
/// `Since(filter)` is the span after the last event that matches the filter. The matching event
/// belongs to the interval it closes, so an event is judged with the interval before it, and the
/// interval starts again before the next event. It starts again too at
/// [`EventKind::SessionStart`], and not at [`EventKind::TaskStart`]. A filter whose condition is
/// unknown on an event (`ok` of a tool call whose result is not back) leaves it unknown whether
/// the interval closed: the slots of the scope become unknown before the next event, and an
/// exemption that lasts within the scope ends. A record that could not be read closes the scope
/// as unknown only when the filter's kind is one the record may have been.
///
/// - `once(test passed, Since(commit))` asks whether a test passed since the last commit. It is
///   judged on the commit itself with the interval before it, so a second commit with no new
///   test in between is stopped.
/// - `once(commit, Since(commit))` is true only on a commit, and `count(commit, Since(commit))`
///   is at most 1.
/// - Closing an interval tightens a rule on `once` (what was seen before is forgotten) and
///   loosens a limit on `count` (the count starts over). An act takes effect whoever it comes
///   from, so the acts of the one the rule is about can start a `count` over: with
///   `count(edit, Since(commit)) <= 3`, one who commits after every third edit never reaches
///   the limit. Write such a limit on a scope those acts cannot close, or accept it. A claim
///   closes the scope only from one who covers the authors of the rules that read it
///   ([`super::tx`]).
/// - To let only a call that succeeded close the interval, restrict the filter to
///   `ok == true`. A call that failed, or that was stopped and never ran, does not match, and
///   the interval it belongs to goes on.
/// - `Lifetime::Within(Since(g))` (see [`super::exempt::Lifetime`]) ends an exemption after the
///   next `g`. Until the next event after `g`, the exemption still shows as in effect, so `g`
///   itself is judged with it.
#[derive(Debug, Clone, PartialEq)]
pub enum Scope {
    /// From [`EventKind::SessionStart`].
    Session,
    /// From [`EventKind::AgentStart`].
    Agent,
    /// From the last mode switch that took effect, a switch to the mode already in effect
    /// included.
    Mode,
    /// From [`EventKind::TaskStart`].
    Task,
    /// After the last event that matches the filter.
    Since(EventFilter),
}

/// A predicate on the judged event and the events before it.
#[derive(Debug, Clone, PartialEq)]
pub enum Pred {
    /// The condition holds of the judged event.
    Now(Cond),
    /// The mode in effect is this one.
    ModeIs(Mode),
    /// Such an event happened within the scope, the judged event included.
    Once {
        /// The event looked for.
        event: EventFilter,
        /// Since when.
        scope: Scope,
    },
    /// The number of such events within the scope, the judged event included, compares to `n`.
    Count {
        /// The events counted.
        event: EventFilter,
        /// Since when.
        scope: Scope,
        /// How the count compares.
        cmp: Cmp,
        /// What it is compared with.
        n: u32,
    },
    /// The field had this value in the last event of its kind within the scope. False when there
    /// was no such event.
    Last {
        /// The field read.
        field: Field,
        /// Since when.
        scope: Scope,
        /// The value it must have had.
        value: Lit,
    },
    /// All of them hold (true when there are none).
    All(Vec<Pred>),
    /// One of them holds (false when there are none).
    Any(Vec<Pred>),
    /// It does not hold.
    Not(Box<Pred>),
}

/// What a temporal operator remembers between events: one slot of the state. Two operators with
/// the same temporal part share a slot.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Temporal {
    Once(EventFilter, Scope),
    Count(EventFilter, Scope),
    Last(Field, Scope),
}

impl Temporal {
    pub(super) fn scope(&self) -> &Scope {
        match self {
            Self::Once(_, scope) | Self::Count(_, scope) | Self::Last(_, scope) => scope,
        }
    }
}

/// What a predicate cannot say about the events it would read.
#[derive(Debug, Clone, PartialEq)]
pub enum PredError {
    /// The field is read from an event of another kind, where it never has a value.
    OtherKind {
        /// The field.
        field: Field,
        /// The kind of event it is read from.
        read_from: EventKind,
    },
    /// The field is compared with an operand of another type.
    Mismatch {
        /// The field.
        field: Field,
        /// Its type.
        ty: FieldType,
    },
}

impl std::fmt::Display for PredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OtherKind { field, read_from } => write!(
                f,
                "{field:?} belongs to {:?} events and is read from {read_from:?} events",
                field.kind()
            ),
            Self::Mismatch { field, ty } => {
                write!(f, "{field:?} is {ty:?} and is compared with another type")
            }
        }
    }
}

/// The type a literal fits.
fn lit_type(lit: &Lit) -> FieldType {
    match lit {
        Lit::Text(_) => FieldType::Text,
        Lit::Bool(_) => FieldType::Bool,
    }
}

/// Checks that `field`, read from a `kind` event, has the type `ty`.
fn check_field(field: Field, kind: EventKind, ty: FieldType, errors: &mut Vec<PredError>) {
    if field.kind() != kind {
        errors.push(PredError::OtherKind {
            field,
            read_from: kind,
        });
    } else if field.ty() != ty {
        errors.push(PredError::Mismatch {
            field,
            ty: field.ty(),
        });
    }
}

impl Cond {
    /// What is wrong with the condition when it is read from a `kind` event.
    pub fn check(&self, kind: EventKind) -> Vec<PredError> {
        let mut errors = Vec::new();
        self.check_into(kind, &mut errors);
        errors
    }

    fn check_into(&self, kind: EventKind, errors: &mut Vec<PredError>) {
        match self {
            Self::Eq(field, lit) => check_field(*field, kind, lit_type(lit), errors),
            Self::In(field, lits) => {
                // An empty set is a condition that never holds, which is not an error.
                let ty = lits.first().map_or(field.ty(), lit_type);
                check_field(*field, kind, ty, errors);
                if lits.iter().any(|lit| lit_type(lit) != ty) {
                    errors.push(PredError::Mismatch {
                        field: *field,
                        ty: field.ty(),
                    });
                }
            }
            Self::Glob(field, _) => check_field(*field, kind, FieldType::Text, errors),
            Self::Words(field, _) => check_field(*field, kind, FieldType::Words, errors),
            Self::Num(field, _, _) => check_field(*field, kind, FieldType::Num, errors),
            Self::All(conds) | Self::Any(conds) => {
                for cond in conds {
                    cond.check_into(kind, errors);
                }
            }
            Self::Not(cond) => cond.check_into(kind, errors),
        }
    }
}

impl EventFilter {
    /// What is wrong with the filter: its condition is read from an event of its own kind.
    pub fn check(&self) -> Vec<PredError> {
        let mut errors = Vec::new();
        self.check_into(&mut errors);
        errors
    }

    fn check_into(&self, errors: &mut Vec<PredError>) {
        if let Some(cond) = &self.cond {
            cond.check_into(self.kind, errors);
        }
    }
}

impl Scope {
    /// What is wrong with the scope: the filter of a `Since` is checked like the filter of a
    /// `once`.
    fn check_into(&self, errors: &mut Vec<PredError>) {
        if let Self::Since(filter) = self {
            filter.check_into(errors);
        }
    }
}

impl Pred {
    /// What is wrong with the predicate when it judges a `subject` event.
    pub fn check(&self, subject: EventKind) -> Vec<PredError> {
        let mut errors = Vec::new();
        self.check_into(subject, &mut errors);
        errors
    }

    fn check_into(&self, subject: EventKind, errors: &mut Vec<PredError>) {
        match self {
            Self::Now(cond) => cond.check_into(subject, errors),
            Self::ModeIs(_) => {}
            Self::Once { event, scope } | Self::Count { event, scope, .. } => {
                event.check_into(errors);
                scope.check_into(errors);
            }
            Self::Last {
                field,
                scope,
                value,
            } => {
                check_field(*field, field.kind(), lit_type(value), errors);
                scope.check_into(errors);
            }
            Self::All(preds) | Self::Any(preds) => {
                for pred in preds {
                    pred.check_into(subject, errors);
                }
            }
            Self::Not(pred) => pred.check_into(subject, errors),
        }
    }

    /// The temporal operators of the predicate, each once, in the order they first appear.
    pub(super) fn temporals(&self) -> Vec<Temporal> {
        let mut out = Vec::new();
        self.temporals_into(&mut out);
        out
    }

    fn temporals_into(&self, out: &mut Vec<Temporal>) {
        let found = match self {
            Self::Now(_) | Self::ModeIs(_) => None,
            Self::Once { event, scope } => Some(Temporal::Once(event.clone(), scope.clone())),
            Self::Count { event, scope, .. } => Some(Temporal::Count(event.clone(), scope.clone())),
            Self::Last { field, scope, .. } => Some(Temporal::Last(*field, scope.clone())),
            Self::All(preds) | Self::Any(preds) => {
                for pred in preds {
                    pred.temporals_into(out);
                }
                None
            }
            Self::Not(pred) => {
                pred.temporals_into(out);
                None
            }
        };
        if let Some(temporal) = found
            && !out.contains(&temporal)
        {
            out.push(temporal);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_logic_is_kleenes() {
        use Truth::{False as F, True as T, Unknown as U};
        assert_eq!(Truth::any([T, U]), T);
        assert_eq!(Truth::any([F, U]), U);
        assert_eq!(Truth::any([F, F]), F);
        assert_eq!(Truth::all([F, U]), F);
        assert_eq!(Truth::all([T, U]), U);
        assert_eq!(Truth::all([T, T]), T);
        assert_eq!(Truth::all([]), T);
        assert_eq!(Truth::any([]), F);
        assert_eq!(!U, U);
        assert_eq!(!T, F);
    }

    #[test]
    fn a_field_is_read_from_its_kind_with_its_type() {
        let cond = Cond::Eq(Field::Tool, Lit::Text("Bash".to_owned()));
        assert!(cond.check(EventKind::ToolUse).is_empty());
        assert_eq!(
            cond.check(EventKind::Stop),
            vec![PredError::OtherKind {
                field: Field::Tool,
                read_from: EventKind::Stop
            }]
        );
        let wrong = Cond::Eq(Field::Ok, Lit::Text("yes".to_owned()));
        assert_eq!(
            wrong.check(EventKind::ToolUse),
            vec![PredError::Mismatch {
                field: Field::Ok,
                ty: FieldType::Bool
            }]
        );
        let mixed = Cond::In(
            Field::Tool,
            vec![Lit::Text("Bash".to_owned()), Lit::Bool(true)],
        );
        assert_eq!(mixed.check(EventKind::ToolUse).len(), 1);
        assert!(
            Cond::Num(Field::Score, Cmp::Ge, 0.5)
                .check(EventKind::Measured)
                .is_empty()
        );
    }

    #[test]
    fn a_temporal_condition_is_read_from_its_own_kind() {
        let ran_tests = Pred::Once {
            event: EventFilter {
                kind: EventKind::ToolUse,
                cond: Some(Cond::Eq(Field::Ok, Lit::Bool(true))),
            },
            scope: Scope::Task,
        };
        // The subject is a stop; the condition inside `once` reads the tool use it looks for.
        assert!(ran_tests.check(EventKind::Stop).is_empty());
        let wrong = Pred::Once {
            event: EventFilter {
                kind: EventKind::Stop,
                cond: Some(Cond::Eq(Field::Ok, Lit::Bool(true))),
            },
            scope: Scope::Task,
        };
        assert_eq!(wrong.check(EventKind::Stop).len(), 1);
    }

    #[test]
    fn the_same_temporal_part_is_one_slot() {
        let once = Pred::Once {
            event: EventFilter {
                kind: EventKind::Stop,
                cond: None,
            },
            scope: Scope::Agent,
        };
        let pred = Pred::All(vec![
            once.clone(),
            Pred::Not(Box::new(once)),
            Pred::Count {
                event: EventFilter {
                    kind: EventKind::Stop,
                    cond: None,
                },
                scope: Scope::Agent,
                cmp: Cmp::Ge,
                n: 2,
            },
        ]);
        assert_eq!(pred.temporals().len(), 2);
    }
}
