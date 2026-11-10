//! What happened: the events that the state is folded from and that a policy judges.
//!
//! The caller reads events from wherever they are kept (the platform's transcript through an
//! adapter, the evidence the application appends) and gives them to the domain as [`Event`]
//! values, in the order it folds them. Each event names the [`Principal`] it comes from; where
//! that principal sits is the caller's arrangement ([`super::authority`]), plus the leaves that
//! spawns add to it ([`super::state`]); a rule reads it with
//! [`Pred::ActorUnder`](super::predicate::Pred::ActorUnder). Whether an event is an
//! act or a claim is its kind's [`Nature`](super::schema::Nature). A record the adapter cannot
//! read is not dropped but becomes [`Body::Unreadable`], with the kinds it may have been, so the
//! state knows what it has not seen.
//!
//! The fold history holds only events that happened. An act judged before it runs (a
//! [`Body::ToolUse`] whose `ok` is not known yet) is judged on a copy of the state with the act
//! folded over it, and it enters the history when it is read back from the transcript, with
//! its result. An act that was stopped never runs, so it is not in the history.

use super::adjust::Adjustment;
use super::authority::Principal;
use super::name::{AdjustmentId, CommandWords, Mode, PolicyId};
use super::predicate::{Cond, Lit, Truth};
use super::schema::{At, EventKind, Field, Judgment, KindSet, Level};

/// One event: when, from whom, and what.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// When it happened.
    pub at: At,
    /// The principal it comes from. An act takes effect whoever it is by; a claim takes effect
    /// as its transaction decides ([`super::tx`]).
    pub by: Principal,
    /// What happened.
    pub body: Body,
}

/// What happened. New kinds are added as the model grows, so a match on it outside this crate
/// needs a wildcard arm.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Body {
    /// A session started.
    SessionStart,
    /// A (sub)agent was spawned. The event is by its spawner. `child` joins the hierarchy of
    /// actors under `under` ([`super::state`]), when `child` is not in it yet and `under` is; a
    /// spawn that does not meet that adds nothing. Where the child is placed can change how the
    /// rules that read the actor take effect, so a spawn is a claim, judged as a transaction
    /// against a place directly under its spawner ([`super::tx`]).
    Spawn {
        /// The new actor. A name the platform makes up for each start: no rule can name it.
        child: Principal,
        /// The actor of the hierarchy it is placed under.
        under: Principal,
    },
    /// A task started.
    TaskStart,
    /// A prompt was submitted.
    PromptSubmit,
    /// A tool was used: before the call when it is judged ahead, after it when it is read back
    /// from the transcript.
    ToolUse {
        /// The tool, as the platform names it.
        tool: String,
        /// The command; `None` when the tool runs none (absent: a comparison with it is false).
        command: Option<CommandWords>,
        /// The path; `None` when the tool touches none (absent: a comparison with it is false).
        path: Option<String>,
        /// Whether the call succeeded; `None` until that is known (unknown).
        ok: Option<bool>,
    },
    /// A turn is about to end.
    Stop,
    /// The mode is switched.
    ModeSwitch {
        /// The mode to put in effect.
        to: Mode,
    },
    /// An oracle measured a score.
    Measured {
        /// The oracle, by name.
        oracle: String,
        /// The score.
        score: f64,
    },
    /// A temporary adjustment is made: an exemption, or bindings added and suspended, for its
    /// lifetime ([`super::adjust`]). It is held, with who made it, when it may take effect and its
    /// transaction keeps it.
    Adjust(Adjustment),
    /// The temporary adjustment in effect with the id ends. A cancel is judged by its result: what
    /// ending that adjustment loosens or tightens.
    Cancel {
        /// The adjustment.
        id: AdjustmentId,
    },
    /// A policy was judged. The record of a judgment is written in the name of the judged
    /// policy's author ([`super::judge::Outcome::evidence`]).
    Judged {
        /// The policy.
        policy: PolicyId,
        /// What the judgment came to, by the level it was enforced at.
        judgment: Judgment,
        /// The level the policy was written at on the event ([`super::judge::GuardResult`]), so
        /// that a warning the platform could not turn into a stop is told from one that was
        /// written as a warning.
        written: Level,
        /// The level the platform enforced it at on the event: the written level held to the
        /// platform's capabilities ([`super::catalog::Capabilities`]).
        enforced: Level,
    },
    /// A record that could not be read.
    Unreadable {
        /// The kinds of event it may have been, as the adapter tells from where the record was.
        /// The state makes unknown what an event of each of them may have changed.
        may_have_been: KindSet,
    },
}

/// The value of a field, read from an event.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Value {
    Text(String),
    Words(CommandWords),
    Bool(bool),
    Num(f64),
}

impl Value {
    /// Whether the value equals the literal; unknown when they are of different types.
    pub(super) fn equals(&self, lit: &Lit) -> Truth {
        match (self, lit) {
            (Self::Text(value), Lit::Text(want)) => Truth::of(value == want),
            (Self::Bool(value), Lit::Bool(want)) => Truth::of(value == want),
            _ => Truth::Unknown,
        }
    }
}

/// What reading a field of an event found.
///
/// Two kinds of "no value" are kept apart. An edit has no command: that is a fact about the
/// event, and "its command is `cargo test`" is false of it. A tool call whose result has not come
/// back has a success it does not show yet: "it succeeded" is unknown of it. Taking the first for
/// the second would make every edit hide whether the tests ran; taking the second for the first
/// would let a call through before its result is known.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Read {
    /// The event is not of the field's kind.
    OtherKind,
    /// The event has no place for the value.
    Absent,
    /// The event has the value, but it was not known when the event was read.
    Unknown,
    /// The value.
    Found(Value),
}

impl Body {
    /// The kind of the event.
    pub fn kind(&self) -> EventKind {
        match self {
            Self::SessionStart => EventKind::SessionStart,
            Self::Spawn { .. } => EventKind::Spawn,
            Self::TaskStart => EventKind::TaskStart,
            Self::PromptSubmit => EventKind::PromptSubmit,
            Self::ToolUse { .. } => EventKind::ToolUse,
            Self::Stop => EventKind::Stop,
            Self::ModeSwitch { .. } => EventKind::ModeSwitch,
            Self::Measured { .. } => EventKind::Measured,
            Self::Adjust(_) => EventKind::Adjust,
            Self::Cancel { .. } => EventKind::Cancel,
            Self::Judged { .. } => EventKind::Judged,
            Self::Unreadable { .. } => EventKind::Unreadable,
        }
    }

    /// Whether the two are the same event body, the score of a measurement compared by its bits:
    /// a NaN is the same as itself, where `==` takes it for a difference. The state compares what
    /// a slot holds this way, so a score that was not touched is not taken for a change.
    pub(super) fn same_as(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Measured {
                    oracle: a,
                    score: x,
                },
                Self::Measured {
                    oracle: b,
                    score: y,
                },
            ) => a == b && x.to_bits() == y.to_bits(),
            _ => self == other,
        }
    }

    /// The value of `field` in this event.
    pub(super) fn read(&self, field: Field) -> Read {
        let absent = |value: Option<Value>| value.map_or(Read::Absent, Read::Found);
        let unknown = |value: Option<Value>| value.map_or(Read::Unknown, Read::Found);
        match (self, field) {
            (Self::ToolUse { tool, .. }, Field::Tool) => Read::Found(Value::Text(tool.clone())),
            (Self::ToolUse { command, .. }, Field::Command) => {
                absent(command.clone().map(Value::Words))
            }
            (Self::ToolUse { path, .. }, Field::Path) => absent(path.clone().map(Value::Text)),
            (Self::ToolUse { ok, .. }, Field::Ok) => unknown(ok.map(Value::Bool)),
            (Self::ModeSwitch { to }, Field::ModeTo) => Read::Found(Value::Text(to.to_string())),
            (Self::Measured { oracle, .. }, Field::Oracle) => {
                Read::Found(Value::Text(oracle.clone()))
            }
            (Self::Measured { score, .. }, Field::Score) => Read::Found(Value::Num(*score)),
            (Self::Judged { policy, .. }, Field::Policy) => {
                Read::Found(Value::Text(policy.to_string()))
            }
            (Self::Judged { judgment, .. }, Field::Judgment) => {
                Read::Found(Value::Text(judgment.as_str().to_owned()))
            }
            _ => Read::OtherKind,
        }
    }

    /// Whether the condition holds of this event. A comparison with an absent value is false; one
    /// with an unknown value, or with a field this kind of event does not have, is unknown.
    pub(super) fn holds(&self, cond: &Cond) -> Truth {
        let compare = |field: Field, test: &dyn Fn(Value) -> Truth| match self.read(field) {
            Read::Found(value) => test(value),
            Read::Absent => Truth::False,
            Read::OtherKind | Read::Unknown => Truth::Unknown,
        };
        match cond {
            Cond::Eq(field, lit) => compare(*field, &|v| v.equals(lit)),
            Cond::In(field, lits) => compare(*field, &|v| {
                Truth::any(lits.iter().map(|lit| v.equals(lit)))
            }),
            Cond::Glob(field, pattern) => compare(*field, &|v| match v {
                Value::Text(text) => Truth::of(pattern.matches(&text)),
                _ => Truth::Unknown,
            }),
            Cond::Words(field, prefix) => compare(*field, &|v| match v {
                Value::Words(words) => Truth::of(words.starts_with(prefix)),
                _ => Truth::Unknown,
            }),
            Cond::Num(field, cmp, n) => compare(*field, &|v| match v {
                Value::Num(score) => cmp.holds(score, *n).map_or(Truth::Unknown, Truth::of),
                _ => Truth::Unknown,
            }),
            Cond::All(conds) => Truth::all(conds.iter().map(|c| self.holds(c))),
            Cond::Any(conds) => Truth::any(conds.iter().map(|c| self.holds(c))),
            Cond::Not(cond) => !self.holds(cond),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::name::GlobPattern;
    use crate::domain::predicate::Cmp;

    fn bash(command: &str, ok: Option<bool>) -> Body {
        Body::ToolUse {
            tool: "Bash".to_owned(),
            command: Some(
                CommandWords::new(command.split_whitespace().map(str::to_owned).collect()).unwrap(),
            ),
            path: None,
            ok,
        }
    }

    #[test]
    fn every_field_reads_from_its_own_kind_only() {
        let tool_use = bash("cargo test", Some(true));
        assert_eq!(
            tool_use.read(Field::Tool),
            Read::Found(Value::Text("Bash".to_owned()))
        );
        assert_eq!(tool_use.read(Field::Path), Read::Absent);
        assert_eq!(bash("cargo test", None).read(Field::Ok), Read::Unknown);
        assert_eq!(tool_use.read(Field::Score), Read::OtherKind);
        assert_eq!(Body::Stop.read(Field::Tool), Read::OtherKind);
    }

    #[test]
    fn an_unknown_value_stays_unknown_under_not() {
        let event = bash("cargo test", None);
        let ok = Cond::Eq(Field::Ok, Lit::Bool(true));
        assert_eq!(event.holds(&ok), Truth::Unknown);
        assert_eq!(event.holds(&Cond::Not(Box::new(ok))), Truth::Unknown);
    }

    #[test]
    fn a_comparison_with_an_absent_value_is_false() {
        // A shell call touches no path, so no path pattern matches it.
        let event = bash("cargo test", Some(true));
        let path = Cond::Glob(Field::Path, GlobPattern::new("*"));
        assert_eq!(event.holds(&path), Truth::False);
    }

    #[test]
    fn conditions_read_the_event() {
        let event = bash("cargo test -p a", Some(true));
        let words = |text: &str| {
            CommandWords::new(text.split_whitespace().map(str::to_owned).collect()).unwrap()
        };
        assert_eq!(
            event.holds(&Cond::Words(Field::Command, words("cargo test"))),
            Truth::True
        );
        assert_eq!(
            event.holds(&Cond::Words(Field::Command, words("cargo build"))),
            Truth::False
        );
        assert_eq!(
            event.holds(&Cond::In(
                Field::Tool,
                vec![Lit::Text("Edit".to_owned()), Lit::Text("Bash".to_owned())]
            )),
            Truth::True
        );
        let measured = Body::Measured {
            oracle: "bench".to_owned(),
            score: f64::NAN,
        };
        assert_eq!(
            measured.holds(&Cond::Num(Field::Score, Cmp::Ge, 0.5)),
            Truth::Unknown
        );
    }
}
