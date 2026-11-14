//! What happened: the events that the state is folded from and that a policy judges.
//!
//! The caller reads events from wherever they are kept (the platform's transcript through an
//! adapter, the evidence the application appends) and gives them to the domain as [`Event`]
//! values, in the order it folds them. Each event names the [`Principal`] it comes from; where
//! that principal sits is the caller's arrangement ([`super::authority`]), plus the leaves that
//! spawns add to it ([`super::state`]); a rule reads it with
//! [`Pred::ActorUnder`](super::predicate::Pred::ActorUnder). Whether an event is an
//! act or a claim is its kind's [`Nature`](super::schema::Nature). A record whose kind the
//! adapter cannot read is not dropped but becomes [`Body::Unreadable`], with the kinds it may have
//! been, so the state knows what it has not seen. A field of an event that cannot be read is
//! another case: the event keeps its kind, and the field is [`Seen::Unreadable`].
//!
//! The fold history holds only events that happened. An act judged before it runs (a
//! [`Body::ToolUse`] whose `ok` is not known yet) is judged on a copy of the state with the act
//! folded over it, and it enters the history when it is read back from the transcript, with
//! its result. An act that was stopped never runs, so it is not in the history.

use super::adjust::Adjustment;
use super::authority::Principal;
use super::name::{AdjustmentId, ClassifierName, CommandWords, Meter, Mode, PolicyId};
use super::predicate::{Amount, Cond, Lit, Truth};
use super::schema::{At, EventKind, Field, Judgment, KindSet, Level};

/// A field of an event that can be missing: the value that was read, nothing there, or something
/// there that could not be read.
///
/// A field that could not be read does not change the kind of its event: the event is judged as
/// the event it is, and only the conditions that read the field cannot tell (FR71). What a
/// condition that cannot tell comes to is the rule of each place that holds one (FR20): the
/// judge, the cap of a platform, an exemption's cover, a selector. "Nothing there" is a fact
/// about the event, and a comparison with it is false; "could not be read" is a fact about the
/// reader, and a comparison with it is unknown.
///
/// Only a field that can be missing is a `Seen`. An amount that was measured has no "nothing
/// there", so [`Body::Used`] keeps an `Option`; the success of a tool call is not yet known, which
/// is neither (`ok`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Seen<T> {
    /// There is nothing: the event has no place for the value (a comparison with it is false).
    Absent,
    /// The value that was read.
    Value(T),
    /// There is something, and it could not be read (a comparison with it is unknown).
    Unreadable,
}

/// One event: when, from whom, and what.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct Event {
    /// When it happened.
    pub at: At,
    /// The principal it comes from. An act takes effect whoever it is by; a claim takes effect
    /// as its transaction decides ([`super::tx`]).
    pub by: Principal,
    /// What happened.
    pub body: Body,
}

/// An event that can be judged: one whose kind a rule may name
/// ([`EventKind::is_nameable`]). A record whose kind could not be read ([`Body::Unreadable`]) is
/// only folded, and is never a `Judgeable`, so [`judge`](super::judge::judge) and the policies
/// are given only events that have a kind (FR71).
///
/// It is made by [`TryFrom<Event>`](TryFrom), which refuses an event of no kind with the event
/// given back, and read as the [`Event`] it holds ([`Judgeable::event`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Judgeable(Event);

impl Judgeable {
    /// The event.
    pub fn event(&self) -> &Event {
        &self.0
    }
}

impl TryFrom<Event> for Judgeable {
    type Error = NoKind;

    fn try_from(event: Event) -> Result<Self, NoKind> {
        if event.body.kind().is_nameable() {
            Ok(Self(event))
        } else {
            Err(NoKind(event))
        }
    }
}

/// An event that is no [`Judgeable`] because its kind could not be read, given back as it was
/// given, as [`StaleApply`](super::tx::StaleApply) gives back its state.
#[derive(Debug, Clone, PartialEq)]
pub struct NoKind(pub Event);

impl std::fmt::Display for NoKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a record whose kind could not be read is not judged")
    }
}

impl std::error::Error for NoKind {}

/// What happened. New kinds are added as the model grows; a match on it outside this crate lists
/// every kind, so a new one stops it compiling until it is handled.
///
/// Two bodies are equal when they are the same event, the score of a measurement and the answer of
/// a classifier compared as a number with every NaN equal to every NaN: a NaN score is the same as
/// itself, where `f64`'s `==` takes it for a difference, and `0.0` and `-0.0` are the same score.
/// So the equality is total ([`Eq`]): a slot of the state that holds an event is not taken for
/// changed when it was not touched, and a fixture, and the policy that holds it, equals itself.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
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
        /// The command; absent when the tool runs none.
        command: Seen<CommandWords>,
        /// The path; absent when the tool touches none.
        path: Seen<String>,
        /// Whether the call succeeded; `None` until that is known (unknown).
        #[cfg_attr(feature = "serde", serde(deserialize_with = "Option::deserialize"))]
        ok: Option<bool>,
    },
    /// A turn is about to end.
    Stop,
    /// What the platform measured as used of a meter, such as the tokens of a model call: an act.
    /// The adapter reads the amount from what the platform measured and carries it, as it carries
    /// the origin of any act ([`super::schema::EventKind::nature`]); the domain takes it as given.
    /// Its actor is the one whose use it was, so a sum chooses it by its actor's place
    /// ([`Whose`](super::predicate::Whose)), and a sub agent's use counts under its parent.
    ///
    /// The amount is read only by [`Pred::Spent`](super::predicate::Pred::Spent), which sums it; a
    /// condition reads the meter ([`Field::Meter`]). An amount is known after the use, so a sum can
    /// pass its bound by one event, and the next act is the one a rule stops.
    Used {
        /// What was measured.
        meter: Meter,
        /// How much was used; `None` when it was measured but the amount could not be read. That
        /// makes only a sum of the meter unknown, as `ok: None` makes a read of a tool call's
        /// success unknown: a count of `Used` events, and a `Since` that a `Used` closes, still
        /// read the event.
        #[cfg_attr(feature = "serde", serde(deserialize_with = "Option::deserialize"))]
        amount: Option<Amount>,
    },
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
        #[cfg_attr(feature = "serde", serde(with = "super::encoding::float"))]
        score: f64,
    },
    /// A classifier answered: a claim, read by the rules that name the classifier (a filter of
    /// `Classified` events narrows to one with `classifier == name`,
    /// [`super::catalog::AcceptError::UnnamedClassifier`]). It counts only from one who covers the
    /// authors of the rules that read it, as any record a rule reads does ([`super::tx`]). The
    /// answer is a judgment that may be wrong, so a guard that reads one stops only while the
    /// classifier's calibration meets its bound ([`super::policy::Classifier`]).
    Classified {
        /// The classifier, by name and version.
        classifier: ClassifierName,
        /// The answer.
        #[cfg_attr(feature = "serde", serde(with = "super::encoding::float"))]
        answer: f64,
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
    /// A record whose kind could not be read. It is only folded, and [`super::judge::judge`] says
    /// why no policy judges it. A field that could not be read is not this but a
    /// [`Seen::Unreadable`] of an event of its kind.
    Unreadable {
        /// The kinds of event it may have been, as the adapter tells from where the record was.
        /// The state makes unknown what an event of each of them may have changed.
        may_have_been: KindSet,
    },
}

// Written by hand, not derived, for the score of a measurement and the answer of a classifier:
// `f64` has no total equality, so the number is compared with NaN equal to NaN (see the doc of
// `Body`), which is an equivalence: reflexive with the NaN case, and symmetric and transitive as
// `==` and "both are NaN" each are, never both at once. Every other field is compared with its
// own `==`. The match is on `self` with no wildcard, so a new kind does not compile until its
// equality is written.
impl PartialEq for Body {
    fn eq(&self, other: &Self) -> bool {
        match self {
            Self::SessionStart => matches!(other, Self::SessionStart),
            Self::Spawn { child, under } => matches!(
                other,
                Self::Spawn { child: c, under: u } if child == c && under == u
            ),
            Self::TaskStart => matches!(other, Self::TaskStart),
            Self::PromptSubmit => matches!(other, Self::PromptSubmit),
            Self::ToolUse {
                tool,
                command,
                path,
                ok,
            } => matches!(
                other,
                Self::ToolUse { tool: t, command: c, path: p, ok: o }
                    if tool == t && command == c && path == p && ok == o
            ),
            Self::Stop => matches!(other, Self::Stop),
            Self::Used { meter, amount } => matches!(
                other,
                Self::Used { meter: m, amount: a } if meter == m && amount == a
            ),
            Self::ModeSwitch { to } => matches!(other, Self::ModeSwitch { to: t } if to == t),
            Self::Measured { oracle, score } => matches!(
                other,
                Self::Measured { oracle: o, score: s }
                    if oracle == o && (score == s || (score.is_nan() && s.is_nan()))
            ),
            Self::Classified { classifier, answer } => matches!(
                other,
                Self::Classified { classifier: c, answer: a }
                    if classifier == c && (answer == a || (answer.is_nan() && a.is_nan()))
            ),
            Self::Adjust(adjustment) => matches!(other, Self::Adjust(a) if adjustment == a),
            Self::Cancel { id } => matches!(other, Self::Cancel { id: i } if id == i),
            Self::Judged {
                policy,
                judgment,
                written,
                enforced,
            } => matches!(
                other,
                Self::Judged { policy: p, judgment: j, written: w, enforced: e }
                    if policy == p && judgment == j && written == w && enforced == e
            ),
            Self::Unreadable { may_have_been } => matches!(
                other,
                Self::Unreadable { may_have_been: m } if may_have_been == m
            ),
        }
    }
}

impl Eq for Body {}

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
    /// The event has the value, but it was not known when the event was read, or it could not be
    /// read ([`Seen::Unreadable`]).
    Unknown,
    /// The value.
    Found(Value),
}

impl<T> Seen<T> {
    /// What reading the field finds: nothing there, the value (made a [`Value`] by `to_value`),
    /// or a value that is not known.
    fn read(&self, to_value: impl FnOnce(&T) -> Value) -> Read {
        match self {
            Self::Absent => Read::Absent,
            Self::Value(value) => Read::Found(to_value(value)),
            Self::Unreadable => Read::Unknown,
        }
    }
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
            Self::Used { .. } => EventKind::Used,
            Self::ModeSwitch { .. } => EventKind::ModeSwitch,
            Self::Measured { .. } => EventKind::Measured,
            Self::Classified { .. } => EventKind::Classified,
            Self::Adjust(_) => EventKind::Adjust,
            Self::Cancel { .. } => EventKind::Cancel,
            Self::Judged { .. } => EventKind::Judged,
            Self::Unreadable { .. } => EventKind::Unreadable,
        }
    }

    /// The value of `field` in this event.
    pub(super) fn read(&self, field: Field) -> Read {
        let unknown = |value: Option<Value>| value.map_or(Read::Unknown, Read::Found);
        match (self, field) {
            (Self::ToolUse { tool, .. }, Field::Tool) => Read::Found(Value::Text(tool.clone())),
            (Self::ToolUse { command, .. }, Field::Command) => {
                command.read(|words| Value::Words(words.clone()))
            }
            (Self::ToolUse { path, .. }, Field::Path) => {
                path.read(|text| Value::Text(text.clone()))
            }
            (Self::ToolUse { ok, .. }, Field::Ok) => unknown(ok.map(Value::Bool)),
            (Self::ModeSwitch { to }, Field::ModeTo) => Read::Found(Value::Text(to.to_string())),
            (Self::Measured { oracle, .. }, Field::Oracle) => {
                Read::Found(Value::Text(oracle.clone()))
            }
            (Self::Measured { score, .. }, Field::Score) => Read::Found(Value::Num(*score)),
            // The text the name holds, so `classifier == "commit-why@3"` is the name's own equality.
            (Self::Classified { classifier, .. }, Field::Classifier) => {
                Read::Found(Value::Text(classifier.as_str().to_owned()))
            }
            (Self::Classified { answer, .. }, Field::Answer) => Read::Found(Value::Num(*answer)),
            (Self::Judged { policy, .. }, Field::Policy) => {
                Read::Found(Value::Text(policy.to_string()))
            }
            (Self::Judged { judgment, .. }, Field::Judgment) => {
                judgment.as_str().map_or(Read::Unknown, |word| {
                    Read::Found(Value::Text(word.to_owned()))
                })
            }
            // The text the meter holds, so `meter == "tokens"` is the meter's own equality.
            (Self::Used { meter, .. }, Field::Meter) => {
                Read::Found(Value::Text(meter.as_str().to_owned()))
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
                Value::Num(score) => cmp.holds(score, n.get()).map_or(Truth::Unknown, Truth::of),
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
    use crate::domain::predicate::{Cmp, Number};

    fn bash(command: &str, ok: Option<bool>) -> Body {
        Body::ToolUse {
            tool: "Bash".to_owned(),
            command: Seen::Value(
                CommandWords::new(command.split_whitespace().map(str::to_owned).collect()).unwrap(),
            ),
            path: Seen::Absent,
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
        // An amount that could not be read leaves the meter known.
        let used = Body::Used {
            meter: "tokens".parse().unwrap(),
            amount: None,
        };
        assert_eq!(
            used.read(Field::Meter),
            Read::Found(Value::Text("tokens".to_owned()))
        );
        assert_eq!(used.read(Field::Tool), Read::OtherKind);
    }

    #[test]
    fn an_unknown_value_stays_unknown_under_not() {
        let event = bash("cargo test", None);
        let ok = Cond::Eq(Field::Ok, Lit::Bool(true));
        assert_eq!(event.holds(&ok), Truth::Unknown);
        assert_eq!(event.holds(&Cond::Not(Box::new(ok))), Truth::Unknown);
    }

    /// FR71: a field that could not be read is unknown, under `not` as well, and the fields that
    /// were read are read as they are.
    #[test]
    fn a_field_that_could_not_be_read_is_unknown() {
        let Body::ToolUse { tool, command, .. } = bash("cargo test", Some(true)) else {
            unreachable!()
        };
        let event = Body::ToolUse {
            tool,
            command,
            path: Seen::Unreadable,
            ok: Some(true),
        };
        assert_eq!(event.read(Field::Path), Read::Unknown);
        let path = Cond::Glob(Field::Path, GlobPattern::new("*").unwrap());
        assert_eq!(event.holds(&path), Truth::Unknown);
        assert_eq!(event.holds(&Cond::Not(Box::new(path))), Truth::Unknown);
        assert_eq!(
            event.read(Field::Tool),
            Read::Found(Value::Text("Bash".to_owned()))
        );
    }

    #[test]
    fn a_comparison_with_an_absent_value_is_false() {
        // A shell call touches no path, so no path pattern matches it.
        let event = bash("cargo test", Some(true));
        let path = Cond::Glob(Field::Path, GlobPattern::new("*").unwrap());
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
            measured.holds(&Cond::Num(Field::Score, Cmp::Ge, Number::new(0.5).unwrap())),
            Truth::Unknown
        );
    }

    #[test]
    fn a_body_equals_itself_and_a_score_is_compared_as_a_number_with_nan_equal_to_nan() {
        let measured = |score| Body::Measured {
            oracle: "bench".to_owned(),
            score,
        };
        assert_eq!(measured(f64::NAN), measured(f64::NAN));
        assert_eq!(measured(f64::NAN), measured(-f64::NAN));
        assert_eq!(measured(0.0), measured(-0.0));
        assert_ne!(measured(f64::NAN), measured(0.0));
        assert_ne!(measured(0.5), measured(0.25));
        assert_ne!(measured(0.5), Body::Stop);
        assert_eq!(bash("cargo test", None), bash("cargo test", None));
        assert_ne!(bash("cargo test", None), bash("cargo test", Some(true)));
    }
}
