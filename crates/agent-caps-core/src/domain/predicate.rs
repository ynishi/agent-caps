//! The structural rule language: what a policy says about an event and the events before it.
//!
//! ```text
//! Pred := Now(Cond) | ModeIs(mode) | ActorUnder(principal)
//!       | Once(selector, scope) | Count(selector, scope) cmp n
//!       | Last(selector, scope) test Cond
//!       | All[Pred…] | Any[Pred…] | Not Pred
//! Cond := field == lit | field in {lit…} | glob(field, pattern) | words(field, words)
//!       | num(field) cmp n | All[Cond…] | Any[Cond…] | Not Cond
//! filter   := kind [where Cond]
//! by       := Anyone | Under(principal) | Only(principal)
//! selector := filter by by
//! scope    := Session | Mode | Task(by) | Turn(by) | Since(selector)
//! ```
//!
//! `ModeIs` and `ActorUnder` read the state rather than the events of a scope: the mode in
//! effect, and where the judged event's actor sits in the hierarchy of actors. A [`By::Under`]
//! reads the hierarchy too, of the actor of each event a selector looks at and of each event
//! that may start a task or a turn again. How a policy reads such an atom, in a direction a
//! transaction can use, is answered in one place, `state_readings`, for every atom that reads
//! the state.
//!
//! A [`Selector`] chooses events by what they are ([`EventFilter`]) and by who acted ([`By`]).
//! The filter alone is what is read where no actor can be: the capabilities of a platform and
//! the cover of an exemption take an [`EventFilter`], which cannot hold a `By`.
//!
//! # Invariants
//!
//! - Every predicate stops, in time linear in its size per event: there is no loop, recursion,
//!   user-defined function or regex. Shell patterns are matched without backtracking.
//! - The past is read only through the three temporal operators, each one level deep: the
//!   condition inside a [`Pred::Once`], [`Pred::Count`] or [`Pred::Last`] is a [`Cond`], which
//!   cannot hold one.
//!   The type, not a check, keeps them from nesting. Each temporal operator becomes one slot of
//!   the state, updated from its last value and the new event alone.
//! - A predicate is evaluated in three values ([`Truth`]). A value the event has but did not
//!   show (a result not yet back, a record not read) is [`Truth::Unknown`], never false, so `not`
//!   cannot turn it into a pass. A value the event has no place for (the command of an edit) is
//!   absent, and a comparison with it is false.
//! - A field is read only from its own kind of event, with an operand of its type. The catalog
//!   checks this ([`Pred::check`]) before it accepts a policy.

use super::authority::Principal;
use super::name::{CommandWords, GlobPattern, Mode, PolicyId};
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

/// Events of one kind, and a condition on the event when only some events of that kind count:
/// what an event is, with nothing of who acted. A temporal operator and a `Since` scope add who
/// acted with a [`Selector`]; the capabilities of a platform and the cover of an exemption read
/// the filter alone.
#[derive(Debug, Clone, PartialEq)]
pub struct EventFilter {
    /// The kind of event.
    pub kind: EventKind,
    /// The condition the event must meet; `None` takes every event of the kind.
    pub cond: Option<Cond>,
}

/// Whose events a selector chooses, and whose start event starts a task or a turn scope again.
/// It has no default: a rule always says whose events it means.
///
/// - `Anyone` takes the events of every actor, which is what a rule over events read before. It
///   lets the one a limit is about start its own count over (see [`Scope`]).
/// - `Under(p)` takes the events of `p` and of every actor below it, the leaves spawns place
///   there included: the form for counting what a part of the hierarchy does, such as the pushes
///   of the agent and its sub agents. Since the one a limit is about sits below whoever set the
///   limit, `Under` of the limit's author takes that one's acts too.
/// - `Only(p)` takes the events of `p` alone: the form for a limit that only `p` may start again,
///   such as a count of pushes since the last review by the user. No spawn can move it, since a
///   spawned leaf is never `p` (its name is new at every start).
///
/// The principal of `Under` and `Only` must be one of the authority's, in a rule and in the
/// lifetime of a temporary adjustment alike.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum By {
    /// The events of every actor.
    Anyone,
    /// The events whose actor (their `by`) is the principal or sits below it in the hierarchy of
    /// actors, as [`Pred::ActorUnder`] reads it. An actor whose place is not known gives
    /// unknown, not "not under".
    Under(Principal),
    /// The events whose actor is the principal itself, not one below it. It reads no hierarchy,
    /// so it is never unknown.
    Only(Principal),
}

impl By {
    /// The principal it names, when it names one.
    pub(super) fn principal(&self) -> Option<&Principal> {
        match self {
            Self::Anyone => None,
            Self::Under(principal) | Self::Only(principal) => Some(principal),
        }
    }
}

/// The events a temporal operator looks at, or that close a [`Scope::Since`]: those that meet
/// the filter and whose actor `by` chooses. Whether an event is chosen is answered in one place,
/// for every reader.
#[derive(Debug, Clone, PartialEq)]
pub struct Selector {
    /// What the event is.
    pub filter: EventFilter,
    /// Who acted.
    pub by: By,
}

/// The span a temporal operator counts within, and that an exemption may last for. Each starts
/// again at its own boundary; a new session starts all of them again.
///
/// A scope has two boundaries, both read from the event being folded: the event before which it
/// starts again, and the event on which it closes (the closing event belongs to the interval it
/// closes, and the interval starts again before the next event). The state folds both in one
/// place, so every scope is handled by one rule.
///
/// # Who may start a scope again
///
/// A scope starts again at an act, and an act takes effect whoever it comes from. So the one a
/// limit is about can start its count over by its own acts, unless the scope says who may. `Task`
/// and `Turn` say whose start event starts them again, and `Since` whose events close it, each
/// with a [`By`] that cannot be left out: `By::Anyone` keeps every actor's events,
/// `By::Under(p)` only those of `p` and the actors below it, and `By::Only(p)` only those of `p`
/// itself. The one a limit is about sits below the one who set it, so a limit that only its
/// author may start again is written with `Only`. `Session` starts again at
/// [`EventKind::SessionStart`], an act of the platform, and has no `By`. A claim, such as a
/// mode switch or a record that closes a `Since`, is judged as a transaction ([`super::tx`]).
///
/// An actor whose place in the hierarchy is not known (one placed after a lost spawn) leaves it
/// unknown whether it starts or closes a scope that chooses by `Under`, and that is handled as
/// any unknown start or close is: the slots of the scope become unknown, and an adjustment that
/// lasts within it is kept as possibly ended, read in the direction that tightens (an exemption
/// covers nothing, a binding it adds still holds, a suspension no longer holds; see
/// [`super::state`]). Placing a child under the principal of an `Under` changes whose acts
/// start or close the scope, so a spawn that does is asked of the rule's author ([`super::tx`]).
/// An `Only` reads no hierarchy: no actor's place leaves it unknown, and no spawn moves it.
///
/// `Session`, `Task` and `Turn` assume their start events are not lost to an unreadable record
/// (a known gap: a lost start leaves the scope looking as if it had not started again).
/// [`Scope::Mode`] and [`Scope::Since`] do not: when a lost record may have been a mode switch,
/// or the event a `Since` looks for, the scope's slots become unknown.
///
/// # `Since`
///
/// `Since(selector)` is the span after the last event the selector chooses. That event belongs
/// to the interval it closes, so an event is judged with the interval before it, and the
/// interval starts again before the next event. It starts again too at
/// [`EventKind::SessionStart`], and not at [`EventKind::TaskStart`]. A filter whose condition is
/// unknown on an event (`ok` of a tool call whose result is not back), or an actor whose place is
/// unknown, leaves it unknown whether the interval closed: the slots of the scope become unknown
/// before the next event, and an adjustment that lasts within the scope is kept as possibly
/// ended: an exemption covers nothing, and a raise still holds. A record that could
/// not be read closes the scope as unknown only when the filter's kind is one the record may have
/// been.
///
/// - `once(test passed, Since(commit))` asks whether a test passed since the last commit. It is
///   judged on the commit itself with the interval before it, so a second commit with no new
///   test in between is stopped.
/// - `once(commit, Since(commit))` is true only on a commit, and `count(commit, Since(commit))`
///   is at most 1.
/// - Closing an interval tightens a rule on `once` (what was seen before is forgotten) and
///   loosens a limit on `count` (the count starts over). With `By::Anyone`, the acts of the one
///   the rule is about can start a `count` over: with `count(edit, Since(commit by Anyone)) <=
///   3`, one who commits after every third edit never reaches the limit. With
///   `count(push, Since(review by Under(reviewer))) <= 3`, only a review by the reviewer or an
///   actor below it starts the count over, and with `Since(review by Only(user))` only the
///   user's own review does.
/// - To let only a call that succeeded close the interval, restrict the filter to
///   `ok == true`. A call that failed, or that was stopped and never ran, does not match, and
///   the interval it belongs to goes on.
/// - `Lifetime::Within(Since(g))` (see [`super::adjust::Lifetime`]) ends a temporary adjustment
///   after the next `g`. Until the next event after `g`, the adjustment still shows as in effect,
///   so `g` itself is judged with it.
#[derive(Debug, Clone, PartialEq)]
pub enum Scope {
    /// From [`EventKind::SessionStart`].
    Session,
    /// From the last mode switch that took effect, a switch to the mode already in effect
    /// included.
    Mode,
    /// From the last [`EventKind::TaskStart`] whose actor the `By` chooses, or the start of the
    /// session.
    Task(By),
    /// From the last [`EventKind::PromptSubmit`] whose actor the `By` chooses, or the start of
    /// the session.
    Turn(By),
    /// After the last event the selector chooses.
    Since(Selector),
}

impl Scope {
    /// Who may start the scope again or close it, when the scope says.
    pub(super) fn by(&self) -> Option<&By> {
        match self {
            Self::Task(by) | Self::Turn(by) => Some(by),
            Self::Since(selector) => Some(&selector.by),
            Self::Session | Self::Mode => None,
        }
    }
}

/// A predicate on the judged event and the events before it.
#[derive(Debug, Clone, PartialEq)]
pub enum Pred {
    /// The condition holds of the judged event.
    Now(Cond),
    /// The mode in effect is this one.
    ModeIs(Mode),
    /// The actor of the judged event (its `by`) is the principal or sits below it in the
    /// hierarchy of actors: the principals of the [`Authority`](super::authority::Authority)
    /// and the leaves that spawns added to them. The principal must be one of the authority's
    /// (a leaf's name is new at every start, so a rule cannot name it). An actor the hierarchy
    /// does not know, or one placed after a lost record, is unknown, not "not under".
    ActorUnder(Principal),
    /// Such an event happened within the scope, the judged event included.
    Once {
        /// The event looked for.
        select: Selector,
        /// Since when.
        scope: Scope,
    },
    /// The number of such events within the scope, the judged event included, compares to `n`.
    Count {
        /// The events counted.
        select: Selector,
        /// Since when.
        scope: Scope,
        /// How the count compares.
        cmp: Cmp,
        /// What it is compared with.
        n: u32,
    },
    /// The last event within the scope that the selector chooses meets the condition. False
    /// when there was no such event. The condition is read from that event as a condition of
    /// [`Pred::Now`] is from the judged one, so it may compare a number
    /// (`Last { Measured where oracle == "bench", Session, score >= 0.8 }`) and an event whose
    /// value is not known gives unknown.
    ///
    /// `Last { select: Selector { filter: EventFilter { kind, cond: None }, by: By::Anyone },
    /// scope, test: Cond::Eq(field, value) }` is "the field had this value in the last event of
    /// its kind".
    Last {
        /// The events looked at: the last one chosen counts.
        select: Selector,
        /// Since when.
        scope: Scope,
        /// What must hold of that event, read from the kind of the filter.
        test: Cond,
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
    Once(Selector, Scope),
    Count(Selector, Scope),
    Last(Selector, Scope),
}

impl Temporal {
    pub(super) fn scope(&self) -> &Scope {
        match self {
            Self::Once(_, scope) | Self::Count(_, scope) | Self::Last(_, scope) => scope,
        }
    }

    /// The events the operator looks at.
    pub(super) fn selector(&self) -> &Selector {
        match self {
            Self::Once(selector, _) | Self::Count(selector, _) | Self::Last(selector, _) => {
                selector
            }
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
        if let Self::Since(selector) = self {
            selector.filter.check_into(errors);
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
            // Whether the principal is one of the hierarchy is the catalog's to check.
            Self::ModeIs(_) | Self::ActorUnder(_) => {}
            Self::Once { select, scope } | Self::Count { select, scope, .. } => {
                select.filter.check_into(errors);
                scope.check_into(errors);
            }
            Self::Last {
                select,
                scope,
                test,
            } => {
                select.filter.check_into(errors);
                test.check_into(select.filter.kind, errors);
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

    /// Adds to `out` every principal the predicate names in the hierarchy of actors that `out`
    /// does not hold yet, in the order they first appear: those of `ActorUnder` and of every `By`
    /// of its selectors and scopes (`Under` and `Only`). What the catalog checks against the
    /// hierarchy, over every predicate of a policy into one `out`.
    pub(super) fn named_actors_into<'a>(&'a self, out: &mut Vec<&'a Principal>) {
        let mut note = |principal: &'a Principal| {
            if !out.contains(&principal) {
                out.push(principal);
            }
        };
        match self {
            Self::Now(_) | Self::ModeIs(_) => {}
            Self::ActorUnder(principal) => note(principal),
            Self::Once { select, scope }
            | Self::Count { select, scope, .. }
            | Self::Last { select, scope, .. } => {
                temporal_bys(select, scope)
                    .filter_map(By::principal)
                    .for_each(note);
            }
            Self::All(preds) | Self::Any(preds) => {
                for pred in preds {
                    pred.named_actors_into(out);
                }
            }
            Self::Not(pred) => pred.named_actors_into(out),
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
            Self::Now(_) | Self::ModeIs(_) | Self::ActorUnder(_) => None,
            Self::Once { select, scope } => Some(Temporal::Once(select.clone(), scope.clone())),
            Self::Count { select, scope, .. } => {
                Some(Temporal::Count(select.clone(), scope.clone()))
            }
            Self::Last { select, scope, .. } => Some(Temporal::Last(select.clone(), scope.clone())),
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

impl Pred {
    /// The judgments the predicate reads, each read once, in the order they first appear: those
    /// of the filter of each temporal operator and of the filter of a `Since` scope. The one
    /// place that builds the read of every operator, a `last`'s included ([`last_read`]).
    pub(super) fn judged_reads(&self) -> Vec<JudgedRead> {
        let mut out = Vec::new();
        self.judged_reads_into(&mut out);
        out
    }

    fn judged_reads_into(&self, out: &mut Vec<JudgedRead>) {
        let since = |scope: &Scope| match scope {
            Scope::Since(selector) => judged_read(&selector.filter),
            _ => None,
        };
        let found = match self {
            Self::Now(_) | Self::ModeIs(_) | Self::ActorUnder(_) => Vec::new(),
            Self::Once { select, scope } | Self::Count { select, scope, .. } => {
                vec![judged_read(&select.filter), since(scope)]
            }
            Self::Last {
                select,
                scope,
                test,
            } => vec![last_read(&select.filter, test), since(scope)],
            Self::All(preds) | Self::Any(preds) => {
                for pred in preds {
                    pred.judged_reads_into(out);
                }
                return;
            }
            Self::Not(pred) => return pred.judged_reads_into(out),
        };
        for read in found.into_iter().flatten() {
            if !out.contains(&read) {
                out.push(read);
            }
        }
    }
}

/// Where a predicate stands in a policy. It decides whether the direction an atom that reads the
/// state is read in can be told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Site {
    /// The `when` of a guard. The guard applies where it holds, so an atom under an even number
    /// of `Not`s that holds more often makes the guard apply to more.
    GuardWhen,
    /// The `rule` of a guard: what must hold of an event the guard applies to. An atom in it
    /// that holds more often can let an event pass or stop it, depending on the rest.
    GuardRule,
    /// Either predicate of a reward. A reward's `Hit` is recorded as a judgment, which guards may
    /// read, so a reward is not neutral and its direction is not read.
    Reward,
}

/// The direction in which a policy reads an atom that reads the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reading {
    /// The atom holding more often makes the policy apply to more, and holding less often makes
    /// it apply to less: the guard's `when`, under an even number of `Not`s.
    Positive,
    /// The direction cannot be told: the atom is under an odd number of `Not`s, or in a guard's
    /// `rule`, or in a reward.
    Unreadable,
}

/// An atom of a predicate that reads the state rather than the events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StateAtom<'a> {
    /// `ModeIs(mode)`.
    Mode(&'a Mode),
    /// `ActorUnder(principal)`, or a `By::Under(principal)` of a selector or a scope.
    Actor(&'a Principal),
}

/// Every atom of `pred` that reads the state, each once, with the direction `pred` reads it in
/// when it stands at `site`: the one place that answers this, for every such atom. An atom read
/// in two directions is `Unreadable`. A `By::Under` of a temporal operator, of its selector or
/// its scope, is read as [`by_reading`] says, wherever it stands.
pub(super) fn state_readings(pred: &Pred, site: Site) -> Vec<(StateAtom<'_>, Reading)> {
    let mut out = Vec::new();
    readings_into(pred, site, false, &mut out);
    out
}

/// The principal a `By::Under` reads, with the direction it is read in: always `Unreadable`.
/// Placing an actor under the principal makes its later acts counted, or able to close or start a scope
/// again, and which way that moves a rule cannot be told. The one answer, for a selector and a
/// scope of a predicate and for the scope a temporary adjustment lasts within.
///
/// `Anyone` and `Only` read nothing a spawn can move: a spawned leaf is never the principal of an
/// `Only`, so they give none.
pub(super) fn by_reading(by: &By) -> Option<(&Principal, Reading)> {
    match by {
        By::Anyone | By::Only(_) => None,
        By::Under(principal) => Some((principal, Reading::Unreadable)),
    }
}

/// The `By`s of a temporal operator: that of its selector, and that of its scope when the scope
/// has one.
fn temporal_bys<'a>(select: &'a Selector, scope: &'a Scope) -> impl Iterator<Item = &'a By> {
    std::iter::once(&select.by).chain(scope.by())
}

fn readings_into<'a>(
    pred: &'a Pred,
    site: Site,
    negated: bool,
    out: &mut Vec<(StateAtom<'a>, Reading)>,
) {
    let atom = match pred {
        Pred::ModeIs(mode) => StateAtom::Mode(mode),
        Pred::ActorUnder(principal) => StateAtom::Actor(principal),
        Pred::All(preds) | Pred::Any(preds) => {
            for pred in preds {
                readings_into(pred, site, negated, out);
            }
            return;
        }
        Pred::Not(pred) => return readings_into(pred, site, !negated, out),
        Pred::Once { select, scope }
        | Pred::Count { select, scope, .. }
        | Pred::Last { select, scope, .. } => {
            for (principal, reading) in temporal_bys(select, scope).filter_map(by_reading) {
                note_reading(out, StateAtom::Actor(principal), reading);
            }
            return;
        }
        Pred::Now(_) => return,
    };
    let reading = if site == Site::GuardWhen && !negated {
        Reading::Positive
    } else {
        Reading::Unreadable
    };
    note_reading(out, atom, reading);
}

/// Notes that `key` is read in `reading`, each key once: read in two directions, it is
/// `Unreadable`. The one rule for merging readings, of one predicate or of a whole policy.
pub(super) fn note_reading<K: PartialEq>(out: &mut Vec<(K, Reading)>, key: K, reading: Reading) {
    match out.iter_mut().find(|(seen, _)| *seen == key) {
        Some((_, seen)) if reading == Reading::Unreadable => *seen = Reading::Unreadable,
        Some(_) => {}
        None => out.push((key, reading)),
    }
}

/// What one filter of judgments reads: how far it narrows the judged policy, and which policies
/// it names. They are two questions with two answers: a filter that narrows to nothing can still
/// name a policy (`any(policy == id, judgment == denied)`), and the naming is what is checked
/// against the hierarchy whatever the shape of the filter. It is a fact about the filter alone;
/// what the catalog makes of it (who is visible, what is rejected) is the catalog's.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct JudgedRead {
    /// The policies the filter narrows to, or `None` when it does not narrow the policy and so
    /// reads every policy.
    pub(super) narrowed: Option<Vec<PolicyId>>,
    /// Every policy the filter names with `policy == id` or `policy in {ids}`, wherever in it.
    pub(super) named: Vec<PolicyId>,
}

impl JudgedRead {
    /// Whether the read is of the policy because it is named, not because the read is of every
    /// policy. What a filter narrows to it names, so the narrowed policies are among `named`.
    pub(super) fn names(&self, id: PolicyId) -> bool {
        self.named.contains(&id)
    }
}

/// Whether the filter looks for judgments and narrows to no policy: the filters the catalog
/// limits to the policies their author may count. The same answer as [`judged_read`]'s
/// `narrowed`, without collecting what the filter names.
pub(super) fn reads_unnarrowed(filter: &EventFilter) -> bool {
    filter.kind == EventKind::Judged && filter.cond.as_ref().and_then(narrowed_policies).is_none()
}

/// What a filter reads, when it looks for judgments. A filter with no condition narrows to no
/// policy and names none. The filter of a `once`, a `count`, a `last` and a `Since` scope are
/// read alike.
pub(super) fn judged_read(filter: &EventFilter) -> Option<JudgedRead> {
    (filter.kind == EventKind::Judged).then(|| match &filter.cond {
        None => JudgedRead {
            narrowed: None,
            named: Vec::new(),
        },
        Some(cond) => {
            let mut named = Vec::new();
            named_policies(cond, &mut named);
            JudgedRead {
                narrowed: narrowed_policies(cond),
                named,
            }
        }
    })
}

/// What a `last` reads, when its filter looks for judgments: what its filter reads
/// ([`judged_read`]), and the policies its test names too. The test is read from the last event
/// the filter matches, so a policy it names (`policy == id`) is a policy the `last` names as much
/// as one in the filter, and is checked against the hierarchy alike. How far the `last` narrows
/// is the filter's alone: the test picks among the events the filter lets through.
pub(super) fn last_read(filter: &EventFilter, test: &Cond) -> Option<JudgedRead> {
    let mut read = judged_read(filter)?;
    named_policies(test, &mut read.named);
    Some(read)
}

/// The policies a text of a condition on a judgment names. A text that is not an id as a
/// judgment's policy reads (its hyphenated, lowercase form) names no policy, since no judgment's
/// policy reads as it: the text is compared as it is ([`super::event`]), though an id is parsed
/// in either case.
fn ids_of(lits: &[Lit]) -> Vec<PolicyId> {
    lits.iter()
        .filter_map(|lit| match lit {
            Lit::Text(text) => text
                .parse::<PolicyId>()
                .ok()
                .filter(|id| id.to_string() == *text),
            Lit::Bool(_) => None,
        })
        .collect()
}

/// Every policy a condition names with `policy == id` or `policy in {ids}`, wherever in it, each
/// once, in the order they first appear.
fn named_policies(cond: &Cond, out: &mut Vec<PolicyId>) {
    let mut push = |ids: Vec<PolicyId>| {
        for id in ids {
            if !out.contains(&id) {
                out.push(id);
            }
        }
    };
    match cond {
        Cond::Eq(Field::Policy, lit) => push(ids_of(std::slice::from_ref(lit))),
        Cond::In(Field::Policy, lits) => push(ids_of(lits)),
        Cond::All(conds) | Cond::Any(conds) => {
            for cond in conds {
                named_policies(cond, out);
            }
        }
        Cond::Not(cond) => named_policies(cond, out),
        Cond::Eq(..) | Cond::In(..) | Cond::Glob(..) | Cond::Words(..) | Cond::Num(..) => {}
    }
}

/// The policies a condition on a judgment narrows to: `policy == id`, `policy in {ids}`, an
/// `all` that holds one or more of them (the policies all of them allow), or an `any` whose every
/// branch narrows (the policies one of them allows). `None` when it does not narrow.
fn narrowed_policies(cond: &Cond) -> Option<Vec<PolicyId>> {
    match cond {
        Cond::Eq(Field::Policy, lit) => Some(ids_of(std::slice::from_ref(lit))),
        Cond::In(Field::Policy, lits) => Some(ids_of(lits)),
        Cond::All(conds) => conds
            .iter()
            .filter_map(narrowed_policies)
            .reduce(|kept, other| kept.into_iter().filter(|id| other.contains(id)).collect()),
        // An `any` narrows only when every branch does, to the policies some branch allows.
        Cond::Any(conds) if !conds.is_empty() => conds
            .iter()
            .map(narrowed_policies)
            .collect::<Option<Vec<_>>>()
            .map(|sets| {
                let mut union: Vec<PolicyId> = Vec::new();
                for id in sets.into_iter().flatten() {
                    if !union.contains(&id) {
                        union.push(id);
                    }
                }
                union
            }),
        _ => None,
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
    fn a_policy_is_named_only_as_a_judgment_reads_it() {
        let filter = |text: &str| EventFilter {
            kind: EventKind::Judged,
            cond: Some(Cond::Eq(Field::Policy, Lit::Text(text.to_owned()))),
        };
        let lower = "0000000a-0000-7000-8000-00000000000b";
        let id: PolicyId = lower.parse().unwrap();
        let read = judged_read(&filter(lower)).unwrap();
        assert_eq!(read.narrowed, Some(vec![id]));
        assert!(read.names(id));
        // Parsed in either case, but compared as written: the upper case matches no judgment.
        let read = judged_read(&filter(&lower.to_uppercase())).unwrap();
        assert_eq!(read.narrowed, Some(vec![]));
        assert!(!read.names(id));
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

    /// Every event of `kind`, of anyone.
    fn any(kind: EventKind, cond: Option<Cond>) -> Selector {
        Selector {
            filter: EventFilter { kind, cond },
            by: By::Anyone,
        }
    }

    #[test]
    fn a_temporal_condition_is_read_from_its_own_kind() {
        let ran_tests = Pred::Once {
            select: any(
                EventKind::ToolUse,
                Some(Cond::Eq(Field::Ok, Lit::Bool(true))),
            ),
            scope: Scope::Task(By::Anyone),
        };
        // The subject is a stop; the condition inside `once` reads the tool use it looks for.
        assert!(ran_tests.check(EventKind::Stop).is_empty());
        let wrong = Pred::Once {
            select: any(EventKind::Stop, Some(Cond::Eq(Field::Ok, Lit::Bool(true)))),
            scope: Scope::Task(By::Anyone),
        };
        assert_eq!(wrong.check(EventKind::Stop).len(), 1);
    }

    #[test]
    fn the_same_temporal_part_is_one_slot() {
        let once = Pred::Once {
            select: any(EventKind::Stop, None),
            scope: Scope::Task(By::Anyone),
        };
        let pred = Pred::All(vec![
            once.clone(),
            Pred::Not(Box::new(once)),
            Pred::Count {
                select: any(EventKind::Stop, None),
                scope: Scope::Task(By::Anyone),
                cmp: Cmp::Ge,
                n: 2,
            },
            // Who acted is part of the temporal part: another slot.
            Pred::Once {
                select: Selector {
                    filter: EventFilter {
                        kind: EventKind::Stop,
                        cond: None,
                    },
                    by: By::Under(Principal::new("user")),
                },
                scope: Scope::Task(By::Anyone),
            },
        ]);
        assert_eq!(pred.temporals().len(), 3);
    }

    #[test]
    fn a_principal_a_selector_or_a_scope_chooses_by_is_read_in_no_direction() {
        let reviewer = Principal::new("reviewer");
        let user = Principal::new("user");
        let count = Pred::Count {
            select: Selector {
                filter: EventFilter {
                    kind: EventKind::ToolUse,
                    cond: None,
                },
                by: By::Under(reviewer.clone()),
            },
            scope: Scope::Task(By::Under(user.clone())),
            cmp: Cmp::Le,
            n: 3,
        };
        // Even in a guard's `when` under no `not`.
        assert_eq!(
            state_readings(&count, Site::GuardWhen),
            vec![
                (StateAtom::Actor(&reviewer), Reading::Unreadable),
                (StateAtom::Actor(&user), Reading::Unreadable),
            ]
        );
        let anyone = Pred::Once {
            select: any(EventKind::Stop, None),
            scope: Scope::Turn(By::Anyone),
        };
        assert!(state_readings(&anyone, Site::GuardWhen).is_empty());
    }

    #[test]
    fn a_state_atom_is_read_positively_only_in_a_guards_when_under_an_even_number_of_nots() {
        let reviewer = Principal::new("reviewer");
        let under = || Pred::ActorUnder(reviewer.clone());
        let not = |pred| Pred::Not(Box::new(pred));
        let reading = |pred: &Pred, site| {
            let found = state_readings(pred, site);
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].0, StateAtom::Actor(&reviewer));
            found[0].1
        };
        assert_eq!(reading(&under(), Site::GuardWhen), Reading::Positive);
        assert_eq!(
            reading(&not(not(under())), Site::GuardWhen),
            Reading::Positive
        );
        assert_eq!(
            reading(&Pred::Any(vec![under()]), Site::GuardWhen),
            Reading::Positive
        );
        assert_eq!(reading(&not(under()), Site::GuardWhen), Reading::Unreadable);
        assert_eq!(reading(&under(), Site::GuardRule), Reading::Unreadable);
        assert_eq!(reading(&under(), Site::Reward), Reading::Unreadable);
        // In both directions at once, it is not read.
        let both = Pred::All(vec![under(), not(under())]);
        assert_eq!(reading(&both, Site::GuardWhen), Reading::Unreadable);
    }

    #[test]
    fn the_atoms_that_read_the_state_are_found_through_the_temporal_operators_of_anyone() {
        let mode: Mode = "strict".parse().unwrap();
        let once = Pred::Once {
            select: any(EventKind::Stop, None),
            scope: Scope::Task(By::Anyone),
        };
        let pred = Pred::All(vec![once, Pred::ModeIs(mode.clone())]);
        assert_eq!(
            state_readings(&pred, Site::GuardWhen),
            vec![(StateAtom::Mode(&mode), Reading::Positive)]
        );
    }
}
