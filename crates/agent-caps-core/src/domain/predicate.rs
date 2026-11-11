//! The structural rule language: what a policy says about an event and the events before it.
//!
//! ```text
//! Pred := Now(Cond) | ModeIs(mode) | ActorUnder(principal)
//!       | Once(selector, scope) | Count(selector, scope) cmp n
//!       | Last(selector, scope) test Cond
//!       | Spent(meter, by, scope) order amount
//!       | All[Pred…] | Any[Pred…] | Not Pred
//! Cond := field == lit | field in {lit…} | glob(field, pattern) | words(field, words)
//!       | num(field) cmp number | All[Cond…] | Any[Cond…] | Not Cond
//! filter   := kind [where Cond]
//! by       := Anyone | Under(principal) | Only(principal)
//! selector := filter by by
//! scope    := Span(span, by) | Mode | Since(selector) | Every(window)
//! span     := Session | Task | Turn
//! order    := < | <= | >= | >
//! ```
//!
//! `Count` and `Spent` are siblings: both gather the events a selector chooses within a scope
//! and compare what they gathered with a bound, `Count` the number of events as a `u32`, `Spent`
//! the sum of the amounts of the [`EventKind::Used`] events of one meter as an [`Amount`]. The
//! type of the bound is the operator's, so neither a count in fractions nor a NaN bound can be
//! written. The number a condition compares a field with (`num(field) cmp number`) is a
//! [`Number`], finite and of either sign, so no condition holds a NaN either, and every
//! predicate equals itself.
//!
//! # Known limits of a sum
//!
//! - An amount is known after the use it measures, so a sum can pass its bound by one event:
//!   `Spent(tokens, …) < n` lets through the act whose use takes the sum to `n` or past it, and
//!   stops the next act.
//! - Only an amount that grows and starts again with its scope can be summed. A gauge, such as
//!   the number of calls running at once, which goes down as well as up, cannot be written.
//!
//! `ModeIs` and `ActorUnder` read the state rather than the events of a scope: the mode in
//! effect, and where the judged event's actor sits in the hierarchy of actors. A [`By::Under`]
//! reads the hierarchy too, of the actor of each event a selector looks at and of each event
//! that may start a task or a turn again. How a policy reads such an atom, in a direction a
//! transaction can use, is answered in one place, `state_readings`, for every atom that reads
//! the state.
//!
//! A filter of `Classified` events narrows to one classifier with `classifier == name`
//! (`classified_read`), the one place that says which classifier a rule reads; the catalog checks
//! the name against the declarations and takes effect on it.
//!
//! A [`Selector`] chooses events by what they are ([`EventFilter`]) and by who acted ([`By`]).
//! The filter alone is what is read where no actor can be: the capabilities of a platform and
//! the cover of an exemption take an [`EventFilter`], which cannot hold a `By`.
//!
//! # Invariants
//!
//! - Every predicate stops, in time linear in its size per event: there is no loop, recursion,
//!   user-defined function or regex. Shell patterns are matched without backtracking.
//! - The past is read only through the four temporal operators, each one level deep: the
//!   condition inside a [`Pred::Once`], [`Pred::Count`] or [`Pred::Last`] is a [`Cond`], which
//!   cannot hold one, and a [`Pred::Spent`] holds no condition but its meter.
//!   The type, not a check, keeps them from nesting. Each temporal operator becomes one slot of
//!   the state, updated from its last value and the new event alone.
//! - A predicate is evaluated in three values ([`Truth`]). A value the event has but did not
//!   show (a result not yet back, a record not read) is [`Truth::Unknown`], never false, so `not`
//!   cannot turn it into a pass. A value the event has no place for (the command of an edit) is
//!   absent, and a comparison with it is false.
//! - A field is read only from its own kind of event, with an operand of its type. The catalog
//!   checks this ([`Pred::check`]) before it accepts a policy.

use std::fmt;

use super::authority::Principal;
use super::name::{ClassifierName, CommandWords, GlobPattern, Meter, Mode, PolicyId};
use super::schema::{At, EventKind, Field, FieldType};

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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub enum Lit {
    /// Text, for a text field.
    Text(String),
    /// True or false, for a bool field.
    Bool(bool),
}

/// A comparison of numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub enum Cond {
    /// The field equals the literal.
    Eq(Field, Lit),
    /// The field equals one of the literals.
    In(Field, Vec<Lit>),
    /// The text field matches the shell pattern as a whole.
    Glob(Field, GlobPattern),
    /// The words field starts with the words: `cargo test -p a` starts with `cargo test`.
    Words(Field, CommandWords),
    /// The number field compares to the number, which is finite ([`Number`]).
    Num(Field, Cmp, Number),
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct EventFilter {
    /// The kind of event.
    pub kind: EventKind,
    /// The condition the event must meet; `None` takes every event of the kind.
    #[cfg_attr(feature = "serde", serde(deserialize_with = "Option::deserialize"))]
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
/// An upper bound on events chosen with `Only(p)` does not count what `p` delegates: the acts of
/// a sub agent `p` spawns are not `p`'s, so `p` escapes the bound by delegating, and no spawn
/// check sees it. A limit on what someone uses or does chooses with `Under`; `Only` is for who
/// may start a scope again or close it. A sum ([`Pred::Spent`]) cannot choose with `Only` at
/// all ([`Whose`]).
///
/// The principal of `Under` and `Only` must be one of the authority's, in a rule and in the
/// lifetime of a temporary adjustment alike.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
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

/// Whose use a sum ([`Pred::Spent`]) counts: a [`By`] without `Only`. A budget limits
/// consumption, and what is delegated is consumed for the one who delegates, so a sub agent's
/// use counts toward the principal it is spawned under, as a platform totals the spend of sub
/// agents and as hierarchical resource accounting does. With `Only(p)`, `p` could escape its
/// budget by handing the work to a sub agent, which no spawn check would catch, so `Only` is not
/// offered here. It becomes a `By` in one place, where the events a sum reads are chosen.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub enum Whose {
    /// The use of every actor.
    Anyone,
    /// The use of the principal and of every actor below it in the hierarchy of actors, the
    /// leaves spawns place there included, read as [`By::Under`] reads it.
    Under(Principal),
}

impl Whose {
    /// The principal it names, when it names one: that of `Under`, read as a [`By::Under`]
    /// is.
    pub(super) fn principal(&self) -> Option<&Principal> {
        match self {
            Self::Anyone => None,
            Self::Under(principal) => Some(principal),
        }
    }
}

/// The events a temporal operator looks at, or that close a [`Scope::Since`]: those that meet
/// the filter and whose actor `by` chooses. Whether an event is chosen is answered in one place,
/// for every reader.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct Selector {
    /// What the event is.
    pub filter: EventFilter,
    /// Who acted.
    pub by: By,
}

/// A period that an event of the platform opens: a session, a task or a turn. A [`Scope::Span`]
/// is one of them, with who may start it again.
///
/// The spans nest, and the nesting is a partial order: a session holds tasks and turns, and a
/// task and a turn are siblings, neither inside the other (a platform does not say how a task and
/// a turn contain each other). The start of a span starts again that span and the spans inside
/// it, and none outside ([`Scope`]). Which event opens a span ([`Span::opening`]) and which span
/// is inside which ([`Span::inside`]) are stated here and nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub enum Span {
    /// A session, opened by [`EventKind::SessionStart`].
    Session,
    /// A task, opened by [`EventKind::TaskStart`].
    Task,
    /// A turn, opened by [`EventKind::PromptSubmit`].
    Turn,
}

impl Span {
    /// Every span.
    pub(super) const ALL: [Self; 3] = [Self::Session, Self::Task, Self::Turn];

    /// The kind of event that opens the span: the one place that says which event opens which
    /// span.
    pub const fn opening(self) -> EventKind {
        match self {
            Self::Session => EventKind::SessionStart,
            Self::Task => EventKind::TaskStart,
            Self::Turn => EventKind::PromptSubmit,
        }
    }

    /// Whether the span is inside `outer`: the one place that says how the spans nest. A task and
    /// a turn are inside a session; a span is not inside itself, and a task and a turn are not
    /// inside each other.
    pub const fn inside(self, outer: Self) -> bool {
        matches!((self, outer), (Self::Task | Self::Turn, Self::Session))
    }
}

/// The period a temporal operator counts within, and that an exemption may last for. Each starts
/// again at its own boundary: a [`Scope::Span`] at the start of its span, or of a span it is
/// inside, [`Scope::Mode`] at a mode switch, [`Scope::Since`] at an event it looks for and
/// [`Scope::Every`] by time.
///
/// A scope bounded by events has two boundaries, both read from the event being folded: the
/// event before which it starts again, and the event on which it closes (the closing event
/// belongs to the interval it closes, and the interval starts again before the next event). The
/// state folds both in one place, so every such scope is handled by one rule. A scope bounded by
/// time, [`Scope::Every`], starts again when the state's clock crosses a boundary of its window,
/// in the carry to an event ([`super::state`]); the clock is advanced by acts alone, so a claim's
/// time never starts one again.
///
/// # Who may start a scope again
///
/// A scope starts again at an act, and an act takes effect whoever it comes from. So the one a
/// limit is about can start its count over by its own acts, unless the scope says who may. A
/// [`Scope::Span`] says whose start event starts it again, and `Since` whose events close it,
/// each with a [`By`] that cannot be left out, whichever span it is of: `By::Anyone` keeps every
/// actor's events, `By::Under(p)` only those of `p` and the actors below it, and `By::Only(p)`
/// only those of `p` itself. The one a limit is about sits below the one who set it, so a limit
/// that only its author may start again is written with `Only`. A claim, such as a mode switch
/// or a record that closes a `Since`, is judged as a transaction ([`super::tx`]).
///
/// # Spans
///
/// The start of a span starts again that span and the spans inside it ([`Span::inside`]), each
/// only when its own `By` chooses the actor of the start event, and never a scope outside it, a
/// `Since` or a `Mode`. So a session's start starts a task again when the task's `By` chooses
/// the one who started the session: `Span { Task, Only(user) }` starts again at a session the
/// user started, and does not at one the agent started, so the agent cannot start its own limit
/// over by starting a session. A task's start starts no turn again, and a turn's no task: they
/// are siblings. Whether a start starts a scope again is answered in one place, `Scope::starts_at`
/// of [`super::state`].
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
/// A record that could not be read leaves a scope unknown when it may have been an event that
/// starts the scope again or closes it: the start of a span (whatever its actor, since the actor
/// of a lost record is not known, `Only` included) for a [`Scope::Span`] of that span and of the
/// spans inside it, a mode switch for [`Scope::Mode`], and the event a `Since` looks for for that
/// `Since`. Its slots become unknown until the scope starts again, so the record that may have
/// been a task's start makes a count within the task unknown, and a stopping rule on it stops.
/// A lost line of a transcript may have been any of the starts, so one lost line leaves the
/// counts of every span unknown until their next start (a known cost of reading a lost record
/// this way: more stops).
///
/// # `Since`
///
/// `Since(selector)` is the period after the last event the selector chooses. That event belongs
/// to the interval it closes, so an event is judged with the interval before it, and the
/// interval starts again before the next event. The start of a span does not start it again,
/// whichever span: a limit on the pushes since the last review goes on across a session, a task
/// and a turn. A filter whose condition is
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
///
/// # `Every`
///
/// `Every(w)` is the window of the time `w` long that the clock is in, the windows aligned to the
/// Unix epoch in UTC (a window of a day is a UTC day). It starts again when the clock's window
/// changes: the clock's milliseconds divided by `w`'s, rounded down
/// ([`i64::div_euclid`], so a time before the epoch is no exception). The clock is the state's,
/// advanced only by acts, to the latest time an act has carried; a claim's time does not move
/// it, and an act dated earlier does not move it back ([`super::state`]). Before the first act
/// there is no time yet, and the window does not start again.
///
/// - `count(push, Every(1h)) <= 5` allows at most five pushes in each hour.
/// - A window is the clock's and not the session's: a [`EventKind::SessionStart`] does not start
///   it again. A window spans sessions only as far as the caller folds: to hold a limit of an
///   hour across sessions, the caller folds the session before too.
/// - A fixed window lets up to twice the limit through around a boundary (a known limit).
/// - It reads no actor and needs no [`By`]: nobody starts it again but the time of the acts.
/// - `Lifetime::Within(Every(w))` (see [`super::adjust::Lifetime`]) ends a temporary adjustment
///   at the next boundary of the window, as the carry to the first act past it finds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub enum Scope {
    /// From the last start of the span, or of a span it is inside, whose actor the `By` chooses.
    /// The `By` cannot be left out, whichever the span is.
    Span {
        /// The span.
        span: Span,
        /// Whose start event starts it again.
        by: By,
    },
    /// From the last mode switch that took effect, a switch to the mode already in effect
    /// included. It has no `By`: a mode switch is a claim, and who may make one is decided by its
    /// transaction ([`super::tx`]), not by the scope. A session's start does not start it again.
    Mode,
    /// After the last event the selector chooses. A span's start does not start it again.
    Since(Selector),
    /// The window of the clock the state is in, started again when the clock crosses a boundary.
    /// No event starts it again, a span's start included.
    Every(Window),
}

impl Scope {
    /// Who may start the scope again or close it, when the scope says: that of a `Span` and of a
    /// `Since`. A `Mode` has none (see [`Scope::Mode`]) and an `Every` is started by time alone.
    pub(super) fn by(&self) -> Option<&By> {
        match self {
            Self::Span { by, .. } => Some(by),
            Self::Since(selector) => Some(&selector.by),
            Self::Mode | Self::Every(_) => None,
        }
    }
}

/// The length of a time window ([`Scope::Every`]), in milliseconds, more than zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "i64", into = "i64"))]
pub struct Window(i64);

/// The stored form of a window is its milliseconds, read back through [`Window::from_millis`].
#[cfg(feature = "serde")]
impl TryFrom<i64> for Window {
    type Error = WindowError;

    fn try_from(millis: i64) -> Result<Self, Self::Error> {
        Self::from_millis(millis)
    }
}

#[cfg(feature = "serde")]
impl From<Window> for i64 {
    fn from(window: Window) -> Self {
        window.millis()
    }
}

impl Window {
    /// The window `millis` milliseconds long; zero and negative lengths are refused.
    pub const fn from_millis(millis: i64) -> Result<Self, WindowError> {
        if millis > 0 {
            Ok(Self(millis))
        } else {
            Err(WindowError::NotPositive(millis))
        }
    }

    /// The length in milliseconds.
    pub const fn millis(self) -> i64 {
        self.0
    }

    /// The number of the window `at` is in, counted from the one that starts at the Unix epoch.
    pub(super) const fn index(self, at: At) -> i64 {
        at.millis().div_euclid(self.0)
    }
}

/// Why a length is not a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowError {
    /// The length, in milliseconds, is zero or negative.
    NotPositive(i64),
}

impl fmt::Display for WindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPositive(millis) => write!(f, "a window of {millis} ms is not positive"),
        }
    }
}

impl std::error::Error for WindowError {}

/// An amount used of a meter ([`Body::Used`](super::event::Body::Used)), or the bound of a
/// [`Pred::Spent`]: a finite number, zero or more. The constructor refuses NaN, the infinities
/// and negative numbers, so a sum of amounts is always ordered and only grows.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "f64", into = "f64"))]
pub struct Amount(f64);

/// The stored form of an amount is its number, read back through [`Amount::new`].
#[cfg(feature = "serde")]
impl TryFrom<f64> for Amount {
    type Error = AmountError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(feature = "serde")]
impl From<Amount> for f64 {
    fn from(amount: Amount) -> Self {
        amount.get()
    }
}

/// `value` when it is finite, a negative zero made zero; `None` for NaN and the infinities. The
/// one check an [`Amount`] and a [`Number`] are made through.
fn finite(value: f64) -> Option<f64> {
    // `-0.0 + 0.0` is `0.0`: one zero.
    value.is_finite().then_some(value + 0.0)
}

impl Amount {
    /// No amount: where a sum starts.
    pub const ZERO: Self = Self(0.0);

    /// The amount `value`; NaN, the infinities and negative numbers are refused. A negative zero
    /// is zero.
    pub fn new(value: f64) -> Result<Self, AmountError> {
        match finite(value) {
            None => Err(AmountError::NotFinite(value)),
            Some(value) if value < 0.0 => Err(AmountError::Negative(value)),
            Some(value) => Ok(Self(value)),
        }
    }

    /// The number.
    pub const fn get(self) -> f64 {
        self.0
    }

    /// The sum of the two, held at the largest finite number when it would pass it, so a sum
    /// stays an amount. The one way amounts are added.
    pub(super) fn saturating_add(self, other: Self) -> Self {
        let sum = self.0 + other.0;
        Self(if sum.is_finite() { sum } else { f64::MAX })
    }
}

/// Why a number is not an amount.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AmountError {
    /// NaN or an infinity.
    NotFinite(f64),
    /// Less than zero.
    Negative(f64),
}

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFinite(value) => write!(f, "{value} is not a finite amount"),
            Self::Negative(value) => write!(f, "{value} is a negative amount"),
        }
    }
}

impl std::error::Error for AmountError {}

// A finite `f64`, which an amount always is, is equal to itself, so `==` is an equivalence.
impl Eq for Amount {}

/// The number a condition compares a number field with ([`Cond::Num`]): a finite number, of
/// either sign. The constructor refuses NaN and the infinities, so a condition always equals
/// itself and a comparison with it is known whenever the field's value is a number.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "f64", into = "f64"))]
pub struct Number(f64);

/// The stored form of a number is the number, read back through [`Number::new`].
#[cfg(feature = "serde")]
impl TryFrom<f64> for Number {
    type Error = NumberError;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(feature = "serde")]
impl From<Number> for f64 {
    fn from(number: Number) -> Self {
        number.get()
    }
}

// A finite `f64`, which a number always is, is equal to itself, so `==` is an equivalence.
impl Eq for Number {}

impl Number {
    /// The number `value`; NaN and the infinities are refused. A negative zero is zero.
    pub fn new(value: f64) -> Result<Self, NumberError> {
        finite(value).map(Self).ok_or(NumberError::NotFinite(value))
    }

    /// The number.
    pub const fn get(self) -> f64 {
        self.0
    }
}

/// Why a value is not a number a condition can compare with.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NumberError {
    /// NaN or an infinity.
    NotFinite(f64),
}

impl fmt::Display for NumberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFinite(value) => write!(f, "{value} is not a finite number"),
        }
    }
}

impl std::error::Error for NumberError {}

/// How a sum of amounts compares with its bound. There is no equality: a sum of amounts measured
/// in fractions rarely meets a bound exactly, so a rule says on which side of it the sum is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub enum Order {
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>=`
    Ge,
    /// `>`
    Gt,
}

impl Order {
    /// Whether `left` compares to `right` this way. Amounts are always ordered, so it is always
    /// known.
    pub(super) fn holds(self, left: Amount, right: Amount) -> bool {
        let (left, right) = (left.0, right.0);
        match self {
            Self::Lt => left < right,
            Self::Le => left <= right,
            Self::Ge => left >= right,
            Self::Gt => left > right,
        }
    }
}

/// A predicate on the judged event and the events before it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
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
    /// (`Last { Measured where oracle == "bench", Span(Session, Anyone), score >= 0.8 }`) and an event whose
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
    /// The sum of the amounts of the [`EventKind::Used`] events of the meter whose actor `by`
    /// chooses, within the scope, the judged event included, compares to `n`. Zero when there was
    /// none. The events summed are those of one selector: a `Used` whose meter is this one
    /// ([`Field::Meter`]), chosen by who acted as any selector chooses, so `Whose::Under(agent)`
    /// sums the use of the agent and of the sub agents spawned below it. A sum always chooses by
    /// place ([`Whose`]), so what is delegated counts toward the one who delegates. A `Used`
    /// whose amount could not be read makes the sum unknown until the scope starts again.
    ///
    /// `Spent { meter: tokens, by: Whose::Under(agent), scope: Span(Task, Only(user)), order: Lt, n }`
    /// is "the agent and its sub agents have used fewer than `n` tokens since the user last
    /// started a task". The sum is of what was measured, after the use, so it can pass `n` by one event (see
    /// the module doc).
    Spent {
        /// What is summed.
        meter: Meter,
        /// Whose use is summed.
        by: Whose,
        /// Since when.
        scope: Scope,
        /// How the sum compares.
        order: Order,
        /// What it is compared with.
        n: Amount,
    },
    /// All of them hold (true when there are none).
    All(Vec<Pred>),
    /// One of them holds (false when there are none).
    Any(Vec<Pred>),
    /// It does not hold.
    Not(Box<Pred>),
}

/// What a temporal operator remembers between events: one slot of the state. Two operators with
/// the same temporal part share a slot; the variant is part of it, so a `count` and a `spent`
/// never share one.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum Temporal {
    Once(Selector, Scope),
    Count(Selector, Scope),
    Last(Selector, Scope),
    /// The selector is the one [`Pred::spent_selector`] makes of the meter and the [`Whose`],
    /// so the key is the meter, the `Whose` and the scope.
    Spent(Selector, Scope),
}

impl Temporal {
    pub(super) fn scope(&self) -> &Scope {
        match self {
            Self::Once(_, scope)
            | Self::Count(_, scope)
            | Self::Last(_, scope)
            | Self::Spent(_, scope) => scope,
        }
    }

    /// The events the operator looks at.
    pub(super) fn selector(&self) -> &Selector {
        match self {
            Self::Once(selector, _)
            | Self::Count(selector, _)
            | Self::Last(selector, _)
            | Self::Spent(selector, _) => selector,
        }
    }
}

impl Pred {
    /// The events a [`Pred::Spent`] of `meter` by `by` sums: the [`EventKind::Used`] events whose
    /// meter ([`Field::Meter`], the meter's own text) is `meter`, whose actor `by` chooses. The
    /// one place that says which events a sum reads, and the one place a [`Whose`] becomes a
    /// [`By`], so whether an event is summed is answered by `Selector::selects`, as for every
    /// other operator, and whether the meter is the same by one comparison of its text.
    pub(super) fn spent_selector(meter: &Meter, by: &Whose) -> Selector {
        Selector {
            filter: EventFilter {
                kind: EventKind::Used,
                cond: Some(Cond::Eq(Field::Meter, Lit::Text(meter.as_str().to_owned()))),
            },
            by: match by {
                Whose::Anyone => By::Anyone,
                Whose::Under(principal) => By::Under(principal.clone()),
            },
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
            // The events it sums are typed by construction (`spent_selector`); its scope is read
            // as any other.
            Self::Spent { scope, .. } => scope.check_into(errors),
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
            Self::Once {
                select: Selector { by, .. },
                scope,
            }
            | Self::Count {
                select: Selector { by, .. },
                scope,
                ..
            }
            | Self::Last {
                select: Selector { by, .. },
                scope,
                ..
            } => {
                temporal_bys(by, scope)
                    .filter_map(By::principal)
                    .for_each(note);
            }
            Self::Spent { by, scope, .. } => {
                by.principal()
                    .into_iter()
                    .chain(scope.by().and_then(By::principal))
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
            Self::Spent {
                meter, by, scope, ..
            } => Some(Temporal::Spent(
                Self::spent_selector(meter, by),
                scope.clone(),
            )),
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
            // It sums `Used` events, never judgments: only its scope may read them.
            Self::Spent { scope, .. } => vec![since(scope)],
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

impl Pred {
    /// The classifiers the predicate reads, each read in the order it first appears: one for the
    /// filter of each temporal operator and of each `Since` scope that looks for `Classified`
    /// events ([`classified_read`]). The operators are those of [`Pred::temporals`], so a `last`,
    /// a `once`, a `count` and the scope of a sum are read alike.
    pub(super) fn classified_reads(&self) -> Vec<ClassifiedRead> {
        let mut out = Vec::new();
        for temporal in self.temporals() {
            let since = match temporal.scope() {
                Scope::Since(selector) => Some(&selector.filter),
                _ => None,
            };
            for read in std::iter::once(&temporal.selector().filter)
                .chain(since)
                .filter_map(classified_read)
            {
                if !out.contains(&read) {
                    out.push(read);
                }
            }
        }
        out
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
        By::Under(principal) => Some(under_reading(principal)),
    }
}

/// How an `Under(principal)` is read, of a [`By`] and of a sum's [`Whose`] alike: always
/// `Unreadable` (see [`by_reading`]).
fn under_reading(principal: &Principal) -> (&Principal, Reading) {
    (principal, Reading::Unreadable)
}

/// The `By`s of a temporal operator that chooses with a selector: that of its selector, and that
/// of its scope when the scope has one.
fn temporal_bys<'a>(by: &'a By, scope: &'a Scope) -> impl Iterator<Item = &'a By> {
    std::iter::once(by).chain(scope.by())
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
        Pred::Once {
            select: Selector { by, .. },
            scope,
        }
        | Pred::Count {
            select: Selector { by, .. },
            scope,
            ..
        }
        | Pred::Last {
            select: Selector { by, .. },
            scope,
            ..
        } => {
            for (principal, reading) in temporal_bys(by, scope).filter_map(by_reading) {
                note_reading(out, StateAtom::Actor(principal), reading);
            }
            return;
        }
        Pred::Spent { by, scope, .. } => {
            let readings = by
                .principal()
                .map(under_reading)
                .into_iter()
                .chain(scope.by().and_then(by_reading));
            for (principal, reading) in readings {
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

/// What one filter of `Classified` events reads: the one classifier it narrows to, or none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ClassifiedRead {
    /// The filter narrows to this classifier with `classifier == name`.
    Named(ClassifierName),
    /// The filter does not narrow to one classifier, or narrows to a text that is no classifier
    /// name (no answer carries it): a read the catalog does not accept.
    Unnamed,
}

/// What a filter reads, when it looks for `Classified` events: the one place that decides which
/// classifier a rule reads, so what the catalog checks against the declarations and what it takes
/// effect on are the same set. A filter narrows to a classifier with `classifier == name`, alone
/// or in an `all` that names one classifier and no other; a condition on the answer beside it
/// narrows nothing further. Any other shape (no condition, an `any`, a `not`, an `in`, a glob)
/// reads no classifier by name.
pub(super) fn classified_read(filter: &EventFilter) -> Option<ClassifiedRead> {
    (filter.kind == EventKind::Classified)
        .then(|| read_of(filter.cond.as_ref().and_then(narrowed_classifier)))
}

/// What a policy that judges `Classified` events reads: the classifier its `when` narrows to by
/// the same rule as a filter ([`classified_read`]), where `when` is a `Now` of a condition, or an
/// `all` of predicates that narrow to one name. The judged event is the answer, so the policy
/// reads the classifier it applies to; with no `when`, or one that narrows to none, it reads no
/// classifier by name. The rule of a policy of any other subject reads through its filters alone.
pub(super) fn classified_subject_read(when: Option<&Pred>) -> ClassifiedRead {
    read_of(when.and_then(narrowed_classifier_of))
}

/// The read of a text a condition narrowed to: the classifier it names, or none when it narrowed
/// to nothing or to a text that is no classifier name (no answer carries it).
fn read_of(narrowed: Option<&str>) -> ClassifiedRead {
    narrowed
        .and_then(|text| text.parse().ok())
        .map_or(ClassifiedRead::Unnamed, ClassifiedRead::Named)
}

/// The one name among `names`, when they are all the same name (the same name given twice is one
/// name; two names narrow to no event, and so to none that can be read) and there is one.
fn the_one<'a>(mut names: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let first = names.next()?;
    names.all(|name| name == first).then_some(first)
}

/// The one classifier a condition on a `Classified` event narrows to: `classifier == name`, or an
/// `all` with exactly one such name among its conditions. `None` when it does not.
fn narrowed_classifier(cond: &Cond) -> Option<&str> {
    match cond {
        Cond::Eq(Field::Classifier, Lit::Text(text)) => Some(text),
        Cond::All(conds) => the_one(conds.iter().filter_map(narrowed_classifier)),
        _ => None,
    }
}

/// [`narrowed_classifier`] for a predicate of the judged event: a `Now`, or an `all` of
/// predicates.
fn narrowed_classifier_of(pred: &Pred) -> Option<&str> {
    match pred {
        Pred::Now(cond) => narrowed_classifier(cond),
        Pred::All(preds) => the_one(preds.iter().filter_map(narrowed_classifier_of)),
        _ => None,
    }
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
            Cond::Num(Field::Score, Cmp::Ge, Number::new(0.5).unwrap())
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
    fn spans_nest_as_a_partial_order_and_each_has_its_own_opening_event() {
        use Span::{Session, Task, Turn};
        assert_eq!(Session.opening(), EventKind::SessionStart);
        assert_eq!(Task.opening(), EventKind::TaskStart);
        assert_eq!(Turn.opening(), EventKind::PromptSubmit);
        // A session holds tasks and turns; a span is not inside itself, nor is a session inside
        // either; a task and a turn are siblings.
        assert!(Task.inside(Session) && Turn.inside(Session));
        for span in Span::ALL {
            assert!(!span.inside(span), "{span:?}");
        }
        assert!(!Session.inside(Task) && !Session.inside(Turn));
        assert!(!Task.inside(Turn) && !Turn.inside(Task));
        // Each span is opened by a kind of its own.
        for (at, span) in Span::ALL.iter().enumerate() {
            for other in &Span::ALL[at + 1..] {
                assert_ne!(span.opening(), other.opening());
            }
        }
    }

    #[test]
    fn a_temporal_condition_is_read_from_its_own_kind() {
        let ran_tests = Pred::Once {
            select: any(
                EventKind::ToolUse,
                Some(Cond::Eq(Field::Ok, Lit::Bool(true))),
            ),
            scope: Scope::Span {
                span: Span::Task,
                by: By::Anyone,
            },
        };
        // The subject is a stop; the condition inside `once` reads the tool use it looks for.
        assert!(ran_tests.check(EventKind::Stop).is_empty());
        let wrong = Pred::Once {
            select: any(EventKind::Stop, Some(Cond::Eq(Field::Ok, Lit::Bool(true)))),
            scope: Scope::Span {
                span: Span::Task,
                by: By::Anyone,
            },
        };
        assert_eq!(wrong.check(EventKind::Stop).len(), 1);
    }

    #[test]
    fn the_same_temporal_part_is_one_slot() {
        let once = Pred::Once {
            select: any(EventKind::Stop, None),
            scope: Scope::Span {
                span: Span::Task,
                by: By::Anyone,
            },
        };
        let pred = Pred::All(vec![
            once.clone(),
            Pred::Not(Box::new(once)),
            Pred::Count {
                select: any(EventKind::Stop, None),
                scope: Scope::Span {
                    span: Span::Task,
                    by: By::Anyone,
                },
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
                scope: Scope::Span {
                    span: Span::Task,
                    by: By::Anyone,
                },
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
            scope: Scope::Span {
                span: Span::Task,
                by: By::Under(user.clone()),
            },
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
            scope: Scope::Span {
                span: Span::Turn,
                by: By::Anyone,
            },
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

    fn spent(by: Whose, scope: Scope) -> Pred {
        Pred::Spent {
            meter: "tokens".parse().unwrap(),
            by,
            scope,
            order: Order::Lt,
            n: Amount::new(100.0).unwrap(),
        }
    }

    #[test]
    fn an_amount_is_finite_and_not_negative_and_its_sum_stays_so() {
        assert_eq!(
            Amount::new(f64::NAN)
                .map(Amount::get)
                .map_err(|e| e.to_string()),
            Err("NaN is not a finite amount".to_owned())
        );
        assert!(matches!(
            Amount::new(f64::INFINITY),
            Err(AmountError::NotFinite(_))
        ));
        assert_eq!(Amount::new(-1.0), Err(AmountError::Negative(-1.0)));
        assert!(Amount::new(-0.0).unwrap().get().is_sign_positive());
        let max = Amount::new(f64::MAX).unwrap();
        assert_eq!(max.saturating_add(max), max);
        let (one, two) = (Amount::new(1.0).unwrap(), Amount::new(2.0).unwrap());
        assert_eq!(one.saturating_add(one), two);
        assert!(Order::Lt.holds(one, two) && Order::Le.holds(two, two));
        assert!(!Order::Gt.holds(two, two) && Order::Ge.holds(two, one));
    }

    #[test]
    fn a_number_is_finite_of_either_sign_with_one_zero() {
        assert_eq!(
            Number::new(f64::NAN).map_err(|e| e.to_string()),
            Err("NaN is not a finite number".to_owned())
        );
        for bad in [f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(Number::new(bad), Err(NumberError::NotFinite(bad)));
        }
        assert_eq!(Number::new(-1.5).map(Number::get), Ok(-1.5));
        assert!(Number::new(-0.0).unwrap().get().is_sign_positive());
    }

    #[test]
    fn a_sum_and_a_count_of_the_same_events_are_two_slots() {
        let pred = Pred::All(vec![
            spent(
                Whose::Anyone,
                Scope::Span {
                    span: Span::Session,
                    by: By::Anyone,
                },
            ),
            spent(
                Whose::Anyone,
                Scope::Span {
                    span: Span::Session,
                    by: By::Anyone,
                },
            ),
            Pred::Count {
                select: Pred::spent_selector(&"tokens".parse().unwrap(), &Whose::Anyone),
                scope: Scope::Span {
                    span: Span::Session,
                    by: By::Anyone,
                },
                cmp: Cmp::Le,
                n: 3,
            },
            // Another meter is another slot.
            Pred::Spent {
                meter: "cost".parse().unwrap(),
                by: Whose::Anyone,
                scope: Scope::Span {
                    span: Span::Session,
                    by: By::Anyone,
                },
                order: Order::Lt,
                n: Amount::ZERO,
            },
        ]);
        assert_eq!(pred.temporals().len(), 3);
    }

    #[test]
    fn a_principal_a_sum_chooses_by_is_named_and_read_in_no_direction() {
        let agent = Principal::new("agent");
        let user = Principal::new("user");
        let pred = spent(
            Whose::Under(agent.clone()),
            Scope::Span {
                span: Span::Task,
                by: By::Only(user.clone()),
            },
        );
        // A sum by place reads its principal as a selector's `By::Under` does.
        assert_eq!(
            Pred::spent_selector(&"tokens".parse().unwrap(), &Whose::Under(agent.clone())).by,
            By::Under(agent.clone())
        );
        let mut named = Vec::new();
        pred.named_actors_into(&mut named);
        assert_eq!(named, vec![&agent, &user]);
        // `Only` reads nothing a spawn can move.
        assert_eq!(
            state_readings(&pred, Site::GuardWhen),
            vec![(StateAtom::Actor(&agent), Reading::Unreadable)]
        );
        assert!(pred.check(EventKind::ToolUse).is_empty());
    }

    #[test]
    fn the_atoms_that_read_the_state_are_found_through_the_temporal_operators_of_anyone() {
        let mode: Mode = "strict".parse().unwrap();
        let once = Pred::Once {
            select: any(EventKind::Stop, None),
            scope: Scope::Span {
                span: Span::Task,
                by: By::Anyone,
            },
        };
        let pred = Pred::All(vec![once, Pred::ModeIs(mode.clone())]);
        assert_eq!(
            state_readings(&pred, Site::GuardWhen),
            vec![(StateAtom::Mode(&mode), Reading::Positive)]
        );
    }
}
