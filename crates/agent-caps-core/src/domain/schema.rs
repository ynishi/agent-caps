//! The vocabulary events are described in: their kinds and their [`Nature`], the fields a
//! predicate can read, and the small values an event carries (when, what a judgment came to,
//! which kinds a lost record may have been), and the [`Level`] a record of a judgment carries.
//!
//! A predicate reads an event through a [`Field`], never through the Rust field of a variant.
//! Each field belongs to one [`EventKind`] and has one [`FieldType`]; that table is the schema the
//! catalog checks a predicate against when it accepts it.

/// When an event happened, in milliseconds since the Unix epoch. The caller reads the clock;
/// the domain only compares the values it is given. The time of an act advances the state's
/// clock, which every end by time reads; the time of a claim does not (see
/// [`super::state`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct At(i64);

impl At {
    /// The instant `millis` milliseconds after the Unix epoch.
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// The milliseconds since the Unix epoch.
    pub const fn millis(self) -> i64 {
        self.0
    }
}

/// What a judgment of one policy came to, as it is recorded in the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Judgment {
    /// A guard let the event through.
    Allowed,
    /// A guard warned.
    Warned,
    /// A guard stopped the event.
    Denied,
    /// A guard did not judge the event because an exemption covered it.
    Exempted,
    /// A reward's recommendation was followed.
    Hit,
}

/// How much the one who acts is trusted with a rule, least first. The level says what a failure
/// costs the one who acts; it does not say when the check happens, which follows from the event the
/// policy judges. It is the strength a policy is written at, and the strength a platform enforces
/// it at: a record of a judgment carries both.
///
/// It lives here so that an event can carry it; it is read as [`super::policy::Level`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Only tells.
    Inform,
    /// A guard warns, a reward recommends; the one who acts may decide otherwise.
    Advise,
    /// A violation is stopped, and so is a finding that is unknown.
    Force,
}

impl Level {
    /// Whether a guard of this level stops the event it fails on: Force only.
    pub fn stops(self) -> bool {
        matches!(self, Self::Force)
    }
}

impl Judgment {
    /// The word a predicate compares with (`judgment == "denied"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Warned => "warned",
            Self::Denied => "denied",
            Self::Exempted => "exempted",
            Self::Hit => "hit",
        }
    }
}

/// Declares [`EventKind`] and [`EventKind::ALL`] from one list of the kinds, so the list of every
/// kind cannot fall behind the enum. A kind missing from `ALL` would let a lost record be taken
/// as not of that kind.
macro_rules! event_kinds {
    ($($(#[$doc:meta])* $kind:ident,)+) => {
        /// The kinds of event, without their values: what a policy judges, and what a temporal
        /// operator looks for. New kinds are added as the model grows, so a match on it outside
        /// this crate needs a wildcard arm.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum EventKind {
            $($(#[$doc])* $kind,)+
        }

        impl EventKind {
            /// Every kind, each once, made from the same list as the enum.
            pub const ALL: &'static [Self] = &[$(Self::$kind,)+];
        }
    };
}

event_kinds! {
    /// A session started.
    SessionStart,
    /// A (sub)agent was spawned: it joins the hierarchy of actors under one.
    Spawn,
    /// A task started.
    TaskStart,
    /// A prompt was submitted.
    PromptSubmit,
    /// A tool was used.
    ToolUse,
    /// A turn is about to end.
    Stop,
    /// The platform measured an amount used of a meter.
    Used,
    /// The mode was switched.
    ModeSwitch,
    /// An oracle measured a score.
    Measured,
    /// A temporary adjustment was made.
    Adjust,
    /// A temporary adjustment was cancelled.
    Cancel,
    /// A policy was judged.
    Judged,
    /// A record could not be read.
    Unreadable,
}

/// What an event is to the rules: something that happened, which they judge, or something said,
/// which may change how they take effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nature {
    /// An act observed on the platform. It is what rules judge, and it always takes effect: a
    /// test that passed makes `once(test)` true, which is the rule at work.
    Act,
    /// A claim: what someone states, which may change how a rule takes effect (an exemption, a
    /// mode switch, a record a rule reads). It takes effect as a transaction, judged by the
    /// difference it makes ([`super::tx`]).
    Claim,
}

impl EventKind {
    /// Whether an event of this kind is an act or a claim. This is the one place that says so.
    ///
    /// An act is taken as it is because of where it comes from: a platform adapter reads it from
    /// what the platform observed, which nobody can forge by writing text. A claim is only as
    /// good as the one who makes it, so it is judged by the difference it makes and by who
    /// covers what it loosens. That guarantee of where an act comes from is the adapter's; the
    /// domain relies on it and does not check it.
    pub fn nature(self) -> Nature {
        match self {
            Self::SessionStart
            | Self::TaskStart
            | Self::PromptSubmit
            | Self::ToolUse
            | Self::Stop
            | Self::Used
            | Self::Unreadable => Nature::Act,
            // A spawn is observed on the platform, but where it places its child is its
            // spawner's choice, and that can change how a rule takes effect: it is a claim.
            Self::Spawn
            | Self::ModeSwitch
            | Self::Measured
            | Self::Adjust
            | Self::Cancel
            | Self::Judged => Nature::Claim,
        }
    }
}

/// A set of kinds of event, each at most once: for a record that could not be read, the kinds
/// it may have been. Which those are is the adapter's to say, from where the record was.
///
/// There is no empty default: a set that leaves a kind out says the lost record cannot have been
/// of that kind, which loosens the rules that read it. An adapter that cannot tell what a record
/// may have been gives [`KindSet::any`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KindSet(Vec<EventKind>);

impl KindSet {
    /// Every kind: what a record may have been when nothing is known of it.
    pub fn any() -> Self {
        Self::new(EventKind::ALL.iter().copied())
    }

    /// The set of `kinds`; a kind given twice is held once.
    pub fn new(kinds: impl IntoIterator<Item = EventKind>) -> Self {
        let mut set = Vec::new();
        for kind in kinds {
            if !set.contains(&kind) {
                set.push(kind);
            }
        }
        Self(set)
    }

    /// Whether the kind is in the set.
    pub fn contains(&self, kind: EventKind) -> bool {
        self.0.contains(&kind)
    }

    /// The kinds, in the order they were first given.
    pub fn iter(&self) -> impl Iterator<Item = EventKind> + '_ {
        self.0.iter().copied()
    }
}

impl FromIterator<EventKind> for KindSet {
    fn from_iter<I: IntoIterator<Item = EventKind>>(kinds: I) -> Self {
        Self::new(kinds)
    }
}

/// A value a predicate can read from an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Field {
    /// The tool of a [`EventKind::ToolUse`] (text).
    Tool,
    /// The command of a [`EventKind::ToolUse`] (words).
    Command,
    /// The path of a [`EventKind::ToolUse`] (text).
    Path,
    /// Whether a [`EventKind::ToolUse`] succeeded (bool).
    Ok,
    /// The mode a [`EventKind::ModeSwitch`] switched to (text).
    ModeTo,
    /// The oracle of a [`EventKind::Measured`] (text).
    Oracle,
    /// The score of a [`EventKind::Measured`] (number).
    Score,
    /// The policy of a [`EventKind::Judged`], as its hyphenated id (text).
    Policy,
    /// What a [`EventKind::Judged`] came to, as [`Judgment::as_str`] (text).
    Judgment,
    /// The meter of a [`EventKind::Used`], as the text of its
    /// [`Meter`](super::name::Meter) (text). The amount is no field: only
    /// [`Pred::Spent`](super::predicate::Pred::Spent) reads it.
    Meter,
}

/// The type of a [`Field`]'s value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldType {
    /// Text, compared whole or by a shell pattern.
    Text,
    /// Command words, compared word by word.
    Words,
    /// True or false.
    Bool,
    /// A number.
    Num,
}

impl Field {
    /// The kind of event the field belongs to.
    pub fn kind(self) -> EventKind {
        match self {
            Self::Tool | Self::Command | Self::Path | Self::Ok => EventKind::ToolUse,
            Self::ModeTo => EventKind::ModeSwitch,
            Self::Oracle | Self::Score => EventKind::Measured,
            Self::Policy | Self::Judgment => EventKind::Judged,
            Self::Meter => EventKind::Used,
        }
    }

    /// The type of the field's value.
    pub fn ty(self) -> FieldType {
        match self {
            Self::Tool
            | Self::Path
            | Self::ModeTo
            | Self::Oracle
            | Self::Policy
            | Self::Judgment
            | Self::Meter => FieldType::Text,
            Self::Command => FieldType::Words,
            Self::Ok => FieldType::Bool,
            Self::Score => FieldType::Num,
        }
    }
}
