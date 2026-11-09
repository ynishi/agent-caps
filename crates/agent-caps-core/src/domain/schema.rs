//! The vocabulary events are described in: their kinds, the fields a predicate can read, and the
//! small values an event carries (when, from whom, which scope).
//!
//! A predicate reads an event through a [`Field`], never through the Rust field of a variant.
//! Each field belongs to one [`EventKind`] and has one [`FieldType`]; that table is the schema the
//! catalog checks a predicate against when it accepts it.

/// When an event happened, in milliseconds since the Unix epoch. The caller reads the clock;
/// the domain only compares the values it is given.
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

/// Who an event comes from. What loosens a rule (a mode switch, an exemption) takes effect only
/// from the user, or from caps recording what the user did; an agent cannot loosen its own
/// rules by saying so in its transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// The person who runs the agent: their prompt or command.
    User,
    /// caps itself: the evidence it appends after a judgment or a user's command.
    Caps,
    /// The agent: its own output and tool calls.
    Agent,
}

/// Where an unreadable record was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// The platform's transcript: a line cut by compaction, or one the adapter could not parse.
    Transcript,
    /// caps's own evidence. A record lost there may have been a mode switch or an exemption, so
    /// the state stops trusting those.
    Evidence,
}

/// The span a temporal operator counts within, and that an exemption may last for. Each starts
/// again at its own start event; a new session starts all of them again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// From [`EventKind::SessionStart`].
    Session,
    /// From [`EventKind::AgentStart`].
    Agent,
    /// From the last mode switch that took effect.
    Mode,
    /// From [`EventKind::TaskStart`].
    Task,
}

/// What a judgment of one policy came to, as caps records it in its evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Judgment {
    /// A guard let the event through.
    Allowed,
    /// A guard warned.
    Warned,
    /// A guard stopped the event.
    Denied,
    /// A guard did not judge the event because the user exempted it.
    Exempted,
    /// A reward's recommendation was followed.
    Hit,
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

/// The kinds of event, without their values: what a policy judges, and what a temporal operator
/// looks for. New kinds are added as the model grows, so a match on it outside this crate needs
/// a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EventKind {
    /// A session started.
    SessionStart,
    /// A (sub)agent started.
    AgentStart,
    /// A task started.
    TaskStart,
    /// The user sent a prompt.
    PromptSubmit,
    /// The agent used a tool.
    ToolUse,
    /// The agent is about to end its turn.
    Stop,
    /// The mode changed.
    ModeSwitch,
    /// An oracle measured a score.
    Measured,
    /// The user exempted a guard for a while.
    Exempt,
    /// caps judged a policy.
    Judged,
    /// A record could not be read.
    Unreadable,
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
    /// The agent type of an [`EventKind::AgentStart`] (text).
    AgentType,
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
            Self::AgentType => EventKind::AgentStart,
            Self::ModeTo => EventKind::ModeSwitch,
            Self::Oracle | Self::Score => EventKind::Measured,
            Self::Policy | Self::Judgment => EventKind::Judged,
        }
    }

    /// The type of the field's value.
    pub fn ty(self) -> FieldType {
        match self {
            Self::Tool
            | Self::Path
            | Self::AgentType
            | Self::ModeTo
            | Self::Oracle
            | Self::Policy
            | Self::Judgment => FieldType::Text,
            Self::Command => FieldType::Words,
            Self::Ok => FieldType::Bool,
            Self::Score => FieldType::Num,
        }
    }
}
