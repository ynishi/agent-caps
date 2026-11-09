//! The one part of a catalog: a policy, and the policy graph it is written in.
//!
//! A policy says, for one kind of event, what must hold (a guard) or what is recommended (a
//! reward), and how strongly ([`Level`]). Knowledge, procedures and roles are not parts of their
//! own: each is a set of policies seen another way.
//!
//! A level is how much the agent is trusted with a rule, not when the rule is checked:
//!
//! ```text
//! Level       Guard (must not)          Reward (should)
//! Force       stop (unknown stops too)  -  (a reward cannot have it)
//! Advise      warn                      recommend
//! Inform      tell                      tell
//! ```
//!
//! When a check happens follows from the event the policy judges (its `subject`): a tool use is
//! judged as it comes, the end of a turn when the turn ends. Which mechanism of a platform stops
//! it is the adapter's to choose; the policy holds no such value.
//!
//! # Invariants
//!
//! - A reward is bound by one guard: the guard is the line not to cross, the reward the way to
//!   go within it. A reward cannot be stronger than its guard, and cannot be Force
//!   ([`RewardLevel`] has no such value).
//! - A [`Policy`] is made only by [`super::catalog::Catalog::accept`], which checks the graph as a
//!   whole (see there). The [`PolicyDef`] it is made from is plain data with no rule of its own.

use super::event::Event;
use super::name::{Mode, PolicyId, PolicyName};
use super::predicate::{Pred, Truth};
use super::schema::EventKind;
use super::state::{SlotTable, State};

/// How much the agent is trusted with a rule, least first. The level says what a failure
/// costs the agent; it does not say when the check happens, which follows from the event the
/// policy judges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Only tells.
    Inform,
    /// A guard warns, a reward recommends; the agent may decide otherwise.
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

/// The levels a reward can have. A recommendation never stops anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RewardLevel {
    /// Only tells.
    Inform,
    /// Recommends.
    Advise,
}

impl From<RewardLevel> for Level {
    fn from(level: RewardLevel) -> Self {
        match level {
            RewardLevel::Inform => Self::Inform,
            RewardLevel::Advise => Self::Advise,
        }
    }
}

/// Whether a policy forbids or recommends.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Polarity {
    /// What must hold. Failing it gives a warning or a denial.
    Guard {
        /// How strongly.
        level: Level,
    },
    /// What is recommended. Following it is a hit; not following it is no failure.
    Reward {
        /// How strongly.
        level: RewardLevel,
        /// The guard it works within.
        bound_by: PolicyId,
    },
}

/// How a policy judges. New ways (a classifier's answer) are added as the model grows.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Rule {
    /// A predicate, judged the same way every time from the same events.
    Structural(Pred),
}

/// The layer a policy is defined in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefLayer {
    /// Fixed: no override reaches it and no exemption covers it.
    Meta,
    /// The user's own: the project and the mode may override it.
    Base,
}

/// What a fixture expects a policy to find on its last event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Expect {
    /// The guard fails, or the reward is not followed.
    Violated,
    /// The guard holds, or the reward is followed.
    Satisfied,
    /// The policy does not judge the event.
    NotApplicable,
    /// The policy cannot tell, because something it reads was not seen.
    Unknown,
}

/// One example of a policy at work: events, and what the policy should find on the last one.
/// Fixtures live in the policy, so a change of the policy and of its examples is one change.
#[derive(Debug, Clone, PartialEq)]
pub struct Fixture {
    /// What the example shows, for the people who read a failure.
    pub name: String,
    /// The events, folded in order; the last is the one judged.
    pub events: Vec<Event>,
    /// What the policy should find.
    pub expect: Expect,
    /// The policy is known to get this example wrong: a failure of it does not reject the
    /// catalog, and it is kept to show the gap.
    pub known_gap: bool,
}

/// A policy as written in a policy graph: plain data, checked when a catalog accepts it.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyDef {
    /// Its id.
    pub id: PolicyId,
    /// Its name.
    pub name: PolicyName,
    /// The layer it is defined in.
    pub layer: DefLayer,
    /// The kind of event it judges.
    pub subject: EventKind,
    /// When it applies; `None` applies to every event of its subject.
    pub when: Option<Pred>,
    /// What it says.
    pub rule: Rule,
    /// Whether it forbids or recommends, and how strongly.
    pub polarity: Polarity,
    /// Whether it is on before any override.
    pub enabled: bool,
    /// Its examples.
    pub fixtures: Vec<Fixture>,
}

/// The layer an override belongs to. A mode's overrides apply over the project's.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OverrideLayer {
    /// The project's.
    Project,
    /// A mode's, while that mode is in effect.
    Mode(Mode),
}

/// What an override changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Change {
    /// The level.
    Level(Level),
    /// Turns the policy off.
    Off,
    /// Turns the policy on.
    On,
}

/// A change a layer makes to one policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Override {
    /// The layer.
    pub layer: OverrideLayer,
    /// The policy.
    pub policy: PolicyId,
    /// The change.
    pub change: Change,
}

/// What a catalog is accepted from: the policies, and the overrides of the layers above them.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PolicyGraph {
    /// The policies.
    pub policies: Vec<PolicyDef>,
    /// The overrides.
    pub overrides: Vec<Override>,
}

/// What a policy found on one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Finding {
    /// The guard fails, or the reward is not followed.
    Violated,
    /// The guard holds, or the reward is followed.
    Satisfied,
    /// The policy does not judge the event: another kind, or its `when` does not hold.
    NotApplicable,
    /// The guard does not judge the event because the user exempted it.
    Exempted,
    /// Something the policy reads was not seen.
    Unknown,
}

/// A policy of an accepted catalog. Only [`super::catalog::Catalog::accept`] makes one.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy(PolicyDef);

impl Policy {
    pub(super) fn new(def: PolicyDef) -> Self {
        Self(def)
    }

    /// Its id.
    pub fn id(&self) -> PolicyId {
        self.0.id
    }

    /// Its name.
    pub fn name(&self) -> &PolicyName {
        &self.0.name
    }

    /// The layer it is defined in.
    pub fn layer(&self) -> DefLayer {
        self.0.layer
    }

    /// The kind of event it judges.
    pub fn subject(&self) -> EventKind {
        self.0.subject
    }

    /// Whether it forbids or recommends, and how strongly before any override.
    pub fn polarity(&self) -> &Polarity {
        &self.0.polarity
    }

    /// Whether it is on before any override.
    pub fn enabled(&self) -> bool {
        self.0.enabled
    }

    /// Its examples.
    pub fn fixtures(&self) -> &[Fixture] {
        &self.0.fixtures
    }

    /// Whether it is a guard.
    pub fn is_guard(&self) -> bool {
        matches!(self.0.polarity, Polarity::Guard { .. })
    }

    /// Its level before any override.
    pub fn base_level(&self) -> Level {
        match self.0.polarity {
            Polarity::Guard { level } => level,
            Polarity::Reward { level, .. } => level.into(),
        }
    }

    /// Every predicate it holds.
    pub(super) fn preds(&self) -> impl Iterator<Item = &Pred> {
        let Rule::Structural(rule) = &self.0.rule;
        self.0.when.iter().chain(std::iter::once(rule))
    }

    /// What the policy finds on `event`, with `state` already folded over it.
    pub(super) fn evaluate(&self, slots: &SlotTable, state: &State, event: &Event) -> Finding {
        if event.body.kind() != self.0.subject {
            return Finding::NotApplicable;
        }
        if let Some(when) = &self.0.when {
            match state.holds(slots, when, event) {
                Truth::False => return Finding::NotApplicable,
                Truth::Unknown => return Finding::Unknown,
                Truth::True => {}
            }
        }
        if self.is_guard() && self.0.layer != DefLayer::Meta && state.exempts(self.0.id, event) {
            return Finding::Exempted;
        }
        let Rule::Structural(rule) = &self.0.rule;
        match state.holds(slots, rule, event) {
            Truth::True => Finding::Satisfied,
            Truth::False => Finding::Violated,
            Truth::Unknown => Finding::Unknown,
        }
    }
}
