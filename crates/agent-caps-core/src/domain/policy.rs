//! The one part of a catalog: a policy, and the policy graph it is written in.
//!
//! A policy says, for one kind of event, what must hold (a guard) or what is recommended (a
//! reward), and how strongly ([`Level`]). Knowledge, procedures and roles are not parts of their
//! own: each is a set of policies seen another way.
//!
//! A level is how much the one who acts is trusted with a rule, not when the rule is checked:
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
//! - A policy and an override each have an author, a [`Principal`]. What may refer to what, and
//!   who may change whose, follows the [`Authority`] the catalog keeps (see
//!   [`super::catalog`] and [`super::change`]).
//! - A [`Policy`] is made only by [`super::catalog::Catalog::accept`], which checks the graph as a
//!   whole (see there). The [`PolicyDef`] it is made from is plain data with no rule of its own.
//! - A [`Policy`] keeps its [`PolicyDef`] as written, and the predicates the catalog uses. The
//!   two differ only in a filter of judgments that narrows to no policy: the catalog's predicate
//!   counts the judgments of the policies its author may count (see [`super::catalog`]). The
//!   written def is what a graph and a difference between graphs are read from; the compiled
//!   predicates are what is evaluated and what the slots are made of.

use super::authority::{Authority, Principal};
use super::event::Event;
use super::name::{Mode, PolicyId, PolicyName};
use super::predicate::{Cond, EventFilter, Lit, Pred, Scope, Truth, reads_unnarrowed};
use super::schema::{EventKind, Field};
use super::state::{SlotTable, State};

/// How much the one who acts is trusted with a rule, least first. The level says what a failure
/// costs the one who acts; it does not say when the check happens, which follows from the event the
/// policy judges.
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
    /// Its author's own: the project and the mode may override it.
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
    /// Who wrote it. The graph is trusted as written; the catalog checks that the author is a
    /// principal of its [`Authority`], that a meta policy's author is a root, and that the
    /// policy refers only to policies of its own author or of one above.
    pub author: Principal,
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
    /// Who wrote it. It may target only a policy whose author is its own or above it.
    pub author: Principal,
}

/// What a catalog is accepted from: the policies, and the overrides of the layers above them.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PolicyGraph {
    /// The policies.
    pub policies: Vec<PolicyDef>,
    /// The overrides.
    pub overrides: Vec<Override>,
}

impl PolicyGraph {
    /// The graph narrowed to what `by` does not cover: the policies and overrides whose author
    /// is neither `by` nor below it. It is what the graph would be had `by` and those below it
    /// written nothing, so a catalog's rules without their work can be compared with its rules
    /// with it.
    ///
    /// A graph a catalog accepts narrows to one it would accept again: an item refers only to
    /// items of its own author or above, so when the target of a reference is dropped, being
    /// covered by `by`, its referrer is covered by `by` too and is dropped with it.
    pub fn not_covered_by(&self, authority: &Authority, by: &Principal) -> Self {
        Self {
            policies: self
                .policies
                .iter()
                .filter(|def| !authority.covers(by, &def.author))
                .cloned()
                .collect(),
            overrides: self
                .overrides
                .iter()
                .filter(|o| !authority.covers(by, &o.author))
                .cloned()
                .collect(),
        }
    }
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
    /// The guard does not judge the event because an exemption in effect covers it.
    Exempted,
    /// Something the policy reads was not seen.
    Unknown,
}

/// A policy of an accepted catalog. Only [`super::catalog::Catalog::accept`] makes one.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    /// As written.
    def: PolicyDef,
    /// What the catalog evaluates and makes its slots of.
    compiled: Compiled,
}

/// The predicates of a policy as the catalog uses them: its `when` and its `rule`.
#[derive(Debug, Clone, PartialEq)]
struct Compiled {
    when: Option<Pred>,
    rule: Rule,
}

impl Policy {
    /// The policy with its predicates as written. Made only where the catalog has decided that
    /// nothing is narrowed: a meta policy, which reads no judgment unnarrowed, and a policy
    /// whose author is not of the hierarchy, which is not accepted; and by a change, which reads
    /// the levels only.
    pub(super) fn new(def: PolicyDef) -> Self {
        let compiled = Compiled {
            when: def.when.clone(),
            rule: def.rule.clone(),
        };
        Self { def, compiled }
    }

    /// The policy whose filters of judgments that narrow to no policy count only the judgments of
    /// `visible`, the policies its author may count. A filter that narrows to policies is kept as
    /// written, and so is everything else. With no such filter the compiled predicates are the
    /// written ones.
    pub(super) fn scoped(def: PolicyDef, visible: &[PolicyId]) -> Self {
        let visible = Cond::In(
            Field::Policy,
            visible.iter().map(|id| Lit::Text(id.to_string())).collect(),
        );
        let Rule::Structural(rule) = &def.rule;
        let compiled = Compiled {
            when: def.when.as_ref().map(|when| scope_pred(when, &visible)),
            rule: Rule::Structural(scope_pred(rule, &visible)),
        };
        Self { def, compiled }
    }

    /// As written.
    pub(super) fn def(&self) -> &PolicyDef {
        &self.def
    }

    /// Its id.
    pub fn id(&self) -> PolicyId {
        self.def.id
    }

    /// Who wrote it.
    pub fn author(&self) -> &Principal {
        &self.def.author
    }

    /// Its name.
    pub fn name(&self) -> &PolicyName {
        &self.def.name
    }

    /// The layer it is defined in.
    pub fn layer(&self) -> DefLayer {
        self.def.layer
    }

    /// The kind of event it judges.
    pub fn subject(&self) -> EventKind {
        self.def.subject
    }

    /// Whether it forbids or recommends, and how strongly before any override.
    pub fn polarity(&self) -> &Polarity {
        &self.def.polarity
    }

    /// Whether it is on before any override.
    pub fn enabled(&self) -> bool {
        self.def.enabled
    }

    /// Its examples.
    pub fn fixtures(&self) -> &[Fixture] {
        &self.def.fixtures
    }

    /// Whether it is a guard.
    pub fn is_guard(&self) -> bool {
        matches!(self.def.polarity, Polarity::Guard { .. })
    }

    /// Its level before any override.
    pub fn base_level(&self) -> Level {
        match self.def.polarity {
            Polarity::Guard { level } => level,
            Polarity::Reward { level, .. } => level.into(),
        }
    }

    /// Every predicate it holds, as the catalog uses it.
    pub(super) fn preds(&self) -> impl Iterator<Item = &Pred> {
        self.when().into_iter().chain(std::iter::once(self.rule()))
    }

    /// The `when` predicate as the catalog uses it, when there is one.
    pub(super) fn when(&self) -> Option<&Pred> {
        self.compiled.when.as_ref()
    }

    /// The `rule` predicate as the catalog uses it.
    pub(super) fn rule(&self) -> &Pred {
        let Rule::Structural(rule) = &self.compiled.rule;
        rule
    }

    /// What the policy finds on `event`, with `state` already folded over it. `authority` is the
    /// hierarchy of the catalog, which the actor of the event is read in.
    pub(super) fn evaluate(
        &self,
        slots: &SlotTable,
        authority: &Authority,
        state: &State,
        event: &Event,
    ) -> Finding {
        if event.body.kind() != self.def.subject {
            return Finding::NotApplicable;
        }
        if let Some(when) = &self.compiled.when {
            match state.holds(slots, authority, when, event) {
                Truth::False => return Finding::NotApplicable,
                Truth::Unknown => return Finding::Unknown,
                Truth::True => {}
            }
        }
        if self.is_guard() && self.def.layer != DefLayer::Meta && state.exempts(self.def.id, event)
        {
            return Finding::Exempted;
        }
        let Rule::Structural(rule) = &self.compiled.rule;
        match state.holds(slots, authority, rule, event) {
            Truth::True => Finding::Satisfied,
            Truth::False => Finding::Violated,
            Truth::Unknown => Finding::Unknown,
        }
    }
}

/// `pred` with each filter of judgments that narrows to no policy limited to the policies in
/// `visible`.
fn scope_pred(pred: &Pred, visible: &Cond) -> Pred {
    let scoped = |scope: &Scope| match scope {
        Scope::Since(filter) => Scope::Since(scope_filter(filter, visible)),
        other => other.clone(),
    };
    match pred {
        Pred::Now(_) | Pred::ModeIs(_) | Pred::ActorUnder(_) => pred.clone(),
        Pred::Once { event, scope } => Pred::Once {
            event: scope_filter(event, visible),
            scope: scoped(scope),
        },
        Pred::Count {
            event,
            scope,
            cmp,
            n,
        } => Pred::Count {
            event: scope_filter(event, visible),
            scope: scoped(scope),
            cmp: *cmp,
            n: *n,
        },
        Pred::Last {
            field,
            scope,
            value,
        } => Pred::Last {
            field: *field,
            scope: scoped(scope),
            value: value.clone(),
        },
        Pred::All(preds) => Pred::All(preds.iter().map(|p| scope_pred(p, visible)).collect()),
        Pred::Any(preds) => Pred::Any(preds.iter().map(|p| scope_pred(p, visible)).collect()),
        Pred::Not(inner) => Pred::Not(Box::new(scope_pred(inner, visible))),
    }
}

/// `filter`, limited to the judgments of `visible` when it looks for judgments and narrows to no
/// policy. What narrows a filter is the one answer of the predicate module
/// ([`reads_unnarrowed`]).
fn scope_filter(filter: &EventFilter, visible: &Cond) -> EventFilter {
    if !reads_unnarrowed(filter) {
        return filter.clone();
    }
    let cond = match &filter.cond {
        None => visible.clone(),
        Some(cond) => Cond::All(vec![visible.clone(), cond.clone()]),
    };
    EventFilter {
        kind: filter.kind,
        cond: Some(cond),
    }
}
