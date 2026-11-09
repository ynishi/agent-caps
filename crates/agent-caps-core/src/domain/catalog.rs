//! The aggregate of the rules: the policies, the overrides of the layers above them, and the
//! slots their predicates need.
//!
//! The catalog is accepted whole, every time: [`Catalog::accept`] is the only way to make one,
//! and a catalog that exists keeps every invariant below. There is no operation that changes one
//! policy of an accepted catalog.
//!
//! # Layers
//!
//! ```text
//! Mode      the overrides of the mode in effect       (one mode at a time)
//! Project   the overrides of the project
//! Base      the policies as defined
//! ───────────────────────────────────────────────
//! Meta      fixed: no override, no exemption
//! ```
//!
//! The effective level of a policy is its base level with the project's override and then the
//! mode's applied over it. The order of the overrides within a layer never matters: a layer
//! holds at most one override per policy. When the mode is unknown, every mode's overrides are
//! tried and the strictest result is taken, so not knowing the mode never loosens a rule.
//!
//! # Invariants
//!
//! - Ids and names are unique.
//! - A reward is bound by a guard that exists, and is not stronger than it as defined. After the
//!   overrides, a reward stronger than its guard is lowered to the guard's level, and a reward
//!   whose guard is off is off; both are reported as [`Degraded`], never done silently.
//! - Every predicate reads each field from its own kind of event, with an operand of its type.
//! - No override reaches a meta policy, and no override gives a reward Force or Require.
//! - A guard that is Force or Require, as defined or through any override of any layer, has at
//!   least one fixture it fails on and one it holds on: an override cannot make a stopping guard
//!   that was never checked on an example.
//! - Every fixture of a structural policy gives the finding it expects, except those marked as
//!   known gaps.
//!
//! # Errors
//!
//! [`Catalog::accept`] returns every [`AcceptError`] it finds at once, in [`Rejected`], so a
//! policy graph can be fixed in one pass.

use std::collections::HashSet;
use std::fmt;

use super::event::Event;
use super::name::{Mode, PolicyId, PolicyName};
use super::policy::{
    Change, DefLayer, Expect, Finding, Level, Override, OverrideLayer, Polarity, Policy, PolicyDef,
    PolicyGraph, Rule,
};
use super::predicate::PredError;
use super::state::{Known, SlotTable, State};

/// One reason a policy graph was not accepted.
#[derive(Debug, Clone, PartialEq)]
pub enum AcceptError {
    /// Two policies have the id.
    DuplicateId(PolicyId),
    /// Two policies have the name.
    DuplicateName(PolicyName),
    /// A predicate of the policy reads a field it cannot.
    Predicate {
        /// The policy.
        policy: PolicyId,
        /// What is wrong.
        error: PredError,
    },
    /// The reward is bound by a policy that does not exist.
    UnknownBound {
        /// The reward.
        reward: PolicyId,
        /// The id it names.
        bound_by: PolicyId,
    },
    /// The reward is bound by another reward, not by a guard.
    BoundByReward {
        /// The reward.
        reward: PolicyId,
        /// The reward it names.
        bound_by: PolicyId,
    },
    /// The reward is defined stronger than its guard.
    RewardAboveGuard {
        /// The reward.
        reward: PolicyId,
        /// Its guard.
        guard: PolicyId,
    },
    /// The Force or Require guard lacks a fixture it fails on, or one it holds on.
    MissingFixtures(PolicyId),
    /// The override raises the guard to Force or Require, and the guard lacks a fixture it fails
    /// on, or one it holds on.
    RaisedWithoutFixtures {
        /// The guard.
        policy: PolicyId,
        /// The layer of the override that raises it.
        layer: OverrideLayer,
        /// The level it is raised to.
        level: Level,
    },
    /// The fixture has no event to judge.
    EmptyFixture {
        /// The policy.
        policy: PolicyId,
        /// The fixture.
        fixture: String,
    },
    /// The fixture's last event was not found as expected.
    FixtureFailed {
        /// The policy.
        policy: PolicyId,
        /// The fixture.
        fixture: String,
        /// What it expects.
        expected: Expect,
        /// What the policy found.
        found: Expect,
    },
    /// The override names a policy that does not exist.
    UnknownOverride(PolicyId),
    /// The override names a meta policy.
    MetaOverride(PolicyId),
    /// The override gives a reward a level it cannot have.
    RewardOverrideLevel {
        /// The reward.
        policy: PolicyId,
        /// The level.
        level: Level,
    },
    /// The layer has two overrides of the policy.
    DuplicateOverride(PolicyId),
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateId(id) => write!(f, "two policies have the id {id}"),
            Self::DuplicateName(name) => write!(f, "two policies have the name {name}"),
            Self::Predicate { policy, error } => write!(f, "policy {policy}: {error}"),
            Self::UnknownBound { reward, bound_by } => {
                write!(
                    f,
                    "reward {reward} is bound by {bound_by}, which does not exist"
                )
            }
            Self::BoundByReward { reward, bound_by } => {
                write!(
                    f,
                    "reward {reward} is bound by {bound_by}, which is not a guard"
                )
            }
            Self::RewardAboveGuard { reward, guard } => {
                write!(f, "reward {reward} is stronger than its guard {guard}")
            }
            Self::MissingFixtures(id) => write!(
                f,
                "guard {id} stops events but lacks a fixture it fails on or one it holds on"
            ),
            Self::RaisedWithoutFixtures {
                policy,
                layer,
                level,
            } => {
                let layer = match layer {
                    OverrideLayer::Project => "the project".to_owned(),
                    OverrideLayer::Mode(mode) => format!("mode {mode}"),
                };
                write!(
                    f,
                    "an override of {layer} raises guard {policy} to {level:?}, but the guard \
                     lacks a fixture it fails on or one it holds on"
                )
            }
            Self::EmptyFixture { policy, fixture } => {
                write!(f, "fixture `{fixture}` of {policy} has no event")
            }
            Self::FixtureFailed {
                policy,
                fixture,
                expected,
                found,
            } => write!(
                f,
                "fixture `{fixture}` of {policy} expects {expected:?} and found {found:?}"
            ),
            Self::UnknownOverride(id) => write!(f, "an override names {id}, which does not exist"),
            Self::MetaOverride(id) => write!(f, "an override names the meta policy {id}"),
            Self::RewardOverrideLevel { policy, level } => {
                write!(
                    f,
                    "an override gives the reward {policy} the level {level:?}"
                )
            }
            Self::DuplicateOverride(id) => write!(f, "a layer overrides {id} twice"),
        }
    }
}

/// Why a policy graph was not accepted: every reason found.
#[derive(Debug, Clone, PartialEq)]
pub struct Rejected(pub Vec<AcceptError>);

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the policy graph was not accepted:")?;
        for error in &self.0 {
            write!(f, "\n- {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Rejected {}

/// A level the platform or the layers could not keep as written, and what was done instead.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Degraded {
    /// The reward was stronger than its guard after the overrides, and was lowered to it.
    RewardLowered {
        /// The reward.
        reward: PolicyId,
        /// Its guard.
        guard: PolicyId,
        /// The level it is lowered to.
        to: Level,
    },
    /// The reward's guard is off, so the reward is off.
    RewardWithoutGuard {
        /// The reward.
        reward: PolicyId,
        /// Its guard.
        guard: PolicyId,
    },
}

/// A policy in effect, with the level it has after the overrides.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct InEffect<'a> {
    pub(super) policy: &'a Policy,
    pub(super) level: Level,
}

/// The accepted rules.
#[derive(Debug, Clone, PartialEq)]
pub struct Catalog {
    policies: Vec<Policy>,
    overrides: Vec<Override>,
    slots: SlotTable,
}

impl Catalog {
    /// The catalog of `graph`, when it keeps every invariant (see the module doc).
    pub fn accept(graph: PolicyGraph) -> Result<Self, Rejected> {
        let mut errors = Vec::new();
        check_policies(&graph, &mut errors);
        check_overrides(&graph, &mut errors);
        let policies: Vec<Policy> = graph.policies.into_iter().map(Policy::new).collect();
        let slots = SlotTable::of(policies.iter().flat_map(Policy::preds));
        let catalog = Self {
            policies,
            overrides: graph.overrides,
            slots,
        };
        // Fixtures are run only on a graph whose predicates type-check.
        if errors.is_empty() {
            catalog.check_fixtures(&mut errors);
        }
        if errors.is_empty() {
            Ok(catalog)
        } else {
            Err(Rejected(errors))
        }
    }

    /// The policies, as defined.
    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    /// The policy with the id.
    pub fn policy(&self, id: PolicyId) -> Option<&Policy> {
        self.policies.iter().find(|p| p.id() == id)
    }

    /// The state before any event.
    pub fn start(&self) -> State {
        State::start(&self.slots)
    }

    /// The state after `event`.
    pub fn apply(&self, state: State, event: &Event) -> State {
        state.apply(&self.slots, event)
    }

    /// The state after `events`, from the start.
    pub fn fold<'e>(&self, events: impl IntoIterator<Item = &'e Event>) -> State {
        events
            .into_iter()
            .fold(self.start(), |state, event| self.apply(state, event))
    }

    pub(super) fn slots(&self) -> &SlotTable {
        &self.slots
    }

    /// The policies in effect under `mode`, with their levels, and what had to be degraded.
    pub(super) fn in_effect(
        &self,
        mode: &Known<Option<Mode>>,
    ) -> (Vec<InEffect<'_>>, Vec<Degraded>) {
        let modes: Vec<Option<&Mode>> = match mode {
            Known::Known(mode) => vec![mode.as_ref()],
            Known::Unknown => std::iter::once(None)
                .chain(self.modes().into_iter().map(Some))
                .collect(),
        };
        let mut in_effect: Vec<(&Policy, Option<Level>)> = self
            .policies
            .iter()
            .map(|policy| {
                // The strictest of the candidates: on if any turns it on, at the highest level.
                let level = modes
                    .iter()
                    .filter_map(|mode| self.level_under(policy, *mode))
                    .max();
                (policy, level)
            })
            .collect();
        let degraded = self.bind_rewards(&mut in_effect);
        let entries = in_effect
            .into_iter()
            .filter_map(|(policy, level)| level.map(|level| InEffect { policy, level }))
            .collect();
        (entries, degraded)
    }

    /// Every mode an override names.
    fn modes(&self) -> Vec<&Mode> {
        let mut modes: Vec<&Mode> = Vec::new();
        for o in &self.overrides {
            if let OverrideLayer::Mode(mode) = &o.layer
                && !modes.contains(&mode)
            {
                modes.push(mode);
            }
        }
        modes
    }

    /// The level of `policy` under `mode`, or `None` when it is off.
    fn level_under(&self, policy: &Policy, mode: Option<&Mode>) -> Option<Level> {
        let mut enabled = policy.enabled();
        let mut level = policy.base_level();
        if policy.layer() == DefLayer::Base {
            let project = self.override_of(policy.id(), &OverrideLayer::Project);
            let by_mode =
                mode.and_then(|m| self.override_of(policy.id(), &OverrideLayer::Mode(m.clone())));
            for change in project.into_iter().chain(by_mode) {
                match change {
                    Change::Level(new) => level = new,
                    Change::Off => enabled = false,
                    Change::On => enabled = true,
                }
            }
        }
        enabled.then_some(level)
    }

    fn override_of(&self, policy: PolicyId, layer: &OverrideLayer) -> Option<Change> {
        self.overrides
            .iter()
            .find(|o| o.policy == policy && o.layer == *layer)
            .map(|o| o.change)
    }

    /// Keeps each reward within its guard: off when the guard is off, no stronger than it.
    fn bind_rewards(&self, in_effect: &mut [(&Policy, Option<Level>)]) -> Vec<Degraded> {
        let guard_levels: Vec<(PolicyId, Option<Level>)> = in_effect
            .iter()
            .map(|(policy, level)| (policy.id(), *level))
            .collect();
        let mut degraded = Vec::new();
        for (policy, level) in in_effect.iter_mut() {
            let (Polarity::Reward { bound_by, .. }, Some(current)) = (policy.polarity(), *level)
            else {
                continue;
            };
            let guard_level = guard_levels
                .iter()
                .find(|(id, _)| id == bound_by)
                .and_then(|(_, level)| *level);
            match guard_level {
                None => {
                    *level = None;
                    degraded.push(Degraded::RewardWithoutGuard {
                        reward: policy.id(),
                        guard: *bound_by,
                    });
                }
                Some(guard) if current > guard => {
                    *level = Some(guard);
                    degraded.push(Degraded::RewardLowered {
                        reward: policy.id(),
                        guard: *bound_by,
                        to: guard,
                    });
                }
                Some(_) => {}
            }
        }
        degraded
    }

    fn check_fixtures(&self, errors: &mut Vec<AcceptError>) {
        for policy in &self.policies {
            for fixture in policy.fixtures() {
                let Some((judged, before)) = fixture.events.split_last() else {
                    errors.push(AcceptError::EmptyFixture {
                        policy: policy.id(),
                        fixture: fixture.name.clone(),
                    });
                    continue;
                };
                let state = self.apply(self.fold(before), judged);
                let found = match policy.evaluate(&self.slots, &state, judged) {
                    Finding::Violated => Expect::Violated,
                    Finding::Satisfied => Expect::Satisfied,
                    Finding::NotApplicable | Finding::Exempted => Expect::NotApplicable,
                    Finding::Unknown => Expect::Unknown,
                };
                if found != fixture.expect && !fixture.known_gap {
                    errors.push(AcceptError::FixtureFailed {
                        policy: policy.id(),
                        fixture: fixture.name.clone(),
                        expected: fixture.expect,
                        found,
                    });
                }
            }
        }
    }
}

fn check_policies(graph: &PolicyGraph, errors: &mut Vec<AcceptError>) {
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for def in &graph.policies {
        if !ids.insert(def.id) {
            errors.push(AcceptError::DuplicateId(def.id));
        }
        if !names.insert(&def.name) {
            errors.push(AcceptError::DuplicateName(def.name.clone()));
        }
        let Rule::Structural(rule) = &def.rule;
        for pred in def.when.iter().chain(std::iter::once(rule)) {
            for error in pred.check(def.subject) {
                errors.push(AcceptError::Predicate {
                    policy: def.id,
                    error,
                });
            }
        }
        match &def.polarity {
            Polarity::Reward { level, bound_by } => {
                match graph.policies.iter().find(|p| p.id == *bound_by) {
                    None => errors.push(AcceptError::UnknownBound {
                        reward: def.id,
                        bound_by: *bound_by,
                    }),
                    Some(guard) => match guard.polarity {
                        Polarity::Reward { .. } => errors.push(AcceptError::BoundByReward {
                            reward: def.id,
                            bound_by: *bound_by,
                        }),
                        Polarity::Guard { level: guard_level } => {
                            if Level::from(*level) > guard_level {
                                errors.push(AcceptError::RewardAboveGuard {
                                    reward: def.id,
                                    guard: *bound_by,
                                });
                            }
                        }
                    },
                }
            }
            Polarity::Guard { level } if level.stops() => {
                if !has_stopping_fixtures(def) {
                    errors.push(AcceptError::MissingFixtures(def.id));
                }
            }
            Polarity::Guard { .. } => {}
        }
    }
}

fn check_overrides(graph: &PolicyGraph, errors: &mut Vec<AcceptError>) {
    let mut seen = HashSet::new();
    for o in &graph.overrides {
        if !seen.insert((&o.layer, o.policy)) {
            errors.push(AcceptError::DuplicateOverride(o.policy));
        }
        let Some(def) = graph.policies.iter().find(|p| p.id == o.policy) else {
            errors.push(AcceptError::UnknownOverride(o.policy));
            continue;
        };
        if def.layer == DefLayer::Meta {
            errors.push(AcceptError::MetaOverride(o.policy));
        }
        match (&def.polarity, o.change) {
            (Polarity::Reward { .. }, Change::Level(level)) if level.stops() => {
                errors.push(AcceptError::RewardOverrideLevel {
                    policy: o.policy,
                    level,
                });
            }
            // A guard that already stops as defined is reported once, by `check_policies`; an
            // override of a meta policy never applies, and is reported as `MetaOverride`.
            (Polarity::Guard { level: defined }, Change::Level(level))
                if def.layer == DefLayer::Base
                    && level.stops()
                    && !defined.stops()
                    && !has_stopping_fixtures(def) =>
            {
                errors.push(AcceptError::RaisedWithoutFixtures {
                    policy: o.policy,
                    layer: o.layer.clone(),
                    level,
                });
            }
            _ => {}
        }
    }
}

/// Whether the guard has, besides its known gaps, a fixture it fails on and one it holds on: what
/// a stopping guard needs, whichever layer makes it stop.
fn has_stopping_fixtures(def: &PolicyDef) -> bool {
    let real = || def.fixtures.iter().filter(|f| !f.known_gap);
    let fails = real().any(|f| f.expect == Expect::Violated);
    let holds = real().any(|f| f.expect == Expect::Satisfied);
    fails && holds
}
