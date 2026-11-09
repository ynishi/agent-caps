//! The judgment of one event: every policy in effect, combined into one verdict.
//!
//! ```text
//! state  = catalog.apply(state, &event)        the event is part of its own past
//! outcome = judge(&catalog, &state, &event)
//!   guards  ─▶ Finding ─▶ combined: Deny > Warn > Allow, in no particular order
//!   rewards ─▶ Recognition, each returned, never combined
//! outcome.evidence(at) ─▶ Judged events, appended by the caller and folded like any other
//! ```
//!
//! # Invariants
//!
//! - The verdict does not depend on the order of the policies.
//! - A guard that cannot tell (its finding is unknown) counts as failing: Force denies,
//!   Advise and Inform warn. Not seeing something never lets an event through a stopping guard.
//! - An exempted guard is left out of the verdict, and recorded as exempted so a one-time
//!   exemption is used up.
//! - A reward that is not followed is no failure: [`Recognition::None`].

use super::catalog::{Catalog, Degraded};
use super::event::{Body, Event};
use super::name::PolicyId;
use super::policy::{Finding, Level};
use super::schema::{At, Judgment, Origin};
use super::state::State;

/// Why a guard warned or denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cause {
    /// The guard failed on the event.
    Violated(PolicyId),
    /// The guard could not tell, because something it reads was not seen.
    Unknown(PolicyId),
}

/// The combined verdict of the guards on an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Let the event through.
    Allow,
    /// Let it through, with the causes to show.
    Warn(Vec<Cause>),
    /// Stop it, for the causes.
    Deny(Vec<Cause>),
}

/// Whether a reward's recommendation was followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Recognition {
    /// It was.
    Hit,
    /// It was not, or it could not be told. This is not a failure.
    None,
}

/// What one guard found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuardResult {
    /// The guard.
    pub policy: PolicyId,
    /// Its level in effect.
    pub level: Level,
    /// What it found.
    pub finding: Finding,
}

impl GuardResult {
    /// What the result comes to on its own.
    pub fn judgment(&self) -> Judgment {
        match self.finding {
            Finding::Satisfied | Finding::NotApplicable => Judgment::Allowed,
            Finding::Exempted => Judgment::Exempted,
            Finding::Violated | Finding::Unknown if self.level.stops() => Judgment::Denied,
            Finding::Violated | Finding::Unknown => Judgment::Warned,
        }
    }

    fn cause(&self) -> Option<Cause> {
        match self.finding {
            Finding::Violated => Some(Cause::Violated(self.policy)),
            Finding::Unknown => Some(Cause::Unknown(self.policy)),
            Finding::Satisfied | Finding::NotApplicable | Finding::Exempted => None,
        }
    }
}

/// What one reward found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RewardResult {
    /// The reward.
    pub policy: PolicyId,
    /// Its level in effect.
    pub level: Level,
    /// Whether it was followed.
    pub recognition: Recognition,
}

/// The judgment of one event.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// The combined verdict of the guards.
    pub verdict: Verdict,
    /// Each guard that judged the event.
    pub guards: Vec<GuardResult>,
    /// Each reward that judged the event.
    pub rewards: Vec<RewardResult>,
    /// What the layers could not keep as written.
    pub degraded: Vec<Degraded>,
}

impl Outcome {
    /// The evidence of this judgment, for the caller to append and fold: one [`Body::Judged`]
    /// per guard that judged the event and per reward that was followed.
    pub fn evidence(&self, at: At) -> Vec<Event> {
        let judged = |policy, judgment| Event {
            at,
            origin: Origin::Caps,
            body: Body::Judged { policy, judgment },
        };
        let guards = self.guards.iter().map(|g| judged(g.policy, g.judgment()));
        let rewards = self
            .rewards
            .iter()
            .filter(|r| r.recognition == Recognition::Hit)
            .map(|r| judged(r.policy, Judgment::Hit));
        guards.chain(rewards).collect()
    }
}

/// Judges `event` by every policy in effect. `state` must already be folded over `event`.
pub fn judge(catalog: &Catalog, state: &State, event: &Event) -> Outcome {
    let effective = catalog.effective(state.mode());
    let mut guards = Vec::new();
    let mut rewards = Vec::new();
    for (policy, level) in effective.on() {
        let finding = policy.evaluate(catalog.slots(), state, event);
        if finding == Finding::NotApplicable {
            continue;
        }
        if policy.is_guard() {
            guards.push(GuardResult {
                policy: policy.id(),
                level,
                finding,
            });
        } else {
            rewards.push(RewardResult {
                policy: policy.id(),
                level,
                recognition: if finding == Finding::Satisfied {
                    Recognition::Hit
                } else {
                    Recognition::None
                },
            });
        }
    }
    Outcome {
        verdict: combine(&guards),
        guards,
        rewards,
        degraded: effective.degraded,
    }
}

/// Deny over Warn over Allow; the causes of the strongest kind are kept.
fn combine(guards: &[GuardResult]) -> Verdict {
    let causes = |judgment: Judgment| -> Vec<Cause> {
        guards
            .iter()
            .filter(|g| g.judgment() == judgment)
            .filter_map(GuardResult::cause)
            .collect()
    };
    let denied = causes(Judgment::Denied);
    if !denied.is_empty() {
        return Verdict::Deny(denied);
    }
    let warned = causes(Judgment::Warned);
    if !warned.is_empty() {
        return Verdict::Warn(warned);
    }
    Verdict::Allow
}
