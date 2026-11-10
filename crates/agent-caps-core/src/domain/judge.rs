//! The judgment of one event: every policy in effect, combined into one verdict.
//!
//! ```text
//! state  = catalog.apply(state, &event)        the event is part of its own past
//! outcome = judge(&catalog, &state, &event, &capabilities)
//!   guards  ─▶ Finding ─▶ combined: Deny > Warn > Allow, in no particular order
//!   rewards ─▶ Recognition, each returned, never combined
//! outcome.evidence(at) ─▶ Judged events, appended by the caller and folded like any other
//! ```
//!
//! A guard is written at a level and enforced at the level the platform can hold on the event
//! ([`Capabilities`]); it stops when it is enforced at Force. Each result and each record of a
//! judgment carries both levels, so a warning that was written as a stop is told from one that
//! was written as a warning, and `Outcome::lowered` reports what the platform held back.
//!
//! # Invariants
//!
//! - A guard stops by the level it is enforced at, not the level it is written at.
//! - The verdict does not depend on the order of the policies.
//! - A guard that cannot tell (its finding is unknown) counts as failing: Force denies,
//!   Advise and Inform warn. Not seeing something never lets an event through a guard enforced
//!   at Force. A guard written at Force but enforced lower warns instead, and the lowering is
//!   reported in `Outcome.lowered`.
//! - An exempted guard is left out of the verdict, and recorded as exempted so a one-time
//!   exemption is used up.
//! - A reward that is not followed is no failure: [`Recognition::None`].
//! - The record of a judgment is written in the name of the judged policy's author. A record is
//!   a claim ([`super::tx`]), and a rule reads the judgments only of policies whose authors cover
//!   its own ([`super::catalog`]), so the genuine record always counts for the rules that read
//!   it.

use super::authority::Principal;
use super::catalog::{Cap, Capabilities, Catalog, Degraded, Lowering, enforce_in};
use super::event::{Body, Event};
use super::name::PolicyId;
use super::policy::{Finding, Level};
use super::schema::{At, Judgment};
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GuardResult {
    /// The guard.
    pub policy: PolicyId,
    /// Its author, in whose name the record of the judgment is written.
    pub author: Principal,
    /// Its level in effect as written, after the layers.
    pub written: Level,
    /// The level the platform enforces it at on this event: `written` held to the platform's
    /// capabilities. This is the level that decides whether the guard stops.
    pub enforced: Level,
    /// What it found.
    pub finding: Finding,
}

impl GuardResult {
    /// What the result comes to on its own, by the level it is enforced at.
    pub fn judgment(&self) -> Judgment {
        match self.finding {
            Finding::Satisfied | Finding::NotApplicable => Judgment::Allowed,
            Finding::Exempted => Judgment::Exempted,
            Finding::Violated | Finding::Unknown if self.enforced.stops() => Judgment::Denied,
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RewardResult {
    /// The reward.
    pub policy: PolicyId,
    /// Its author, in whose name the record of the judgment is written.
    pub author: Principal,
    /// Its level in effect as written, after the layers.
    pub written: Level,
    /// The level the platform enforces it at on this event: `written` held to the platform's
    /// capabilities, and to the level its guard is enforced at.
    pub enforced: Level,
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
    /// What the platform's capabilities lowered, apart from `degraded`, of the policies that
    /// judged this event: one enforced less strongly on this event than it is written
    /// ([`Lowering::BeyondCapability`], with the value for this event), and a reward that
    /// followed its guard. A policy that did not judge the event (another kind of event, or
    /// a condition that did not apply) is not reported.
    pub lowered: Vec<Lowering>,
}

impl Outcome {
    /// The evidence of this judgment, for the caller to append and fold: one [`Body::Judged`]
    /// per guard that judged the event and per reward that was followed, each by the author of
    /// the judged policy and with both the level it was written at and the level it was
    /// enforced at.
    pub fn evidence(&self, at: At) -> Vec<Event> {
        let judged = |policy, author: &Principal, judgment, written, enforced| Event {
            at,
            by: author.clone(),
            body: Body::Judged {
                policy,
                judgment,
                written,
                enforced,
            },
        };
        let guards = self
            .guards
            .iter()
            .map(|g| judged(g.policy, &g.author, g.judgment(), g.written, g.enforced));
        let rewards = self
            .rewards
            .iter()
            .filter(|r| r.recognition == Recognition::Hit)
            .map(|r| judged(r.policy, &r.author, Judgment::Hit, r.written, r.enforced));
        guards.chain(rewards).collect()
    }
}

/// Judges `event` by every policy in effect on a platform with `caps`. `state` must already be
/// folded over `event`.
///
/// What is in effect is [`Catalog::effective`] (the strength as written), held to the
/// capabilities as [`Catalog::enforced`] states, with the cap of this event
/// ([`Capabilities::cap`]) in place of the cap of its kind. Whether a guard stops is decided by
/// the enforced level. A claim's transaction does not take the capabilities: they are the
/// platform's fact, and what a claim loosens is judged by the written strength.
pub fn judge(catalog: &Catalog, state: &State, event: &Event, caps: &Capabilities) -> Outcome {
    let effective = catalog.effective(state.mode());
    let kind = event.body.kind();
    let cap = Cap::Fixed(caps.cap(event));
    let enforced = enforce_in(&effective, caps, |policy| {
        (policy.subject() == kind).then_some(cap)
    });
    let mut guards = Vec::new();
    let mut rewards = Vec::new();
    for (policy, written, cap) in enforced.on() {
        let finding = policy.evaluate(catalog.slots(), catalog.authority(), state, event);
        if finding == Finding::NotApplicable {
            continue;
        }
        // The cap of a policy that judges this event is fixed; `at_least` is its value.
        let enforced = cap.at_least();
        if policy.is_guard() {
            guards.push(GuardResult {
                policy: policy.id(),
                author: policy.author().clone(),
                written,
                enforced,
                finding,
            });
        } else {
            rewards.push(RewardResult {
                policy: policy.id(),
                author: policy.author().clone(),
                written,
                enforced,
                recognition: if finding == Finding::Satisfied {
                    Recognition::Hit
                } else {
                    Recognition::None
                },
            });
        }
    }
    // Of the policies that judged this event: one of the same kind whose `when` did not apply
    // was not held back on it.
    let mut lowered = enforced.lowered;
    lowered.retain(|l| {
        let policy = l.policy();
        guards.iter().any(|g| g.policy == policy) || rewards.iter().any(|r| r.policy == policy)
    });
    Outcome {
        verdict: combine(&guards),
        guards,
        rewards,
        degraded: effective.degraded,
        lowered,
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
