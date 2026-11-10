//! Scenarios S6 and L4: a reward is bound by its guard. It goes when the guard goes, it is kept
//! within the guard's level, and not following it is never a failure (S6, by the project's
//! bindings). The same holds when the guard is lowered or turned off by a mode (L4): the reward
//! is lowered (`RewardLowered`) or gone (`RewardWithoutGuard`) only while that mode is in effect.

use agent_caps_core::domain::catalog::Degraded;
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Recognition, Verdict};
use agent_caps_core::domain::policy::Level;
use agent_caps_core::domain::schema::{At, Judgment};

use super::common::{
    GUARD, REWARD, agent, at, bash, bind, catalog, clippy_reward, id, inside, mode_switch, outcome,
    outside, test_guard, the_user,
};

/// FR42: a project turns a policy off, leaving it no binding. FR13, UC9: the reward bound by it
/// goes with it.
#[test]
fn the_project_turns_a_policy_off_and_its_reward_goes_with_it() {
    let mut off = test_guard(Level::Force);
    off.level = None;
    let catalog = catalog(vec![off, clippy_reward(Level::Advise)], vec![]);
    let out = outcome(&catalog, &[agent(Body::TaskStart), agent(Body::Stop)]);
    assert_eq!(out.verdict, Verdict::Allow);
    assert!(out.rewards.is_empty());
    assert_eq!(
        out.degraded,
        vec![Degraded::RewardWithoutGuard {
            reward: id(REWARD),
            guard: id(GUARD)
        }]
    );
}

/// FR42: a project binds a guard at Inform. FR13, UC9: its Advise reward is lowered to it, and
/// not following a reward is no failure.
#[test]
fn a_reward_is_kept_within_its_guard_and_is_never_a_failure() {
    let catalog = catalog(
        vec![test_guard(Level::Inform), clippy_reward(Level::Advise)],
        vec![],
    );
    let out = outcome(
        &catalog,
        &[
            agent(Body::TaskStart),
            bash("cargo test", Some(true)),
            agent(Body::Stop),
        ],
    );
    assert_eq!(out.verdict, Verdict::Allow);
    assert_eq!(out.rewards.len(), 1);
    assert_eq!(out.rewards[0].recognition, Recognition::None);
    assert_eq!(out.rewards[0].written, Level::Inform);
    assert_eq!(
        out.degraded,
        vec![Degraded::RewardLowered {
            reward: id(REWARD),
            guard: id(GUARD),
            to: Level::Inform
        }]
    );

    let followed = outcome(
        &catalog,
        &[
            agent(Body::TaskStart),
            bash("cargo clippy", Some(true)),
            agent(Body::Stop),
        ],
    );
    assert_eq!(followed.rewards[0].recognition, Recognition::Hit);
    assert!(followed.evidence(At::from_millis(0)).contains(&at(
        the_user(),
        0,
        Body::Judged {
            policy: id(REWARD),
            judgment: Judgment::Hit,
            written: Level::Inform,
            enforced: Level::Inform,
        }
    )));
}

/// L4, UC9, UC8: the guard is Force outside explore and Inform inside it, so the Advise reward is
/// lowered with it, in that mode only.
#[test]
fn a_mode_that_lowers_a_guard_lowers_its_reward() {
    let mut guard = test_guard(Level::Force);
    guard.level = None;
    let catalog = catalog(
        vec![guard, clippy_reward(Level::Advise)],
        vec![
            bind(GUARD, 1, Level::Force, outside(&["explore"]), the_user()),
            bind(GUARD, 2, Level::Inform, inside("explore"), the_user()),
        ],
    );
    let stop = [agent(Body::TaskStart), agent(Body::Stop)];

    let normal = outcome(&catalog, &stop);
    assert_eq!(normal.rewards.len(), 1);
    assert_eq!(normal.rewards[0].written, Level::Advise);
    assert!(normal.degraded.is_empty());

    let explore = outcome(
        &catalog,
        &[mode_switch("explore"), stop[0].clone(), stop[1].clone()],
    );
    assert_eq!(explore.rewards.len(), 1);
    assert_eq!(explore.rewards[0].written, Level::Inform);
    assert_eq!(
        explore.degraded,
        vec![Degraded::RewardLowered {
            reward: id(REWARD),
            guard: id(GUARD),
            to: Level::Inform
        }]
    );
}

/// L4, UC9, UC8: a guard bound only outside a mode is off in it, which takes the reward away, and
/// says so.
#[test]
fn a_mode_that_turns_a_guard_off_takes_its_reward_away() {
    let mut guard = test_guard(Level::Force);
    guard.level = None;
    let catalog = catalog(
        vec![guard, clippy_reward(Level::Advise)],
        vec![bind(
            GUARD,
            1,
            Level::Force,
            outside(&["explore"]),
            the_user(),
        )],
    );
    let stop = [agent(Body::TaskStart), agent(Body::Stop)];

    assert_eq!(outcome(&catalog, &stop).rewards.len(), 1);

    let explore = outcome(
        &catalog,
        &[mode_switch("explore"), stop[0].clone(), stop[1].clone()],
    );
    assert!(explore.guards.is_empty());
    assert!(explore.rewards.is_empty());
    assert_eq!(
        explore.degraded,
        vec![Degraded::RewardWithoutGuard {
            reward: id(REWARD),
            guard: id(GUARD)
        }]
    );
}
