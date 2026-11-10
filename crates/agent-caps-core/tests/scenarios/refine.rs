//! Scenario V4: refining one intent by the layers. The same intent, "test before stop", is
//! written once in the base as Inform, raised to Advise by the project, and to Force by the
//! bugfix mode; the explore mode turns it off. The reward bound to it follows: it goes off with
//! the guard.
//!
//! The levels are read from `Outcome.guards[].written` and `rewards[].written`, and `degraded`, as
//! literals; nothing here works out the stacking.
//!
//! The fixtures of a guard are checked at the levels the guard is defined with. A guard defined
//! as Inform or Advise needs none, and an override that raises it to a stopping level would make
//! a stopping guard that was never checked on an example it fails on and one it holds on. That was
//! a gap (#11) and is fixed: `Catalog::accept` rejects such an override, in every layer, and the
//! guard here has its fixtures so that the layers may raise it.

use agent_caps_core::domain::catalog::{AcceptError, Catalog, Degraded};
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::policy::{Change, Level, OverrideLayer, RewardLevel};

use super::common::{
    GUARD, REWARD, agent, catalog, clippy_reward, id, in_mode, mode, mode_switch, outcome, over,
    project, rejected, test_guard, the_user, violated,
};

/// The base: Inform. The project: Advise. Bugfix: Force. Explore: Off. The reward is Inform, the
/// most the base guard holds it to.
fn refined() -> Catalog {
    catalog(
        vec![
            test_guard(Level::Inform),
            clippy_reward(RewardLevel::Inform),
        ],
        vec![
            project(GUARD, Change::Level(Level::Advise)),
            in_mode("bugfix", GUARD, Change::Level(Level::Force)),
            in_mode("explore", GUARD, Change::Off),
        ],
    )
}

/// FR1, FR13: the base alone, without the layers above it, only informs, and its reward is at the
/// level it is written.
#[test]
fn the_base_alone_only_informs() {
    let catalog = catalog(
        vec![
            test_guard(Level::Inform),
            clippy_reward(RewardLevel::Inform),
        ],
        vec![],
    );
    let out = outcome(&catalog, &[agent(Body::TaskStart), agent(Body::Stop)]);
    assert_eq!(out.verdict, Verdict::Warn(vec![Cause::Violated(id(GUARD))]));
    assert_eq!(out.guards[0].written, Level::Inform);
    assert_eq!(out.rewards[0].written, Level::Inform);
}

/// UC7, UC8, FR5: the project raises the guard from Inform to Advise, and the bugfix mode raises
/// it again to Force; the reward is kept at its own level.
#[test]
fn the_project_raises_it_and_the_bugfix_mode_raises_it_again() {
    let catalog = refined();
    let stop = [agent(Body::TaskStart), agent(Body::Stop)];

    let no_mode = outcome(&catalog, &stop);
    assert_eq!(
        no_mode.verdict,
        Verdict::Warn(vec![Cause::Violated(id(GUARD))])
    );
    assert_eq!(no_mode.guards[0].written, Level::Advise);
    assert_eq!(no_mode.rewards[0].written, Level::Inform);
    assert!(no_mode.degraded.is_empty());

    let bugfix = outcome(
        &catalog,
        &[mode_switch("bugfix"), stop[0].clone(), stop[1].clone()],
    );
    assert_eq!(bugfix.verdict, violated());
    assert_eq!(bugfix.guards[0].written, Level::Force);
    assert_eq!(bugfix.rewards[0].written, Level::Inform);
    assert!(bugfix.degraded.is_empty());
}

/// UC8, UC9, FR13: the explore mode turns the guard off, and the reward goes off with it.
#[test]
fn the_explore_mode_turns_the_guard_off_and_the_reward_with_it() {
    let catalog = refined();
    let explore = outcome(
        &catalog,
        &[
            mode_switch("explore"),
            agent(Body::TaskStart),
            agent(Body::Stop),
        ],
    );
    assert_eq!(explore.verdict, Verdict::Allow);
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

/// FR2, UC12: an override that raises a guard to a stopping level needs the guard's fixtures, in
/// every layer; a guard that has them may be raised, and one already stopping as defined is
/// reported once, as missing its fixtures.
#[test]
fn an_override_that_makes_a_guard_stop_needs_its_fixtures() {
    let mut bare = test_guard(Level::Advise);
    bare.fixtures.clear();
    let raises = [
        (OverrideLayer::Project, Level::Force),
        (OverrideLayer::Mode(mode("bugfix")), Level::Force),
    ];
    for (layer, level) in raises {
        let errors = rejected(
            vec![bare.clone()],
            vec![over(layer.clone(), GUARD, Change::Level(level), the_user())],
        );
        assert_eq!(
            errors,
            vec![AcceptError::RaisedWithoutFixtures {
                policy: id(GUARD),
                layer,
                level,
            }]
        );
    }

    // Lowering, or raising only to Advise, needs no fixture.
    catalog(
        vec![bare.clone()],
        vec![project(GUARD, Change::Level(Level::Inform))],
    );
    let mut informs = test_guard(Level::Inform);
    informs.fixtures.clear();
    catalog(
        vec![informs],
        vec![project(GUARD, Change::Level(Level::Advise))],
    );

    // A guard with its fixtures may be raised.
    let raise = project(GUARD, Change::Level(Level::Force));
    catalog(vec![test_guard(Level::Advise)], vec![raise.clone()]);

    // Stopping as defined and raised again: one error, not two.
    let mut stopping = test_guard(Level::Force);
    stopping.fixtures.clear();
    assert_eq!(
        rejected(vec![stopping], vec![raise]),
        vec![AcceptError::MissingFixtures(id(GUARD))]
    );
}
