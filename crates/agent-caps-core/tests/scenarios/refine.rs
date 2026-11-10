//! Scenario V4: refining one intent by bindings. The same intent, "test before stop", is written
//! once and bound at Inform as the base, at Advise by the project, and at Force inside the bugfix
//! mode; none of the bindings holds in the explore mode, which turns it off. The strongest binding
//! that holds wins. The reward bound to it follows: it goes off with the guard.
//!
//! The levels are read from `Outcome.guards[].written` and `rewards[].written`, and `degraded`, as
//! literals; nothing here works out the stacking.
//!
//! A guard bound at Inform or Advise needs no fixture, and a binding that makes it stop would make
//! a stopping guard that was never checked on an example it fails on and one it holds on. That was
//! a gap (#11) and is fixed: `Catalog::accept` rejects such a binding, under any mode scope, and
//! the guard here has its fixtures so that it may be bound at Force.

use agent_caps_core::domain::catalog::{AcceptError, Catalog, Degraded};
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::policy::{Level, ModeScope};

use super::common::{
    GUARD, REWARD, agent, bind, binding_id, catalog, clippy_reward, id, inside, mode_switch,
    outcome, outside, rejected, test_guard, the_user, violated,
};

/// The base: Inform. The project: Advise. Bugfix: Force. Explore: none holds. The reward is Inform.
fn refined() -> Catalog {
    let mut guard = test_guard(Level::Inform);
    guard.level = None;
    catalog(
        vec![guard, clippy_reward(Level::Inform)],
        vec![
            bind(GUARD, 1, Level::Inform, outside(&["explore"]), the_user()),
            bind(GUARD, 2, Level::Advise, outside(&["explore"]), the_user()),
            bind(GUARD, 3, Level::Force, inside("bugfix"), the_user()),
        ],
    )
}

/// FR1, FR13: the base alone, without the bindings above it, only informs, and its reward is at
/// the level it is bound.
#[test]
fn the_base_alone_only_informs() {
    let catalog = catalog(
        vec![test_guard(Level::Inform), clippy_reward(Level::Inform)],
        vec![],
    );
    let out = outcome(&catalog, &[agent(Body::TaskStart), agent(Body::Stop)]);
    assert_eq!(out.verdict, Verdict::Warn(vec![Cause::Violated(id(GUARD))]));
    assert_eq!(out.guards[0].written, Level::Inform);
    assert_eq!(out.rewards[0].written, Level::Inform);
}

/// UC7, UC8, FR42: the project's binding raises the guard from Inform to Advise, and the bugfix
/// mode's raises it again to Force; the reward is kept at its own level.
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

/// UC8, UC9, FR13: in the explore mode no binding of the guard holds, so it is off, and the
/// reward goes off with it.
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

/// FR2, UC12: a binding that makes a guard stop needs the guard's fixtures, under every mode and
/// inside one; a guard that has them may be bound at Force, and each binding at Force of a guard
/// without them is reported.
#[test]
fn a_binding_that_makes_a_guard_stop_needs_its_fixtures() {
    let mut bare = test_guard(Level::Advise);
    bare.fixtures.clear();
    for scope in [ModeScope::Any, inside("bugfix")] {
        let errors = rejected(
            vec![bare.clone()],
            vec![bind(GUARD, 1, Level::Force, scope, the_user())],
        );
        assert_eq!(
            errors,
            vec![AcceptError::MissingFixtures {
                policy: id(GUARD),
                binding: binding_id(id(GUARD), 1),
            }]
        );
    }

    // A binding at Inform or Advise needs no fixture.
    catalog(
        vec![bare.clone()],
        vec![bind(GUARD, 1, Level::Inform, ModeScope::Any, the_user())],
    );
    let mut informs = test_guard(Level::Inform);
    informs.fixtures.clear();
    catalog(
        vec![informs],
        vec![bind(GUARD, 1, Level::Advise, ModeScope::Any, the_user())],
    );

    // A guard with its fixtures may be bound at Force.
    let raise = bind(GUARD, 1, Level::Force, ModeScope::Any, the_user());
    catalog(vec![test_guard(Level::Advise)], vec![raise.clone()]);

    // Bound at Force by its author and by another binding: each binding is reported.
    let mut stopping = test_guard(Level::Force);
    stopping.fixtures.clear();
    assert_eq!(
        rejected(vec![stopping], vec![raise]),
        vec![
            AcceptError::MissingFixtures {
                policy: id(GUARD),
                binding: binding_id(id(GUARD), 0),
            },
            AcceptError::MissingFixtures {
                policy: id(GUARD),
                binding: binding_id(id(GUARD), 1),
            },
        ]
    );
}
