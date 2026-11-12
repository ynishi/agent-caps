//! `Catalog::effective`: what a catalog comes to under a mode, without judging any event. Each
//! policy is `On` at a level or `Off`, and `judge` reads the same list as written (what a
//! platform can hold of it is the topic of `capability`).

use agent_caps_core::domain::catalog::{Capabilities, Catalog, Degraded, Effect};
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::judge;
use agent_caps_core::domain::policy::Level;
use agent_caps_core::domain::state::{Known, Origin};

use super::common::{
    GUARD, REWARD, Written, agent, bind, catalog, clippy_reward, id, inside, judgeable, listed,
    mode, outside, test_guard, the_user,
};

/// The guard with no binding of its author's under every mode: its bindings are the scenario's.
fn unbound_guard() -> Written {
    let mut guard = test_guard(Level::Advise);
    guard.level = None;
    guard
}

/// FR12, UC17: the policies in effect under a mode are listed with their levels, without judging
/// any event; a policy with no binding that holds is listed as off, not left out; an unknown mode
/// takes the strongest level; and the list is what the judgment reads.
#[test]
fn the_effective_policies_are_listed_per_mode() {
    let bugfix = mode("bugfix");
    let explore = mode("explore");
    // Advise outside explore, and Force inside bugfix: off in explore.
    let catalog = catalog(
        vec![unbound_guard(), clippy_reward(Level::Advise)],
        vec![
            bind(GUARD, 1, Level::Advise, outside(&["explore"]), the_user()),
            bind(GUARD, 2, Level::Force, inside("bugfix"), the_user()),
        ],
    );
    let effects = |under| listed(&catalog, under);

    assert_eq!(
        effects(Known::Known(None)),
        vec![
            (id(GUARD), Effect::On(Level::Advise)),
            (id(REWARD), Effect::On(Level::Advise)),
        ]
    );
    assert_eq!(
        effects(Known::Known(Some(bugfix))),
        vec![
            (id(GUARD), Effect::On(Level::Force)),
            (id(REWARD), Effect::On(Level::Advise)),
        ]
    );
    // Off is listed, and the reward bound by the guard goes off with it.
    assert_eq!(
        effects(Known::Known(Some(explore.clone()))),
        vec![(id(GUARD), Effect::Off), (id(REWARD), Effect::Off)]
    );
    assert_eq!(
        catalog.effective(&Known::Known(Some(explore))).degraded,
        vec![Degraded::RewardWithoutGuard {
            reward: id(REWARD),
            guard: id(GUARD)
        }]
    );
    // Not knowing the mode takes every binding that may hold: the strongest of them.
    assert_eq!(
        effects(Known::Unknown),
        vec![
            (id(GUARD), Effect::On(Level::Force)),
            (id(REWARD), Effect::On(Level::Advise)),
        ]
    );
    // What explore degraded does not show where the strongest effect keeps the reward on.
    assert!(catalog.effective(&Known::Unknown).degraded.is_empty());
    // The judgment of an event both policies apply to reads the same list, as written.
    let events = [agent(Body::TaskStart), agent(Body::Stop)];
    let state = catalog.fold(Origin::Genesis, &events);
    let effective = catalog.effective(state.mode());
    let in_effect: Vec<_> = effective
        .on()
        .map(|(policy, level)| (policy.id(), level))
        .collect();
    assert_eq!(
        in_effect,
        vec![(id(GUARD), Level::Advise), (id(REWARD), Level::Advise)]
    );
    let outcome = judge(
        &catalog,
        &state,
        &judgeable(events.last().unwrap()),
        &Capabilities::full(),
    )
    .unwrap();
    let judged: Vec<_> = outcome
        .guards
        .iter()
        .map(|g| (g.policy, g.written))
        .chain(outcome.rewards.iter().map(|r| (r.policy, r.written)))
        .collect();
    assert_eq!(judged, in_effect);
    assert_eq!(outcome.degraded, effective.degraded);
}

/// FR12: effects are ordered by how much they hold, the one comparison of them.
#[test]
fn effects_are_ordered_by_how_much_they_hold() {
    let ordered = [
        Effect::Off,
        Effect::On(Level::Inform),
        Effect::On(Level::Advise),
        Effect::On(Level::Force),
    ];
    assert!(ordered.windows(2).all(|pair| pair[0] < pair[1]));
}

/// FR20, UC9: an unknown mode is the strongest of the modes it may be, each computed to the end
/// with rewards held to their guards. Not knowing the mode never loosens a rule, and never gives
/// a value no mode gives: a reward is not held to a guard level of another mode.
#[test]
fn an_unknown_mode_is_the_strongest_of_the_modes_it_may_be() {
    let review = || inside("review");
    let not_review = || outside(&["review"]);
    let mut reward = clippy_reward(Level::Advise);
    reward.level = None;
    let catalog = catalog(
        vec![unbound_guard(), reward],
        vec![
            bind(GUARD, 1, Level::Inform, not_review(), the_user()),
            bind(GUARD, 2, Level::Advise, review(), the_user()),
            bind(REWARD, 1, Level::Advise, not_review(), the_user()),
            bind(REWARD, 2, Level::Inform, review(), the_user()),
        ],
    );
    let effect_of = |catalog: &Catalog, under: Known<_>, policy: &str| {
        catalog
            .effective(&under)
            .policies
            .iter()
            .find(|p| p.policy.id() == id(policy))
            .unwrap()
            .effect
    };
    let inform = Effect::On(Level::Inform);
    let advise = Effect::On(Level::Advise);
    // No mode: the guard is at Inform and holds the reward down to it. Review: the user binds
    // the reward at Inform.
    assert_eq!(effect_of(&catalog, Known::Known(None), REWARD), inform);
    assert_eq!(
        effect_of(&catalog, Known::Known(Some(mode("review"))), REWARD),
        inform
    );
    // Unknown: the guard at the strongest of its modes, Advise (review). The reward is Inform
    // under every mode, so it is Inform, not its own strongest binding held to the guard's.
    assert_eq!(effect_of(&catalog, Known::Unknown, GUARD), advise);
    assert_eq!(effect_of(&catalog, Known::Unknown, REWARD), inform);
}
