//! `Catalog::effective`: what a catalog comes to under a mode, without judging any event. Each
//! policy is `On` at a level or `Off`, and `judge` reads the same list as written (what a
//! platform can hold of it is the topic of `capability`).

use agent_caps_core::domain::catalog::{Capabilities, Catalog, Degraded, Effect};
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::judge;
use agent_caps_core::domain::policy::{Change, Level, OverrideLayer, RewardLevel};
use agent_caps_core::domain::state::Known;

use super::common::{
    GUARD, REWARD, agent, catalog, clippy_reward, graph_of, id, in_mode, listed, mode, over,
    test_guard, the_agent, the_user,
};

/// FR12, UC17: the policies in effect under a mode are listed with their levels, without judging
/// any event; a policy turned off is listed as off, not left out; an unknown mode takes the
/// strictest level; and the list is what the judgment reads.
#[test]
fn the_effective_policies_are_listed_per_mode() {
    let bugfix = mode("bugfix");
    let explore = mode("explore");
    let catalog = catalog(
        vec![
            test_guard(Level::Advise),
            clippy_reward(RewardLevel::Advise),
        ],
        vec![
            in_mode("bugfix", GUARD, Change::Level(Level::Force)),
            in_mode("explore", GUARD, Change::Off),
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
    // Not knowing the mode takes the strictest of every mode.
    assert_eq!(
        effects(Known::Unknown),
        vec![
            (id(GUARD), Effect::On(Level::Force)),
            (id(REWARD), Effect::On(Level::Advise)),
        ]
    );
    // What explore degraded does not show where the strictest effect keeps the reward on.
    assert!(catalog.effective(&Known::Unknown).degraded.is_empty());
    // The judgment of an event both policies apply to reads the same list, as written.
    let events = [agent(Body::TaskStart), agent(Body::Stop)];
    let state = catalog.fold(&events);
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
        events.last().unwrap(),
        &Capabilities::full(),
    );
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

/// FR20, UC9: an unknown mode is the strictest effect any mode gives, each mode computed to the
/// end with its rewards bound, never a value of its own. So a change that lowers nothing under
/// any mode lowers nothing under an unknown one either.
#[test]
fn an_unknown_mode_is_the_strictest_a_mode_gives() {
    let review = || OverrideLayer::Mode(mode("review"));
    let policies = || {
        vec![
            test_guard(Level::Advise),
            clippy_reward(RewardLevel::Advise),
        ]
    };
    let users = || {
        vec![
            over(
                OverrideLayer::Project,
                GUARD,
                Change::Level(Level::Inform),
                the_user(),
            ),
            over(review(), GUARD, Change::Level(Level::Advise), the_user()),
            over(review(), REWARD, Change::Level(Level::Inform), the_user()),
        ]
    };
    let unknown = |catalog: &Catalog| {
        catalog
            .effective(&Known::Unknown)
            .policies
            .iter()
            .find(|p| p.policy.id() == id(REWARD))
            .unwrap()
            .effect
    };
    // No mode: the guard is at Inform and holds the reward down to it. Review: the user holds
    // the reward at Inform. No mode gives the reward Advise, so an unknown mode does not either.
    let before = catalog(policies(), users());
    let inform = Effect::On(Level::Inform);
    assert_eq!(unknown(&before), inform);

    // The agent's project override lowers the reward where the guard holds it down anyway (no
    // mode), and the user's own mode override holds it at Inform under review: nothing comes
    // to less under any mode, an unknown one included.
    let mut overrides = users();
    overrides.push(over(
        OverrideLayer::Project,
        REWARD,
        Change::Level(Level::Inform),
        the_agent(),
    ));
    let after = before
        .change(graph_of(policies(), overrides), &the_agent())
        .unwrap();
    assert_eq!(unknown(&after), inform);
}
