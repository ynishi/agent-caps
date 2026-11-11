//! Capabilities: what a platform can enforce, given as data in the words of an event filter and
//! supplied with each judgment. A policy written above what the platform can hold is enforced at
//! what it can, and the lowering is reported, not done silently.
//!
//! The written strength (`Effective`) and the enforced strength (`Enforced`) are apart: a
//! judgment and a record carry both, the list of the catalog has both, and a change of the rules
//! and the transaction of a claim read only the written one, so they do not depend on the
//! platform.

use agent_caps_core::domain::catalog::{
    Cap, Capabilities, Catalog, Effect, EnforcedEffect, Lowering,
};
use agent_caps_core::domain::change::ChangeRejected;
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Outcome, Recognition, Verdict, judge};
use agent_caps_core::domain::policy::{Level, ModeScope};
use agent_caps_core::domain::predicate::{Cond, EventFilter, Lit};
use agent_caps_core::domain::schema::{At, EventKind, Field, Judgment};
use agent_caps_core::domain::state::{Known, Origin};

use super::common::{
    GUARD, OTHER, REWARD, Written, agent, at, bash, bind, by_author, catalog, clippy_reward,
    commit_after_test_guard, edit, graph_of, id, inside, mode, outside, src_edit_guard, test_guard,
    the_agent, the_user, violated,
};

/// Every tool call, whatever the tool.
fn any_tool() -> EventFilter {
    EventFilter {
        kind: EventKind::ToolUse,
        cond: None,
    }
}

/// A tool call that meets the condition.
fn tool_where(cond: Cond) -> EventFilter {
    EventFilter {
        kind: EventKind::ToolUse,
        cond: Some(cond),
    }
}

/// A call of the tool.
fn tool_is(name: &str) -> EventFilter {
    tool_where(Cond::Eq(Field::Tool, Lit::Text(name.to_owned())))
}

/// A call whose result is a success.
fn succeeded() -> EventFilter {
    tool_where(Cond::Eq(Field::Ok, Lit::Bool(true)))
}

fn capabilities(caps: Vec<(EventFilter, Level)>, otherwise: Level) -> Capabilities {
    Capabilities::new(caps, otherwise).unwrap()
}

/// A platform that cannot stop a tool call before it runs: it holds a tool call at Advise, and
/// anything else at Force.
fn cannot_stop_ahead() -> Capabilities {
    capabilities(vec![(any_tool(), Level::Advise)], Level::Force)
}

/// The outcome on the last event, with the state folded over all of them, on a platform.
fn judged_on(catalog: &Catalog, events: &[Event], caps: &Capabilities) -> Outcome {
    let state = catalog.fold(Origin::Genesis, events);
    judge(catalog, &state, events.last().unwrap(), caps)
}

fn commit() -> [Event; 2] {
    [agent(Body::TaskStart), bash("git commit -m x", None)]
}

/// A second stopping guard, on an edit under `src/`, beside the guard on a commit.
fn other_src_edit_guard() -> Written {
    let mut guard = src_edit_guard();
    guard.id = id(OTHER);
    guard.name = "src-edit-after-test".parse().unwrap();
    guard
}

/// The record of a judgment of the guard of the scenarios, by its author.
fn record(judgment: Judgment, written: Level, enforced: Level) -> Event {
    at(
        the_user(),
        0,
        Body::Judged {
            policy: id(GUARD),
            judgment,
            written,
            enforced,
        },
    )
}

/// FR40, UC11: on a platform that cannot stop a tool call before it runs, a guard written to
/// stop one warns instead. The result has both levels, and the lowering is reported apart from
/// what the layers degraded.
#[test]
fn a_platform_that_cannot_stop_ahead_warns_where_the_guard_is_written_to_stop() {
    let catalog = catalog(vec![commit_after_test_guard()], vec![]);

    let out = judged_on(&catalog, &commit(), &cannot_stop_ahead());
    assert_eq!(out.verdict, Verdict::Warn(vec![Cause::Violated(id(GUARD))]));
    assert_eq!(out.guards[0].written, Level::Force);
    assert_eq!(out.guards[0].enforced, Level::Advise);
    assert_eq!(
        out.lowered,
        vec![Lowering::BeyondCapability {
            policy: id(GUARD),
            written: Level::Force,
            enforced: Cap::Fixed(Level::Advise),
        }]
    );
    assert!(out.degraded.is_empty());

    // The same catalog and events on a platform that holds it: stopped, and nothing lowered.
    let held = judged_on(&catalog, &commit(), &Capabilities::full());
    assert_eq!(held.verdict, violated());
    assert_eq!(held.guards[0].enforced, Level::Force);
    assert!(held.lowered.is_empty());
}

/// FR40, UC11: the capabilities are written in the words of a filter, so a platform can hold one
/// tool and not another: the guard on a shell call stops, the guard on an edit warns.
#[test]
fn a_filter_tells_the_tools_a_platform_can_stop_from_those_it_cannot() {
    let catalog = catalog(
        vec![commit_after_test_guard(), other_src_edit_guard()],
        vec![],
    );
    let caps = capabilities(vec![(tool_is("Bash"), Level::Force)], Level::Advise);

    let shell = judged_on(&catalog, &commit(), &caps);
    assert_eq!(shell.verdict, violated());
    assert!(shell.lowered.is_empty());

    let edited = judged_on(&catalog, &[agent(Body::TaskStart), edit("src/a.rs")], &caps);
    assert_eq!(
        edited.verdict,
        Verdict::Warn(vec![Cause::Violated(id(OTHER))])
    );
    assert_eq!(edited.guards[0].written, Level::Force);
    assert_eq!(edited.guards[0].enforced, Level::Advise);
    // Only the guard that judged the edit is reported: the guard on a commit did not apply.
    assert_eq!(
        edited.lowered,
        vec![Lowering::BeyondCapability {
            policy: id(OTHER),
            written: Level::Force,
            enforced: Cap::Fixed(Level::Advise),
        }]
    );
}

/// FR40, FR20: a filter that cannot tell whether it matches (the result of a call that has not
/// come back) counts for the weakest: the cap is the lowest level among the possible worlds,
/// the level `otherwise` included, since the filter may not match.
#[test]
fn a_filter_that_cannot_tell_is_the_lowest_of_the_worlds_it_may_be() {
    let running = bash("git commit -m x", None);
    let passed = bash("git commit -m x", Some(true));
    let failed = bash("git commit -m x", Some(false));

    // Force where the call succeeded, Advise elsewhere: not knowing is Advise.
    let caps = capabilities(vec![(succeeded(), Level::Force)], Level::Advise);
    assert_eq!(caps.cap(&passed), Level::Force);
    assert_eq!(caps.cap(&failed), Level::Advise);
    assert_eq!(caps.cap(&running), Level::Advise);

    // Advise where the call succeeded, Force elsewhere: not knowing is still the lowest, so
    // the level of the world in which the filter does not match joins, and the lower one wins.
    let caps = capabilities(vec![(succeeded(), Level::Advise)], Level::Force);
    assert_eq!(caps.cap(&passed), Level::Advise);
    assert_eq!(caps.cap(&failed), Level::Force);
    assert_eq!(caps.cap(&running), Level::Advise);

    // A filter by tool is known on every call, so it never needs this.
    let caps = capabilities(vec![(tool_is("Bash"), Level::Force)], Level::Advise);
    assert_eq!(caps.cap(&running), Level::Force);
    assert_eq!(caps.cap(&edit("src/a.rs")), Level::Advise);

    // The platform's cap is not looser than the world it cannot see: a guard judged ahead of its
    // result is enforced at the lowest.
    let catalog = catalog(vec![commit_after_test_guard()], vec![]);
    let caps = capabilities(vec![(succeeded(), Level::Force)], Level::Advise);
    let out = judged_on(&catalog, &commit(), &caps);
    assert_eq!(out.guards[0].enforced, Level::Advise);
}

/// FR40, UC11: the record of a judgment carries the level the policy was written at and the level
/// it was enforced at, so a warning that was written as a stop is told from one written as a
/// warning.
#[test]
fn the_record_of_a_judgment_has_the_written_and_the_enforced_level() {
    // A guard written to stop, on a platform that cannot.
    let stopping = catalog(vec![commit_after_test_guard()], vec![]);
    let lowered = judged_on(&stopping, &commit(), &cannot_stop_ahead());
    assert_eq!(
        lowered.evidence(At::from_millis(0)),
        vec![record(Judgment::Warned, Level::Force, Level::Advise)]
    );

    // A guard written to warn, on a platform that holds everything.
    let mut warning = commit_after_test_guard();
    warning.level = Some(Level::Advise);
    let warning = catalog(vec![warning], vec![]);
    let written = judged_on(&warning, &commit(), &Capabilities::full());
    assert_eq!(
        written.evidence(At::from_millis(0)),
        vec![record(Judgment::Warned, Level::Advise, Level::Advise)]
    );

    // Both are a warning; the records tell them apart.
    assert_eq!(lowered.guards[0].judgment(), Judgment::Warned);
    assert_eq!(written.guards[0].judgment(), Judgment::Warned);
    assert_ne!(
        lowered.evidence(At::from_millis(0)),
        written.evidence(At::from_millis(0))
    );
}

/// A guard that stops a commit, and a reward bound to it that judges the end of a turn: they judge
/// events of two kinds.
fn guard_with_reward_at_stop() -> Catalog {
    catalog(
        vec![commit_after_test_guard(), clippy_reward(Level::Advise)],
        vec![],
    )
}

/// FR40, UC17: a reward judges the end of a turn, and its guard judges tool calls. The reward is
/// held to the level its guard is enforced at on every tool call (the `at_least` of the guard's
/// kind), not to the cap of the event it happens to judge, so a judgment and the list give the
/// same level.
#[test]
fn a_reward_of_another_kind_is_held_to_what_its_guard_holds_on_every_event() {
    let catalog = guard_with_reward_at_stop();
    // A shell call is held at Force and an edit at Inform: the guard holds Inform on every call.
    let caps = capabilities(vec![(tool_is("Edit"), Level::Inform)], Level::Force);
    let by_event = Cap::ByEvent {
        at_least: Level::Inform,
        at_most: Level::Force,
    };
    assert_eq!(caps.cap_kind(EventKind::ToolUse), by_event);
    assert_eq!(caps.cap_kind(EventKind::Stop), Cap::Fixed(Level::Force));

    // The end of a turn is held at Force, yet the reward that follows `cargo clippy` is Inform.
    let events = [
        agent(Body::TaskStart),
        bash("cargo clippy", Some(true)),
        agent(Body::Stop),
    ];
    let out = judged_on(&catalog, &events, &caps);
    assert_eq!(out.rewards[0].recognition, Recognition::Hit);
    assert_eq!(out.rewards[0].written, Level::Advise);
    assert_eq!(out.rewards[0].enforced, Level::Inform);
    assert_eq!(
        out.lowered,
        vec![Lowering::RewardFollowsGuard {
            reward: id(REWARD),
            guard: id(GUARD),
            to: Level::Inform,
        }]
    );
    assert_eq!(
        out.evidence(At::from_millis(0)),
        vec![at(
            the_user(),
            0,
            Body::Judged {
                policy: id(REWARD),
                judgment: Judgment::Hit,
                written: Level::Advise,
                enforced: Level::Inform,
            }
        )]
    );

    // The list says the same of the reward.
    let list = catalog.enforced(&Known::Known(None), &caps);
    let of = |policy: &str| {
        list.policies
            .iter()
            .find(|p| p.policy.id() == id(policy))
            .unwrap()
            .enforced
    };
    assert_eq!(of(REWARD), EnforcedEffect::On(Cap::Fixed(Level::Inform)));
    assert_eq!(of(GUARD), EnforcedEffect::On(by_event));
    assert!(list.lowered.contains(&Lowering::RewardFollowsGuard {
        reward: id(REWARD),
        guard: id(GUARD),
        to: Level::Inform,
    }));
}

/// FR40, UC11: a reward and its guard both judge tool calls. On an event the guard is enforced at
/// Force on, it is not lowered, so neither is its reward, whatever the guard holds on other calls;
/// the list, where no event is judged, still holds the reward to what the guard holds on every call.
#[test]
fn a_reward_of_the_guards_own_kind_follows_the_guard_on_the_event_not_on_the_kind() {
    let mut reward = clippy_reward(Level::Advise);
    reward.subject = EventKind::ToolUse;
    let catalog = catalog(vec![commit_after_test_guard(), reward], vec![]);
    let caps = capabilities(vec![(tool_is("Edit"), Level::Inform)], Level::Force);

    let events = [
        agent(Body::TaskStart),
        bash("cargo clippy", Some(true)),
        bash("git commit -m x", None),
    ];
    let out = judged_on(&catalog, &events, &caps);
    assert_eq!(out.guards[0].enforced, Level::Force);
    assert_eq!(out.rewards[0].recognition, Recognition::Hit);
    assert_eq!(out.rewards[0].written, Level::Advise);
    assert_eq!(out.rewards[0].enforced, Level::Advise);
    assert!(out.lowered.is_empty());

    // The list has no event: the reward follows what the guard holds on every tool call.
    let list = catalog.enforced(&Known::Known(None), &caps);
    assert!(list.lowered.contains(&Lowering::RewardFollowsGuard {
        reward: id(REWARD),
        guard: id(GUARD),
        to: Level::Inform,
    }));
}

/// FR40, FR13, UC9: a guard the platform lowers lowers the reward bound by it, and both the
/// judgment and the list report it.
#[test]
fn a_reward_follows_a_guard_that_is_lowered() {
    let catalog = guard_with_reward_at_stop();
    let caps = capabilities(vec![(any_tool(), Level::Inform)], Level::Force);
    let events = [agent(Body::TaskStart), agent(Body::Stop)];

    // The reward does not hit (clippy was not run), but is judged, at the level it is held to.
    let out = judged_on(&catalog, &events, &caps);
    assert_eq!(out.rewards[0].recognition, Recognition::None);
    assert_eq!(out.rewards[0].written, Level::Advise);
    assert_eq!(out.rewards[0].enforced, Level::Inform);

    let follows = Lowering::RewardFollowsGuard {
        reward: id(REWARD),
        guard: id(GUARD),
        to: Level::Inform,
    };
    assert!(out.lowered.contains(&follows));
    let list = catalog.enforced(&Known::Known(None), &caps);
    assert_eq!(
        list.lowered,
        vec![
            Lowering::BeyondCapability {
                policy: id(GUARD),
                written: Level::Force,
                enforced: Cap::Fixed(Level::Inform),
            },
            follows,
        ]
    );
    // What the layers degraded is not in either: the written strength is intact.
    assert!(out.degraded.is_empty());
    assert!(catalog.effective(&Known::Known(None)).degraded.is_empty());
}

/// FR40, UC17, UC11: the list of the catalog shows a cap that differs by event as such, and
/// never says more than a judgment does: the level it holds on every event of a kind is no
/// higher than the cap of any one event of it.
#[test]
fn the_list_shows_a_cap_that_differs_by_event_and_never_says_more_than_a_judgment() {
    let catalog = catalog(vec![commit_after_test_guard()], vec![]);
    let caps = capabilities(vec![(tool_is("Edit"), Level::Inform)], Level::Force);

    let list = catalog.enforced(&Known::Known(None), &caps);
    assert_eq!(list.policies.len(), 1);
    assert_eq!(list.policies[0].written, Effect::On(Level::Force));
    assert_eq!(
        list.policies[0].enforced,
        EnforcedEffect::On(Cap::ByEvent {
            at_least: Level::Inform,
            at_most: Level::Force,
        })
    );
    assert_eq!(
        list.lowered,
        vec![Lowering::BeyondCapability {
            policy: id(GUARD),
            written: Level::Force,
            enforced: Cap::ByEvent {
                at_least: Level::Inform,
                at_most: Level::Force,
            },
        }]
    );
    // The written strength is unchanged by any of this.
    let written = catalog.effective(&Known::Known(None));
    assert_eq!(written.on().next().unwrap().1, Level::Force);

    // A kind with an unconditional filter and a conditional one beside it.
    let both = capabilities(
        vec![
            (any_tool(), Level::Advise),
            (tool_is("Bash"), Level::Inform),
        ],
        Level::Force,
    );
    assert_eq!(
        both.cap_kind(EventKind::ToolUse),
        Cap::ByEvent {
            at_least: Level::Inform,
            at_most: Level::Advise,
        }
    );
    // A kind no filter names is held at `otherwise`, on every event.
    assert_eq!(both.cap_kind(EventKind::Stop), Cap::Fixed(Level::Force));

    let events = [
        bash("git commit -m x", None),
        bash("git commit -m x", Some(true)),
        edit("src/a.rs"),
        agent(Body::Stop),
    ];
    for caps in [&caps, &both] {
        for event in &events {
            let kind = event.body.kind();
            assert!(caps.cap_kind(kind).at_least() <= caps.cap(event));
        }
    }
    assert_eq!(both.cap(&events[0]), Level::Inform);
    assert_eq!(both.cap(&events[2]), Level::Advise);
}

/// FR40, UC11: a catalog can be checked against the capabilities before use. The check lists what
/// a platform cannot hold, mode by mode; it is empty when the catalog is enforced as written.
#[test]
fn a_catalog_is_checked_against_the_capabilities_mode_by_mode() {
    // Written to warn, and to stop in the bugfix mode.
    let mut guard = commit_after_test_guard();
    guard.level = Some(Level::Advise);
    let catalog = catalog(
        vec![guard],
        vec![bind(GUARD, 1, Level::Force, inside("bugfix"), the_user())],
    );

    assert!(catalog.check_capabilities(&Capabilities::full()).is_empty());

    // A platform that cannot stop a tool call holds the warning, and not the stop.
    assert_eq!(
        catalog.check_capabilities(&cannot_stop_ahead()),
        vec![(
            Some(mode("bugfix")),
            Lowering::BeyondCapability {
                policy: id(GUARD),
                written: Level::Force,
                enforced: Cap::Fixed(Level::Advise),
            }
        )]
    );

    // A catalog with no stop at all is held as written by that platform.
    let warns = self::catalog(vec![test_guard(Level::Advise)], vec![]);
    assert!(warns.check_capabilities(&cannot_stop_ahead()).is_empty());
    // Whatever it finds is what the list reports under that mode, nothing more.
    let found = catalog.enforced(&Known::Known(Some(mode("bugfix"))), &cannot_stop_ahead());
    assert_eq!(
        found.lowered,
        catalog
            .check_capabilities(&cannot_stop_ahead())
            .into_iter()
            .map(|(_, lowering)| lowering)
            .collect::<Vec<_>>()
    );
}

/// FR40, FR42: a change of the rules is judged by the written strength, not by what a platform
/// holds. On a platform that squashes Force to Advise, one below the guard's author still cannot
/// lower the guard to Advise, by putting a binding of its own at Advise in place of the author's.
#[test]
fn a_change_is_judged_by_the_written_strength_whatever_the_platform_holds() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let squashed = capabilities(vec![(any_tool(), Level::Advise)], Level::Advise);

    // On this platform the guard already comes to Advise, as it would after the change.
    let list = catalog.enforced(&Known::Known(None), &squashed);
    assert_eq!(
        list.policies[0].enforced,
        EnforcedEffect::On(Cap::Fixed(Level::Advise))
    );

    let mut unbound = test_guard(Level::Force);
    unbound.level = None;
    let lowered = graph_of(
        vec![unbound],
        vec![bind(GUARD, 1, Level::Advise, ModeScope::Any, the_agent())],
    );
    assert!(matches!(
        catalog.change(by_author(lowered), &the_agent()),
        Err(ChangeRejected::Loosens(_))
    ));
}

/// FR40, FR11: the transaction of a claim does not see the capabilities either. A mode switch
/// from below that loosens the guard is aborted, though on this platform the guard comes to the
/// same level in both modes.
#[test]
fn a_claim_is_judged_by_the_written_strength_whatever_the_platform_holds() {
    // Advise outside the relaxed mode, Inform inside it.
    let mut guard = test_guard(Level::Advise);
    guard.level = None;
    let catalog = catalog(
        vec![guard],
        vec![
            bind(GUARD, 0, Level::Advise, outside(&["relaxed"]), the_user()),
            bind(GUARD, 1, Level::Inform, inside("relaxed"), the_user()),
        ],
    );
    let squashed = capabilities(vec![(any_tool(), Level::Inform)], Level::Inform);
    let enforced_in = |mode: Option<&str>| {
        catalog
            .enforced(&Known::Known(mode.map(self::mode)), &squashed)
            .policies[0]
            .enforced
    };
    assert_eq!(enforced_in(None), enforced_in(Some("relaxed")));

    let switch = agent(Body::ModeSwitch {
        to: mode("relaxed"),
    });
    assert_eq!(
        catalog.fold(Origin::Genesis, &[switch]).mode(),
        &Known::Known(None)
    );
}

/// FR40: the capabilities are type-checked like any filter: one whose condition reads a field its
/// kind of event does not have is rejected, with the errors of the type check.
#[test]
fn capabilities_reject_a_filter_that_does_not_type_check() {
    let bad = EventFilter {
        kind: EventKind::Stop,
        cond: Some(Cond::Eq(Field::Ok, Lit::Bool(true))),
    };
    let good = EventFilter {
        kind: EventKind::Stop,
        cond: None,
    };
    let errors = Capabilities::new(
        vec![(good.clone(), Level::Force), (bad.clone(), Level::Advise)],
        Level::Force,
    )
    .unwrap_err();
    assert!(!errors.is_empty());
    assert_eq!(errors, bad.check());
    assert!(Capabilities::new(vec![(good, Level::Advise)], Level::Force).is_ok());
}
