//! Tests across the modules: a catalog, a fold of events and a judgment, end to end.

use super::catalog::{AcceptError, Catalog, Degraded, Effect};
use super::event::{Body, Event};
use super::exempt::{Exempt, Lifetime};
use super::judge::{Cause, Recognition, Verdict, judge};
use super::name::{CommandWords, GlobPattern, Mode, PolicyId};
use super::policy::{
    Change, DefLayer, Expect, Fixture, Level, Override, OverrideLayer, Polarity, PolicyDef,
    PolicyGraph, RewardLevel, Rule,
};
use super::predicate::{Cmp, Cond, EventFilter, Lit, Pred};
use super::schema::{At, EventKind, Field, Judgment, Origin, Scope, Source};
use super::state::Known;

const GUARD: &str = "00000000-0000-7000-8000-000000000001";
const REWARD: &str = "00000000-0000-7000-8000-000000000002";
const OTHER: &str = "00000000-0000-7000-8000-000000000003";

fn id(text: &str) -> PolicyId {
    text.parse().unwrap()
}

fn words(text: &str) -> CommandWords {
    CommandWords::new(text.split_whitespace().map(str::to_owned).collect()).unwrap()
}

fn at(origin: Origin, millis: i64, body: Body) -> Event {
    Event {
        at: At::from_millis(millis),
        origin,
        body,
    }
}

fn agent(body: Body) -> Event {
    at(Origin::Agent, 0, body)
}

fn user(body: Body) -> Event {
    at(Origin::User, 0, body)
}

fn bash(command: &str, ok: Option<bool>) -> Event {
    agent(Body::ToolUse {
        tool: "Bash".to_owned(),
        command: Some(words(command)),
        path: None,
        ok,
    })
}

fn edit(path: &str) -> Event {
    agent(Body::ToolUse {
        tool: "Edit".to_owned(),
        command: None,
        path: Some(path.to_owned()),
        ok: None,
    })
}

fn unreadable(source: Source) -> Event {
    agent(Body::Unreadable { source })
}

/// `cargo test` passed within the task.
fn tested() -> Pred {
    Pred::Once {
        event: EventFilter {
            kind: EventKind::ToolUse,
            cond: Some(Cond::All(vec![
                Cond::Words(Field::Command, words("cargo test")),
                Cond::Eq(Field::Ok, Lit::Bool(true)),
            ])),
        },
        scope: Scope::Task,
    }
}

fn fixture(name: &str, events: Vec<Event>, expect: Expect) -> Fixture {
    Fixture {
        name: name.to_owned(),
        events,
        expect,
        known_gap: false,
    }
}

/// A stopping guard: the end of a turn needs `cargo test` to have passed within the task.
fn test_guard(level: Level) -> PolicyDef {
    PolicyDef {
        id: id(GUARD),
        name: "test-before-stop".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::Stop,
        when: None,
        rule: Rule::Structural(tested()),
        polarity: Polarity::Guard { level },
        enabled: true,
        fixtures: vec![
            fixture(
                "untested",
                vec![agent(Body::TaskStart), agent(Body::Stop)],
                Expect::Violated,
            ),
            fixture(
                "tested",
                vec![
                    agent(Body::TaskStart),
                    bash("cargo test", Some(true)),
                    agent(Body::Stop),
                ],
                Expect::Satisfied,
            ),
        ],
    }
}

/// A reward within the guard: run clippy before stopping.
fn clippy_reward(level: RewardLevel) -> PolicyDef {
    PolicyDef {
        id: id(REWARD),
        name: "clippy-before-stop".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::Stop,
        when: None,
        rule: Rule::Structural(Pred::Once {
            event: EventFilter {
                kind: EventKind::ToolUse,
                cond: Some(Cond::Words(Field::Command, words("cargo clippy"))),
            },
            scope: Scope::Task,
        }),
        polarity: Polarity::Reward {
            level,
            bound_by: id(GUARD),
        },
        enabled: true,
        fixtures: vec![],
    }
}

fn catalog(policies: Vec<PolicyDef>, overrides: Vec<Override>) -> Catalog {
    Catalog::accept(PolicyGraph {
        policies,
        overrides,
    })
    .unwrap()
}

fn rejected(policies: Vec<PolicyDef>, overrides: Vec<Override>) -> Vec<AcceptError> {
    Catalog::accept(PolicyGraph {
        policies,
        overrides,
    })
    .unwrap_err()
    .0
}

/// The verdict on the last event, with the state folded over all of them.
fn verdict(catalog: &Catalog, events: &[Event]) -> Verdict {
    let state = catalog.fold(events);
    judge(catalog, &state, events.last().unwrap()).verdict
}

/// FR1, UC1: a written guard stops the end of a turn until a passing test run has been seen in
/// the task.
#[test]
fn a_stopping_guard_denies_until_its_condition_is_seen() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let start = agent(Body::TaskStart);
    let stop = agent(Body::Stop);
    assert_eq!(
        verdict(&catalog, &[start.clone(), stop.clone()]),
        Verdict::Deny(vec![Cause::Violated(id(GUARD))])
    );
    assert_eq!(
        verdict(
            &catalog,
            &[start.clone(), bash("cargo test", Some(false)), stop.clone()]
        ),
        Verdict::Deny(vec![Cause::Violated(id(GUARD))])
    );
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                bash("cargo test -p a", Some(true)),
                stop.clone()
            ]
        ),
        Verdict::Allow
    );
    // A new task starts the count again.
    assert_eq!(
        verdict(
            &catalog,
            &[start.clone(), bash("cargo test", Some(true)), start, stop]
        ),
        Verdict::Deny(vec![Cause::Violated(id(GUARD))])
    );
}

/// FR20, UC3: a lost line makes an unseen fact unknown and a stopping guard denies; a seen fact
/// stays seen.
#[test]
fn an_unreadable_record_makes_an_unseen_once_unknown_but_not_a_seen_one() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let start = agent(Body::TaskStart);
    let stop = agent(Body::Stop);
    let lost = unreadable(Source::Transcript);
    // The lost line may have been the test run: the guard cannot tell, and a stopping guard denies.
    assert_eq!(
        verdict(&catalog, &[start.clone(), lost.clone(), stop.clone()]),
        Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
    );
    // The run was seen; a later lost line cannot unsee it.
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                bash("cargo test", Some(true)),
                lost.clone(),
                stop.clone()
            ]
        ),
        Verdict::Allow
    );
    // Seeing the run after the lost line settles it too.
    assert_eq!(
        verdict(
            &catalog,
            &[start, lost, bash("cargo test", Some(true)), stop]
        ),
        Verdict::Allow
    );
}

/// FR20, UC3: when a fact cannot be seen, an advising guard warns where a stopping one denies.
#[test]
fn an_advising_guard_warns_where_a_stopping_one_denies() {
    let catalog = catalog(vec![test_guard(Level::Advise)], vec![]);
    let events = [
        agent(Body::TaskStart),
        unreadable(Source::Transcript),
        agent(Body::Stop),
    ];
    assert_eq!(
        verdict(&catalog, &events),
        Verdict::Warn(vec![Cause::Unknown(id(GUARD))])
    );
}

/// FR1, UC2: the guard stops the first end of a turn and lets the second one through.
#[test]
fn a_guard_can_let_the_second_stop_through_by_counting_its_own_denials() {
    // The judgment is not part of the state; the evidence of it is, and a count reads it.
    let mut guard = test_guard(Level::Force);
    guard.when = Some(Pred::Count {
        event: EventFilter {
            kind: EventKind::Judged,
            cond: Some(Cond::All(vec![
                Cond::Eq(Field::Policy, Lit::Text(GUARD.to_owned())),
                Cond::Eq(Field::Judgment, Lit::Text("denied".to_owned())),
            ])),
        },
        scope: Scope::Agent,
        cmp: Cmp::Lt,
        n: 1,
    });
    let catalog = catalog(vec![guard], vec![]);
    let mut events = vec![
        agent(Body::AgentStart { agent_type: None }),
        agent(Body::TaskStart),
    ];
    let stop = agent(Body::Stop);
    let state = catalog.fold(events.iter().chain([&stop]));
    let first = judge(&catalog, &state, &stop);
    assert!(matches!(first.verdict, Verdict::Deny(_)));
    events.push(stop.clone());
    events.extend(first.evidence(At::from_millis(1)));
    events.push(stop.clone());
    assert_eq!(verdict(&catalog, &events), Verdict::Allow);
}

/// UC4: a judgment record the agent wrote itself does not count as caps's own, so it does not
/// let the second end of a turn through.
///
/// TODO(#3): the fold reads a `Judged` event whatever its origin, so this fails today. Which
/// records are caps's own evidence, and how they reach the fold, is decided with the
/// application layer that keeps them (#19); until then the domain is not changed for it.
#[test]
#[ignore = "TODO(#3): waits for the application layer (#19)"]
fn a_judgment_record_the_agent_wrote_does_not_count() {
    let mut guard = test_guard(Level::Force);
    guard.when = Some(Pred::Count {
        event: EventFilter {
            kind: EventKind::Judged,
            cond: Some(Cond::All(vec![
                Cond::Eq(Field::Policy, Lit::Text(GUARD.to_owned())),
                Cond::Eq(Field::Judgment, Lit::Text("denied".to_owned())),
            ])),
        },
        scope: Scope::Agent,
        cmp: Cmp::Lt,
        n: 1,
    });
    let catalog = catalog(vec![guard], vec![]);
    let stop = agent(Body::Stop);
    let mut events = vec![
        agent(Body::AgentStart { agent_type: None }),
        agent(Body::TaskStart),
        stop.clone(),
    ];
    // The same `denied` record as caps would write, but from the agent.
    events.push(agent(Body::Judged {
        policy: id(GUARD),
        judgment: Judgment::Denied,
    }));
    events.push(stop);
    assert!(matches!(verdict(&catalog, &events), Verdict::Deny(_)));
}

/// FR9, UC6: an exemption from the user covers its target for its lifetime. UC4: one from the
/// agent is nothing.
#[test]
fn a_users_exemption_covers_its_target_for_its_lifetime() {
    let mut guard = test_guard(Level::Force);
    guard.subject = EventKind::ToolUse;
    // No edit under `src/` before the tests pass.
    guard.when = Some(Pred::Now(Cond::Glob(
        Field::Path,
        GlobPattern::new("src/*"),
    )));
    guard.fixtures = vec![
        fixture(
            "untested edit",
            vec![agent(Body::TaskStart), edit("src/a.rs")],
            Expect::Violated,
        ),
        fixture(
            "tested edit",
            vec![
                agent(Body::TaskStart),
                bash("cargo test", Some(true)),
                edit("src/a.rs"),
            ],
            Expect::Satisfied,
        ),
    ];
    let catalog = catalog(vec![guard], vec![]);
    let exempt = |lifetime| {
        Body::Exempt(Exempt {
            guard: id(GUARD),
            target: Some(Cond::Eq(Field::Path, Lit::Text("src/a.rs".to_owned()))),
            lifetime,
            reason: "generated file".parse().unwrap(),
        })
    };
    let start = agent(Body::TaskStart);

    // From the agent, an exemption is nothing.
    assert!(matches!(
        verdict(
            &catalog,
            &[
                start.clone(),
                agent(exempt(Lifetime::Next)),
                edit("src/a.rs")
            ]
        ),
        Verdict::Deny(_)
    ));

    // From the user, it covers its target, not another path.
    let next = [
        start.clone(),
        user(exempt(Lifetime::Next)),
        edit("src/a.rs"),
    ];
    assert_eq!(verdict(&catalog, &next), Verdict::Allow);
    assert!(matches!(
        verdict(
            &catalog,
            &[
                start.clone(),
                user(exempt(Lifetime::Next)),
                edit("src/b.rs")
            ]
        ),
        Verdict::Deny(_)
    ));

    // `Next` is used up by the judgment it covered.
    let state = catalog.fold(&next);
    let outcome = judge(&catalog, &state, &next[2]);
    let mut events = next.to_vec();
    events.extend(outcome.evidence(At::from_millis(1)));
    events.push(edit("src/a.rs"));
    assert!(matches!(verdict(&catalog, &events), Verdict::Deny(_)));

    // `Within(Task)` lasts until the task starts again.
    let within = user(exempt(Lifetime::Within(Scope::Task)));
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                within.clone(),
                edit("src/a.rs"),
                edit("src/a.rs")
            ]
        ),
        Verdict::Allow
    );
    assert!(matches!(
        verdict(
            &catalog,
            &[start.clone(), within, start.clone(), edit("src/a.rs")]
        ),
        Verdict::Deny(_)
    ));

    // `Until` is compared with the time of the judged event.
    let until = at(
        Origin::User,
        0,
        exempt(Lifetime::Until(At::from_millis(100))),
    );
    let edit_at = |millis| at(Origin::Agent, millis, edit("src/a.rs").body);
    assert_eq!(
        verdict(&catalog, &[start.clone(), until.clone(), edit_at(99)]),
        Verdict::Allow
    );
    assert!(matches!(
        verdict(&catalog, &[start.clone(), until, edit_at(100)]),
        Verdict::Deny(_)
    ));

    // A lost record of the evidence may have used the exemption up: it ends.
    assert!(matches!(
        verdict(
            &catalog,
            &[
                start,
                user(exempt(Lifetime::Within(Scope::Session))),
                unreadable(Source::Evidence),
                edit("src/a.rs")
            ]
        ),
        Verdict::Deny(_)
    ));
}

/// FR14, UC10: no exemption covers a Meta guard.
#[test]
fn no_exemption_covers_a_meta_guard() {
    let mut guard = test_guard(Level::Force);
    guard.layer = DefLayer::Meta;
    let catalog = catalog(vec![guard], vec![]);
    let exempt = user(Body::Exempt(Exempt {
        guard: id(GUARD),
        target: None,
        lifetime: Lifetime::Within(Scope::Session),
        reason: "please".parse().unwrap(),
    }));
    assert!(matches!(
        verdict(
            &catalog,
            &[agent(Body::TaskStart), exempt, agent(Body::Stop)]
        ),
        Verdict::Deny(_)
    ));
}

/// UC8: a mode changes the level of a policy. UC4: a loosening switch from the agent is
/// nothing; only the user or caps make it. FR20: a lost record puts the strictest mode in force.
#[test]
fn a_mode_overrides_the_level_and_only_the_user_or_caps_switch_it() {
    let modeling = "modeling".parse().unwrap();
    let catalog = catalog(
        vec![test_guard(Level::Force)],
        vec![Override {
            layer: OverrideLayer::Mode(modeling),
            policy: id(GUARD),
            change: Change::Level(Level::Inform),
        }],
    );
    let switch = |origin| {
        at(
            origin,
            0,
            Body::ModeSwitch {
                to: "modeling".parse().unwrap(),
            },
        )
    };
    let stop = agent(Body::Stop);
    let warned = Verdict::Warn(vec![Cause::Violated(id(GUARD))]);
    assert_eq!(
        verdict(&catalog, &[switch(Origin::User), stop.clone()]),
        warned
    );
    assert_eq!(
        verdict(&catalog, &[switch(Origin::Caps), stop.clone()]),
        warned
    );
    // The agent cannot loosen its own rules.
    assert!(matches!(
        verdict(&catalog, &[switch(Origin::Agent), stop.clone()]),
        Verdict::Deny(_)
    ));
    // A lost evidence record may have been a switch: the strictest mode applies.
    let state = catalog.fold(&[switch(Origin::User), unreadable(Source::Evidence)]);
    assert_eq!(state.mode(), &Known::Unknown);
    assert!(matches!(
        judge(&catalog, &state, &stop).verdict,
        Verdict::Deny(_)
    ));
}

/// FR6: a project turns a policy off. FR13, UC9: the reward bound by it goes with it.
#[test]
fn the_project_turns_a_policy_off_and_its_reward_goes_with_it() {
    let catalog = catalog(
        vec![test_guard(Level::Force), clippy_reward(RewardLevel::Advise)],
        vec![Override {
            layer: OverrideLayer::Project,
            policy: id(GUARD),
            change: Change::Off,
        }],
    );
    let events = [agent(Body::TaskStart), agent(Body::Stop)];
    let state = catalog.fold(&events);
    let outcome = judge(&catalog, &state, &events[1]);
    assert_eq!(outcome.verdict, Verdict::Allow);
    assert!(outcome.rewards.is_empty());
    assert_eq!(
        outcome.degraded,
        vec![Degraded::RewardWithoutGuard {
            reward: id(REWARD),
            guard: id(GUARD)
        }]
    );
}

/// FR12, UC17: the policies in effect under a mode are listed with their levels, without judging
/// any event; a policy turned off is listed as off, not left out; an unknown mode takes the
/// strictest level; and the list is what the judgment reads.
#[test]
fn the_effective_policies_are_listed_per_mode() {
    let bugfix: Mode = "bugfix".parse().unwrap();
    let explore: Mode = "explore".parse().unwrap();
    let catalog = catalog(
        vec![
            test_guard(Level::Advise),
            clippy_reward(RewardLevel::Advise),
        ],
        vec![
            Override {
                layer: OverrideLayer::Mode(bugfix.clone()),
                policy: id(GUARD),
                change: Change::Level(Level::Force),
            },
            Override {
                layer: OverrideLayer::Mode(explore.clone()),
                policy: id(GUARD),
                change: Change::Off,
            },
        ],
    );
    let effects = |mode: Known<Option<Mode>>| -> Vec<(PolicyId, Effect)> {
        catalog
            .effective(&mode)
            .policies
            .iter()
            .map(|p| (p.policy.id(), p.effect))
            .collect()
    };

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
    // The judgment of an event both policies apply to reads the same list.
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
    let outcome = judge(&catalog, &state, events.last().unwrap());
    let judged: Vec<_> = outcome
        .guards
        .iter()
        .map(|g| (g.policy, g.level))
        .chain(outcome.rewards.iter().map(|r| (r.policy, r.level)))
        .collect();
    assert_eq!(judged, in_effect);
    assert_eq!(outcome.degraded, effective.degraded);
}

/// FR5: a project override lowers the level of a guard. FR13, UC9: its reward is lowered with it,
/// and not following a reward is no failure.
#[test]
fn a_reward_is_kept_within_its_guard_and_is_never_a_failure() {
    let catalog = catalog(
        vec![test_guard(Level::Force), clippy_reward(RewardLevel::Advise)],
        vec![Override {
            layer: OverrideLayer::Project,
            policy: id(GUARD),
            change: Change::Level(Level::Inform),
        }],
    );
    let events = [
        agent(Body::TaskStart),
        bash("cargo test", Some(true)),
        agent(Body::Stop),
    ];
    let state = catalog.fold(&events);
    let outcome = judge(&catalog, &state, &events[2]);
    assert_eq!(outcome.verdict, Verdict::Allow);
    assert_eq!(outcome.rewards.len(), 1);
    assert_eq!(outcome.rewards[0].recognition, Recognition::None);
    assert_eq!(outcome.rewards[0].level, Level::Inform);
    assert_eq!(
        outcome.degraded,
        vec![Degraded::RewardLowered {
            reward: id(REWARD),
            guard: id(GUARD),
            to: Level::Inform
        }]
    );

    let followed = [
        agent(Body::TaskStart),
        bash("cargo clippy", Some(true)),
        agent(Body::Stop),
    ];
    let state = catalog.fold(&followed);
    let outcome = judge(&catalog, &state, &followed[2]);
    assert_eq!(outcome.rewards[0].recognition, Recognition::Hit);
    assert!(outcome.evidence(At::from_millis(0)).contains(&at(
        Origin::Caps,
        0,
        Body::Judged {
            policy: id(REWARD),
            judgment: Judgment::Hit
        }
    )));
}

/// FR29: with several policies in effect on one event, the strongest decides, whatever their
/// order.
#[test]
fn the_verdict_takes_the_strongest_and_ignores_the_order() {
    let mut warn = test_guard(Level::Advise);
    warn.id = id(OTHER);
    warn.name = "advice".parse().unwrap();
    let deny = test_guard(Level::Force);
    let events = [agent(Body::TaskStart), agent(Body::Stop)];
    let one = catalog(vec![warn.clone(), deny.clone()], vec![]);
    let other = catalog(vec![deny, warn], vec![]);
    let expected = Verdict::Deny(vec![Cause::Violated(id(GUARD))]);
    assert_eq!(verdict(&one, &events), expected);
    assert_eq!(verdict(&other, &events), expected);
}

/// FR2, UC12: an override that raises a guard to a stopping level needs the guard's fixtures, in
/// every layer; a guard that has them may be raised, and one already stopping as defined is
/// reported once, as missing its fixtures.
#[test]
fn an_override_that_makes_a_guard_stop_needs_its_fixtures() {
    let mut bare = test_guard(Level::Advise);
    bare.fixtures.clear();
    let bugfix: Mode = "bugfix".parse().unwrap();
    let raises = [
        (OverrideLayer::Project, Level::Force),
        (OverrideLayer::Mode(bugfix), Level::Force),
    ];
    for (layer, level) in raises {
        let errors = rejected(
            vec![bare.clone()],
            vec![Override {
                layer: layer.clone(),
                policy: id(GUARD),
                change: Change::Level(level),
            }],
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
    let not_stopping = Override {
        layer: OverrideLayer::Project,
        policy: id(GUARD),
        change: Change::Level(Level::Inform),
    };
    catalog(vec![bare.clone()], vec![not_stopping]);
    let mut informs = test_guard(Level::Inform);
    informs.fixtures.clear();
    let to_advise = Override {
        layer: OverrideLayer::Project,
        policy: id(GUARD),
        change: Change::Level(Level::Advise),
    };
    catalog(vec![informs], vec![to_advise]);

    // A guard with its fixtures may be raised.
    let raise = Override {
        layer: OverrideLayer::Project,
        policy: id(GUARD),
        change: Change::Level(Level::Force),
    };
    catalog(vec![test_guard(Level::Advise)], vec![raise.clone()]);

    // Stopping as defined and raised again: one error, not two.
    let mut stopping = test_guard(Level::Force);
    stopping.fixtures.clear();
    assert_eq!(
        rejected(vec![stopping], vec![raise]),
        vec![AcceptError::MissingFixtures(id(GUARD))]
    );
}

/// FR2, UC12: a stopping guard without fixtures is not accepted. FR14: a Meta policy takes no
/// override.
#[test]
fn accept_reports_every_broken_invariant() {
    let mut bad_pred = test_guard(Level::Advise);
    bad_pred.id = id(OTHER);
    bad_pred.name = "bad".parse().unwrap();
    // The subject is a stop, which has no tool.
    bad_pred.rule = Rule::Structural(Pred::Now(Cond::Eq(
        Field::Tool,
        Lit::Text("Bash".to_owned()),
    )));
    let mut no_fixtures = test_guard(Level::Force);
    no_fixtures.fixtures.clear();
    let errors = rejected(
        vec![no_fixtures, bad_pred, clippy_reward(RewardLevel::Advise)],
        vec![Override {
            layer: OverrideLayer::Project,
            policy: id(REWARD),
            change: Change::Level(Level::Force),
        }],
    );
    assert!(errors.contains(&AcceptError::MissingFixtures(id(GUARD))));
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, AcceptError::Predicate { policy, .. } if *policy == id(OTHER)))
    );
    assert!(errors.contains(&AcceptError::RewardOverrideLevel {
        policy: id(REWARD),
        level: Level::Force
    }));

    // A reward stronger than its guard, or bound by nothing.
    let errors = rejected(
        vec![
            test_guard(Level::Inform),
            clippy_reward(RewardLevel::Advise),
        ],
        vec![],
    );
    assert_eq!(
        errors,
        vec![AcceptError::RewardAboveGuard {
            reward: id(REWARD),
            guard: id(GUARD)
        }]
    );
    let errors = rejected(vec![clippy_reward(RewardLevel::Advise)], vec![]);
    assert_eq!(
        errors,
        vec![AcceptError::UnknownBound {
            reward: id(REWARD),
            bound_by: id(GUARD)
        }]
    );

    // A meta policy takes no override.
    let mut meta = test_guard(Level::Force);
    meta.layer = DefLayer::Meta;
    let errors = rejected(
        vec![meta],
        vec![Override {
            layer: OverrideLayer::Project,
            policy: id(GUARD),
            change: Change::Off,
        }],
    );
    assert_eq!(errors, vec![AcceptError::MetaOverride(id(GUARD))]);
}

/// FR2, UC12: a fixture that fails rejects the catalog.
#[test]
fn a_fixture_that_fails_rejects_the_catalog_unless_it_is_a_known_gap() {
    let mut guard = test_guard(Level::Force);
    // Wrong on purpose: a lost line makes the guard unknown, not satisfied.
    let wrong = || {
        fixture(
            "lost line",
            vec![
                agent(Body::TaskStart),
                unreadable(Source::Transcript),
                agent(Body::Stop),
            ],
            Expect::Satisfied,
        )
    };
    guard.fixtures.push(wrong());
    assert_eq!(
        rejected(vec![guard.clone()], vec![]),
        vec![AcceptError::FixtureFailed {
            policy: id(GUARD),
            fixture: "lost line".to_owned(),
            expected: Expect::Satisfied,
            found: Expect::Unknown
        }]
    );
    guard.fixtures.pop();
    guard.fixtures.push(Fixture {
        known_gap: true,
        ..wrong()
    });
    assert!(
        Catalog::accept(PolicyGraph {
            policies: vec![guard],
            overrides: vec![]
        })
        .is_ok()
    );
}

/// FR20: a lost line makes the last value unknown, so an advising guard warns with an unknown
/// cause.
#[test]
fn a_last_value_is_false_when_unseen_and_unknown_when_lost() {
    let mut guard = test_guard(Level::Advise);
    guard.rule = Rule::Structural(Pred::Last {
        field: Field::Ok,
        scope: Scope::Task,
        value: Lit::Bool(true),
    });
    guard.fixtures = vec![];
    let catalog = catalog(vec![guard], vec![]);
    let start = agent(Body::TaskStart);
    let stop = agent(Body::Stop);
    let violated = Verdict::Warn(vec![Cause::Violated(id(GUARD))]);
    assert_eq!(verdict(&catalog, &[start.clone(), stop.clone()]), violated);
    assert_eq!(
        verdict(
            &catalog,
            &[start.clone(), bash("cargo build", Some(true)), stop.clone()]
        ),
        Verdict::Allow
    );
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                bash("cargo build", Some(true)),
                bash("cargo build", Some(false)),
                stop.clone()
            ]
        ),
        violated
    );
    assert_eq!(
        verdict(
            &catalog,
            &[
                start,
                bash("cargo build", Some(true)),
                unreadable(Source::Transcript),
                stop
            ]
        ),
        Verdict::Warn(vec![Cause::Unknown(id(GUARD))])
    );
}
