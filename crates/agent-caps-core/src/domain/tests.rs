//! Tests across the modules: a catalog, a fold of events and a judgment, end to end.

use super::authority::{Authority, AuthorityError, Principal};
use super::catalog::{AcceptError, Catalog, Degraded, Effect, Target};
use super::change::{ChangeRejected, Loosening};
use super::event::{Body, Event};
use super::exempt::{Exempt, Lifetime};
use super::judge::{Cause, Recognition, Verdict, judge};
use super::name::{CommandWords, GlobPattern, Mode, PolicyId};
use super::policy::{
    Change, DefLayer, Expect, Fixture, Level, Override, OverrideLayer, Polarity, PolicyDef,
    PolicyGraph, RewardLevel, Rule,
};
use super::predicate::{Cmp, Cond, EventFilter, Lit, Pred, Scope};
use super::schema::{At, EventKind, Field, Judgment, Origin, Source};
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

/// `cargo test` passed within the scope.
fn tested_in(scope: Scope) -> Pred {
    Pred::Once {
        event: EventFilter {
            kind: EventKind::ToolUse,
            cond: Some(Cond::All(vec![
                Cond::Words(Field::Command, words("cargo test")),
                Cond::Eq(Field::Ok, Lit::Bool(true)),
            ])),
        },
        scope,
    }
}

/// `cargo test` passed within the task.
fn tested() -> Pred {
    tested_in(Scope::Task)
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
        author: the_user(),
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
        author: the_user(),
    }
}

/// The one who owns the rules: the root of the hierarchy of the tests.
fn the_user() -> Principal {
    Principal::new("user")
}

/// Below the user.
fn the_agent() -> Principal {
    Principal::new("agent")
}

/// Below the agent.
fn the_helper() -> Principal {
    Principal::new("helper")
}

/// The user, the agent below it, and the helper below the agent. A test that does not care who
/// wrote what gives everything to the user.
fn hierarchy() -> Authority {
    Authority::new([
        (the_user(), None),
        (the_agent(), Some(the_user())),
        (the_helper(), Some(the_agent())),
    ])
    .unwrap()
}

fn catalog(policies: Vec<PolicyDef>, overrides: Vec<Override>) -> Catalog {
    Catalog::accept(
        PolicyGraph {
            policies,
            overrides,
        },
        hierarchy(),
    )
    .unwrap()
}

fn rejected(policies: Vec<PolicyDef>, overrides: Vec<Override>) -> Vec<AcceptError> {
    Catalog::accept(
        PolicyGraph {
            policies,
            overrides,
        },
        hierarchy(),
    )
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
            author: the_user(),
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
            author: the_user(),
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
                author: the_user(),
            },
            Override {
                layer: OverrideLayer::Mode(explore.clone()),
                policy: id(GUARD),
                change: Change::Off,
                author: the_user(),
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
    // What explore degraded does not show where the strictest effect keeps the reward on.
    assert!(catalog.effective(&Known::Unknown).degraded.is_empty());
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
            author: the_user(),
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
                author: the_user(),
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
        author: the_user(),
    };
    catalog(vec![bare.clone()], vec![not_stopping]);
    let mut informs = test_guard(Level::Inform);
    informs.fixtures.clear();
    let to_advise = Override {
        layer: OverrideLayer::Project,
        policy: id(GUARD),
        change: Change::Level(Level::Advise),
        author: the_user(),
    };
    catalog(vec![informs], vec![to_advise]);

    // A guard with its fixtures may be raised.
    let raise = Override {
        layer: OverrideLayer::Project,
        policy: id(GUARD),
        change: Change::Level(Level::Force),
        author: the_user(),
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
            author: the_user(),
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
            author: the_user(),
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
        Catalog::accept(
            PolicyGraph {
                policies: vec![guard],
                overrides: vec![]
            },
            hierarchy()
        )
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

fn test_run() -> Event {
    bash("cargo test", Some(true))
}

fn commit(ok: Option<bool>) -> Event {
    bash("git commit -m x", ok)
}

/// A commit; with `ok_only`, one that succeeded.
fn commit_filter(ok_only: bool) -> EventFilter {
    let is_commit = Cond::Words(Field::Command, words("git commit"));
    EventFilter {
        kind: EventKind::ToolUse,
        cond: Some(if ok_only {
            Cond::All(vec![is_commit, Cond::Eq(Field::Ok, Lit::Bool(true))])
        } else {
            is_commit
        }),
    }
}

fn violated() -> Verdict {
    Verdict::Deny(vec![Cause::Violated(id(GUARD))])
}

fn unknown() -> Verdict {
    Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
}

/// A stopping guard on the end of a turn: `cargo test` passed since the boundary `scope` names.
fn stop_guard_in(scope: Scope) -> PolicyDef {
    let mut guard = test_guard(Level::Force);
    guard.rule = Rule::Structural(tested_in(scope));
    guard
}

/// A stopping guard on a commit: `cargo test` passed since the last commit.
fn commit_guard() -> PolicyDef {
    let mut guard = test_guard(Level::Force);
    guard.subject = EventKind::ToolUse;
    guard.when = Some(Pred::Now(Cond::Words(Field::Command, words("git commit"))));
    guard.rule = Rule::Structural(tested_in(Scope::Since(commit_filter(false))));
    guard.fixtures = vec![
        fixture(
            "first commit after a test",
            vec![agent(Body::TaskStart), test_run(), commit(None)],
            Expect::Satisfied,
        ),
        fixture(
            "second commit without a new test",
            vec![
                agent(Body::TaskStart),
                test_run(),
                commit(Some(true)),
                commit(None),
            ],
            Expect::Violated,
        ),
    ];
    guard
}

/// FR33, UC1: a second commit with no test after the first one is stopped, however recent the
/// test before the first commit was; a new test in between lets it through.
#[test]
fn a_second_commit_without_a_new_test_is_stopped() {
    let catalog = catalog(vec![commit_guard()], vec![]);
    let start = agent(Body::TaskStart);
    assert_eq!(
        verdict(&catalog, &[start.clone(), test_run(), commit(None)]),
        Verdict::Allow
    );
    assert_eq!(
        verdict(&catalog, &[start.clone(), commit(None)]),
        violated()
    );
    // The same task, but the test came before the first commit only.
    assert_eq!(
        verdict(
            &catalog,
            &[start.clone(), test_run(), commit(Some(true)), commit(None)]
        ),
        violated()
    );
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                test_run(),
                commit(Some(true)),
                test_run(),
                commit(None)
            ]
        ),
        Verdict::Allow
    );
    // An edit between the commits is not a test.
    assert_eq!(
        verdict(
            &catalog,
            &[
                start,
                test_run(),
                commit(Some(true)),
                edit("src/a.rs"),
                commit(None)
            ]
        ),
        violated()
    );
}

/// FR33, UC1: the event that closes an interval is judged with the interval before it, and
/// the interval starts again before the next event: `once(commit, Since(commit))` is true on a
/// commit and on nothing else, and `count(commit, Since(commit))` is at most 1.
#[test]
fn the_closing_event_is_judged_with_the_interval_before_it() {
    let advise = |rule| {
        let mut guard = test_guard(Level::Advise);
        guard.subject = EventKind::ToolUse;
        guard.rule = Rule::Structural(rule);
        guard.fixtures = vec![];
        catalog(vec![guard], vec![])
    };
    let since = || Scope::Since(commit_filter(false));
    let once = advise(Pred::Once {
        event: commit_filter(false),
        scope: since(),
    });
    let start = agent(Body::TaskStart);
    assert_eq!(
        verdict(&once, &[start.clone(), commit(None)]),
        Verdict::Allow
    );
    assert_eq!(
        verdict(&once, &[start.clone(), commit(None), edit("src/a.rs")]),
        Verdict::Warn(vec![Cause::Violated(id(GUARD))])
    );
    assert_eq!(
        verdict(
            &once,
            &[start.clone(), commit(None), edit("src/a.rs"), commit(None)]
        ),
        Verdict::Allow
    );
    let twice = advise(Pred::Not(Box::new(Pred::Count {
        event: commit_filter(false),
        scope: since(),
        cmp: Cmp::Ge,
        n: 2,
    })));
    assert_eq!(
        verdict(
            &twice,
            &[start.clone(), commit(None), commit(None), commit(None)]
        ),
        Verdict::Allow
    );
    // Closing loosens a count: without the scope, the third commit is the third.
    let task = advise(Pred::Not(Box::new(Pred::Count {
        event: commit_filter(false),
        scope: Scope::Task,
        cmp: Cmp::Ge,
        n: 2,
    })));
    assert_eq!(
        verdict(&task, &[start, commit(None), commit(None), commit(None)]),
        Verdict::Warn(vec![Cause::Violated(id(GUARD))])
    );
}

/// FR33, UC1: a `Since` scope starts again at a new session and not at a new task.
#[test]
fn a_since_scope_starts_again_at_a_session_and_not_at_a_task() {
    let catalog = catalog(
        vec![stop_guard_in(Scope::Since(commit_filter(false)))],
        vec![],
    );
    let stop = agent(Body::Stop);
    let task = agent(Body::TaskStart);
    assert_eq!(
        verdict(
            &catalog,
            &[task.clone(), test_run(), task.clone(), stop.clone()]
        ),
        Verdict::Allow
    );
    assert_eq!(
        verdict(
            &catalog,
            &[task, test_run(), agent(Body::SessionStart), stop]
        ),
        violated()
    );
}

/// FR33, UC1: one event can close several `Since` scopes at once, and each starts again.
#[test]
fn two_since_scopes_close_on_one_event() {
    let edited = || EventFilter {
        kind: EventKind::ToolUse,
        cond: Some(Cond::Eq(Field::Tool, Lit::Text("Edit".to_owned()))),
    };
    let bash_call = EventFilter {
        kind: EventKind::ToolUse,
        cond: Some(Cond::Eq(Field::Tool, Lit::Text("Bash".to_owned()))),
    };
    // No edit since the last commit, and none since the last shell call.
    let mut guard = test_guard(Level::Force);
    guard.rule = Rule::Structural(Pred::All(vec![
        Pred::Not(Box::new(Pred::Once {
            event: edited(),
            scope: Scope::Since(commit_filter(false)),
        })),
        Pred::Not(Box::new(Pred::Once {
            event: edited(),
            scope: Scope::Since(bash_call),
        })),
    ]));
    guard.fixtures = vec![
        fixture(
            "edited",
            vec![agent(Body::TaskStart), edit("src/a.rs"), agent(Body::Stop)],
            Expect::Violated,
        ),
        fixture(
            "clean",
            vec![agent(Body::TaskStart), agent(Body::Stop)],
            Expect::Satisfied,
        ),
    ];
    let catalog = catalog(vec![guard], vec![]);
    let start = agent(Body::TaskStart);
    let stop = agent(Body::Stop);
    // A commit is also a shell call: both scopes close on it.
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                edit("src/a.rs"),
                commit(Some(true)),
                stop.clone()
            ]
        ),
        Verdict::Allow
    );
    // Another shell call closes only one of them.
    assert_eq!(
        verdict(
            &catalog,
            &[start, edit("src/a.rs"), bash("ls", Some(true)), stop]
        ),
        violated()
    );
}

/// FR33, FR20, UC3: an unreadable record closes a `Since` scope as unknown only when the filter's
/// kind is recorded where the record was lost; elsewhere a fact already seen stays seen.
#[test]
fn an_unreadable_record_closes_a_since_scope_only_where_its_kind_is_recorded() {
    let stop = agent(Body::Stop);
    let tested_after_commit = catalog(
        vec![stop_guard_in(Scope::Since(commit_filter(false)))],
        vec![],
    );
    let events = |lost| {
        [
            agent(Body::TaskStart),
            test_run(),
            unreadable(lost),
            stop.clone(),
        ]
    };
    // A commit is a tool use, recorded in the transcript: the lost line may have been one.
    assert_eq!(
        verdict(&tested_after_commit, &events(Source::Transcript)),
        unknown()
    );
    // A lost record of the evidence cannot have been a tool use.
    assert_eq!(
        verdict(&tested_after_commit, &events(Source::Evidence)),
        Verdict::Allow
    );

    // The other way round, for a kind recorded in the evidence.
    let judged = EventFilter {
        kind: EventKind::Judged,
        cond: None,
    };
    let tested_after_judgment = catalog(vec![stop_guard_in(Scope::Since(judged))], vec![]);
    assert_eq!(
        verdict(&tested_after_judgment, &events(Source::Evidence)),
        unknown()
    );
    assert_eq!(
        verdict(&tested_after_judgment, &events(Source::Transcript)),
        Verdict::Allow
    );

    // A mode switch the agent writes is read from the transcript and closes the scope like any
    // other, so a lost record of either source may have been one.
    let switched = EventFilter {
        kind: EventKind::ModeSwitch,
        cond: None,
    };
    let tested_after_switch = catalog(vec![stop_guard_in(Scope::Since(switched))], vec![]);
    for lost in [Source::Transcript, Source::Evidence] {
        assert_eq!(verdict(&tested_after_switch, &events(lost)), unknown());
    }
}

/// FR33, FR20: when the filter's condition is not known on an event (`ok` of a call whose result
/// has not come back), it is not known whether the interval closed, and the guard cannot tell.
#[test]
fn a_filter_whose_condition_is_unknown_leaves_the_close_unknown() {
    let catalog = catalog(
        vec![stop_guard_in(Scope::Since(commit_filter(true)))],
        vec![],
    );
    let start = agent(Body::TaskStart);
    let stop = agent(Body::Stop);
    let after = |commit| verdict(&catalog, &[start.clone(), test_run(), commit, stop.clone()]);
    assert_eq!(after(commit(None)), unknown());
    // A commit that failed does not close the interval.
    assert_eq!(after(commit(Some(false))), Verdict::Allow);
    assert_eq!(after(commit(Some(true))), violated());
}

/// A stopping guard on every tool use but a commit, which is what an exemption can lift.
fn no_commit_guard() -> PolicyDef {
    let mut guard = test_guard(Level::Force);
    guard.subject = EventKind::ToolUse;
    guard.rule = Rule::Structural(Pred::Now(Cond::Not(Box::new(Cond::Words(
        Field::Command,
        words("git commit"),
    )))));
    guard.fixtures = vec![
        fixture(
            "commit",
            vec![agent(Body::TaskStart), commit(None)],
            Expect::Violated,
        ),
        fixture(
            "edit",
            vec![agent(Body::TaskStart), edit("src/a.rs")],
            Expect::Satisfied,
        ),
    ];
    guard
}

fn exemption(target: Option<Cond>, lifetime: Lifetime) -> Event {
    user(Body::Exempt(Exempt {
        guard: id(GUARD),
        target,
        lifetime,
        reason: "for now".parse().unwrap(),
    }))
}

/// FR33, FR9, UC1: an exemption that lasts within `Since(g)` ends after `g`: `g` itself is judged
/// with it, the next event without it. A `g` that failed does not end it, and one whose result is
/// not known ends it, since it is not known whether it did.
#[test]
fn a_within_since_exemption_ends_after_the_event() {
    let catalog = catalog(vec![no_commit_guard()], vec![]);
    let start = agent(Body::TaskStart);
    let until_commit = || exemption(None, Lifetime::Within(Scope::Since(commit_filter(true))));
    let after = |first: Event| {
        verdict(
            &catalog,
            &[start.clone(), until_commit(), first, commit(Some(true))],
        )
    };
    // The closing commit is judged with the exemption still in effect.
    assert_eq!(
        verdict(
            &catalog,
            &[start.clone(), until_commit(), commit(Some(true))]
        ),
        Verdict::Allow
    );
    // The next one is not.
    assert_eq!(after(commit(Some(true))), violated());
    // A failed commit does not end it; an unknown one does.
    assert_eq!(after(commit(Some(false))), Verdict::Allow);
    assert_eq!(after(commit(None)), violated());
}

/// FR33: a filter of a `Since` scope that reads a field from another kind of event is rejected by
/// accept, wherever the scope stands.
#[test]
fn an_ill_typed_since_filter_is_rejected() {
    let bad = || {
        Scope::Since(EventFilter {
            kind: EventKind::Stop,
            cond: Some(Cond::Eq(Field::Ok, Lit::Bool(true))),
        })
    };
    let mut guard = test_guard(Level::Advise);
    guard.fixtures = vec![];
    guard.rule = Rule::Structural(Pred::All(vec![
        tested_in(bad()),
        Pred::Count {
            event: commit_filter(false),
            scope: bad(),
            cmp: Cmp::Ge,
            n: 2,
        },
        Pred::Last {
            field: Field::Ok,
            scope: bad(),
            value: Lit::Bool(true),
        },
    ]));
    let error = AcceptError::Predicate {
        policy: id(GUARD),
        error: super::predicate::PredError::OtherKind {
            field: Field::Ok,
            read_from: EventKind::Stop,
        },
    };
    assert_eq!(rejected(vec![guard], vec![]), vec![error; 3]);
}

/// FR33, FR9, UC4: an exemption that arrives as an event takes effect only if it type-checks
/// against the guard it names, its target and the filter of its `Within(Since(..))` alike.
#[test]
fn an_ill_typed_exemption_takes_no_effect() {
    let mut guard = test_guard(Level::Force);
    guard.subject = EventKind::ToolUse;
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
    let on_a = Cond::Eq(Field::Path, Lit::Text("src/a.rs".to_owned()));
    let judged = |exempt: Event| {
        verdict(
            &catalog,
            &[agent(Body::TaskStart), exempt, edit("src/a.rs")],
        )
    };
    // Well typed: it covers the edit.
    assert_eq!(
        judged(exemption(Some(on_a.clone()), Lifetime::Next)),
        Verdict::Allow
    );
    // The target reads the type of an agent from a tool use, though it would hold on this
    // event through its other branch.
    let ill_target = Cond::Any(vec![
        on_a.clone(),
        Cond::Eq(Field::AgentType, Lit::Text("x".to_owned())),
    ]);
    assert_eq!(
        judged(exemption(Some(ill_target), Lifetime::Next)),
        violated()
    );
    // The same for the filter of the scope it lasts within.
    let within = |filter| exemption(Some(on_a.clone()), Lifetime::Within(Scope::Since(filter)));
    let good = EventFilter {
        kind: EventKind::Stop,
        cond: None,
    };
    let bad = EventFilter {
        kind: EventKind::Stop,
        cond: Some(Cond::Eq(Field::Ok, Lit::Bool(true))),
    };
    assert_eq!(judged(within(good)), Verdict::Allow);
    assert_eq!(judged(within(bad)), violated());
}

// ---------------------------------------------------------------------------------------------
// Authority: who may change whose rules

const AGENT_REWARD: &str = "00000000-0000-7000-8000-000000000004";
const HELPER_REWARD: &str = "00000000-0000-7000-8000-000000000005";

/// A guard of the agent's own, beside the user's: the same checks, written by the agent.
fn agent_guard(level: Level) -> PolicyDef {
    let mut guard = test_guard(level);
    guard.id = id(OTHER);
    guard.name = "agent-guard".parse().unwrap();
    guard.author = the_agent();
    guard
}

/// A second guard of the user's.
fn other_user_guard(level: Level) -> PolicyDef {
    let mut guard = test_guard(level);
    guard.id = id(OTHER);
    guard.name = "other-guard".parse().unwrap();
    guard
}

/// A reward bound by `bound_by`, written by `author`.
fn reward_by(policy: &str, bound_by: &str, author: Principal) -> PolicyDef {
    let mut reward = clippy_reward(RewardLevel::Advise);
    reward.id = id(policy);
    reward.name = format!("reward-{policy}").parse().unwrap();
    reward.polarity = Polarity::Reward {
        level: RewardLevel::Advise,
        bound_by: id(bound_by),
    };
    reward.author = author;
    reward
}

fn graph_of(policies: Vec<PolicyDef>, overrides: Vec<Override>) -> PolicyGraph {
    PolicyGraph {
        policies,
        overrides,
    }
}

fn over(layer: OverrideLayer, policy: &str, change: Change, author: Principal) -> Override {
    Override {
        layer,
        policy: id(policy),
        change,
        author,
    }
}

fn mode(name: &str) -> Mode {
    name.parse().unwrap()
}

/// What the policy comes to under the mode (no mode when `None`).
fn effect_of(catalog: &Catalog, policy: &str, under: Option<&str>) -> Effect {
    let under = Known::Known(under.map(mode));
    catalog
        .effective(&under)
        .policies
        .iter()
        .find(|p| p.policy.id() == id(policy))
        .unwrap()
        .effect
}

/// The loosenings of a change that was rejected for loosening, and nothing else.
fn loosenings(result: Result<Catalog, ChangeRejected>) -> Vec<Loosening> {
    match result.unwrap_err() {
        ChangeRejected::Loosens(loosenings) => loosenings,
        other => panic!("rejected, but not for loosening: {other:?}"),
    }
}

fn uncovered_policy(policy: &str) -> Loosening {
    Loosening::Uncovered {
        target: Target::Policy(id(policy)),
    }
}

fn below(policy: &str, under: Option<&str>, before: Effect, after: Effect) -> Loosening {
    Loosening::BelowUncovered {
        policy: id(policy),
        mode: under.map(mode),
        before,
        after,
    }
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

/// FR16, UC19: an agent below the user adds a guard of its own without approval, and it takes
/// effect: it stops, and the user's rules are what they were.
#[test]
fn an_agent_below_the_user_adds_a_guard_and_it_takes_effect() {
    let before = catalog(vec![test_guard(Level::Advise)], vec![]);
    let after = graph_of(
        vec![test_guard(Level::Advise), agent_guard(Level::Force)],
        vec![],
    );
    let changed = before.change(after, &the_agent()).unwrap();
    assert_eq!(effect_of(&changed, OTHER, None), Effect::On(Level::Force));
    assert_eq!(effect_of(&changed, GUARD, None), Effect::On(Level::Advise));
    let events = [agent(Body::TaskStart), agent(Body::Stop)];
    assert!(matches!(verdict(&changed, &events), Verdict::Deny(_)));
    // The catalog it came from is not changed by the change.
    assert_eq!(before.policies().len(), 1);
}

/// FR5, FR6, FR7, FR18, UC20: an agent cannot lower the user's guard, turn it off, remove it or
/// rewrite its rule, whether in the guard itself or by an override of its own; the user can.
#[test]
fn an_agent_cannot_loosen_the_users_guard() {
    let before = catalog(vec![test_guard(Level::Force)], vec![]);
    let by_agent = |policies, overrides| before.change(graph_of(policies, overrides), &the_agent());

    let mut off = test_guard(Level::Force);
    off.enabled = false;
    let mut rewritten = test_guard(Level::Force);
    rewritten.rule = Rule::Structural(Pred::All(vec![tested()]));
    let in_the_guard = [
        test_guard(Level::Advise),
        off.clone(),
        rewritten,
        // Authored by the agent, so that the guard is the agent's own: taken over.
        {
            let mut taken = test_guard(Level::Force);
            taken.author = the_agent();
            taken
        },
    ];
    for guard in in_the_guard {
        assert_eq!(
            loosenings(by_agent(vec![guard], vec![])),
            vec![uncovered_policy(GUARD)]
        );
    }
    assert_eq!(
        loosenings(by_agent(vec![], vec![])),
        vec![uncovered_policy(GUARD)]
    );

    let by_override = |change| {
        by_agent(
            vec![test_guard(Level::Force)],
            vec![over(OverrideLayer::Project, GUARD, change, the_agent())],
        )
    };
    let force = Effect::On(Level::Force);
    assert_eq!(
        loosenings(by_override(Change::Level(Level::Advise))),
        vec![below(GUARD, None, force, Effect::On(Level::Advise))]
    );
    assert_eq!(
        loosenings(by_override(Change::Off)),
        vec![below(GUARD, None, force, Effect::Off)]
    );

    // The user, who covers what it wrote, changes its own guard freely.
    let user = |policies| before.change(graph_of(policies, vec![]), &the_user());
    assert!(user(vec![test_guard(Level::Advise)]).is_ok());
    assert!(user(vec![off]).is_ok());
    assert!(user(vec![]).is_ok());
}

/// FR2, FR18: an agent cannot weaken the examples of the user's guard, by marking one as a known
/// gap or by dropping one: they are the evidence for the rule. The user may.
#[test]
fn an_agent_cannot_weaken_the_examples_of_the_users_guard() {
    // An advising guard, since a stopping one needs both of its examples to be accepted at all.
    let before = catalog(vec![test_guard(Level::Advise)], vec![]);
    let mut marked = test_guard(Level::Advise);
    marked.fixtures[0].known_gap = true;
    let mut dropped = test_guard(Level::Advise);
    dropped.fixtures.pop();
    for guard in [marked, dropped] {
        let after = graph_of(vec![guard], vec![]);
        assert_eq!(
            loosenings(before.change(after.clone(), &the_agent())),
            vec![uncovered_policy(GUARD)]
        );
        assert!(before.change(after, &the_user()).is_ok());
    }
}

/// FR7, FR13, UC9: an agent cannot remove or lower the user's reward, nor turn off the guard
/// that binds it, which takes the reward with it.
#[test]
fn an_agent_cannot_remove_the_users_reward() {
    let policies = || vec![test_guard(Level::Force), clippy_reward(RewardLevel::Advise)];
    let before = catalog(policies(), vec![]);
    let by_agent = |policies, overrides| before.change(graph_of(policies, overrides), &the_agent());

    assert_eq!(
        loosenings(by_agent(vec![test_guard(Level::Force)], vec![])),
        vec![uncovered_policy(REWARD)]
    );
    assert_eq!(
        loosenings(by_agent(
            vec![test_guard(Level::Force), clippy_reward(RewardLevel::Inform)],
            vec![]
        )),
        vec![uncovered_policy(REWARD)]
    );
    // Turning the guard off turns its reward off: both fall below what they are.
    let off = over(OverrideLayer::Project, GUARD, Change::Off, the_agent());
    assert_eq!(
        loosenings(by_agent(policies(), vec![off])),
        vec![
            below(GUARD, None, Effect::On(Level::Force), Effect::Off),
            below(REWARD, None, Effect::On(Level::Advise), Effect::Off),
        ]
    );
}

/// FR18, UC20: an agent removes the guard it added and the override it placed, and the user's
/// rules are what they were before it.
#[test]
fn an_agent_removes_its_own_guard_and_its_own_override() {
    let raise = over(
        OverrideLayer::Project,
        GUARD,
        Change::Level(Level::Force),
        the_agent(),
    );
    let before = catalog(
        vec![test_guard(Level::Advise), agent_guard(Level::Force)],
        vec![raise],
    );
    assert_eq!(effect_of(&before, GUARD, None), Effect::On(Level::Force));

    let changed = before
        .change(
            graph_of(vec![test_guard(Level::Advise)], vec![]),
            &the_agent(),
        )
        .unwrap();
    assert_eq!(effect_of(&changed, GUARD, None), Effect::On(Level::Advise));
    assert!(changed.policy(id(OTHER)).is_none());
}

/// FR5, FR16, UC19: an override of the agent's raises the user's guard, in the project and in
/// a mode, and takes effect.
#[test]
fn an_agents_override_can_raise_the_users_guard() {
    let before = catalog(vec![test_guard(Level::Advise)], vec![]);
    let raise = |layer| over(layer, GUARD, Change::Level(Level::Force), the_agent());
    let after = graph_of(
        vec![test_guard(Level::Advise)],
        vec![
            raise(OverrideLayer::Project),
            // Even when the mode is the one that was never named before.
            raise(OverrideLayer::Mode(mode("bug-fix"))),
        ],
    );
    let changed = before.change(after, &the_agent()).unwrap();
    assert_eq!(effect_of(&changed, GUARD, None), Effect::On(Level::Force));
    assert_eq!(
        effect_of(&changed, GUARD, Some("bug-fix")),
        Effect::On(Level::Force)
    );
}

/// FR5, FR6, UC8: an override for a mode that nothing named before cannot weaken the user's
/// guard: the compared modes are those of the change too.
#[test]
fn an_override_for_a_new_mode_cannot_weaken_the_users_guard() {
    let before = catalog(vec![test_guard(Level::Force)], vec![]);
    let weaken = |change| {
        graph_of(
            vec![test_guard(Level::Force)],
            vec![over(
                OverrideLayer::Mode(mode("explore")),
                GUARD,
                change,
                the_agent(),
            )],
        )
    };
    let force = Effect::On(Level::Force);
    assert_eq!(
        loosenings(before.change(weaken(Change::Off), &the_agent())),
        vec![below(GUARD, Some("explore"), force, Effect::Off)]
    );
    assert_eq!(
        loosenings(before.change(weaken(Change::Level(Level::Inform)), &the_agent())),
        vec![below(
            GUARD,
            Some("explore"),
            force,
            Effect::On(Level::Inform)
        )]
    );
}

/// FR6, FR5: the agent removes the user's override that turns a guard off, which tightens, and
/// it is accepted.
#[test]
fn removing_the_users_off_override_tightens_and_is_accepted() {
    let off = over(OverrideLayer::Project, GUARD, Change::Off, the_user());
    let before = catalog(vec![test_guard(Level::Force)], vec![off]);
    assert_eq!(effect_of(&before, GUARD, None), Effect::Off);

    let changed = before
        .change(
            graph_of(vec![test_guard(Level::Force)], vec![]),
            &the_agent(),
        )
        .unwrap();
    assert_eq!(effect_of(&changed, GUARD, None), Effect::On(Level::Force));
}

/// FR6, FR5: the conservative case. The agent removes the user's override that turns a guard off
/// and places an override of its own that sets it to Inform: the guard is stricter than before,
/// but weaker than it is with nothing of the agent's, so the change is rejected. Removing the
/// override alone is accepted.
#[test]
fn removing_an_off_override_and_placing_an_inform_one_is_rejected_though_it_tightens() {
    let off = over(OverrideLayer::Project, GUARD, Change::Off, the_user());
    let before = catalog(vec![test_guard(Level::Force)], vec![off]);
    let inform = |layer| {
        graph_of(
            vec![test_guard(Level::Force)],
            vec![over(
                layer,
                GUARD,
                Change::Level(Level::Inform),
                the_agent(),
            )],
        )
    };
    let force = Effect::On(Level::Force);

    // In another layer: stricter in every mode, and still below what the guard is without it.
    let elsewhere = inform(OverrideLayer::Mode(mode("explore")));
    let stricter = Catalog::accept(elsewhere.clone(), hierarchy()).unwrap();
    for under in [None, Some("explore")] {
        assert!(effect_of(&stricter, GUARD, under) > effect_of(&before, GUARD, under));
    }
    assert_eq!(
        loosenings(before.change(elsewhere, &the_agent())),
        vec![below(
            GUARD,
            Some("explore"),
            force,
            Effect::On(Level::Inform)
        )]
    );

    // In the same layer, the agent also takes over what was the user's.
    assert_eq!(
        loosenings(before.change(inform(OverrideLayer::Project), &the_agent())),
        vec![
            Loosening::Uncovered {
                target: Target::Override(OverrideLayer::Project, id(GUARD))
            },
            below(GUARD, None, force, Effect::On(Level::Inform)),
        ]
    );
}

/// FR16, FR18: an item refers only to items of its own author or above: what is above never
/// depends on what is below. The agent's reward may be bound by the user's guard; the user's
/// reward may not be bound by the agent's guard, nor the user's override target the agent's.
#[test]
fn an_item_refers_only_to_items_of_its_own_author_or_above() {
    // The agent's reward, bound by the user's guard.
    catalog(
        vec![
            test_guard(Level::Force),
            reward_by(AGENT_REWARD, GUARD, the_agent()),
        ],
        vec![],
    );
    // The user's reward, bound by the agent's guard.
    let mut under_the_agent = agent_guard(Level::Force);
    under_the_agent.id = id(GUARD);
    let errors = rejected(
        vec![under_the_agent.clone(), clippy_reward(RewardLevel::Advise)],
        vec![],
    );
    assert_eq!(
        errors,
        vec![AcceptError::ReferencesBelow {
            item: Target::Policy(id(REWARD)),
            referenced: id(GUARD),
        }]
    );
    // The user's override, on the agent's guard.
    let errors = rejected(
        vec![under_the_agent],
        vec![over(
            OverrideLayer::Project,
            GUARD,
            Change::Level(Level::Inform),
            the_user(),
        )],
    );
    assert_eq!(
        errors,
        vec![AcceptError::ReferencesBelow {
            item: Target::Override(OverrideLayer::Project, id(GUARD)),
            referenced: id(GUARD),
        }]
    );
}

/// FR16, FR18: an author must be of the hierarchy, whether of a policy or of an override, and so
/// must the one who changes.
#[test]
fn an_author_or_a_changer_outside_the_hierarchy_is_rejected() {
    let stranger = Principal::new("stranger");
    let mut written = test_guard(Level::Force);
    written.author = stranger.clone();
    assert_eq!(
        rejected(vec![written], vec![]),
        vec![AcceptError::UnknownAuthor {
            item: Target::Policy(id(GUARD)),
            author: stranger.clone(),
        }]
    );
    assert_eq!(
        rejected(
            vec![test_guard(Level::Force)],
            vec![over(
                OverrideLayer::Project,
                GUARD,
                Change::Off,
                stranger.clone()
            )]
        ),
        vec![AcceptError::UnknownAuthor {
            item: Target::Override(OverrideLayer::Project, id(GUARD)),
            author: stranger.clone(),
        }]
    );

    // A change whose graph has such an author is invalid.
    let before = catalog(vec![test_guard(Level::Force)], vec![]);
    let mut also = agent_guard(Level::Force);
    also.author = stranger.clone();
    let result = before.change(
        graph_of(vec![test_guard(Level::Force), also], vec![]),
        &the_user(),
    );
    assert!(matches!(result.unwrap_err(), ChangeRejected::Invalid(_)));
    // And one who is not of the hierarchy cannot change, even with nothing changed.
    assert_eq!(
        before.change(before.graph(), &stranger).unwrap_err(),
        ChangeRejected::UnknownPrincipal
    );
}

/// FR14, UC5, UC10: a meta policy is placed by a root, and no change differs in one, whoever
/// makes it, a root included.
#[test]
fn a_meta_policy_never_differs_for_anyone() {
    let meta = |level| {
        let mut guard = test_guard(level);
        guard.layer = DefLayer::Meta;
        guard
    };
    // Only a root places one.
    let mut by_the_agent = meta(Level::Force);
    by_the_agent.author = the_agent();
    assert_eq!(
        rejected(vec![by_the_agent], vec![]),
        vec![AcceptError::MetaAuthorNotRoot {
            policy: id(GUARD),
            author: the_agent(),
        }]
    );

    let before = catalog(vec![meta(Level::Force)], vec![]);
    let mut other_meta = other_user_guard(Level::Force);
    other_meta.layer = DefLayer::Meta;
    let differences = [
        (vec![meta(Level::Force), other_meta], vec![id(OTHER)]),
        (vec![meta(Level::Advise)], vec![id(GUARD)]),
        (vec![], vec![id(GUARD)]),
    ];
    for by in [the_user(), the_agent()] {
        for (policies, ids) in &differences {
            assert_eq!(
                before
                    .change(graph_of(policies.clone(), vec![]), &by)
                    .unwrap_err(),
                ChangeRejected::Meta(ids.clone())
            );
        }
    }
    // What is not meta is another matter: a root adds a guard beside it.
    let beside = graph_of(
        vec![meta(Level::Force), other_user_guard(Level::Force)],
        vec![],
    );
    assert!(before.change(beside, &the_user()).is_ok());
}

/// FR5, FR6, FR16: a change that tightens one of the user's guards and loosens another is
/// rejected as a whole, for the loosening only; each half alone is judged on its own.
#[test]
fn a_change_that_mixes_tightening_and_loosening_is_rejected_as_a_whole() {
    let before = catalog(
        vec![test_guard(Level::Advise), other_user_guard(Level::Advise)],
        vec![],
    );
    let both = graph_of(
        vec![test_guard(Level::Force), other_user_guard(Level::Inform)],
        vec![],
    );
    assert_eq!(
        loosenings(before.change(both, &the_agent())),
        vec![uncovered_policy(OTHER)]
    );
    let tightens = graph_of(
        vec![test_guard(Level::Force), other_user_guard(Level::Advise)],
        vec![],
    );
    let changed = before.change(tightens, &the_agent()).unwrap();
    assert_eq!(effect_of(&changed, GUARD, None), Effect::On(Level::Force));
}

/// FR16, FR18: a graph a catalog accepts, narrowed to what a principal does not cover, is
/// accepted again, for every principal of the hierarchy.
#[test]
fn the_narrowed_graph_always_accepts() {
    let graph = graph_of(
        vec![
            test_guard(Level::Force),
            clippy_reward(RewardLevel::Advise),
            agent_guard(Level::Force),
            reward_by(AGENT_REWARD, GUARD, the_agent()),
            reward_by(HELPER_REWARD, OTHER, the_helper()),
        ],
        vec![
            over(
                OverrideLayer::Project,
                GUARD,
                Change::Level(Level::Advise),
                the_user(),
            ),
            over(
                OverrideLayer::Mode(mode("explore")),
                OTHER,
                Change::Level(Level::Advise),
                the_agent(),
            ),
            over(OverrideLayer::Project, OTHER, Change::Off, the_helper()),
        ],
    );
    let full = Catalog::accept(graph.clone(), hierarchy()).unwrap();
    assert_eq!(full.graph(), graph);

    let remaining = |by: &Principal| {
        let narrowed = graph.not_covered_by(&hierarchy(), by);
        Catalog::accept(narrowed.clone(), hierarchy()).unwrap();
        narrowed.policies.len() + narrowed.overrides.len()
    };
    assert_eq!(remaining(&the_user()), 0);
    // The agent and the helper below it are gone; the user's two policies and one override stay.
    assert_eq!(remaining(&the_agent()), 3);
    // The helper's own reward and override are gone.
    assert_eq!(remaining(&the_helper()), 6);
}

/// FR16, FR18: two roots do not cover each other: the work of one is not the other's to loosen,
/// and each changes its own freely.
#[test]
fn two_roots_do_not_cover_each_other() {
    let (a, b) = (Principal::new("a"), Principal::new("b"));
    let authority = Authority::new([(a.clone(), None), (b.clone(), None)]).unwrap();
    assert!(authority.covers(&a, &a));
    assert!(!authority.covers(&a, &b));
    assert!(!authority.covers(&b, &a));
    assert!(authority.is_root(&a) && authority.is_root(&b));

    let mut guard_a = test_guard(Level::Force);
    guard_a.author = a.clone();
    let mut guard_b = other_user_guard(Level::Force);
    guard_b.author = b.clone();
    let before = Catalog::accept(
        graph_of(vec![guard_a.clone(), guard_b.clone()], vec![]),
        authority,
    )
    .unwrap();

    let mut lowered_b = guard_b.clone();
    lowered_b.polarity = Polarity::Guard {
        level: Level::Advise,
    };
    assert_eq!(
        loosenings(before.change(graph_of(vec![guard_a.clone(), lowered_b], vec![]), &a)),
        vec![uncovered_policy(OTHER)]
    );
    let mut lowered_a = guard_a;
    lowered_a.polarity = Polarity::Guard {
        level: Level::Advise,
    };
    assert!(
        before
            .change(graph_of(vec![lowered_a, guard_b], vec![]), &a)
            .is_ok()
    );
}

/// FR16, FR18: a hierarchy with a cycle, an unknown parent, a principal twice or no root is
/// never made; what is above and what is beside are told apart.
#[test]
fn a_hierarchy_with_a_cycle_is_rejected() {
    let p = |key: &str| Principal::new(key);
    let link = |key: &str, parent: Option<&str>| (p(key), parent.map(p));

    assert_eq!(
        Authority::new([link("a", Some("b")), link("b", Some("a"))]).unwrap_err(),
        AuthorityError::Cycle(p("a"))
    );
    // A cycle beside a root is still a cycle.
    assert_eq!(
        Authority::new([link("r", None), link("a", Some("b")), link("b", Some("a"))]).unwrap_err(),
        AuthorityError::Cycle(p("a"))
    );
    assert_eq!(
        Authority::new([link("r", None), link("a", Some("a"))]).unwrap_err(),
        AuthorityError::Cycle(p("a"))
    );
    assert_eq!(
        Authority::new([link("r", None), link("a", Some("x"))]).unwrap_err(),
        AuthorityError::UnknownParent {
            principal: p("a"),
            parent: p("x"),
        }
    );
    assert_eq!(
        Authority::new([link("r", None), link("r", None)]).unwrap_err(),
        AuthorityError::Duplicate(p("r"))
    );
    assert_eq!(Authority::new([]).unwrap_err(), AuthorityError::Empty);

    let authority = hierarchy();
    assert!(authority.covers(&the_user(), &the_helper()));
    assert!(authority.covers(&the_agent(), &the_helper()));
    assert!(!authority.covers(&the_helper(), &the_agent()));
    assert!(authority.covers(&the_agent(), &the_agent()));
    assert_eq!(authority.roots().collect::<Vec<_>>(), vec![&the_user()]);
}

/// FR16, FR18: a catalog accepted again with another hierarchy uses it. Where the agent is below
/// the user, the user removes the agent's guard; where they are two roots, it may not; and a
/// hierarchy without the agent does not accept what the agent wrote.
#[test]
fn a_catalog_accepted_again_with_a_new_hierarchy_uses_it() {
    let graph = graph_of(
        vec![test_guard(Level::Force), agent_guard(Level::Force)],
        vec![],
    );
    let removed = || graph_of(vec![test_guard(Level::Force)], vec![]);

    let below = Catalog::accept(graph.clone(), hierarchy()).unwrap();
    assert!(below.change(removed(), &the_user()).is_ok());

    let two_roots = Authority::new([(the_user(), None), (the_agent(), None)]).unwrap();
    let beside = Catalog::accept(graph.clone(), two_roots.clone()).unwrap();
    assert_eq!(beside.authority(), &two_roots);
    assert_eq!(
        loosenings(beside.change(removed(), &the_user())),
        vec![uncovered_policy(OTHER)]
    );

    let errors = Catalog::accept(graph, Authority::single(the_user())).unwrap_err();
    assert_eq!(
        errors.0,
        vec![AcceptError::UnknownAuthor {
            item: Target::Policy(id(OTHER)),
            author: the_agent(),
        }]
    );
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
