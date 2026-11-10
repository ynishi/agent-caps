//! Helpers shared by the scenarios: ids, events, principals, fixtures, and the two entry points
//! every scenario goes through (`Catalog::accept` for a graph, `Catalog::fold` plus `judge` for a
//! verdict). Nothing here decides anything the domain decides. A helper that only one module uses
//! lives in that module.

use agent_caps_core::domain::authority::{Authority, Principal};
use agent_caps_core::domain::catalog::{AcceptError, Catalog, Effect, Rejected};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::exempt::{Exempt, Lifetime};
use agent_caps_core::domain::judge::{Cause, Outcome, Verdict, judge};
use agent_caps_core::domain::name::{CommandWords, GlobPattern, Mode, PolicyId};
use agent_caps_core::domain::policy::{
    Change, DefLayer, Expect, Fixture, Level, Override, OverrideLayer, Polarity, PolicyDef,
    PolicyGraph, RewardLevel, Rule,
};
use agent_caps_core::domain::predicate::{Cond, EventFilter, Lit, Pred, Scope};
use agent_caps_core::domain::schema::{At, EventKind, Field, KindSet};
use agent_caps_core::domain::state::Known;

pub const GUARD: &str = "00000000-0000-7000-8000-000000000001";
pub const REWARD: &str = "00000000-0000-7000-8000-000000000002";
pub const OTHER: &str = "00000000-0000-7000-8000-000000000003";

pub fn id(text: &str) -> PolicyId {
    text.parse().unwrap()
}

pub fn words(text: &str) -> CommandWords {
    CommandWords::new(text.split_whitespace().map(str::to_owned).collect()).unwrap()
}

/// The event, by the principal, at the instant.
pub fn at(by: Principal, millis: i64, body: Body) -> Event {
    Event {
        at: At::from_millis(millis),
        by,
        body,
    }
}

/// The event by the principal below the root of the scenarios' hierarchy.
pub fn agent(body: Body) -> Event {
    at(the_agent(), 0, body)
}

/// The event by the root of the scenarios' hierarchy.
pub fn user(body: Body) -> Event {
    at(the_user(), 0, body)
}

pub fn bash(command: &str, ok: Option<bool>) -> Event {
    agent(Body::ToolUse {
        tool: "Bash".to_owned(),
        command: Some(words(command)),
        path: None,
        ok,
    })
}

pub fn edit(path: &str) -> Event {
    agent(Body::ToolUse {
        tool: "Edit".to_owned(),
        command: None,
        path: Some(path.to_owned()),
        ok: None,
    })
}

pub fn read(path: &str) -> Event {
    agent(Body::ToolUse {
        tool: "Read".to_owned(),
        command: None,
        path: Some(path.to_owned()),
        ok: None,
    })
}

/// A record that could not be read, and may have been an event of any of the kinds.
pub fn unreadable(may_have_been: &[EventKind]) -> Event {
    agent(Body::Unreadable {
        may_have_been: KindSet::new(may_have_been.iter().copied()),
    })
}

/// The kinds of act a platform's transcript records, which a line lost from it may have been.
pub const ACTS: [EventKind; 6] = [
    EventKind::SessionStart,
    EventKind::AgentStart,
    EventKind::TaskStart,
    EventKind::PromptSubmit,
    EventKind::ToolUse,
    EventKind::Stop,
];

/// A line of the transcript that could not be read: it may have been any act.
pub fn lost_line() -> Event {
    unreadable(&ACTS)
}

pub fn mode(name: &str) -> Mode {
    name.parse().unwrap()
}

/// The root switches to the mode.
pub fn mode_switch(name: &str) -> Event {
    user(Body::ModeSwitch { to: mode(name) })
}

/// The one who owns the rules: the root of the hierarchy of the scenarios.
pub fn the_user() -> Principal {
    Principal::new("user")
}

/// Below the user.
pub fn the_agent() -> Principal {
    Principal::new("agent")
}

/// Below the agent.
pub fn the_helper() -> Principal {
    Principal::new("helper")
}

/// The user, the agent below it, and the helper below the agent. A scenario that does not care
/// who wrote what gives everything to the user.
pub fn authority() -> Authority {
    Authority::new([
        (the_user(), None),
        (the_agent(), Some(the_user())),
        (the_helper(), Some(the_agent())),
    ])
    .unwrap()
}

/// An override of the policy in the layer, written by `author`.
pub fn over(layer: OverrideLayer, policy: &str, change: Change, author: Principal) -> Override {
    Override {
        layer,
        policy: id(policy),
        change,
        author,
    }
}

/// A project override of the policy, written by the user.
pub fn project(policy: &str, change: Change) -> Override {
    over(OverrideLayer::Project, policy, change, the_user())
}

/// An override of the policy by the mode, written by the user.
pub fn in_mode(name: &str, policy: &str, change: Change) -> Override {
    over(OverrideLayer::Mode(mode(name)), policy, change, the_user())
}

/// `cargo test` passed within the scope.
pub fn tested_in(scope: Scope) -> Pred {
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
pub fn tested() -> Pred {
    tested_in(Scope::Task)
}

/// A commit; with `ok_only`, one that succeeded.
pub fn commit_filter(ok_only: bool) -> EventFilter {
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

/// An exemption from the root for the guard of the scenarios.
pub fn exemption(target: Option<Cond>, lifetime: Lifetime) -> Event {
    user(Body::Exempt(Exempt {
        guard: id(GUARD),
        target,
        lifetime,
        reason: "for now".parse().unwrap(),
    }))
}

pub fn fixture(name: &str, events: Vec<Event>, expect: Expect) -> Fixture {
    Fixture {
        name: name.to_owned(),
        events,
        expect,
        known_gap: false,
    }
}

/// A stopping guard: the end of a turn needs `cargo test` to have passed within the task.
pub fn test_guard(level: Level) -> PolicyDef {
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

/// The test guard on a commit instead of on the end of a turn, at Force: a `git commit` needs
/// `cargo test` to have passed within the task.
pub fn commit_after_test_guard() -> PolicyDef {
    let mut guard = test_guard(Level::Force);
    guard.subject = EventKind::ToolUse;
    guard.when = Some(Pred::Now(Cond::Words(Field::Command, words("git commit"))));
    guard.fixtures = vec![
        fixture(
            "commit before any test",
            vec![agent(Body::TaskStart), bash("git commit -m x", None)],
            Expect::Violated,
        ),
        fixture(
            "commit after a passing test",
            vec![
                agent(Body::TaskStart),
                bash("cargo test", Some(true)),
                bash("git commit -m x", None),
            ],
            Expect::Satisfied,
        ),
    ];
    guard
}

/// The test guard on an edit instead of on the end of a turn, at Force: no edit under `src/`
/// before the tests pass.
pub fn src_edit_guard() -> PolicyDef {
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
    guard
}

/// A reward within the guard: run clippy before stopping.
pub fn clippy_reward(level: RewardLevel) -> PolicyDef {
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

pub fn graph_of(policies: Vec<PolicyDef>, overrides: Vec<Override>) -> PolicyGraph {
    PolicyGraph {
        policies,
        overrides,
    }
}

/// `Catalog::accept` of the graph with the hierarchy of the scenarios.
pub fn accept(graph: PolicyGraph) -> Result<Catalog, Rejected> {
    Catalog::accept(graph, authority())
}

pub fn catalog(policies: Vec<PolicyDef>, overrides: Vec<Override>) -> Catalog {
    accept(graph_of(policies, overrides)).unwrap()
}

pub fn rejected(policies: Vec<PolicyDef>, overrides: Vec<Override>) -> Vec<AcceptError> {
    accept(graph_of(policies, overrides)).unwrap_err().0
}

/// Every policy of the catalog with what it comes to under the mode, in the catalog's order.
pub fn listed(catalog: &Catalog, under: Known<Option<Mode>>) -> Vec<(PolicyId, Effect)> {
    catalog
        .effective(&under)
        .policies
        .iter()
        .map(|p| (p.policy.id(), p.effect))
        .collect()
}

/// The verdict of a stopping guard (`GUARD`) that was violated.
pub fn violated() -> Verdict {
    Verdict::Deny(vec![Cause::Violated(id(GUARD))])
}

/// The verdict on the last event, with the state folded over all of them.
pub fn verdict(catalog: &Catalog, events: &[Event]) -> Verdict {
    outcome(catalog, events).verdict
}

/// The whole outcome on the last event, with the state folded over all of them.
pub fn outcome(catalog: &Catalog, events: &[Event]) -> Outcome {
    let state = catalog.fold(events);
    judge(catalog, &state, events.last().unwrap())
}

/// Judges `event` after the `log`, then appends the event and the evidence of its judgment to the
/// log, as a caller does between turns.
pub fn step(catalog: &Catalog, log: &mut Vec<Event>, event: Event) -> Outcome {
    let state = catalog.fold(log.iter().chain([&event]));
    let outcome = judge(catalog, &state, &event);
    log.push(event);
    log.extend(outcome.evidence(At::from_millis(0)));
    outcome
}
