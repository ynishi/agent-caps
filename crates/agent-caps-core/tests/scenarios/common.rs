//! Helpers shared by the scenarios: ids, events, principals, fixtures, bindings, temporary
//! adjustments, and the two entry points every scenario goes through (`Catalog::accept` for a
//! graph, given as one set of policies per author, `Catalog::fold` plus `judge` for a verdict).
//! Nothing here decides anything the domain decides. A helper that only one module uses lives in
//! that module.
//!
//! A scenario writes a policy with the level its own author puts it into effect at under every
//! mode ([`Written`]); the graph is that policy and that one binding ([`base_of`]), plus the
//! bindings the scenario gives.

use std::ops::{Deref, DerefMut};

use agent_caps_core::domain::adjust::{Adjustment, Lifetime, Temporary};
use agent_caps_core::domain::authority::{Authority, Principal};
use agent_caps_core::domain::catalog::{AcceptError, Capabilities, Catalog, Effect, Rejected};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Outcome, Verdict, judge};
use agent_caps_core::domain::name::{
    AdjustmentId, BindingId, CommandWords, GlobPattern, Mode, PolicyId,
};
use agent_caps_core::domain::policy::{
    Binding, DefLayer, Expect, Fixture, Level, ModeScope, ModeSet, Polarity, PolicyDef,
    PolicyGraph, Rule,
};
use agent_caps_core::domain::predicate::{By, Cond, EventFilter, Lit, Pred, Scope, Selector, Span};
use agent_caps_core::domain::schema::{At, EventKind, Field, KindSet};
use agent_caps_core::domain::set::{SetId, SetName, Source, Sources};
use agent_caps_core::domain::state::{Known, Origin};

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

/// The kinds of event a platform's transcript records, which a line lost from it may have been.
/// A spawn is one: it is a claim, but the platform is where it is read from.
pub const ACTS: [EventKind; 6] = [
    EventKind::SessionStart,
    EventKind::Spawn,
    EventKind::TaskStart,
    EventKind::PromptSubmit,
    EventKind::ToolUse,
    EventKind::Stop,
];

/// A line of the transcript that could not be read: it may have been any event it records.
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

/// A role, below the agent: a node of the hierarchy that a rule can read an actor against
/// (`ActorUnder`), and that a spawn can place a child under.
pub fn the_reviewer() -> Principal {
    Principal::new("reviewer")
}

/// The user, the agent below it, and the helper and the reviewer role below the agent. A
/// scenario that does not care who wrote what gives everything to the user.
pub fn authority() -> Authority {
    Authority::new([
        (the_user(), None),
        (the_agent(), Some(the_user())),
        (the_helper(), Some(the_agent())),
        (the_reviewer(), Some(the_agent())),
    ])
    .unwrap()
}

/// A policy as a scenario writes it, with the level of the binding its own author puts it into
/// effect at under every mode (`None`: no such binding, so it is off unless another binding puts it
/// into effect). It reads as the policy it holds.
#[derive(Debug, Clone)]
pub struct Written {
    pub def: PolicyDef,
    pub level: Option<Level>,
}

impl Deref for Written {
    type Target = PolicyDef;

    fn deref(&self) -> &PolicyDef {
        &self.def
    }
}

impl DerefMut for Written {
    fn deref_mut(&mut self) -> &mut PolicyDef {
        &mut self.def
    }
}

/// The policy, put into effect at the level by its author under every mode.
pub fn written(def: PolicyDef, level: Level) -> Written {
    Written {
        def,
        level: Some(level),
    }
}

/// The id of a binding of the policy: the policy's id with its first group made `b` and `n`, so
/// `n` tells the bindings of one policy apart. `0` is the binding of [`base_of`].
pub fn binding_id(policy: PolicyId, n: u8) -> BindingId {
    let text = policy.to_string();
    format!("b{n:07x}{}", &text[8..]).parse().unwrap()
}

/// The `n`th binding of the policy, at the level, under the mode scope, by `author`.
pub fn bind(policy: &str, n: u8, level: Level, mode: ModeScope, author: Principal) -> Binding {
    Binding {
        id: binding_id(id(policy), n),
        policy: id(policy),
        level,
        mode,
        author,
    }
}

/// The binding a written policy's author puts it into effect with, under every mode.
pub fn base_of(written: &Written) -> Option<Binding> {
    written.level.map(|level| Binding {
        id: binding_id(written.id, 0),
        policy: written.id,
        level,
        mode: ModeScope::Any,
        author: written.author.clone(),
    })
}

/// Only while the mode is in effect.
pub fn inside(name: &str) -> ModeScope {
    ModeScope::In(mode(name))
}

/// Only while none of the modes is in effect.
pub fn outside(names: &[&str]) -> ModeScope {
    ModeScope::Outside(ModeSet::new(names.iter().map(|n| mode(n)).collect()).unwrap())
}

/// The events the filter takes, whoever acted: what a rule over events read before it said whose
/// events it means.
pub fn anyone(filter: EventFilter) -> Selector {
    Selector {
        filter,
        by: By::Anyone,
    }
}

/// `cargo test` passed within the scope.
pub fn tested_in(scope: Scope) -> Pred {
    Pred::Once {
        select: anyone(EventFilter {
            kind: EventKind::ToolUse,
            cond: Some(Cond::All(vec![
                Cond::Words(Field::Command, words("cargo test")),
                Cond::Eq(Field::Ok, Lit::Bool(true)),
            ])),
        }),
        scope,
    }
}

/// `cargo test` passed within the task, which any actor's `TaskStart` starts again.
pub fn tested() -> Pred {
    tested_in(Scope::Span {
        span: Span::Task,
        by: By::Anyone,
    })
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

/// The id of the `n`th temporary adjustment of a scenario.
pub fn adjustment_id(n: u8) -> AdjustmentId {
    format!("a{n:07x}-0000-7000-8000-000000000000")
        .parse()
        .unwrap()
}

/// The `n`th temporary adjustment, changing `change` for the lifetime.
pub fn adjustment(n: u8, change: Temporary, lifetime: Lifetime) -> Body {
    Body::Adjust(Adjustment {
        id: adjustment_id(n),
        change,
        lifetime,
        reason: "for now".parse().unwrap(),
    })
}

/// The `n`th temporary adjustment, an exemption of `guard` with the cover, for the lifetime.
pub fn exempt_n(n: u8, guard: &str, cover: Option<Cond>, lifetime: Lifetime) -> Body {
    adjustment(
        n,
        Temporary::Exempt {
            guard: id(guard),
            cover,
        },
        lifetime,
    )
}

/// An exemption from the root for the guard of the scenarios.
pub fn exemption(cover: Option<Cond>, lifetime: Lifetime) -> Event {
    user(exempt_n(1, GUARD, cover, lifetime))
}

pub fn fixture(name: &str, events: Vec<Event>, expect: Expect) -> Fixture {
    Fixture {
        name: name.to_owned(),
        events,
        expect,
        known_gap: false,
    }
}

/// A stopping guard: the end of a turn needs `cargo test` to have passed within the task. Its
/// author binds it at `level`.
pub fn test_guard(level: Level) -> Written {
    written(test_guard_def(), level)
}

/// The test guard as a policy, with no binding.
pub fn test_guard_def() -> PolicyDef {
    PolicyDef {
        id: id(GUARD),
        name: "test-before-stop".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::Stop,
        when: None,
        rule: Rule::Structural(tested()),
        polarity: Polarity::Guard,
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
pub fn commit_after_test_guard() -> Written {
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
pub fn src_edit_guard() -> Written {
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

/// The root's advising guard on a `git push` (it has no fixtures, so it does not stop), whose rule
/// reads the judgments of the policy `read`: the last of them within the session was an
/// `allowed`. A rule that reads another's judgments.
pub fn push_after_allowed(read: &str) -> Written {
    let mut guard = test_guard(Level::Advise);
    guard.id = id(OTHER);
    guard.name = "push-after-allowed".parse().unwrap();
    guard.subject = EventKind::ToolUse;
    guard.when = Some(Pred::Now(Cond::Words(Field::Command, words("git push"))));
    guard.rule = Rule::Structural(Pred::Last {
        select: anyone(EventFilter {
            kind: EventKind::Judged,
            cond: Some(Cond::Eq(Field::Policy, Lit::Text(read.to_owned()))),
        }),
        scope: Scope::Span {
            span: Span::Session,
            by: By::Anyone,
        },
        test: Cond::Eq(Field::Judgment, Lit::Text("allowed".to_owned())),
    });
    guard.fixtures = vec![];
    guard
}

/// A reward within the guard: run clippy before stopping. Its author binds it at `level`.
pub fn clippy_reward(level: Level) -> Written {
    written(
        PolicyDef {
            id: id(REWARD),
            name: "clippy-before-stop".parse().unwrap(),
            layer: DefLayer::Base,
            subject: EventKind::Stop,
            when: None,
            rule: Rule::Structural(Pred::Once {
                select: anyone(EventFilter {
                    kind: EventKind::ToolUse,
                    cond: Some(Cond::Words(Field::Command, words("cargo clippy"))),
                }),
                scope: Scope::Span {
                    span: Span::Task,
                    by: By::Anyone,
                },
            }),
            polarity: Polarity::Reward {
                bound_by: id(GUARD),
            },
            fixtures: vec![],
            author: the_user(),
        },
        level,
    )
}

/// The graph of the written policies, each with its base binding, and the bindings given. A
/// scenario that gives a duplicate calls `PolicyGraph::parse` itself (see `graph.rs`).
pub fn graph_of(policies: Vec<Written>, bindings: Vec<Binding>) -> PolicyGraph {
    let base: Vec<Binding> = policies.iter().filter_map(base_of).collect();
    PolicyGraph::parse(
        policies.into_iter().map(|w| w.def).collect(),
        base.into_iter().chain(bindings).collect(),
    )
    .unwrap()
}

/// The graph of `graph`'s policies and of its bindings that `keep` keeps, each changed by `edit`.
pub fn rebuilt(
    graph: &PolicyGraph,
    keep: impl Fn(&Binding) -> bool,
    edit: impl Fn(&mut Binding),
) -> PolicyGraph {
    let (policies, mut bindings, classifiers) = graph.clone().into_parts();
    bindings.retain(|b| keep(b));
    bindings.iter_mut().for_each(edit);
    PolicyGraph::parse_with(policies, bindings, classifiers).unwrap()
}

/// The fixed id the scenarios give the set first named `name`: a stable hash of the name (64-bit
/// FNV-1a, its low 48 bits) as the last group of a UUID, read by `SetId`'s own parse. Sets keep it
/// when renamed. The order of two ids says nothing of their names, so a scenario that reads an
/// order of sets sorts what it expects ([`set_pair`]).
pub fn set_id(name: &str) -> SetId {
    let hash = name.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    format!("5e700000-0000-7000-8000-{:012x}", hash & 0xffff_ffff_ffff)
        .parse()
        .unwrap()
}

/// The ids of the sets named `a` and `b`, the lower first: the order a conflict names two sets in.
pub fn set_pair(a: &str, b: &str) -> [SetId; 2] {
    let mut pair = [set_id(a), set_id(b)];
    pair.sort();
    pair
}

/// The name of a set of policies.
pub fn set_name(name: &str) -> SetName {
    name.parse().unwrap()
}

/// The set named `name`, with the fixed id of that name, of `owner`, holding `graph`.
pub fn set(name: &str, owner: Principal, graph: PolicyGraph) -> Source {
    Source {
        id: set_id(name),
        name: set_name(name),
        owner,
        graph,
    }
}

/// The graph as sets of policies, one per author, each owned by its author, named by the author's
/// key and given the fixed id of that name ([`set_id`]): what the application gives when each
/// principal keeps its own file. A scenario
/// that gives everything to the user has a catalog of one set; one where the agent adds to the
/// user's rules has the user's set and the agent's beside it, so a change of the agent's own work
/// leaves the user's set as it is.
pub fn by_author(graph: PolicyGraph) -> Sources {
    let (policies, bindings, classifiers) = graph.into_parts();
    let mut owners: Vec<Principal> = policies
        .iter()
        .map(|p| p.author.clone())
        .chain(bindings.iter().map(|b| b.author.clone()))
        .chain(classifiers.iter().map(|c| c.author.clone()))
        .collect();
    owners.sort();
    owners.dedup();
    let sets = owners
        .into_iter()
        .map(|owner| {
            let graph = PolicyGraph::parse_with(
                policies
                    .iter()
                    .filter(|p| p.author == owner)
                    .cloned()
                    .collect(),
                bindings
                    .iter()
                    .filter(|b| b.author == owner)
                    .cloned()
                    .collect(),
                classifiers
                    .iter()
                    .filter(|c| c.author == owner)
                    .cloned()
                    .collect(),
            )
            .unwrap();
            let id = owner.key().to_owned();
            set(&id, owner, graph)
        })
        .collect();
    Sources::new(sets).unwrap()
}

/// `Catalog::accept` of the graph, as one set per author ([`by_author`]), with the hierarchy of
/// the scenarios.
pub fn accept(graph: PolicyGraph) -> Result<Catalog, Rejected> {
    Catalog::accept(by_author(graph), authority())
}

pub fn catalog(policies: Vec<Written>, bindings: Vec<Binding>) -> Catalog {
    accept(graph_of(policies, bindings)).unwrap()
}

pub fn rejected(policies: Vec<Written>, bindings: Vec<Binding>) -> Vec<AcceptError> {
    accept(graph_of(policies, bindings)).unwrap_err().0
}

/// Every policy of the catalog with what it comes to under the mode, by id.
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

/// The verdict on the last event, with the state folded over all of them, a history that is
/// whole ([`Origin::Genesis`]).
pub fn verdict(catalog: &Catalog, events: &[Event]) -> Verdict {
    outcome(catalog, events).verdict
}

/// The whole outcome on the last event, with the state folded over all of them.
pub fn outcome(catalog: &Catalog, events: &[Event]) -> Outcome {
    let state = catalog.fold(Origin::Genesis, events);
    judge(
        catalog,
        &state,
        events.last().unwrap(),
        &Capabilities::full(),
    )
}

/// Judges `event` after the `log`, then appends the event and the evidence of its judgment to the
/// log, as a caller does between turns.
pub fn step(catalog: &Catalog, log: &mut Vec<Event>, event: Event) -> Outcome {
    let state = catalog.fold(Origin::Genesis, log.iter().chain([&event]));
    let outcome = judge(catalog, &state, &event, &Capabilities::full());
    log.push(event);
    log.extend(outcome.evidence(At::from_millis(0)));
    outcome
}
