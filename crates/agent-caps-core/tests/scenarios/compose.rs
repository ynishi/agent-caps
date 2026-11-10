//! Scenario L5: a shared set of policies (a guard and its reward) together with a project's own.
//!
//! What cannot be written (#7): the domain has no operation that combines graphs, and a
//! `PolicyGraph` does not say where a policy comes from, so nothing tells a shared policy from a
//! project's. The right expectation, "a project changes a shared policy only by an override",
//! cannot be stated without the test inventing that distinction; it is left to the issue.
//!
//! What these tests state is what holds today: the caller composes the policies and the bindings
//! into one `PolicyGraph`, `Catalog::accept` takes it as any other, and two sets that share an id
//! or a name cannot be made one graph (`PolicyGraph::parse` refuses them with a `Clash`). A
//! project changes the level of a shared policy by giving a binding with the id of the shared
//! one, which the caller's composition puts in its place: the core sees only the composed graph,
//! and keeps the ids unique.
//!
//! `concat` is kept as the caller's composition of today, with its replacement of a binding by
//! id, only until composing sets is the core's (the issue that follows the normalized graph),
//! which replaces it and these tests.

use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::policy::{
    Clash, DefLayer, GraphError, Level, ModeScope, Polarity, PolicyDef, PolicyGraph, Rule,
};
use agent_caps_core::domain::predicate::{Cond, Lit, Pred};
use agent_caps_core::domain::schema::{EventKind, Field};

use super::common::{
    GUARD, OTHER, REWARD, accept, agent, bash, bind, clippy_reward, graph_of, id, outcome,
    test_guard, the_user, violated, written,
};

/// The shared set: the test guard and the reward bound by it.
fn shared() -> PolicyGraph {
    graph_of(
        vec![test_guard(Level::Force), clippy_reward(Level::Advise)],
        vec![],
    )
}

/// The project's own: a guard that warns when a shell call failed, and the binding that takes
/// the place of the shared reward's (the same id), at Inform.
fn project_graph(project_id: &str, project_name: &str) -> PolicyGraph {
    let guard = PolicyDef {
        id: id(project_id),
        name: project_name.parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: None,
        rule: Rule::Structural(Pred::Now(Cond::Eq(Field::Ok, Lit::Bool(true)))),
        polarity: Polarity::Guard,
        fixtures: vec![],
        author: the_user(),
    };
    graph_of(
        vec![written(guard, Level::Advise)],
        vec![bind(REWARD, 0, Level::Inform, ModeScope::Any, the_user())],
    )
}

/// What the caller does today to put two sets side by side: the policies of both, and the
/// bindings of both, a binding of the second taking the place of the first's with its id.
fn concat(first: PolicyGraph, second: PolicyGraph) -> Result<PolicyGraph, Vec<GraphError>> {
    let (mut policies, first_bindings) = first.into_parts();
    let (second_policies, second_bindings) = second.into_parts();
    policies.extend(second_policies);
    let mut bindings: Vec<_> = first_bindings
        .into_iter()
        .filter(|b| !second_bindings.iter().any(|s| s.id == b.id))
        .collect();
    bindings.extend(second_bindings);
    PolicyGraph::parse(policies, bindings)
}

/// UC7, FR4, FR42: two sets joined by the caller are accepted as one catalog, and the project's
/// binding of a shared policy applies.
#[test]
fn two_sets_joined_by_the_caller_are_one_catalog() {
    let catalog =
        accept(concat(shared(), project_graph(OTHER, "project-bash-ok")).unwrap()).unwrap();
    assert_eq!(catalog.policies().len(), 3);

    // The shared guard and reward work as they did alone ...
    let stop = [agent(Body::TaskStart), agent(Body::Stop)];
    let out = outcome(&catalog, &stop);
    assert_eq!(out.verdict, violated());
    // ... with the project's binding of the reward in place of the shared one.
    assert_eq!(out.rewards.len(), 1);
    assert_eq!(out.rewards[0].written, Level::Inform);

    // And the project's guard judges a tool call.
    let call = outcome(
        &catalog,
        &[agent(Body::TaskStart), bash("cargo build", Some(false))],
    );
    assert_eq!(
        call.verdict,
        Verdict::Warn(vec![Cause::Violated(id(OTHER))])
    );
}

/// UC7, FR4: two sets that share an id are rejected.
#[test]
fn two_sets_with_the_same_id_are_rejected() {
    let clashes = clashes(concat(shared(), project_graph(GUARD, "project-bash-ok")));
    assert_eq!(clashes, vec![Clash::Policy(id(GUARD))]);
}

/// UC7, FR4: two sets that share a name are rejected.
#[test]
fn two_sets_with_the_same_name_are_rejected() {
    let clashes = clashes(concat(shared(), project_graph(OTHER, "test-before-stop")));
    assert_eq!(
        clashes,
        vec![Clash::Name("test-before-stop".parse().unwrap())]
    );
}

fn clashes(graph: Result<PolicyGraph, Vec<GraphError>>) -> Vec<Clash> {
    graph
        .unwrap_err()
        .iter()
        .map(|error| error.clash().clone())
        .collect()
}
