//! Scenario L5: a shared set of policies (a guard and its reward) together with a project's own.
//!
//! What cannot be written (#7): the domain has no operation that combines graphs, and a
//! `PolicyGraph` does not say where a policy comes from, so nothing tells a shared policy from a
//! project's. The right expectation, "a project changes a shared policy only by an override",
//! cannot be stated without the test inventing that distinction; it is left to the issue.
//!
//! What these tests state is what holds today: the caller concatenates the policies and the
//! overrides into one `PolicyGraph`, `Catalog::accept` takes it as any other, and two sets that
//! share an id or a name are rejected with `DuplicateId` or `DuplicateName`.

use agent_caps_core::domain::catalog::AcceptError;
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::policy::{
    Change, DefLayer, Level, Polarity, PolicyDef, PolicyGraph, RewardLevel, Rule,
};
use agent_caps_core::domain::predicate::{Cond, Lit, Pred};
use agent_caps_core::domain::schema::{EventKind, Field};

use super::common::{
    GUARD, OTHER, REWARD, accept, agent, bash, clippy_reward, graph_of, id, outcome, project,
    test_guard, the_user, violated,
};

/// The shared set: the test guard and the reward bound by it.
fn shared() -> PolicyGraph {
    graph_of(
        vec![test_guard(Level::Force), clippy_reward(RewardLevel::Advise)],
        vec![],
    )
}

/// The project's own: a guard that warns when a shell call failed, and its override of a shared
/// policy.
fn project_graph(project_id: &str, project_name: &str) -> PolicyGraph {
    PolicyGraph {
        policies: vec![PolicyDef {
            id: id(project_id),
            name: project_name.parse().unwrap(),
            layer: DefLayer::Base,
            subject: EventKind::ToolUse,
            when: None,
            rule: Rule::Structural(Pred::Now(Cond::Eq(Field::Ok, Lit::Bool(true)))),
            polarity: Polarity::Guard {
                level: Level::Advise,
            },
            enabled: true,
            fixtures: vec![],
            author: the_user(),
        }],
        overrides: vec![project(REWARD, Change::Level(Level::Inform))],
    }
}

/// What the caller does today to put two sets side by side.
fn concat(first: PolicyGraph, second: PolicyGraph) -> PolicyGraph {
    let mut policies = first.policies;
    policies.extend(second.policies);
    let mut overrides = first.overrides;
    overrides.extend(second.overrides);
    PolicyGraph {
        policies,
        overrides,
    }
}

/// UC7, FR4: two sets joined by the caller are accepted as one catalog, and the project's
/// override of a shared policy applies.
#[test]
fn two_sets_joined_by_the_caller_are_one_catalog() {
    let catalog = accept(concat(shared(), project_graph(OTHER, "project-bash-ok"))).unwrap();
    assert_eq!(catalog.policies().len(), 3);

    // The shared guard and reward work as they did alone ...
    let stop = [agent(Body::TaskStart), agent(Body::Stop)];
    let out = outcome(&catalog, &stop);
    assert_eq!(out.verdict, violated());
    // ... with the project's override of the reward applied.
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
    let errors = rejected_graph(concat(shared(), project_graph(GUARD, "project-bash-ok")));
    assert_eq!(errors, vec![AcceptError::DuplicateId(id(GUARD))]);
}

/// UC7, FR4: two sets that share a name are rejected.
#[test]
fn two_sets_with_the_same_name_are_rejected() {
    let errors = rejected_graph(concat(shared(), project_graph(OTHER, "test-before-stop")));
    assert_eq!(
        errors,
        vec![AcceptError::DuplicateName(
            "test-before-stop".parse().unwrap()
        )]
    );
}

fn rejected_graph(graph: PolicyGraph) -> Vec<AcceptError> {
    accept(graph).unwrap_err().0
}
