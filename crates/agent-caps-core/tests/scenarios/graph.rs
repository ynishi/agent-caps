//! The policy graph: policies and bindings keyed by id, made only by `PolicyGraph::parse`, which
//! refuses a duplicate id with every clash at once (a name is no identity); and the one order, by
//! id, that the lists of a catalog and the reports of a judgment follow whatever order the caller gave.

use agent_caps_core::domain::catalog::Effect;
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::policy::{
    Binding, Clash, Level, ModeScope, Polarity, PolicyDef, PolicyGraph,
};
use agent_caps_core::domain::state::Known;

use super::common::{
    GUARD, OTHER, REWARD, Written, accept, agent, bind, binding_id, clippy_reward, id, listed,
    outcome, test_guard, test_guard_def, the_user, written,
};

/// The clashes `parse` finds, in the order it reports them.
fn clashes(policies: Vec<PolicyDef>, bindings: Vec<Binding>) -> Vec<Clash> {
    PolicyGraph::parse(policies, bindings)
        .unwrap_err()
        .iter()
        .map(|error| error.clash().clone())
        .collect()
}

/// FR1, FR42: a second policy with an id already there and a second binding with an id already
/// there are each refused, all reported at once, in the order of the clashes whatever the order
/// they were given in.
#[test]
fn a_duplicate_id_is_refused_with_every_clash_at_once() {
    // The guard's id again, with other examples.
    let mut same_id = test_guard_def();
    same_id.fixtures.clear();
    let policies = vec![same_id, test_guard_def()];
    let other = bind(GUARD, 1, Level::Inform, ModeScope::Any, the_user());
    let bindings = vec![other.clone(), other];
    let expected = vec![
        Clash::Policy(id(GUARD)),
        Clash::Binding(binding_id(id(GUARD), 1)),
    ];
    assert_eq!(clashes(policies.clone(), bindings.clone()), expected);
    assert_eq!(
        clashes(
            policies.into_iter().rev().collect(),
            bindings.into_iter().rev().collect()
        ),
        expected
    );
}

/// FR67: a policy's name is no identity. Two policies of one name under two ids are two policies
/// of the graph; only their ids are checked, whatever order they are given in.
#[test]
fn two_policies_of_one_name_under_two_ids_are_both_in_the_graph() {
    let named = |policy: &str, name: &str| {
        let mut def = test_guard_def();
        def.id = id(policy);
        def.name = name.parse().unwrap();
        def
    };
    let (b, other_b) = (named(GUARD, "b"), named(OTHER, "b"));
    for policies in [
        vec![b.clone(), other_b.clone()],
        vec![other_b.clone(), b.clone()],
    ] {
        let graph = PolicyGraph::parse(policies, vec![]).unwrap();
        assert_eq!(graph.policies().count(), 2);
    }
    // A third under the guard's id is refused by its id alone.
    assert_eq!(
        clashes(vec![named(GUARD, "a"), b, other_b], vec![]),
        vec![Clash::Policy(id(GUARD))]
    );
}

/// FR1, FR42: within one graph, an item given twice is a slip even when the two are equal: it is
/// refused, once.
#[test]
fn an_equal_duplicate_is_still_refused() {
    assert_eq!(
        clashes(
            vec![test_guard_def(), test_guard_def(), test_guard_def()],
            vec![]
        ),
        vec![Clash::Policy(id(GUARD))]
    );
    let binding = bind(GUARD, 0, Level::Force, ModeScope::Any, the_user());
    assert_eq!(
        clashes(vec![test_guard_def()], vec![binding.clone(), binding]),
        vec![Clash::Binding(binding_id(id(GUARD), 0))]
    );
}

/// A second guard, read at the end of a turn: clippy ran within the task.
fn clippy_guard(level: Level) -> Written {
    let mut def = clippy_reward(level).def;
    def.id = id(OTHER);
    def.name = "clippy-guard".parse().unwrap();
    def.polarity = Polarity::Guard;
    written(def, level)
}

/// The graph of the written policies, in the order given, each with its base binding.
fn graph_in_order(policies: Vec<Written>) -> PolicyGraph {
    let bindings = policies
        .iter()
        .filter_map(|w| {
            w.level
                .map(|level| bind(&w.def.id.to_string(), 0, level, ModeScope::Any, the_user()))
        })
        .rev()
        .collect();
    PolicyGraph::parse(policies.into_iter().map(|w| w.def).collect(), bindings).unwrap()
}

/// FR12, FR29: the policies of a catalog, the list of what takes effect and the causes of a
/// verdict are in id order, whatever order the caller gave the policies and bindings in: two
/// graphs of the same items are one graph, and give one catalog.
#[test]
fn outputs_follow_id_order_whatever_order_was_given() {
    let given = || {
        vec![
            clippy_guard(Level::Advise),
            clippy_reward(Level::Inform),
            test_guard(Level::Advise),
        ]
    };
    let reversed = graph_in_order(given().into_iter().rev().collect());
    let graph = graph_in_order(given());
    assert_eq!(graph, reversed);
    let ids: Vec<_> = graph.policies().map(|p| p.id).collect();
    assert_eq!(ids, vec![id(GUARD), id(REWARD), id(OTHER)]);

    let catalog = accept(graph).unwrap();
    assert_eq!(catalog, accept(reversed).unwrap());
    let in_catalog: Vec<_> = catalog.policies().iter().map(|p| p.id()).collect();
    assert_eq!(in_catalog, ids);
    assert_eq!(
        listed(&catalog, Known::Known(None)),
        vec![
            (id(GUARD), Effect::On(Level::Advise)),
            (id(REWARD), Effect::On(Level::Inform)),
            (id(OTHER), Effect::On(Level::Advise)),
        ]
    );
    let out = outcome(&catalog, &[agent(Body::TaskStart), agent(Body::Stop)]);
    assert_eq!(
        out.verdict,
        Verdict::Warn(vec![Cause::Violated(id(GUARD)), Cause::Violated(id(OTHER))])
    );
}
