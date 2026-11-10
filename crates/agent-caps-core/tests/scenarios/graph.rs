//! The policy graph: policies and bindings keyed by id, made only by `PolicyGraph::parse`, which
//! refuses a duplicate id or name with every clash at once; and the one order, by id, that the
//! lists of a catalog and the reports of a judgment follow whatever order the caller gave.

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

/// FR1, FR42: a second policy with an id already there, a second binding with an id already
/// there and a second policy with a name already there are each refused, all reported at once, in
/// the order of the clashes whatever the order they were given in.
#[test]
fn a_duplicate_id_or_name_is_refused_with_every_clash_at_once() {
    // The guard's id again, with other examples; and the guard's name again, on another id.
    let mut same_id = test_guard_def();
    same_id.fixtures.clear();
    let mut same_name = test_guard_def();
    same_name.id = id(OTHER);
    let policies = vec![same_name, same_id, test_guard_def()];
    let other = bind(GUARD, 1, Level::Inform, ModeScope::Any, the_user());
    let bindings = vec![other.clone(), other];
    let expected = vec![
        Clash::Policy(id(GUARD)),
        Clash::Binding(binding_id(id(GUARD), 1)),
        Clash::Name("test-before-stop".parse().unwrap()),
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

/// FR1, FR42: the name of a policy refused for its id is still checked: a policy with that name
/// on another id clashes by the name, whatever order the three are given in.
#[test]
fn the_name_of_a_policy_refused_for_its_id_is_still_checked() {
    let named = |policy: &str, name: &str| {
        let mut def = test_guard_def();
        def.id = id(policy);
        def.name = name.parse().unwrap();
        def
    };
    let expected = vec![Clash::Policy(id(GUARD)), Clash::Name("b".parse().unwrap())];
    let (a, b, other_b) = (named(GUARD, "a"), named(GUARD, "b"), named(OTHER, "b"));
    for policies in [
        vec![a.clone(), b.clone(), other_b.clone()],
        vec![b.clone(), a.clone(), other_b.clone()],
        vec![other_b.clone(), a.clone(), b.clone()],
        vec![other_b, b, a],
    ] {
        assert_eq!(clashes(policies, vec![]), expected);
    }
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
