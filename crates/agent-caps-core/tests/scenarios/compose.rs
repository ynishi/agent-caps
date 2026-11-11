//! Scenario L5: a shared set of policies (a guard and its reward), owned by the user, together
//! with a project's own, owned by the agent below the user.
//!
//! The catalog is accepted from its sets and keeps them (`Sources`); the sets compose by adding
//! only (`Sources::compose`): an item two sets hold the same is one item, and two different items
//! under one id conflict; a name is no identity, so two policies, or two sets, may share one. So a
//! project's set adds to the shared one and strengthens it, and never replaces or lowers what it holds; a shared rule is weakened for a
//! project only by a version of the shared set that its owner gives. Adding, removing and swapping
//! a set are changes of the sources, judged as one change. The join's laws are checked over every
//! combination of a small pool of graphs (exhaustively, with no generator of random cases).

use std::collections::BTreeSet;

use agent_caps_core::domain::authority::Principal;
use agent_caps_core::domain::catalog::{AcceptError, Catalog, Target};
use agent_caps_core::domain::change::{ChangeRejected, Loosening};
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::name::PolicyName;
use agent_caps_core::domain::policy::{
    Clash, DefLayer, Level, ModeScope, Polarity, PolicyDef, PolicyGraph, Rule,
};
use agent_caps_core::domain::predicate::{Cond, Lit, Pred};
use agent_caps_core::domain::schema::{EventKind, Field};
use agent_caps_core::domain::set::{JoinConflict, SetId, Source, Sources, SourcesError};

use super::common::{
    GUARD, OTHER, REWARD, Written, agent, authority, bash, bind, binding_id, clippy_reward,
    declaring, default_bound, graph_of, id, lineage, outcome, push_after_allowed, set, set_id,
    set_name, set_pair, test_guard, the_agent, the_user, violated, written,
};

const PROJECT_GUARD: &str = "00000000-0000-7000-8000-000000000004";

/// The graph of the shared set: the test guard and the reward bound by it.
fn shared_graph(guard: Level) -> PolicyGraph {
    graph_of(
        vec![test_guard(guard), clippy_reward(Level::Advise)],
        vec![],
    )
}

/// A set of the user's, which declares the scenarios' bound as every set a root owns does.
fn users_set(name: &str, graph: PolicyGraph) -> Source {
    set(name, the_user(), declaring(graph, Some(default_bound())))
}

/// The shared set, the user's.
fn shared(guard: Level) -> Source {
    users_set("shared", shared_graph(guard))
}

/// A guard of the project's: a shell call must succeed, written by `author` at Advise.
fn project_guard(policy: &str, name: &str, author: Principal) -> Written {
    written(
        PolicyDef {
            id: id(policy),
            name: name.parse().unwrap(),
            layer: DefLayer::Base,
            subject: EventKind::ToolUse,
            when: None,
            rule: Rule::Structural(Pred::Now(Cond::Eq(Field::Ok, Lit::Bool(true)))),
            polarity: Polarity::Guard,
            fixtures: vec![],
            author,
        },
        Level::Advise,
    )
}

/// The project's set, the agent's: a guard of its own, and a binding of the shared reward at
/// Inform, which adds to the shared binding and lowers nothing.
fn project() -> Source {
    set(
        "project",
        the_agent(),
        graph_of(
            vec![project_guard(PROJECT_GUARD, "project-bash-ok", the_agent())],
            vec![bind(REWARD, 1, Level::Inform, ModeScope::Any, the_agent())],
        ),
    )
}

fn sources(sets: Vec<Source>) -> Sources {
    Sources::new(sets).unwrap()
}

fn accept(sets: Vec<Source>) -> Result<Catalog, Vec<AcceptError>> {
    Catalog::accept(sources(sets), authority(), lineage()).map_err(|rejected| rejected.0)
}

/// The conflicts of sets that do not compose, as each clash with its pair of sets.
fn conflicts(sets: Vec<Source>) -> Vec<(Clash, [SetId; 2])> {
    sources(sets)
        .compose()
        .unwrap_err()
        .iter()
        .map(|conflict: &JoinConflict| (conflict.clash().clone(), *conflict.sets()))
        .collect()
}

/// The pair of sets `a` and `b`, the lower id first.
fn pair(a: &str, b: &str) -> [SetId; 2] {
    set_pair(a, b)
}

/// The conflicts in the order `compose` gives them: by clash, then by the pair of ids.
fn in_order(mut conflicts: Vec<(Clash, [SetId; 2])>) -> Vec<(Clash, [SetId; 2])> {
    conflicts.sort();
    conflicts
}

fn loosenings(result: Result<Catalog, ChangeRejected>) -> Vec<Loosening> {
    match result.unwrap_err() {
        ChangeRejected::Loosens(loosenings) => loosenings,
        other => panic!("rejected, but not for loosening: {other:?}"),
    }
}

fn uncovered(target: Target) -> Loosening {
    Loosening::Uncovered { target }
}

/// UC27, FR67, FR42: the shared set and the project's compose to one catalog. The shared guard
/// and reward work as they did alone, the project's binding of the reward adds to the shared one
/// and does not lower it, and the project's guard judges a tool call.
#[test]
fn two_sets_compose_to_one_catalog() {
    let catalog = accept(vec![shared(Level::Force), project()]).unwrap();
    assert_eq!(catalog.policies().len(), 3);
    assert_eq!(catalog.sources().iter().count(), 2);

    let stop = [agent(Body::TaskStart), agent(Body::Stop)];
    let out = outcome(&catalog, &stop);
    assert_eq!(out.verdict, violated());
    assert_eq!(out.rewards.len(), 1);
    assert_eq!(out.rewards[0].written, Level::Advise);

    let call = outcome(
        &catalog,
        &[agent(Body::TaskStart), bash("cargo build", Some(false))],
    );
    assert_eq!(
        call.verdict,
        Verdict::Warn(vec![Cause::Violated(id(PROJECT_GUARD))])
    );
}

/// UC27, FR67: two sets that hold different policies under one id are refused with the pair of
/// sets, whichever comes first; the catalog is not accepted.
#[test]
fn two_sets_that_disagree_on_an_item_are_refused_with_the_pair() {
    let same_id = set(
        "project",
        the_user(),
        graph_of(
            vec![project_guard(GUARD, "project-bash-ok", the_user())],
            vec![],
        ),
    );
    // The policy differs, and so does its binding (it binds another policy at the same id).
    assert_eq!(
        conflicts(vec![shared(Level::Force), same_id.clone()]),
        vec![
            (Clash::Policy(id(GUARD)), pair("project", "shared")),
            (
                Clash::Binding(binding_id(id(GUARD), 0)),
                pair("project", "shared")
            ),
        ]
    );
    assert_eq!(
        conflicts(vec![same_id, shared(Level::Force)]),
        conflicts(vec![
            shared(Level::Force),
            set(
                "project",
                the_user(),
                graph_of(
                    vec![project_guard(GUARD, "project-bash-ok", the_user())],
                    vec![]
                ),
            ),
        ])
    );
}

/// UC27, FR67: a name is no identity. Two sets that hold two policies of one name under two ids
/// compose to a catalog that holds both.
#[test]
fn two_policies_of_one_name_under_two_ids_are_two_policies() {
    let same_name = users_set(
        "project",
        graph_of(
            vec![project_guard(OTHER, "test-before-stop", the_user())],
            vec![],
        ),
    );
    let catalog = accept(vec![shared(Level::Force), same_name]).unwrap();
    let name: PolicyName = "test-before-stop".parse().unwrap();
    let named: BTreeSet<_> = catalog
        .graph()
        .policies()
        .filter(|def| def.name == name)
        .map(|def| def.id)
        .collect();
    assert_eq!(named, BTreeSet::from([id(GUARD), id(OTHER)]));
}

/// FR67: of three sets under one id, every pair with different items is a conflict, in the order
/// of the sets' ids, and two sets with the same item are not a pair.
#[test]
fn three_sets_under_one_id_give_every_pair_that_differs() {
    let copy = users_set("copy", shared_graph(Level::Force));
    let other = users_set("other", shared_graph(Level::Advise));
    assert_eq!(
        conflicts(vec![shared(Level::Force), other.clone(), copy.clone()]),
        in_order(vec![
            (
                Clash::Binding(binding_id(id(GUARD), 0)),
                pair("copy", "other")
            ),
            (
                Clash::Binding(binding_id(id(GUARD), 0)),
                pair("other", "shared")
            ),
        ])
    );
    let third = users_set("third", shared_graph(Level::Inform));
    assert_eq!(
        conflicts(vec![other, third, shared(Level::Force)]),
        in_order(vec![
            (
                Clash::Binding(binding_id(id(GUARD), 0)),
                pair("other", "shared")
            ),
            (
                Clash::Binding(binding_id(id(GUARD), 0)),
                pair("other", "third")
            ),
            (
                Clash::Binding(binding_id(id(GUARD), 0)),
                pair("shared", "third")
            ),
        ])
    );
}

/// FR67: one pass of errors. What a set says of its own items is checked before the sets are
/// composed, so two sets that conflict and a third that holds a binding by one outside the
/// hierarchy are reported in one rejection.
#[test]
fn a_conflict_and_an_unknown_author_are_reported_at_once() {
    let stranger = Principal::new("stranger");
    let with_stranger = users_set(
        "third",
        graph_of(
            vec![],
            vec![bind(
                GUARD,
                2,
                Level::Advise,
                ModeScope::Any,
                stranger.clone(),
            )],
        ),
    );
    let errors = accept(vec![
        shared(Level::Force),
        users_set("other", shared_graph(Level::Advise)),
        with_stranger,
    ])
    .unwrap_err();
    assert_eq!(
        errors,
        vec![
            AcceptError::UnknownAuthor {
                item: Target::Binding(binding_id(id(GUARD), 2)),
                author: stranger,
            },
            AcceptError::Conflict(
                sources(vec![
                    shared(Level::Force),
                    users_set("other", shared_graph(Level::Advise))
                ])
                .compose()
                .unwrap_err()
                .remove(0)
            ),
        ]
    );
}

/// UC27, FR67, FR49: two sets that hold the same items compose to one of each, and taking one of
/// them out keeps what the other holds: the sources are composed again.
#[test]
fn two_sets_with_the_same_item_hold_it_once_and_removing_one_keeps_it() {
    let copy = users_set("copy", shared_graph(Level::Force));
    let both = sources(vec![shared(Level::Force), copy]);
    assert_eq!(both.compose().unwrap(), shared_graph(Level::Force));

    let catalog = Catalog::accept(both, authority(), lineage()).unwrap();
    let without_copy = catalog.sources().without(&set_id("copy")).unwrap();
    let after = catalog.change(without_copy, &the_user()).unwrap();
    assert_eq!(after.graph(), catalog.graph());
    let stop = [agent(Body::TaskStart), agent(Body::Stop)];
    assert_eq!(outcome(&after, &stop).verdict, violated());

    assert_eq!(
        catalog.sources().without(&set_id("missing")),
        Err(SourcesError::Unknown(set_id("missing")))
    );
}

/// UC27, FR67, FR49: the project cannot replace or lower a shared binding. By composition, a
/// binding of the project's with the shared binding's id is a conflict, not a replacement; by a
/// change, a version of the shared set made by the project's owner loosens the shared set, the
/// user's binding and the guard, and each is reported.
#[test]
fn a_project_set_cannot_replace_or_lower_a_shared_binding() {
    let replacing = set(
        "project",
        the_agent(),
        graph_of(
            vec![],
            vec![bind(GUARD, 0, Level::Inform, ModeScope::Any, the_agent())],
        ),
    );
    assert_eq!(
        conflicts(vec![shared(Level::Force), replacing]),
        vec![(
            Clash::Binding(binding_id(id(GUARD), 0)),
            pair("project", "shared")
        )]
    );

    let before = accept(vec![shared(Level::Force), project()]).unwrap();
    let lowered = before.sources().replaced(shared(Level::Inform)).unwrap();
    let found = loosenings(before.change(lowered, &the_agent()));
    assert_eq!(
        found[0],
        uncovered(Target::Binding(binding_id(id(GUARD), 0)))
    );
    assert_eq!(found[1], uncovered(Target::Set(set_id("shared"))));
    assert!(matches!(found[2], Loosening::Moves { .. }), "{found:?}");
    assert_eq!(found.len(), 3, "{found:?}");
}

/// UC27, FR49, FR42: the shared owner gives the project a lower version of the shared set, and
/// it takes effect.
#[test]
fn the_shared_owner_publishes_a_lower_version_for_the_project() {
    let before = accept(vec![shared(Level::Force), project()]).unwrap();
    let lowered = before.sources().replaced(shared(Level::Advise)).unwrap();
    let after = before.change(lowered, &the_user()).unwrap();
    let stop = [agent(Body::TaskStart), agent(Body::Stop)];
    assert_eq!(
        outcome(&after, &stop).verdict,
        Verdict::Warn(vec![Cause::Violated(id(GUARD))])
    );
}

/// FR67: an item in a set by one who is neither the set's owner nor below it is refused when the
/// catalog is accepted: a set holds only what its owner may loosen.
#[test]
fn an_item_by_an_author_outside_the_sets_owner_is_refused_at_accept() {
    let users_work_in_the_project = set(
        "project",
        the_agent(),
        graph_of(
            vec![project_guard(PROJECT_GUARD, "project-bash-ok", the_user())],
            vec![],
        ),
    );
    assert_eq!(
        accept(vec![shared(Level::Force), users_work_in_the_project]).unwrap_err(),
        vec![
            AcceptError::NotWithinOwner {
                set: set_id("project"),
                item: Target::Policy(id(PROJECT_GUARD)),
                owner: the_agent(),
            },
            AcceptError::NotWithinOwner {
                set: set_id("project"),
                item: Target::Binding(binding_id(id(PROJECT_GUARD), 0)),
                owner: the_agent(),
            },
        ]
    );
}

/// FR49: a swap of a set is one change and one difference. The project's binding raises the
/// shared guard, which a rule of the user reads. A new version of the project's set that keeps
/// the binding and adds a guard only tightens, and the agent makes it without approval; taking
/// the set out, the first half of a removal and an addition, lowers the guard, moves the user's
/// rule that reads it, and is not the agent's to make.
#[test]
fn a_swap_of_a_set_is_judged_as_one_change() {
    let shared = users_set(
        "shared",
        graph_of(
            vec![test_guard(Level::Inform), push_after_allowed(GUARD)],
            vec![],
        ),
    );
    let raise = bind(GUARD, 1, Level::Advise, ModeScope::Any, the_agent());
    let version = |guards: Vec<Written>| {
        set(
            "project",
            the_agent(),
            graph_of(guards, vec![raise.clone()]),
        )
    };
    let before = accept(vec![shared, version(vec![])]).unwrap();

    let next = version(vec![project_guard(
        PROJECT_GUARD,
        "project-bash-ok",
        the_agent(),
    )]);
    let swapped = before.sources().replaced(next).unwrap();
    let after = before.change(swapped, &the_agent()).unwrap();
    assert!(after.policy(id(PROJECT_GUARD)).is_some());

    let taken_out = before.sources().without(&set_id("project")).unwrap();
    let found = loosenings(before.change(taken_out, &the_agent()));
    assert!(
        matches!(found.as_slice(), [Loosening::Moves { authors, .. }] if authors.contains(&the_user())),
        "{found:?}"
    );
}

/// FR49, FR14, UC10: a set that holds a meta policy enters when a catalog is first accepted, and
/// never by a change, whoever makes it.
#[test]
fn a_set_with_a_meta_policy_cannot_be_added_by_a_change() {
    let mut meta = project_guard(OTHER, "meta-guard", the_user());
    meta.layer = DefLayer::Meta;
    meta.level = Some(Level::Advise);
    let meta_set = users_set("meta", graph_of(vec![meta], vec![]));

    assert!(accept(vec![shared(Level::Force), meta_set.clone()]).is_ok());

    let before = accept(vec![shared(Level::Force)]).unwrap();
    let with_meta = before.sources().with(meta_set.clone()).unwrap();
    for by in [the_user(), the_agent()] {
        assert_eq!(
            before.change(with_meta.clone(), &by).unwrap_err(),
            ChangeRejected::Meta(vec![id(OTHER)])
        );
    }

    // Nor a second set with a copy of a meta policy already in the catalog: the composed graph
    // is the same, but a set that holds a meta policy enters only at accept. Taking the copy out
    // again is refused as well; a set that keeps it may still be renamed.
    let with_both = accept(vec![shared(Level::Force), meta_set.clone()]).unwrap();
    let copy = Source {
        id: set_id("copy"),
        name: set_name("copy"),
        ..meta_set.clone()
    };
    let with_copy = with_both.sources().with(copy.clone()).unwrap();
    assert_eq!(
        with_both
            .change(with_copy.clone(), &the_user())
            .unwrap_err(),
        ChangeRejected::Meta(vec![id(OTHER)])
    );
    let three = Catalog::accept(with_copy, authority(), lineage()).unwrap();
    assert_eq!(
        three
            .change(three.sources().without(&copy.id).unwrap(), &the_user())
            .unwrap_err(),
        ChangeRejected::Meta(vec![id(OTHER)])
    );
    let renamed = Source {
        name: set_name("meta-renamed"),
        ..meta_set
    };
    assert!(
        with_both
            .change(with_both.sources().replaced(renamed).unwrap(), &the_user())
            .is_ok()
    );
}

/// UC27, FR49: the agent adds a set of its own without approval; a set in the user's name is not
/// the agent's to add, even an empty one, and an item of the user's in it is reported as well.
#[test]
fn adding_a_set_by_its_owner_needs_no_approval_and_one_in_another_name_is_refused() {
    let before = accept(vec![shared(Level::Force)]).unwrap();
    let with_project = before.sources().with(project()).unwrap();
    assert!(before.change(with_project, &the_agent()).is_ok());

    let empty = users_set("more", PolicyGraph::default());
    assert_eq!(
        loosenings(before.change(before.sources().with(empty).unwrap(), &the_agent())),
        vec![uncovered(Target::Set(set_id("more")))]
    );
    let users = users_set(
        "more",
        graph_of(
            vec![project_guard(PROJECT_GUARD, "more-bash-ok", the_user())],
            vec![],
        ),
    );
    assert_eq!(
        loosenings(before.change(before.sources().with(users.clone()).unwrap(), &the_agent())),
        vec![
            uncovered(Target::Policy(id(PROJECT_GUARD))),
            uncovered(Target::Binding(binding_id(id(PROJECT_GUARD), 0))),
            uncovered(Target::Set(set_id("more"))),
        ]
    );
    // The user may.
    assert!(
        before
            .change(before.sources().with(users).unwrap(), &the_user())
            .is_ok()
    );
    // A set's id is its own among the sources.
    assert_eq!(
        before.sources().with(shared(Level::Advise)),
        Err(SourcesError::Duplicate(set_id("shared")))
    );
    // A set given twice is one id given twice, whatever the order.
    assert_eq!(
        Sources::new(vec![shared(Level::Force), shared(Level::Advise), project()]),
        Err(vec![SourcesError::Duplicate(set_id("shared"))])
    );
}

/// UC27, FR67: a set's name is no identity. Two sets of one name under two ids are two sets, and
/// taking one out by its id leaves the other.
#[test]
fn two_sets_of_one_name_are_two_sets() {
    let before = accept(vec![shared(Level::Force), project()]).unwrap();
    let same_name = Source {
        id: set_id("another"),
        ..project()
    };
    assert!(Sources::new(vec![same_name.clone(), project()]).is_ok());
    let both = before.sources().with(same_name).unwrap();
    assert_eq!(
        both.iter()
            .filter(|source| source.name == set_name("project"))
            .count(),
        2
    );
    let left = both.without(&set_id("another")).unwrap();
    assert_eq!(left, *before.sources());
}

/// FR49: a set is the one with its id, and its name is its owner's to say. The owner renames its
/// set freely, a new version keeping the id; renaming a set whose owner the one who changes does
/// not cover changes that set, and loosens like any other difference of it.
#[test]
fn a_rename_is_a_change_of_the_set() {
    let before = accept(vec![shared(Level::Force), project()]).unwrap();
    let renamed = |source: Source, name: &str| Source {
        name: set_name(name),
        ..source
    };

    let project_renamed = before
        .sources()
        .replaced(renamed(project(), "project-a"))
        .unwrap();
    let after = before.change(project_renamed, &the_agent()).unwrap();
    let kept = after.sources().get(&set_id("project")).unwrap();
    assert_eq!(kept.name, set_name("project-a"));
    assert_eq!(after.graph(), before.graph());

    let shared_renamed = before
        .sources()
        .replaced(renamed(shared(Level::Force), "best-practice"))
        .unwrap();
    assert_eq!(
        loosenings(before.change(shared_renamed.clone(), &the_agent())),
        vec![uncovered(Target::Set(set_id("shared")))]
    );
    assert!(before.change(shared_renamed, &the_user()).is_ok());

    // A new name another set has is a name like any other: the two sets stay two by their ids.
    let shared_twice = before
        .sources()
        .replaced(renamed(project(), "shared"))
        .unwrap();
    assert!(shared_twice.get(&set_id("project")).is_some());
    assert!(before.change(shared_twice, &the_agent()).is_ok());
}

/// The pool of graphs the laws are checked over: empty, the guard alone, the guard with the
/// reward (which holds the guard the same), the guard at another level (a conflict with it), and a
/// policy with the guard's name under another id (another policy, which joins beside it).
fn pool() -> Vec<PolicyGraph> {
    vec![
        PolicyGraph::default(),
        graph_of(vec![test_guard(Level::Force)], vec![]),
        shared_graph(Level::Force),
        graph_of(vec![test_guard(Level::Advise)], vec![]),
        graph_of(
            vec![project_guard(OTHER, "test-before-stop", the_user())],
            vec![],
        ),
        graph_of(
            vec![project_guard(PROJECT_GUARD, "project-bash-ok", the_user())],
            vec![],
        ),
    ]
}

/// The graphs, each a set of the user's named by its place, composed; a conflict as the clashes
/// found, which do not depend on the names of the sets.
fn join(graphs: &[&PolicyGraph]) -> Result<PolicyGraph, Vec<Clash>> {
    let sets = graphs
        .iter()
        .enumerate()
        .map(|(at, graph)| set(&format!("s{at}"), the_user(), (*graph).clone()))
        .collect();
    sources(sets).compose().map_err(|conflicts| {
        let mut clashes: Vec<Clash> = conflicts.iter().map(|c| c.clash().clone()).collect();
        clashes.dedup();
        clashes
    })
}

/// FR67: the join is commutative, idempotent and has the empty sources as its unit, over every
/// pair of the pool.
#[test]
fn the_join_is_commutative_and_idempotent_with_a_unit() {
    let pool = pool();
    assert_eq!(join(&[]), Ok(PolicyGraph::default()));
    for a in &pool {
        assert_eq!(join(&[a]), Ok(a.clone()));
        assert_eq!(join(&[a, a]), Ok(a.clone()), "idempotent");
        assert_eq!(join(&[a, &PolicyGraph::default()]), Ok(a.clone()), "unit");
        for b in &pool {
            assert_eq!(join(&[a, b]), join(&[b, a]), "commutative");
        }
    }
}

/// FR67: the join is associative over every triple of the pool: joining two first and then the
/// third gives what joining the three does, and a conflict of two stays one with the third.
#[test]
fn the_join_is_associative() {
    let pool = pool();
    for a in &pool {
        for b in &pool {
            for c in &pool {
                let all = join(&[a, b, c]);
                for (first, then) in [(join(&[a, b]), c), (join(&[b, c]), a)] {
                    match first {
                        Ok(first) => assert_eq!(join(&[&first, then]), all),
                        Err(_) => assert!(all.is_err()),
                    }
                }
            }
        }
    }
}
