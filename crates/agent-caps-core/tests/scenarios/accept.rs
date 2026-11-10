//! `Catalog::accept`: it reports every broken invariant of a policy graph at once, and a fixture
//! that fails rejects the catalog unless it is marked as a known gap.

use agent_caps_core::domain::adjust::Lifetime;
use agent_caps_core::domain::catalog::{AcceptError, Target};
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::policy::{DefLayer, Expect, Fixture, Level, ModeScope, Rule};
use agent_caps_core::domain::predicate::{By, Cond, Lit, Pred, Scope};
use agent_caps_core::domain::schema::Field;

use super::common::{
    GUARD, OTHER, REWARD, accept, agent, bind, binding_id, clippy_reward, exempt_n, fixture,
    graph_of, id, inside, lost_line, rejected, test_guard, the_agent, the_user, user,
};

/// FR2, UC12: a guard bound at Force without fixtures is not accepted, and neither is a reward
/// bound at Force. FR14: a Meta policy has its one binding, by its author, under every mode, and
/// no other. FR42: a binding names a policy, has an id of its own, and is by the policy's author
/// or one below it.
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
        vec![no_fixtures, bad_pred, clippy_reward(Level::Advise)],
        vec![bind(REWARD, 1, Level::Force, ModeScope::Any, the_user())],
    );
    assert!(errors.contains(&AcceptError::MissingFixtures {
        policy: id(GUARD),
        binding: binding_id(id(GUARD), 0),
    }));
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, AcceptError::Predicate { policy, .. } if *policy == id(OTHER)))
    );
    assert!(errors.contains(&AcceptError::RewardForce {
        policy: id(REWARD),
        binding: binding_id(id(REWARD), 1),
    }));

    // A guard bound at Force only inside a mode needs its fixtures as well.
    let mut no_fixtures = test_guard(Level::Advise);
    no_fixtures.fixtures.clear();
    let errors = rejected(
        vec![no_fixtures],
        vec![bind(GUARD, 1, Level::Force, inside("bugfix"), the_user())],
    );
    assert_eq!(
        errors,
        vec![AcceptError::MissingFixtures {
            policy: id(GUARD),
            binding: binding_id(id(GUARD), 1),
        }]
    );

    // A reward bound stronger than its guard is accepted: it takes effect at its guard's level
    // (see the reward scenarios). A reward bound by nothing is not.
    assert!(
        accept(graph_of(
            vec![test_guard(Level::Inform), clippy_reward(Level::Advise)],
            vec![],
        ))
        .is_ok()
    );
    let errors = rejected(vec![clippy_reward(Level::Advise)], vec![]);
    assert_eq!(
        errors,
        vec![AcceptError::UnknownBound {
            reward: id(REWARD),
            bound_by: id(GUARD)
        }]
    );

    // A binding with an id another has, one that names no policy, and one by the root on a
    // policy of the principal below it.
    let mut agents = test_guard(Level::Advise);
    agents.id = id(OTHER);
    agents.name = "agents".parse().unwrap();
    agents.author = the_agent();
    let errors = rejected(
        vec![test_guard(Level::Advise), agents],
        vec![
            bind(GUARD, 0, Level::Inform, ModeScope::Any, the_user()),
            bind(REWARD, 1, Level::Inform, ModeScope::Any, the_user()),
            bind(OTHER, 1, Level::Inform, ModeScope::Any, the_user()),
        ],
    );
    assert_eq!(
        errors,
        vec![
            AcceptError::ReferencesBelow {
                item: Target::Binding(binding_id(id(OTHER), 1)),
                referenced: id(OTHER),
            },
            AcceptError::DuplicateBinding(binding_id(id(GUARD), 0)),
            AcceptError::UnknownBindingPolicy {
                binding: binding_id(id(REWARD), 1),
                policy: id(REWARD),
            },
        ]
    );

    // A meta policy has exactly its one binding: not none, not one more, not one under a mode.
    let mut meta = test_guard(Level::Force);
    meta.layer = DefLayer::Meta;
    let mut unbound = meta.clone();
    unbound.level = None;
    assert_eq!(
        rejected(vec![unbound], vec![]),
        vec![AcceptError::MetaBinding(id(GUARD))]
    );
    assert_eq!(
        rejected(
            vec![meta.clone()],
            vec![bind(GUARD, 1, Level::Force, ModeScope::Any, the_user())],
        ),
        vec![AcceptError::MetaBinding(id(GUARD))]
    );
    let mut in_mode = meta;
    in_mode.level = None;
    assert_eq!(
        rejected(
            vec![in_mode],
            vec![bind(GUARD, 1, Level::Force, inside("bugfix"), the_user())],
        ),
        vec![AcceptError::MetaBinding(id(GUARD))]
    );
}

/// FR2, UC12: a fixture that fails rejects the catalog.
#[test]
fn a_fixture_that_fails_rejects_the_catalog_unless_it_is_a_known_gap() {
    let mut guard = test_guard(Level::Force);
    // Wrong on purpose: a lost line makes the guard unknown, not satisfied.
    let wrong = || {
        fixture(
            "lost line",
            vec![agent(Body::TaskStart), lost_line(), agent(Body::Stop)],
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
    assert!(accept(graph_of(vec![guard], vec![])).is_ok());
}

/// FR2, FR34, UC12: a fixture is folded as a run is. An exemption of the root's guard from the
/// principal below it takes no effect in a fixture either, so the guard still fails there; the
/// same exemption from the root covers the guard.
#[test]
fn a_loosening_claim_in_a_fixture_takes_effect_as_it_would_at_run_time() {
    let exempt = exempt_n(1, GUARD, None, Lifetime::Within(Scope::Task(By::Anyone)));
    let with = |claim, expect| {
        let mut guard = test_guard(Level::Force);
        guard.fixtures.push(fixture(
            "exempted",
            vec![agent(Body::TaskStart), claim, agent(Body::Stop)],
            expect,
        ));
        accept(graph_of(vec![guard], vec![]))
    };
    // From below: not exempted, the guard fails as it would in a run.
    assert!(with(agent(exempt.clone()), Expect::Violated).is_ok());
    assert_eq!(
        with(agent(exempt.clone()), Expect::NotApplicable)
            .unwrap_err()
            .0,
        vec![AcceptError::FixtureFailed {
            policy: id(GUARD),
            fixture: "exempted".to_owned(),
            expected: Expect::NotApplicable,
            found: Expect::Violated,
        }]
    );
    // From the root: exempted.
    assert!(with(user(exempt), Expect::NotApplicable).is_ok());
}
