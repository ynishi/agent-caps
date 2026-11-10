//! `Catalog::accept`: it reports every broken invariant of a policy graph at once, and a fixture
//! that fails rejects the catalog unless it is marked as a known gap.

use agent_caps_core::domain::catalog::AcceptError;
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::exempt::{Exempt, Lifetime};
use agent_caps_core::domain::policy::{
    Change, DefLayer, Expect, Fixture, Level, RewardLevel, Rule,
};
use agent_caps_core::domain::predicate::{Cond, Lit, Pred, Scope};
use agent_caps_core::domain::schema::Field;

use super::common::{
    GUARD, OTHER, REWARD, accept, agent, clippy_reward, fixture, graph_of, id, lost_line, project,
    rejected, test_guard, user,
};

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
        vec![project(REWARD, Change::Level(Level::Force))],
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
    let errors = rejected(vec![meta], vec![project(GUARD, Change::Off)]);
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
    let exempt = Body::Exempt(Exempt {
        guard: id(GUARD),
        target: None,
        lifetime: Lifetime::Within(Scope::Task),
        reason: "in the example".parse().unwrap(),
    });
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
