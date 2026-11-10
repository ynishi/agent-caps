//! `Catalog::accept`: it reports every broken invariant of a policy graph at once, and a fixture
//! that fails rejects the catalog unless it is marked as a known gap.

use agent_caps_core::domain::catalog::AcceptError;
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::policy::{
    Change, DefLayer, Expect, Fixture, Level, RewardLevel, Rule,
};
use agent_caps_core::domain::predicate::{Cond, Lit, Pred};
use agent_caps_core::domain::schema::{Field, Source};

use super::common::{
    GUARD, OTHER, REWARD, accept, agent, clippy_reward, fixture, graph_of, id, project, rejected,
    test_guard, unreadable,
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
    assert!(accept(graph_of(vec![guard], vec![])).is_ok());
}
