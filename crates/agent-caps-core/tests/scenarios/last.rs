//! The `Last` operator (the last value of a field within a scope), and scenario S7, the "latest
//! value" that `Last` cannot express.
//!
//! S7 wants: "stop the turn unless the latest bench score is 0.8 or more". Nothing in the
//! predicate language says "the latest score at least this": `Last` compares the field of the
//! last event of its kind for equality with a `Lit`, and a `Lit` is text or a bool, never a
//! number; `Once` and `Count` take a filter with a number comparison but cannot ask which
//! event was the last. The nearest policy counts the events with a score of 0.8 or more and asks
//! for at least one, which means "at some time", not "the latest". After a high score and a low
//! one it is satisfied, where it should be violated (#4).
//!
//! The gap is kept in the guard: a fixture with the right expectation and `known_gap: true`,
//! and a paired test that pins the finding the guard gives today.

use agent_caps_core::domain::authority::Principal;
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::policy::{
    DefLayer, Expect, Finding, Fixture, Level, Polarity, PolicyDef, Rule,
};
use agent_caps_core::domain::predicate::{Cmp, Cond, EventFilter, Lit, Pred, Scope};
use agent_caps_core::domain::schema::{EventKind, Field};

use super::common::{
    GUARD, agent, at, bash, catalog, fixture, id, lost_line, outcome, test_guard, the_agent,
    the_user, verdict, violated,
};

/// A score of the bench, recorded by `by`.
fn bench_by(by: Principal, score: f64) -> Event {
    at(
        by,
        0,
        Body::Measured {
            oracle: "bench".to_owned(),
            score,
        },
    )
}

/// A score of the bench, recorded by the root, where the scenarios place the oracle.
fn bench(score: f64) -> Event {
    bench_by(the_user(), score)
}

/// The events of the example the guard gets wrong: a high score, then a low one.
fn high_then_low() -> Vec<Event> {
    vec![bench(0.9), bench(0.5), agent(Body::Stop)]
}

/// Force: at the end of a turn, the bench must have scored 0.8 or more. This is the nearest
/// form: "ever", not "the latest".
fn bench_guard() -> PolicyDef {
    PolicyDef {
        id: id(GUARD),
        name: "bench-score".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::Stop,
        when: None,
        rule: Rule::Structural(Pred::Count {
            event: EventFilter {
                kind: EventKind::Measured,
                cond: Some(Cond::All(vec![
                    Cond::Eq(Field::Oracle, Lit::Text("bench".to_owned())),
                    Cond::Num(Field::Score, Cmp::Ge, 0.8),
                ])),
            },
            scope: Scope::Session,
            cmp: Cmp::Ge,
            n: 1,
        }),
        polarity: Polarity::Guard {
            level: Level::Force,
        },
        enabled: true,
        author: the_user(),
        fixtures: vec![
            // A stopping guard needs a real example it fails on, and one it holds on.
            fixture("no score at all", vec![agent(Body::Stop)], Expect::Violated),
            fixture(
                "a score of 0.5 only",
                vec![bench(0.5), agent(Body::Stop)],
                Expect::Violated,
            ),
            fixture(
                "a score of 0.9",
                vec![bench(0.9), agent(Body::Stop)],
                Expect::Satisfied,
            ),
            // What the guard should do: the latest score is the one that counts.
            Fixture {
                known_gap: true,
                ..fixture(
                    "a high score and then a low one",
                    high_then_low(),
                    Expect::Violated,
                )
            },
        ],
    }
}

/// UC16: pins the gap of S7 (#4): the guard finds the high-then-low example satisfied. When the
/// model can say "the latest", this fails; then the fixture loses `known_gap` and this test goes.
#[test]
fn gap_s7_an_earlier_high_score_still_satisfies_the_guard() {
    let out = outcome(&catalog(vec![bench_guard()], vec![]), &high_then_low());
    // Today (wrong): satisfied, so the turn may end. It should be Violated.
    assert_eq!(out.guards.len(), 1);
    assert_eq!(out.guards[0].finding, Finding::Satisfied);
    assert_eq!(out.verdict, Verdict::Allow);
}

/// UC16: the bench guard stops without a high score and lets one through.
#[test]
fn the_bench_guard_stops_without_a_high_score_and_lets_one_through() {
    let catalog = catalog(vec![bench_guard()], vec![]);
    assert_eq!(
        verdict(&catalog, &[bench(0.5), agent(Body::Stop)]),
        violated()
    );
    assert_eq!(
        verdict(&catalog, &[bench(0.9), agent(Body::Stop)]),
        Verdict::Allow
    );
}

/// UC16, FR35, UC25: a score recorded by one below the guard's author does not move the
/// guard's slot, so a high score from there does not let the turn end.
#[test]
fn a_score_from_below_the_guards_author_does_not_count() {
    let catalog = catalog(vec![bench_guard()], vec![]);
    assert_eq!(
        verdict(&catalog, &[bench_by(the_agent(), 0.9), agent(Body::Stop)]),
        violated()
    );
}

/// FR20: a lost line makes the last value unknown, so an advising guard warns with an unknown
/// cause.
#[test]
fn a_last_value_is_false_when_unseen_and_unknown_when_lost() {
    let mut guard = test_guard(Level::Advise);
    guard.rule = Rule::Structural(Pred::Last {
        field: Field::Ok,
        scope: Scope::Task,
        value: Lit::Bool(true),
    });
    guard.fixtures = vec![];
    let catalog = catalog(vec![guard], vec![]);
    let start = agent(Body::TaskStart);
    let stop = agent(Body::Stop);
    let warned = Verdict::Warn(vec![Cause::Violated(id(GUARD))]);
    assert_eq!(verdict(&catalog, &[start.clone(), stop.clone()]), warned);
    assert_eq!(
        verdict(
            &catalog,
            &[start.clone(), bash("cargo build", Some(true)), stop.clone()]
        ),
        Verdict::Allow
    );
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                bash("cargo build", Some(true)),
                bash("cargo build", Some(false)),
                stop.clone()
            ]
        ),
        warned
    );
    assert_eq!(
        verdict(
            &catalog,
            &[start, bash("cargo build", Some(true)), lost_line(), stop]
        ),
        Verdict::Warn(vec![Cause::Unknown(id(GUARD))])
    );
}
