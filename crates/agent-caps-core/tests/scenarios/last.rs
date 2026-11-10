//! The `Last` operator (the last event that matches a filter within a scope, and a condition on
//! it), and scenario S7, the "latest value".
//!
//! S7 wants: "stop the turn unless the latest bench score is 0.8 or more". `Last` reads the last
//! event that matches its filter (a measurement of the oracle `bench`) and asks a condition of
//! it (`score >= 0.8`), the same condition a `Now`, a `Once` or a `Count` takes. After a high
//! score and a low one the guard is violated, where "some score was high" would be satisfied (#4).

use agent_caps_core::domain::authority::Principal;
use agent_caps_core::domain::catalog::AcceptError;
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::policy::{
    DefLayer, Expect, Finding, Level, Polarity, PolicyDef, Rule,
};
use agent_caps_core::domain::predicate::{Cmp, Cond, EventFilter, Lit, Pred, PredError, Scope};
use agent_caps_core::domain::schema::{EventKind, Field, FieldType};
use agent_caps_core::domain::tx::{TxDecision, TxPolicy};

use super::common::{
    GUARD, agent, at, bash, catalog, fixture, id, lost_line, outcome, rejected, test_guard,
    the_agent, the_user, verdict, violated,
};

/// A score of `oracle`, recorded by `by`.
fn measured_by(by: Principal, oracle: &str, score: f64) -> Event {
    at(
        by,
        0,
        Body::Measured {
            oracle: oracle.to_owned(),
            score,
        },
    )
}

/// A score of the bench, recorded by `by`.
fn bench_by(by: Principal, score: f64) -> Event {
    measured_by(by, "bench", score)
}

/// A score of the bench, recorded by the root, where the scenarios place the oracle.
fn bench(score: f64) -> Event {
    bench_by(the_user(), score)
}

/// A score of another oracle, recorded by the root.
fn lint(score: f64) -> Event {
    measured_by(the_user(), "lint", score)
}

/// The measurements of the oracle `bench`.
fn bench_scores() -> EventFilter {
    EventFilter {
        kind: EventKind::Measured,
        cond: Some(Cond::Eq(Field::Oracle, Lit::Text("bench".to_owned()))),
    }
}

/// The last score of the bench within the session is at least 0.8.
fn latest_bench_score() -> Pred {
    Pred::Last {
        event: bench_scores(),
        scope: Scope::Session,
        test: Cond::Num(Field::Score, Cmp::Ge, 0.8),
    }
}

/// Force: at the end of a turn, the latest bench score must be 0.8 or more.
fn bench_guard() -> PolicyDef {
    PolicyDef {
        id: id(GUARD),
        name: "bench-score".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::Stop,
        when: None,
        rule: Rule::Structural(latest_bench_score()),
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
            // The latest score is the one that counts (#4).
            fixture(
                "a high score and then a low one",
                vec![bench(0.9), bench(0.5), agent(Body::Stop)],
                Expect::Violated,
            ),
        ],
    }
}

/// UC16: the turn is held until the latest bench score is high enough, and a high score that a
/// lower one followed does not let it end (#4); a low score that a higher one followed does.
#[test]
fn the_latest_bench_score_decides_whether_the_turn_may_end() {
    let catalog = catalog(vec![bench_guard()], vec![]);
    let stop = || agent(Body::Stop);
    assert_eq!(verdict(&catalog, &[stop()]), violated());
    assert_eq!(verdict(&catalog, &[bench(0.5), stop()]), violated());
    assert_eq!(verdict(&catalog, &[bench(0.9), stop()]), Verdict::Allow);
    assert_eq!(
        verdict(&catalog, &[bench(0.9), bench(0.5), stop()]),
        violated()
    );
    assert_eq!(
        verdict(&catalog, &[bench(0.5), bench(0.9), stop()]),
        Verdict::Allow
    );
    // The bound is inclusive.
    assert_eq!(verdict(&catalog, &[bench(0.8), stop()]), Verdict::Allow);
}

/// UC16: the score of another oracle is not the bench's: it neither lets the turn end nor
/// replaces the bench's last score.
#[test]
fn the_score_of_another_oracle_is_not_counted() {
    let catalog = catalog(vec![bench_guard()], vec![]);
    let stop = || agent(Body::Stop);
    assert_eq!(verdict(&catalog, &[lint(0.99), stop()]), violated());
    assert_eq!(
        verdict(&catalog, &[bench(0.5), lint(0.99), stop()]),
        violated()
    );
    assert_eq!(
        verdict(&catalog, &[bench(0.9), lint(0.1), stop()]),
        Verdict::Allow
    );
}

/// UC16, FR20: a score that is not a number cannot be ordered, so the guard cannot tell and the
/// turn is not let through; and a later score takes its place.
#[test]
fn a_last_score_that_is_not_a_number_is_unknown() {
    let catalog = catalog(vec![bench_guard()], vec![]);
    let stop = || agent(Body::Stop);
    let events = [bench(f64::NAN), stop()];
    assert_eq!(
        outcome(&catalog, &events).guards[0].finding,
        Finding::Unknown
    );
    assert_ne!(verdict(&catalog, &events), Verdict::Allow);
    assert_eq!(
        verdict(&catalog, &[bench(f64::NAN), bench(0.9), stop()]),
        Verdict::Allow
    );
}

/// UC16, UC25: a score recorded by one below the guard's author does not move the guard's slot,
/// so a high score from there does not let the turn end.
#[test]
fn a_score_from_below_the_guards_author_does_not_count() {
    let catalog = catalog(vec![bench_guard()], vec![]);
    assert_eq!(
        verdict(&catalog, &[bench_by(the_agent(), 0.9), agent(Body::Stop)]),
        violated()
    );
}

/// UC16, UC25: a score that is not a number, held by the slot, is not a change when a claim
/// leaves it as it is: a measurement of another oracle from one below the guard's author takes
/// effect, where a NaN taken for a change would loosen the guard's slot and stop it.
#[test]
fn a_score_that_is_not_a_number_is_not_a_change_when_it_is_left_alone() {
    let catalog = catalog(vec![bench_guard()], vec![]);
    let state = catalog.fold(&[bench(f64::NAN)]);
    let report = catalog.admit(
        &state,
        &measured_by(the_agent(), "lint", 0.1),
        &TxPolicy::standard(),
    );
    assert_eq!(report.decision, TxDecision::Commit);
    assert!(report.uncovered.is_empty());
    // The same score again from the bench is no change either; a score that replaces it is one,
    // and from one below the guard's author it does not take effect.
    let same = bench_by(the_agent(), f64::NAN);
    let report = catalog.admit(&state, &same, &TxPolicy::standard());
    assert_eq!(report.decision, TxDecision::Commit);
    let report = catalog.admit(&state, &bench_by(the_agent(), 0.9), &TxPolicy::standard());
    assert_eq!(report.decision, TxDecision::Abort);
}

/// FR2, FR41: a condition that does not fit the events the filter looks for is rejected when the
/// catalog is accepted: a field of another kind, an operand of another type, and a filter that
/// is itself ill-typed. Each is the error a `Now`, a `Once` or a `Count` gives.
#[test]
fn a_last_whose_test_does_not_fit_its_events_is_rejected() {
    let with = |event: EventFilter, test: Cond| {
        let mut guard = test_guard(Level::Advise);
        guard.fixtures = vec![];
        guard.rule = Rule::Structural(Pred::Last {
            event,
            scope: Scope::Session,
            test,
        });
        rejected(vec![guard], vec![])
    };
    let error = |error| {
        vec![AcceptError::Predicate {
            policy: id(GUARD),
            error,
        }]
    };
    // A field of a tool use, read from a measurement.
    assert_eq!(
        with(bench_scores(), Cond::Eq(Field::Ok, Lit::Bool(true))),
        error(PredError::OtherKind {
            field: Field::Ok,
            read_from: EventKind::Measured,
        })
    );
    // A number, compared with text.
    assert_eq!(
        with(
            bench_scores(),
            Cond::Eq(Field::Score, Lit::Text("high".to_owned()))
        ),
        error(PredError::Mismatch {
            field: Field::Score,
            ty: FieldType::Num,
        })
    );
    // The filter reads a field of another kind.
    let ill_filter = EventFilter {
        kind: EventKind::Measured,
        cond: Some(Cond::Eq(Field::Tool, Lit::Text("Bash".to_owned()))),
    };
    assert_eq!(
        with(ill_filter, Cond::Num(Field::Score, Cmp::Ge, 0.8)),
        error(PredError::OtherKind {
            field: Field::Tool,
            read_from: EventKind::Measured,
        })
    );
}

/// FR20: a lost line makes the last value unknown, so an advising guard warns with an unknown
/// cause; a call whose result is not known is unknown too, and a later one takes its place.
#[test]
fn a_last_value_is_false_when_unseen_and_unknown_when_lost() {
    let mut guard = test_guard(Level::Advise);
    guard.rule = Rule::Structural(Pred::Last {
        event: EventFilter {
            kind: EventKind::ToolUse,
            cond: None,
        },
        scope: Scope::Task,
        test: Cond::Eq(Field::Ok, Lit::Bool(true)),
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
