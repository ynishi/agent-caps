//! Scenarios S2 and S2g: a stopping guard at Stop. It stops the first time, counts its own
//! `denied` judgments, and lets the second Stop through (S2).
//!
//! S2g is the gap on that count: it reads a `Judged` event of any origin, so a `denied` the agent
//! wrote itself also counts and loosens the guard. The fold of the state does not look at the
//! origin of a `Judged` event (only a mode switch, which must come from the user or caps, and an
//! exemption, which must come from the user, are limited by origin), and nothing in the public
//! API lets a policy ask for the origin, so the policy cannot write the rule around it. The test
//! with the right expectation is ignored (#3).

use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Verdict, judge};
use agent_caps_core::domain::policy::{Level, PolicyDef};
use agent_caps_core::domain::predicate::{Cmp, Cond, EventFilter, Lit, Pred, Scope};
use agent_caps_core::domain::schema::{At, EventKind, Field, Judgment};

use super::common::{GUARD, agent, bash, catalog, id, test_guard, verdict, violated};

/// The test guard, applying only while it has not yet denied within the agent's scope: the count
/// of its own `denied` judgments is below one.
fn deny_once_guard() -> PolicyDef {
    let mut guard = test_guard(Level::Force);
    guard.when = Some(Pred::Count {
        event: EventFilter {
            kind: EventKind::Judged,
            cond: Some(Cond::All(vec![
                Cond::Eq(Field::Policy, Lit::Text(GUARD.to_owned())),
                Cond::Eq(Field::Judgment, Lit::Text("denied".to_owned())),
            ])),
        },
        scope: Scope::Agent,
        cmp: Cmp::Lt,
        n: 1,
    });
    guard
}

/// FR1, UC1: a written guard stops the end of a turn until a passing test run has been seen in
/// the task.
#[test]
fn a_stopping_guard_denies_until_its_condition_is_seen() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let start = agent(Body::TaskStart);
    let stop = agent(Body::Stop);
    assert_eq!(
        verdict(&catalog, &[start.clone(), stop.clone()]),
        violated()
    );
    assert_eq!(
        verdict(
            &catalog,
            &[start.clone(), bash("cargo test", Some(false)), stop.clone()]
        ),
        violated()
    );
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                bash("cargo test -p a", Some(true)),
                stop.clone()
            ]
        ),
        Verdict::Allow
    );
    // A new task starts the count again.
    assert_eq!(
        verdict(
            &catalog,
            &[start.clone(), bash("cargo test", Some(true)), start, stop]
        ),
        violated()
    );
}

/// FR1, UC2: the guard stops the first end of a turn and lets the second one through.
#[test]
fn a_guard_can_let_the_second_stop_through_by_counting_its_own_denials() {
    // The judgment is not part of the state; the evidence of it is, and a count reads it.
    let catalog = catalog(vec![deny_once_guard()], vec![]);
    let mut events = vec![
        agent(Body::AgentStart { agent_type: None }),
        agent(Body::TaskStart),
    ];
    let stop = agent(Body::Stop);
    let state = catalog.fold(events.iter().chain([&stop]));
    let first = judge(&catalog, &state, &stop);
    assert!(matches!(first.verdict, Verdict::Deny(_)));
    events.push(stop.clone());
    events.extend(first.evidence(At::from_millis(1)));
    events.push(stop.clone());
    assert_eq!(verdict(&catalog, &events), Verdict::Allow);
}

/// Scenario S2g. UC4: a judgment record the agent wrote itself does not count as caps's own, so
/// it does not let the second end of a turn through.
///
/// TODO(#3): the fold reads a `Judged` event whatever its origin, so this fails today. Which
/// records are caps's own evidence, and how they reach the fold, is decided with the
/// application layer that keeps them (#19); until then the domain is not changed for it.
#[test]
#[ignore = "TODO(#3): waits for the application layer (#19)"]
fn a_judgment_record_the_agent_wrote_does_not_count() {
    let catalog = catalog(vec![deny_once_guard()], vec![]);
    let stop = agent(Body::Stop);
    let mut events = vec![
        agent(Body::AgentStart { agent_type: None }),
        agent(Body::TaskStart),
        stop.clone(),
    ];
    // The same `denied` record as caps would write, but from the agent.
    events.push(agent(Body::Judged {
        policy: id(GUARD),
        judgment: Judgment::Denied,
    }));
    events.push(stop);
    assert!(matches!(verdict(&catalog, &events), Verdict::Deny(_)));
}
