//! Scenarios S2 and S2g: a stopping guard at Stop. It stops the first time, counts its own
//! `denied` judgments, and lets the second Stop through (S2).
//!
//! S2g was a gap on that count (#3), and is fixed: a `denied` written by one below the guard's
//! author counted as the real record, and let the second Stop through. A record of a judgment is
//! now a claim, written in the name of the judged policy's author: one that would move the
//! count of a policy counts only from one who covers that policy's author, so a forged record is
//! aborted and the genuine one counts.

use agent_caps_core::domain::catalog::Capabilities;
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Verdict, judge};
use agent_caps_core::domain::policy::Level;
use agent_caps_core::domain::predicate::{Cmp, Cond, EventFilter, Lit, Pred, Scope};
use agent_caps_core::domain::schema::{At, EventKind, Field, Judgment};

use super::common::{
    GUARD, Written, agent, bash, catalog, id, test_guard, the_user, verdict, violated,
};

/// The test guard, applying only while it has not yet denied within the session: the count of
/// its own `denied` judgments is below one.
///
/// This was once counted within the agent, so that each sub agent was stopped once. There is no
/// scope of one agent now (FR39 is not decided): the count is the session's, and a sub agent
/// that starts later is let through where its parent was stopped.
fn deny_once_guard() -> Written {
    let mut guard = test_guard(Level::Force);
    guard.when = Some(Pred::Count {
        event: EventFilter {
            kind: EventKind::Judged,
            cond: Some(Cond::All(vec![
                Cond::Eq(Field::Policy, Lit::Text(GUARD.to_owned())),
                Cond::Eq(Field::Judgment, Lit::Text("denied".to_owned())),
            ])),
        },
        scope: Scope::Session,
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

/// FR1, UC2, FR41: the guard stops the first end of a turn and lets the second one through. The
/// record of the denial is written in the name of the guard's author, so it counts. The count is
/// the session's: "once for each agent" can no longer be written (FR39).
#[test]
fn a_guard_can_let_the_second_stop_through_by_counting_its_own_denials() {
    // The judgment is not part of the state; the evidence of it is, and a count reads it.
    let catalog = catalog(vec![deny_once_guard()], vec![]);
    let mut events = vec![agent(Body::SessionStart), agent(Body::TaskStart)];
    let stop = agent(Body::Stop);
    let state = catalog.fold(events.iter().chain([&stop]));
    let first = judge(&catalog, &state, &stop, &Capabilities::full());
    assert!(matches!(first.verdict, Verdict::Deny(_)));
    let evidence = first.evidence(At::from_millis(1));
    assert!(evidence.iter().all(|e| e.by == the_user()));
    events.push(stop.clone());
    events.extend(evidence);
    events.push(stop.clone());
    assert_eq!(verdict(&catalog, &events), Verdict::Allow);
}

/// Scenario S2g. UC25, FR41, UC2: a record of a denial written by one below the guard's author
/// does not move the guard's count, so it does not let the second end of a turn through.
#[test]
fn a_judgment_record_the_agent_wrote_does_not_count() {
    let catalog = catalog(vec![deny_once_guard()], vec![]);
    let stop = agent(Body::Stop);
    let mut events = vec![
        agent(Body::SessionStart),
        agent(Body::TaskStart),
        stop.clone(),
    ];
    // The same `denied` record as caps would write, but from the agent.
    events.push(agent(Body::Judged {
        policy: id(GUARD),
        judgment: Judgment::Denied,
        written: Level::Force,
        enforced: Level::Force,
    }));
    events.push(stop);
    assert!(matches!(verdict(&catalog, &events), Verdict::Deny(_)));
}
