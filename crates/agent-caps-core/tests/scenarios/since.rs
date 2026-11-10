//! The `Since` scope: a period that is "since the last event matching X". The event that closes
//! an interval is judged with the interval before it, and the interval starts again before the
//! next event.
//!
//! This is where starting a procedure again inside the same task is checked (#10, fixed): a
//! commit that needs a test since the last commit is stopped when the only test came before the
//! earlier commit. The `Task` scope, in which one test is enough for the whole task, is stated in
//! the `commit_after_test` module.

use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::exempt::Lifetime;
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::policy::{Expect, Level, PolicyDef, Rule};
use agent_caps_core::domain::predicate::{Cmp, Cond, EventFilter, Lit, Pred, Scope};
use agent_caps_core::domain::schema::{EventKind, Field, Source};

use super::common::{
    GUARD, agent, bash, catalog, commit_filter, edit, exemption, fixture, id, test_guard,
    tested_in, unreadable, verdict, violated, words,
};

fn test_run() -> Event {
    bash("cargo test", Some(true))
}

fn commit(ok: Option<bool>) -> Event {
    bash("git commit -m x", ok)
}

fn unknown() -> Verdict {
    Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
}

/// A stopping guard on the end of a turn: `cargo test` passed since the boundary `scope` names.
fn stop_guard_in(scope: Scope) -> PolicyDef {
    let mut guard = test_guard(Level::Force);
    guard.rule = Rule::Structural(tested_in(scope));
    guard
}

/// A stopping guard on a commit: `cargo test` passed since the last commit.
fn commit_guard() -> PolicyDef {
    let mut guard = test_guard(Level::Force);
    guard.subject = EventKind::ToolUse;
    guard.when = Some(Pred::Now(Cond::Words(Field::Command, words("git commit"))));
    guard.rule = Rule::Structural(tested_in(Scope::Since(commit_filter(false))));
    guard.fixtures = vec![
        fixture(
            "first commit after a test",
            vec![agent(Body::TaskStart), test_run(), commit(None)],
            Expect::Satisfied,
        ),
        fixture(
            "second commit without a new test",
            vec![
                agent(Body::TaskStart),
                test_run(),
                commit(Some(true)),
                commit(None),
            ],
            Expect::Violated,
        ),
    ];
    guard
}

/// A stopping guard on every tool use but a commit, which is what an exemption can lift.
fn no_commit_guard() -> PolicyDef {
    let mut guard = test_guard(Level::Force);
    guard.subject = EventKind::ToolUse;
    guard.rule = Rule::Structural(Pred::Now(Cond::Not(Box::new(Cond::Words(
        Field::Command,
        words("git commit"),
    )))));
    guard.fixtures = vec![
        fixture(
            "commit",
            vec![agent(Body::TaskStart), commit(None)],
            Expect::Violated,
        ),
        fixture(
            "edit",
            vec![agent(Body::TaskStart), edit("src/a.rs")],
            Expect::Satisfied,
        ),
    ];
    guard
}

/// FR33, UC1: a second commit with no test after the first one is stopped, however recent the
/// test before the first commit was; a new test in between lets it through.
#[test]
fn a_second_commit_without_a_new_test_is_stopped() {
    let catalog = catalog(vec![commit_guard()], vec![]);
    let start = agent(Body::TaskStart);
    assert_eq!(
        verdict(&catalog, &[start.clone(), test_run(), commit(None)]),
        Verdict::Allow
    );
    assert_eq!(
        verdict(&catalog, &[start.clone(), commit(None)]),
        violated()
    );
    // The same task, but the test came before the first commit only.
    assert_eq!(
        verdict(
            &catalog,
            &[start.clone(), test_run(), commit(Some(true)), commit(None)]
        ),
        violated()
    );
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                test_run(),
                commit(Some(true)),
                test_run(),
                commit(None)
            ]
        ),
        Verdict::Allow
    );
    // An edit between the commits is not a test.
    assert_eq!(
        verdict(
            &catalog,
            &[
                start,
                test_run(),
                commit(Some(true)),
                edit("src/a.rs"),
                commit(None)
            ]
        ),
        violated()
    );
}

/// FR33, UC1: the event that closes an interval is judged with the interval before it, and
/// the interval starts again before the next event: `once(commit, Since(commit))` is true on a
/// commit and on nothing else, and `count(commit, Since(commit))` is at most 1.
#[test]
fn the_closing_event_is_judged_with_the_interval_before_it() {
    let advise = |rule| {
        let mut guard = test_guard(Level::Advise);
        guard.subject = EventKind::ToolUse;
        guard.rule = Rule::Structural(rule);
        guard.fixtures = vec![];
        catalog(vec![guard], vec![])
    };
    let since = || Scope::Since(commit_filter(false));
    let once = advise(Pred::Once {
        event: commit_filter(false),
        scope: since(),
    });
    let start = agent(Body::TaskStart);
    assert_eq!(
        verdict(&once, &[start.clone(), commit(None)]),
        Verdict::Allow
    );
    assert_eq!(
        verdict(&once, &[start.clone(), commit(None), edit("src/a.rs")]),
        Verdict::Warn(vec![Cause::Violated(id(GUARD))])
    );
    assert_eq!(
        verdict(
            &once,
            &[start.clone(), commit(None), edit("src/a.rs"), commit(None)]
        ),
        Verdict::Allow
    );
    let twice = advise(Pred::Not(Box::new(Pred::Count {
        event: commit_filter(false),
        scope: since(),
        cmp: Cmp::Ge,
        n: 2,
    })));
    assert_eq!(
        verdict(
            &twice,
            &[start.clone(), commit(None), commit(None), commit(None)]
        ),
        Verdict::Allow
    );
    // Closing loosens a count: without the scope, the third commit is the third.
    let task = advise(Pred::Not(Box::new(Pred::Count {
        event: commit_filter(false),
        scope: Scope::Task,
        cmp: Cmp::Ge,
        n: 2,
    })));
    assert_eq!(
        verdict(&task, &[start, commit(None), commit(None), commit(None)]),
        Verdict::Warn(vec![Cause::Violated(id(GUARD))])
    );
}

/// FR33, UC1: a `Since` scope starts again at a new session and not at a new task.
#[test]
fn a_since_scope_starts_again_at_a_session_and_not_at_a_task() {
    let catalog = catalog(
        vec![stop_guard_in(Scope::Since(commit_filter(false)))],
        vec![],
    );
    let stop = agent(Body::Stop);
    let task = agent(Body::TaskStart);
    assert_eq!(
        verdict(
            &catalog,
            &[task.clone(), test_run(), task.clone(), stop.clone()]
        ),
        Verdict::Allow
    );
    assert_eq!(
        verdict(
            &catalog,
            &[task, test_run(), agent(Body::SessionStart), stop]
        ),
        violated()
    );
}

/// FR33, UC1: one event can close several `Since` scopes at once, and each starts again.
#[test]
fn two_since_scopes_close_on_one_event() {
    let edited = || EventFilter {
        kind: EventKind::ToolUse,
        cond: Some(Cond::Eq(Field::Tool, Lit::Text("Edit".to_owned()))),
    };
    let bash_call = EventFilter {
        kind: EventKind::ToolUse,
        cond: Some(Cond::Eq(Field::Tool, Lit::Text("Bash".to_owned()))),
    };
    // No edit since the last commit, and none since the last shell call.
    let mut guard = test_guard(Level::Force);
    guard.rule = Rule::Structural(Pred::All(vec![
        Pred::Not(Box::new(Pred::Once {
            event: edited(),
            scope: Scope::Since(commit_filter(false)),
        })),
        Pred::Not(Box::new(Pred::Once {
            event: edited(),
            scope: Scope::Since(bash_call),
        })),
    ]));
    guard.fixtures = vec![
        fixture(
            "edited",
            vec![agent(Body::TaskStart), edit("src/a.rs"), agent(Body::Stop)],
            Expect::Violated,
        ),
        fixture(
            "clean",
            vec![agent(Body::TaskStart), agent(Body::Stop)],
            Expect::Satisfied,
        ),
    ];
    let catalog = catalog(vec![guard], vec![]);
    let start = agent(Body::TaskStart);
    let stop = agent(Body::Stop);
    // A commit is also a shell call: both scopes close on it.
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                edit("src/a.rs"),
                commit(Some(true)),
                stop.clone()
            ]
        ),
        Verdict::Allow
    );
    // Another shell call closes only one of them.
    assert_eq!(
        verdict(
            &catalog,
            &[start, edit("src/a.rs"), bash("ls", Some(true)), stop]
        ),
        violated()
    );
}

/// FR33, FR20, UC3: an unreadable record closes a `Since` scope as unknown only when the filter's
/// kind is recorded where the record was lost; elsewhere a fact already seen stays seen.
#[test]
fn an_unreadable_record_closes_a_since_scope_only_where_its_kind_is_recorded() {
    let stop = agent(Body::Stop);
    let tested_after_commit = catalog(
        vec![stop_guard_in(Scope::Since(commit_filter(false)))],
        vec![],
    );
    let events = |lost| {
        [
            agent(Body::TaskStart),
            test_run(),
            unreadable(lost),
            stop.clone(),
        ]
    };
    // A commit is a tool use, recorded in the transcript: the lost line may have been one.
    assert_eq!(
        verdict(&tested_after_commit, &events(Source::Transcript)),
        unknown()
    );
    // A lost record of the evidence cannot have been a tool use.
    assert_eq!(
        verdict(&tested_after_commit, &events(Source::Evidence)),
        Verdict::Allow
    );

    // The other way round, for a kind recorded in the evidence.
    let judged = EventFilter {
        kind: EventKind::Judged,
        cond: None,
    };
    let tested_after_judgment = catalog(vec![stop_guard_in(Scope::Since(judged))], vec![]);
    assert_eq!(
        verdict(&tested_after_judgment, &events(Source::Evidence)),
        unknown()
    );
    assert_eq!(
        verdict(&tested_after_judgment, &events(Source::Transcript)),
        Verdict::Allow
    );

    // A mode switch the agent writes is read from the transcript and closes the scope like any
    // other, so a lost record of either source may have been one.
    let switched = EventFilter {
        kind: EventKind::ModeSwitch,
        cond: None,
    };
    let tested_after_switch = catalog(vec![stop_guard_in(Scope::Since(switched))], vec![]);
    for lost in [Source::Transcript, Source::Evidence] {
        assert_eq!(verdict(&tested_after_switch, &events(lost)), unknown());
    }
}

/// FR33, FR20: when the filter's condition is not known on an event (`ok` of a call whose result
/// has not come back), it is not known whether the interval closed, and the guard cannot tell.
#[test]
fn a_filter_whose_condition_is_unknown_leaves_the_close_unknown() {
    let catalog = catalog(
        vec![stop_guard_in(Scope::Since(commit_filter(true)))],
        vec![],
    );
    let start = agent(Body::TaskStart);
    let stop = agent(Body::Stop);
    let after = |commit| verdict(&catalog, &[start.clone(), test_run(), commit, stop.clone()]);
    assert_eq!(after(commit(None)), unknown());
    // A commit that failed does not close the interval.
    assert_eq!(after(commit(Some(false))), Verdict::Allow);
    assert_eq!(after(commit(Some(true))), violated());
}

/// FR33, FR9, UC1: an exemption that lasts within `Since(g)` ends after `g`: `g` itself is judged
/// with it, the next event without it. A `g` that failed does not end it, and one whose result is
/// not known ends it, since it is not known whether it did.
#[test]
fn a_within_since_exemption_ends_after_the_event() {
    let catalog = catalog(vec![no_commit_guard()], vec![]);
    let start = agent(Body::TaskStart);
    let until_commit = || exemption(None, Lifetime::Within(Scope::Since(commit_filter(true))));
    let after = |first: Event| {
        verdict(
            &catalog,
            &[start.clone(), until_commit(), first, commit(Some(true))],
        )
    };
    // The closing commit is judged with the exemption still in effect.
    assert_eq!(
        verdict(
            &catalog,
            &[start.clone(), until_commit(), commit(Some(true))]
        ),
        Verdict::Allow
    );
    // The next one is not.
    assert_eq!(after(commit(Some(true))), violated());
    // A failed commit does not end it; an unknown one does.
    assert_eq!(after(commit(Some(false))), Verdict::Allow);
    assert_eq!(after(commit(None)), violated());
}
