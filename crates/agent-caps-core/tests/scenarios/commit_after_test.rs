//! Scenario S1: a commit (`git commit`, Force) passes only when `cargo test` succeeded within the
//! same task. A new task counts again. A test whose result has not come back (`ok` is `None`) is
//! not a success: the guard cannot tell and denies with `Cause::Unknown`, not `Cause::Violated`.
//!
//! Within one task the check is not repeated: the test that passed stays seen until the next
//! task starts, so a second commit after more edits passes without a new test run. That is what
//! the `Task` scope means. A commit that needs a new test every time uses `Since` instead (the
//! `since` module).

use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Cause, Verdict};

use super::common::{
    GUARD, agent, bash, catalog, commit_after_test_guard as commit_guard, edit, id, verdict,
    violated,
};

/// UC1: a commit is stopped until `cargo test` has passed within the task; a failing test is not
/// a pass.
#[test]
fn a_commit_is_denied_until_a_test_passed_in_the_task() {
    let catalog = catalog(vec![commit_guard()], vec![]);
    let start = agent(Body::TaskStart);
    let commit = bash("git commit -m x", None);
    assert_eq!(
        verdict(&catalog, &[start.clone(), commit.clone()]),
        violated()
    );
    // A failing test is not a pass.
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                bash("cargo test", Some(false)),
                commit.clone()
            ]
        ),
        violated()
    );
    assert_eq!(
        verdict(&catalog, &[start, bash("cargo test", Some(true)), commit],),
        Verdict::Allow
    );
}

/// UC1: a new task starts the count of tests again.
#[test]
fn a_new_task_counts_the_tests_again() {
    let catalog = catalog(vec![commit_guard()], vec![]);
    let start = agent(Body::TaskStart);
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                bash("cargo test", Some(true)),
                start,
                bash("git commit -m x", None)
            ]
        ),
        violated()
    );
}

/// UC1: with the `Task` scope, one passing test is enough for the whole task: a second commit
/// after more edits needs no new test run. A commit that needs a new test every time uses `Since`
/// (see the `since` module).
#[test]
fn within_a_task_a_second_commit_after_more_edits_needs_no_new_test() {
    let catalog = catalog(vec![commit_guard()], vec![]);
    assert_eq!(
        verdict(
            &catalog,
            &[
                agent(Body::TaskStart),
                bash("cargo test", Some(true)),
                bash("git commit -m x", None),
                edit("src/a.rs"),
                bash("git commit -m y", None)
            ]
        ),
        Verdict::Allow
    );
}

/// UC1, FR20: a test whose result has not come back is not a pass: the guard cannot tell and
/// denies with an unknown cause.
#[test]
fn a_test_without_its_result_leaves_the_commit_unknown_not_violated() {
    let catalog = catalog(vec![commit_guard()], vec![]);
    assert_eq!(
        verdict(
            &catalog,
            &[
                agent(Body::TaskStart),
                bash("cargo test", None),
                bash("git commit -m x", None)
            ]
        ),
        Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
    );
}

/// UC1: what is not a commit is not judged by the commit guard.
#[test]
fn what_is_not_a_commit_is_not_judged() {
    let catalog = catalog(vec![commit_guard()], vec![]);
    assert_eq!(
        verdict(
            &catalog,
            &[agent(Body::TaskStart), bash("git status", None)]
        ),
        Verdict::Allow
    );
    assert_eq!(
        verdict(&catalog, &[agent(Body::TaskStart), edit("src/a.rs")]),
        Verdict::Allow
    );
}
