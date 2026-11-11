//! Scenario V3: a procedure (the source of a skill) seen as policies. "Test, then clippy, then
//! commit" is written as rewards, one per stage, and a guard:
//!
//! - `test-stage` (reward): a `cargo test` that succeeded is a hit.
//! - `clippy-stage` (reward): a `cargo clippy` is a hit when the test stage was a hit in the task.
//! - `commit-after-test` (Force guard): a `git commit` needs the test stage to have been a hit
//!   in the task.
//!
//! Where the procedure stands is read from the judgments caps recorded: `Once` of a `Judged`
//! event of the stage's policy with the judgment `hit`. The caller appends the evidence of each
//! judgment and folds it (`Outcome::evidence`), so the tests go through the `step` helper.
//!
//! A straight run of the procedure is expressible, and the tests below state it. The guard has a
//! real example it fails on and one it holds on, as a stopping guard needs.
//!
//! Starting the procedure again inside the same task was a gap (#10). It was fixed by the `Since`
//! scope: a guard that reads "a test since the last commit" stops a second commit with no new
//! test. The `since` module checks that, not this one.
//!
//! The reward edges are only stated as facts: `Outcome.rewards[].recognition` is `Hit` or `None`,
//! so a stage that was not reached (violated) and one that could not be told (unknown, after a
//! record that could not be read) both give `None`. No gap is placed there.

use agent_caps_core::domain::catalog::Catalog;
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Recognition, Verdict};
use agent_caps_core::domain::policy::{
    DefLayer, Expect, Finding, Level, Polarity, PolicyDef, Rule,
};
use agent_caps_core::domain::predicate::{By, Cond, EventFilter, Lit, Pred, Scope, Span};
use agent_caps_core::domain::schema::{EventKind, Field, Judgment};

use super::common::{
    GUARD, OTHER, REWARD, Written, agent, anyone, at, bash, catalog, fixture, id, outcome, step,
    the_user, unreadable, verdict, words, written,
};

const COMMIT: &str = GUARD;
const TEST_STAGE: &str = REWARD;
const CLIPPY_STAGE: &str = OTHER;

/// The record that the policy was a hit, in the name of its author.
fn hit(policy: &str) -> Event {
    at(
        the_user(),
        0,
        Body::Judged {
            policy: id(policy),
            judgment: Judgment::Hit,
            written: Level::Advise,
            enforced: Level::Advise,
        },
    )
}

fn commit() -> Event {
    bash("git commit -m x", None)
}

/// The stage `policy` was a hit within the task.
fn stage_reached(policy: &str) -> Pred {
    Pred::Once {
        select: anyone(EventFilter {
            kind: EventKind::Judged,
            cond: Some(Cond::All(vec![
                Cond::Eq(Field::Policy, Lit::Text(policy.to_owned())),
                Cond::Eq(Field::Judgment, Lit::Text("hit".to_owned())),
            ])),
        }),
        scope: Scope::Span {
            span: Span::Task,
            by: By::Anyone,
        },
    }
}

fn commit_guard() -> Written {
    let def = PolicyDef {
        id: id(COMMIT),
        name: "commit-after-test".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: Some(Pred::Now(Cond::Words(Field::Command, words("git commit")))),
        rule: Rule::Structural(stage_reached(TEST_STAGE)),
        polarity: Polarity::Guard,
        author: the_user(),
        fixtures: vec![
            fixture(
                "a commit before the test",
                vec![agent(Body::TaskStart), commit()],
                Expect::Violated,
            ),
            fixture(
                "a commit after the test stage was a hit",
                vec![
                    agent(Body::TaskStart),
                    bash("cargo test", Some(true)),
                    hit(TEST_STAGE),
                    commit(),
                ],
                Expect::Satisfied,
            ),
        ],
    };
    written(def, Level::Force)
}

/// An advising stage of the procedure, bound by the commit guard.
fn stage(id_text: &str, name: &str, command: &str, rule: Rule) -> Written {
    let def = PolicyDef {
        id: id(id_text),
        name: name.parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: Some(Pred::Now(Cond::Words(Field::Command, words(command)))),
        rule,
        polarity: Polarity::Reward {
            bound_by: id(COMMIT),
        },
        fixtures: vec![],
        author: the_user(),
    };
    written(def, Level::Advise)
}

fn procedure() -> Catalog {
    catalog(
        vec![
            commit_guard(),
            stage(
                TEST_STAGE,
                "test-stage",
                "cargo test",
                Rule::Structural(Pred::Now(Cond::Eq(Field::Ok, Lit::Bool(true)))),
            ),
            stage(
                CLIPPY_STAGE,
                "clippy-stage",
                "cargo clippy",
                Rule::Structural(stage_reached(TEST_STAGE)),
            ),
        ],
        vec![],
    )
}

/// UC15, FR13: a straight run of the procedure is a hit at each stage and lets the commit
/// through.
#[test]
fn a_straight_run_is_a_hit_at_each_stage_and_lets_the_commit_through() {
    let catalog = procedure();
    let mut log = Vec::new();
    step(&catalog, &mut log, agent(Body::TaskStart));

    let test = step(&catalog, &mut log, bash("cargo test", Some(true)));
    assert_eq!(test.rewards.len(), 1);
    assert_eq!(test.rewards[0].policy, id(TEST_STAGE));
    assert_eq!(test.rewards[0].recognition, Recognition::Hit);

    let clippy = step(&catalog, &mut log, bash("cargo clippy", Some(true)));
    assert_eq!(clippy.rewards.len(), 1);
    assert_eq!(clippy.rewards[0].policy, id(CLIPPY_STAGE));
    assert_eq!(clippy.rewards[0].recognition, Recognition::Hit);

    let done = step(&catalog, &mut log, commit());
    assert_eq!(done.verdict, Verdict::Allow);
    assert_eq!(done.guards.len(), 1);
    assert_eq!(done.guards[0].finding, Finding::Satisfied);
}

/// UC15, FR13: a stage out of order is not a hit and not a failure.
#[test]
fn a_stage_out_of_order_is_not_a_hit_and_not_a_failure() {
    let catalog = procedure();
    let mut log = Vec::new();
    step(&catalog, &mut log, agent(Body::TaskStart));
    let clippy = step(&catalog, &mut log, bash("cargo clippy", Some(true)));
    assert_eq!(clippy.verdict, Verdict::Allow);
    assert_eq!(clippy.rewards.len(), 1);
    assert_eq!(clippy.rewards[0].recognition, Recognition::None);
}

/// UC15, UC1: a commit before the test stage is stopped.
#[test]
fn a_commit_before_the_test_is_stopped() {
    let catalog = procedure();
    assert_eq!(
        verdict(&catalog, &[agent(Body::TaskStart), commit()]),
        Verdict::Deny(vec![Cause::Violated(id(COMMIT))])
    );
}

/// UC15: a new task starts the procedure again.
#[test]
fn a_new_task_starts_the_procedure_again() {
    let catalog = procedure();
    let mut log = Vec::new();
    for event in [
        agent(Body::TaskStart),
        bash("cargo test", Some(true)),
        commit(),
        agent(Body::TaskStart),
    ] {
        step(&catalog, &mut log, event);
    }
    let again = step(&catalog, &mut log, commit());
    assert_eq!(
        again.verdict,
        Verdict::Deny(vec![Cause::Violated(id(COMMIT))])
    );
}

/// UC15, FR13: a stage not reached and a stage that could not be told both come out as `None`;
/// the outcome of a reward does not say which.
#[test]
fn an_edge_gives_none_both_for_a_stage_not_reached_and_for_one_not_seen() {
    let catalog = procedure();
    let not_reached = outcome(
        &catalog,
        &[agent(Body::TaskStart), bash("cargo clippy", Some(true))],
    );
    let not_seen = outcome(
        &catalog,
        &[
            agent(Body::TaskStart),
            unreadable(&[EventKind::Judged]),
            bash("cargo clippy", Some(true)),
        ],
    );
    assert_eq!(not_reached.rewards[0].recognition, Recognition::None);
    assert_eq!(not_seen.rewards[0].recognition, Recognition::None);
}
