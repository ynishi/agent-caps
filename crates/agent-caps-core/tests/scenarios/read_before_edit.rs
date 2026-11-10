//! Scenario: an edit of a domain source file without having read the design document within the
//! task is warned and not stopped. This is an ordinary guard, bound at Advise.
//!
//! The design document itself is knowledge, which is no part of the Core domain: putting it into
//! the agent's context is the platform's (FR51). What the core judges is only what can be
//! observed, the edit without the read.

use agent_caps_core::domain::catalog::Catalog;
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::name::GlobPattern;
use agent_caps_core::domain::policy::{DefLayer, Level, Polarity, PolicyDef, Rule};
use agent_caps_core::domain::predicate::{By, Cond, EventFilter, Lit, Pred, Scope};
use agent_caps_core::domain::schema::{At, EventKind, Field, Judgment};

use super::common::{
    GUARD, Written, agent, anyone, at, bash, catalog, edit, id, outcome, read, the_user, written,
};

const DESIGN: &str = "docs/design.md";
const DOMAIN_FILE: &str = "crates/agent-caps-core/src/domain/judge.rs";

/// Advise: an edit of a domain source file comes after a read of the design document within the
/// task.
fn read_before_edit() -> Written {
    let def = PolicyDef {
        id: id(GUARD),
        name: "read-design-before-domain-edit".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: Some(Pred::Now(Cond::All(vec![
            Cond::Eq(Field::Tool, Lit::Text("Edit".to_owned())),
            Cond::Glob(Field::Path, GlobPattern::new("crates/*/src/domain/*.rs")),
        ]))),
        rule: Rule::Structural(Pred::Once {
            select: anyone(EventFilter {
                kind: EventKind::ToolUse,
                cond: Some(Cond::All(vec![
                    Cond::Eq(Field::Tool, Lit::Text("Read".to_owned())),
                    Cond::Eq(Field::Path, Lit::Text(DESIGN.to_owned())),
                ])),
            }),
            scope: Scope::Task(By::Anyone),
        }),
        polarity: Polarity::Guard,
        fixtures: vec![],
        author: the_user(),
    };
    written(def, Level::Advise)
}

fn guarded() -> Catalog {
    catalog(vec![read_before_edit()], vec![])
}

/// UC28: an edit of a domain file after reading the design document passes without a warning.
#[test]
fn an_edit_after_reading_the_design_passes() {
    let out = outcome(
        &guarded(),
        &[agent(Body::TaskStart), read(DESIGN), edit(DOMAIN_FILE)],
    );
    assert_eq!(out.verdict, Verdict::Allow);
}

/// UC28: an edit without the read is warned, not stopped, and the warning is recorded.
#[test]
fn an_edit_without_reading_the_design_is_warned_and_recorded() {
    let out = outcome(&guarded(), &[agent(Body::TaskStart), edit(DOMAIN_FILE)]);
    assert_eq!(out.verdict, Verdict::Warn(vec![Cause::Violated(id(GUARD))]));
    assert!(out.evidence(At::from_millis(0)).contains(&at(
        the_user(),
        0,
        Body::Judged {
            policy: id(GUARD),
            judgment: Judgment::Warned,
            written: Level::Advise,
            enforced: Level::Advise,
        }
    )));
}

/// UC28: reading another file, or the design in an earlier task, does not count.
#[test]
fn reading_something_else_or_in_an_earlier_task_does_not_count() {
    let guarded = guarded();
    let start = agent(Body::TaskStart);
    let warned = Verdict::Warn(vec![Cause::Violated(id(GUARD))]);
    let other = outcome(
        &guarded,
        &[start.clone(), read("README.md"), edit(DOMAIN_FILE)],
    );
    assert_eq!(other.verdict, warned);
    let earlier = outcome(
        &guarded,
        &[start.clone(), read(DESIGN), start, edit(DOMAIN_FILE)],
    );
    assert_eq!(earlier.verdict, warned);
}

/// UC28: an edit of another file, or a call that is not an edit, is not judged by the guard.
#[test]
fn an_edit_of_another_file_is_not_judged() {
    let out = outcome(
        &guarded(),
        &[
            agent(Body::TaskStart),
            edit("crates/agent-caps-core/src/lib.rs"),
        ],
    );
    assert_eq!(out.verdict, Verdict::Allow);
    assert!(out.guards.is_empty());
    let call = outcome(&guarded(), &[agent(Body::TaskStart), bash("ls", None)]);
    assert_eq!(call.verdict, Verdict::Allow);
    assert!(call.guards.is_empty());
}
