//! Scenario V1: knowledge seen as a policy. "Before an edit of a domain source file, read the
//! design document" is a reward (Advise): it applies to an edit of such a file, and is followed
//! when the document was read within the task. An edit without the read is not a failure, only
//! not a hit.
//!
//! It can be written, and the tests pass, but two things are awkward and are kept as facts here
//! (#12):
//!
//! - A reward is bound by a guard, so knowledge needs a guard even where there is no line not to
//!   cross. Here the guard is one that cannot fail (`Pred::All` of nothing holds); it exists only
//!   to carry the reward, and it is judged, and recorded, on every tool call.
//! - The shell pattern has no `**` and no token takes a `/`, so one pattern reaches one depth of
//!   a path. `crates/*/src/domain/*.rs` does not reach `crates/*/src/domain/sub/x.rs`; a second
//!   pattern is needed for each depth, and an edit at a depth nobody wrote is silently outside
//!   the knowledge.

use agent_caps_core::domain::catalog::Catalog;
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Recognition, Verdict};
use agent_caps_core::domain::name::GlobPattern;
use agent_caps_core::domain::policy::{DefLayer, Level, Polarity, PolicyDef, RewardLevel, Rule};
use agent_caps_core::domain::predicate::{Cond, EventFilter, Lit, Pred, Scope};
use agent_caps_core::domain::schema::{At, EventKind, Field, Judgment, Origin};

use super::common::{GUARD, REWARD, agent, at, bash, catalog, edit, id, outcome, read, the_user};

const DESIGN: &str = "docs/design.md";

/// The guard that exists to bind the reward: it cannot fail.
fn carrier_guard() -> PolicyDef {
    PolicyDef {
        id: id(GUARD),
        name: "domain-knowledge-carrier".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: None,
        rule: Rule::Structural(Pred::All(vec![])),
        polarity: Polarity::Guard {
            level: Level::Advise,
        },
        enabled: true,
        fixtures: vec![],
        author: the_user(),
    }
}

/// Advise: before an edit of a domain source file, read the design document.
fn design_reward() -> PolicyDef {
    PolicyDef {
        id: id(REWARD),
        name: "read-design-before-domain-edit".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: Some(Pred::Now(Cond::All(vec![
            Cond::Eq(Field::Tool, Lit::Text("Edit".to_owned())),
            Cond::Glob(Field::Path, GlobPattern::new("crates/*/src/domain/*.rs")),
        ]))),
        rule: Rule::Structural(Pred::Once {
            event: EventFilter {
                kind: EventKind::ToolUse,
                cond: Some(Cond::All(vec![
                    Cond::Eq(Field::Tool, Lit::Text("Read".to_owned())),
                    Cond::Eq(Field::Path, Lit::Text(DESIGN.to_owned())),
                ])),
            },
            scope: Scope::Task,
        }),
        polarity: Polarity::Reward {
            level: RewardLevel::Advise,
            bound_by: id(GUARD),
        },
        enabled: true,
        fixtures: vec![],
        author: the_user(),
    }
}

fn knowledge() -> Catalog {
    catalog(vec![carrier_guard(), design_reward()], vec![])
}

const DOMAIN_FILE: &str = "crates/agent-caps-core/src/domain/judge.rs";

/// UC13: an edit of a domain file after reading the design document is a hit of the reward.
#[test]
fn an_edit_after_reading_the_design_is_a_hit() {
    let out = outcome(
        &knowledge(),
        &[agent(Body::TaskStart), read(DESIGN), edit(DOMAIN_FILE)],
    );
    assert_eq!(out.verdict, Verdict::Allow);
    assert_eq!(out.rewards.len(), 1);
    assert_eq!(out.rewards[0].policy, id(REWARD));
    assert_eq!(out.rewards[0].level, Level::Advise);
    assert_eq!(out.rewards[0].recognition, Recognition::Hit);
}

/// UC13, FR13: an edit without the read is not a hit and not a failure.
#[test]
fn an_edit_without_reading_it_is_not_a_hit_and_not_a_failure() {
    let out = outcome(&knowledge(), &[agent(Body::TaskStart), edit(DOMAIN_FILE)]);
    assert_eq!(out.verdict, Verdict::Allow);
    assert_eq!(out.rewards.len(), 1);
    assert_eq!(out.rewards[0].recognition, Recognition::None);
}

/// UC13: reading another file, or the design in an earlier task, does not count.
#[test]
fn reading_something_else_or_in_an_earlier_task_does_not_count() {
    let knowledge = knowledge();
    let start = agent(Body::TaskStart);
    let other = outcome(
        &knowledge,
        &[start.clone(), read("README.md"), edit(DOMAIN_FILE)],
    );
    assert_eq!(other.rewards[0].recognition, Recognition::None);
    let earlier = outcome(
        &knowledge,
        &[start.clone(), read(DESIGN), start, edit(DOMAIN_FILE)],
    );
    assert_eq!(earlier.rewards[0].recognition, Recognition::None);
}

/// UC13: an edit of another file, or a call that is not an edit, does not reach the reward.
#[test]
fn an_edit_of_another_file_does_not_reach_the_reward() {
    let out = outcome(
        &knowledge(),
        &[
            agent(Body::TaskStart),
            edit("crates/agent-caps-core/src/lib.rs"),
        ],
    );
    assert!(out.rewards.is_empty());
    let call = outcome(&knowledge(), &[agent(Body::TaskStart), bash("ls", None)]);
    assert!(call.rewards.is_empty());
}

/// UC13: the awkward glob (#12): one depth only. A file one directory deeper is outside the
/// knowledge, and nothing says so.
#[test]
fn a_file_one_directory_deeper_is_outside_the_pattern() {
    let out = outcome(
        &knowledge(),
        &[
            agent(Body::TaskStart),
            edit("crates/agent-caps-core/src/domain/sub/x.rs"),
        ],
    );
    assert!(out.rewards.is_empty());
}

/// UC13: the awkward guard (#12): it cannot fail, yet it is judged, and listed, on every tool
/// call.
#[test]
fn the_carrier_guard_is_listed_on_every_tool_call_and_never_fails() {
    let out = outcome(&knowledge(), &[agent(Body::TaskStart), bash("ls", None)]);
    assert_eq!(out.guards.len(), 1);
    assert_eq!(out.guards[0].policy, id(GUARD));
    assert_eq!(out.verdict, Verdict::Allow);
    // And recorded: its evidence is appended on every tool call.
    assert!(out.evidence(At::from_millis(0)).contains(&at(
        Origin::Caps,
        0,
        Body::Judged {
            policy: id(GUARD),
            judgment: Judgment::Allowed
        }
    )));
}
