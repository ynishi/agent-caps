//! Scenario S9: when to stop is not in the outcome.
//!
//! A level says how much the agent is trusted (#5), not when to stop. Whether a platform stops
//! before an action or at the end of a turn follows from the event that is judged and from the
//! mechanism the adapter has for it (UC24), so a guard at Force gives the same `Verdict::Deny` on
//! a tool use and on the end of a turn, and the outcome carries no timing: the two outcomes are
//! equal.

use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::policy::{Finding, Level};

use super::common::{agent, bash, catalog, commit_after_test_guard, outcome, test_guard, violated};

/// UC24: the same violation, judged on a tool use and on the end of a turn by a guard at Force,
/// gives the same `Verdict::Deny`, and the outcome of the two is the same: it carries no timing.
/// The guard on the tool use is the test guard moved to a commit: the same rule and the same
/// level.
#[test]
fn a_force_guard_gives_the_same_deny_on_a_tool_use_and_on_a_stop() {
    let denied = violated();
    let on_tool_use = outcome(
        &catalog(vec![commit_after_test_guard()], vec![]),
        &[agent(Body::TaskStart), bash("git commit -m x", None)],
    );
    let on_stop = outcome(
        &catalog(vec![test_guard(Level::Force)], vec![]),
        &[agent(Body::TaskStart), agent(Body::Stop)],
    );
    assert_eq!(on_tool_use.verdict, denied);
    assert_eq!(on_stop.verdict, denied);
    assert_eq!(on_tool_use.guards.len(), 1);
    assert_eq!(on_tool_use.guards[0].level, Level::Force);
    assert_eq!(on_tool_use.guards[0].finding, Finding::Violated);
    assert_eq!(on_tool_use, on_stop);
}
