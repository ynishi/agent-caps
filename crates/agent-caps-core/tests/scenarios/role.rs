//! Scenario V2: a role seen as a policy. Inside a sub agent of type `reviewer`, an edit is
//! stopped (Force). The guard applies while the last agent type seen in the agent's scope is
//! `reviewer`, and its rule is that the tool is not an edit.
//!
//! What can be written is "inside a reviewer". What cannot be written (#9): nothing says an
//! agent ended. There is no event for returning to the parent, and the agent scope lasts until
//! the next `AgentStart` or `SessionStart`. So "an edit after returning to the parent" cannot be
//! told from "an edit inside the reviewer" by the events, and cannot be a fixture or a test with
//! the right expectation. The result is too tight: after a reviewer, every edit stays stopped
//! until another agent starts. The tests below state exactly this, today's fact, and not the
//! right behavior.
//!
//! One more awkwardness (#12): each role needs its own `when` copied from this one; the
//! model has no word for a set of roles.

use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::policy::{DefLayer, Expect, Level, Polarity, PolicyDef, Rule};
use agent_caps_core::domain::predicate::{Cond, Lit, Pred, Scope};
use agent_caps_core::domain::schema::{EventKind, Field};

use super::common::{GUARD, agent, catalog, edit, fixture, id, read, the_user, verdict, violated};

fn start(agent_type: Option<&str>) -> Event {
    agent(Body::AgentStart {
        agent_type: agent_type.map(str::to_owned),
    })
}

/// Force: no edit inside a `reviewer`.
fn reviewer_guard() -> PolicyDef {
    PolicyDef {
        id: id(GUARD),
        name: "reviewer-does-not-edit".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: Some(Pred::Last {
            field: Field::AgentType,
            scope: Scope::Agent,
            value: Lit::Text("reviewer".to_owned()),
        }),
        rule: Rule::Structural(Pred::Not(Box::new(Pred::Now(Cond::Eq(
            Field::Tool,
            Lit::Text("Edit".to_owned()),
        ))))),
        polarity: Polarity::Guard {
            level: Level::Force,
        },
        enabled: true,
        fixtures: vec![
            fixture(
                "an edit inside a reviewer",
                vec![start(Some("reviewer")), edit("src/a.rs")],
                Expect::Violated,
            ),
            fixture(
                "a read inside a reviewer",
                vec![start(Some("reviewer")), read("src/a.rs")],
                Expect::Satisfied,
            ),
        ],
        author: the_user(),
    }
}

/// UC14: an edit is stopped inside a reviewer and only there.
#[test]
fn an_edit_is_stopped_inside_a_reviewer_and_only_there() {
    let catalog = catalog(vec![reviewer_guard()], vec![]);
    assert_eq!(
        verdict(&catalog, &[start(Some("reviewer")), edit("src/a.rs")]),
        violated()
    );
    // Reading is allowed in a reviewer.
    assert_eq!(
        verdict(&catalog, &[start(Some("reviewer")), read("src/a.rs")]),
        Verdict::Allow
    );
    // Another type of agent, and no agent started at all, may edit.
    assert_eq!(
        verdict(&catalog, &[start(Some("implementer")), edit("src/a.rs")]),
        Verdict::Allow
    );
    assert_eq!(verdict(&catalog, &[edit("src/a.rs")]), Verdict::Allow);
}

/// UC14: today's fact: the stop lasts until the next `AgentStart` or `SessionStart`, because
/// nothing ends an agent. This is the too-tight result of #9, not a wanted behavior.
#[test]
fn today_a_reviewer_stops_every_later_edit_until_another_agent_or_session_starts() {
    let catalog = catalog(vec![reviewer_guard()], vec![]);
    let denied = violated();
    let in_reviewer = [
        start(Some("reviewer")),
        read("src/a.rs"),
        edit("src/a.rs"),
        read("src/b.rs"),
        edit("src/b.rs"),
    ];
    // Whatever happens after the reviewer's work, the edits go on being stopped.
    assert_eq!(verdict(&catalog, &in_reviewer[..3]), denied);
    assert_eq!(verdict(&catalog, &in_reviewer), denied);

    // The next agent start ends it, and so does a new session.
    let mut other = in_reviewer.to_vec();
    other.extend([start(Some("implementer")), edit("src/a.rs")]);
    assert_eq!(verdict(&catalog, &other), Verdict::Allow);
    let mut new_session = in_reviewer.to_vec();
    new_session.extend([agent(Body::SessionStart), edit("src/a.rs")]);
    assert_eq!(verdict(&catalog, &new_session), Verdict::Allow);
}

/// UC14, FR20: today's fact: an agent start whose type is not known makes the last type unknown,
/// so the guard cannot tell whether it applies, and a stopping guard denies. The edits stay
/// stopped with `Cause::Unknown` until a start with a known type, or a new session.
#[test]
fn today_an_agent_start_without_a_type_leaves_every_edit_stopped_as_unknown() {
    let catalog = catalog(vec![reviewer_guard()], vec![]);
    let unknown = Verdict::Deny(vec![Cause::Unknown(id(GUARD))]);
    // Right after a reviewer, then from a start with no type at all.
    assert_eq!(
        verdict(
            &catalog,
            &[start(Some("reviewer")), start(None), edit("src/a.rs")]
        ),
        unknown
    );
    assert_eq!(verdict(&catalog, &[start(None), edit("src/a.rs")]), unknown);
    // A start with a known type settles it again.
    assert_eq!(
        verdict(
            &catalog,
            &[start(None), start(Some("implementer")), edit("src/a.rs")]
        ),
        Verdict::Allow
    );
}
