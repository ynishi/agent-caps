//! Scenario: what one principal keeps, such as the policy store and the approval records, written
//! only by that principal or one above it. The domain has no store and no agent: the store is a
//! resource whose place (its paths) the caller knows, and those below its keeper are the actors the
//! hierarchy places under it. The rule is an ordinary meta guard by the keeper: a write to the
//! keeper's paths is not by an actor under the principal directly below the keeper. A meta policy
//! takes no exemption and no other binding, and reads no mode, so nothing during a run lets the
//! write through (FR14).
//!
//! What the caller supplies: which paths and tools are a write to the store (here `Edit` and
//! `Write` under `.caps/`). A write through a shell command is a write the caller has to read as
//! one; this scenario does not cover it.

use agent_caps_core::domain::adjust::Lifetime;
use agent_caps_core::domain::authority::Principal;
use agent_caps_core::domain::catalog::Catalog;
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::name::GlobPattern;
use agent_caps_core::domain::policy::{DefLayer, Expect, Level, Polarity, PolicyDef, Rule};
use agent_caps_core::domain::predicate::{Cond, Lit, Pred};
use agent_caps_core::domain::schema::{EventKind, Field};

use super::common::{
    GUARD, at, catalog, exemption, fixture, id, mode_switch, the_agent, the_helper, the_user,
    verdict, violated, written,
};

/// The act of `actor`.
fn by(actor: &Principal, body: Body) -> Event {
    at(actor.clone(), 0, body)
}

/// A tool use of `tool` on `path`, by `actor`.
fn write(actor: &Principal, tool: &str, path: &str) -> Event {
    by(
        actor,
        Body::ToolUse {
            tool: tool.to_owned(),
            command: None,
            path: Some(path.to_owned()),
            ok: None,
        },
    )
}

const STORE: &str = ".caps/policies.toml";

/// The user's meta guard: a write to the store is not by an actor under the agent, the principal
/// directly below the user.
fn keeper() -> Catalog {
    let def = PolicyDef {
        id: id(GUARD),
        name: "store-kept-by-its-owner".parse().unwrap(),
        layer: DefLayer::Meta,
        subject: EventKind::ToolUse,
        when: Some(Pred::Now(Cond::All(vec![
            Cond::Any(vec![
                Cond::Eq(Field::Tool, Lit::Text("Edit".to_owned())),
                Cond::Eq(Field::Tool, Lit::Text("Write".to_owned())),
            ]),
            Cond::Glob(Field::Path, GlobPattern::new(".caps/*")),
        ]))),
        rule: Rule::Structural(Pred::Not(Box::new(Pred::ActorUnder(the_agent())))),
        polarity: Polarity::Guard,
        fixtures: vec![
            fixture(
                "the keeper writes",
                vec![write(&the_user(), "Edit", STORE)],
                Expect::Satisfied,
            ),
            fixture(
                "one below writes",
                vec![write(&the_agent(), "Edit", STORE)],
                Expect::Violated,
            ),
        ],
        author: the_user(),
    };
    catalog(vec![written(def, Level::Force)], vec![])
}

/// FR57: a write to the store by an actor below its keeper is stopped before it runs, at every
/// depth below; the keeper's own write, and a write elsewhere, are not.
#[test]
fn a_write_to_the_store_from_below_its_keeper_is_stopped() {
    let keeper = keeper();
    assert_eq!(
        verdict(&keeper, &[write(&the_agent(), "Edit", STORE)]),
        violated()
    );
    assert_eq!(
        verdict(&keeper, &[write(&the_agent(), "Write", STORE)]),
        violated()
    );
    assert_eq!(
        verdict(&keeper, &[write(&the_helper(), "Edit", STORE)]),
        violated()
    );
    assert_eq!(
        verdict(&keeper, &[write(&the_user(), "Edit", STORE)]),
        Verdict::Allow
    );
    assert_eq!(
        verdict(&keeper, &[write(&the_agent(), "Edit", "src/a.rs")]),
        Verdict::Allow
    );
}

/// FR57, FR14, UC10: nothing during a run lets the write through: not an exemption, even the
/// keeper's own, and not a mode switch.
#[test]
fn no_exemption_or_mode_lets_the_write_through() {
    let keeper = keeper();
    let attempt = write(&the_agent(), "Edit", STORE);
    assert_eq!(
        verdict(&keeper, &[exemption(None, Lifetime::Next), attempt.clone()]),
        violated()
    );
    assert_eq!(
        verdict(&keeper, &[mode_switch("open"), attempt]),
        violated()
    );
}

/// FR57: a child spawned below the keeper is below it too. Placed under its spawner, it is under the
/// agent and its write is a violation. Placed by its spawner beside the keeper's own place, the
/// spawn loosens the keeper's rule and is aborted (FR38): the child has no place in the hierarchy,
/// the guard cannot tell, and a stopping guard that cannot tell stops it.
#[test]
fn a_spawned_child_is_below_the_keeper() {
    let keeper = keeper();
    let child = Principal::new("child");
    let spawn = |under: Principal| {
        by(
            &the_agent(),
            Body::Spawn {
                child: child.clone(),
                under,
            },
        )
    };
    assert_eq!(
        verdict(&keeper, &[spawn(the_agent()), write(&child, "Edit", STORE)]),
        violated()
    );
    assert_eq!(
        verdict(&keeper, &[spawn(the_user()), write(&child, "Edit", STORE)]),
        Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
    );
}
