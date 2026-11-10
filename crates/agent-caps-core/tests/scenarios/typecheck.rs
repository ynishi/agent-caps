//! The type check of a `Since` filter: `Catalog::accept` rejects a policy whose filter reads a
//! field from another kind of event, and an exemption that arrives as an event takes effect only
//! if it type-checks against the guard it names.

use agent_caps_core::domain::catalog::AcceptError;
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::exempt::Lifetime;
use agent_caps_core::domain::judge::Verdict;
use agent_caps_core::domain::policy::{Level, Rule};
use agent_caps_core::domain::predicate::{Cmp, Cond, EventFilter, Lit, Pred, PredError, Scope};
use agent_caps_core::domain::schema::{EventKind, Field};

use super::common::{
    GUARD, agent, catalog, commit_filter, edit, exemption, id, rejected, src_edit_guard,
    test_guard, tested_in, verdict, violated,
};

/// FR33: a filter of a `Since` scope that reads a field from another kind of event is rejected by
/// accept, wherever the scope stands.
#[test]
fn an_ill_typed_since_filter_is_rejected() {
    let bad = || {
        Scope::Since(EventFilter {
            kind: EventKind::Stop,
            cond: Some(Cond::Eq(Field::Ok, Lit::Bool(true))),
        })
    };
    let mut guard = test_guard(Level::Advise);
    guard.fixtures = vec![];
    guard.rule = Rule::Structural(Pred::All(vec![
        tested_in(bad()),
        Pred::Count {
            event: commit_filter(false),
            scope: bad(),
            cmp: Cmp::Ge,
            n: 2,
        },
        Pred::Last {
            field: Field::Ok,
            scope: bad(),
            value: Lit::Bool(true),
        },
    ]));
    let error = AcceptError::Predicate {
        policy: id(GUARD),
        error: PredError::OtherKind {
            field: Field::Ok,
            read_from: EventKind::Stop,
        },
    };
    assert_eq!(rejected(vec![guard], vec![]), vec![error; 3]);
}

/// FR33, FR34, UC25: an exemption that arrives as an event takes effect only if it type-checks
/// against the guard it names, its target and the filter of its `Within(Since(..))` alike.
#[test]
fn an_ill_typed_exemption_takes_no_effect() {
    let catalog = catalog(vec![src_edit_guard()], vec![]);
    let on_a = Cond::Eq(Field::Path, Lit::Text("src/a.rs".to_owned()));
    let judged = |exempt| {
        verdict(
            &catalog,
            &[agent(Body::TaskStart), exempt, edit("src/a.rs")],
        )
    };
    // Well typed: it covers the edit.
    assert_eq!(
        judged(exemption(Some(on_a.clone()), Lifetime::Next)),
        Verdict::Allow
    );
    // The target reads the type of an agent from a tool use, though it would hold on this
    // event through its other branch.
    let ill_target = Cond::Any(vec![
        on_a.clone(),
        Cond::Eq(Field::AgentType, Lit::Text("x".to_owned())),
    ]);
    assert_eq!(
        judged(exemption(Some(ill_target), Lifetime::Next)),
        violated()
    );
    // The same for the filter of the scope it lasts within.
    let within = |filter| exemption(Some(on_a.clone()), Lifetime::Within(Scope::Since(filter)));
    let good = EventFilter {
        kind: EventKind::Stop,
        cond: None,
    };
    let bad = EventFilter {
        kind: EventKind::Stop,
        cond: Some(Cond::Eq(Field::Ok, Lit::Bool(true))),
    };
    assert_eq!(judged(within(good)), Verdict::Allow);
    assert_eq!(judged(within(bad)), violated());
}
