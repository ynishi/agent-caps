//! Scenario: an aborted claim leaves the state as it was, so a history folded without its aborted
//! claims gives the same state as one folded with them. The claim here is a record of a judgment
//! in another's name, which is never admitted (FR59); it comes right after a prompt that closed
//! the interval the guard reads, which the next carry is still to settle.

use agent_caps_core::domain::catalog::Catalog;
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::policy::{Level, Rule};
use agent_caps_core::domain::predicate::{EventFilter, Scope};
use agent_caps_core::domain::schema::{EventKind, Judgment};
use agent_caps_core::domain::state::Origin;
use agent_caps_core::domain::tx::{TxDecision, TxPolicy};

use super::common::{
    GUARD, agent, anyone, at, bash, catalog, id, test_guard, tested_in, the_agent,
};

/// The test guard, reading `cargo test` since the last prompt.
fn guarded() -> Catalog {
    let mut guard = test_guard(Level::Advise);
    guard.rule = Rule::Structural(tested_in(Scope::Since(anyone(EventFilter {
        kind: EventKind::PromptSubmit,
        cond: None,
    }))));
    catalog(vec![guard], vec![])
}

/// A claim that is never admitted: a record of the guard's judgment in the agent's name.
fn aborted() -> Event {
    at(
        the_agent(),
        0,
        Body::Judged {
            policy: id(GUARD),
            judgment: Judgment::Allowed,
            written: Level::Advise,
            enforced: Level::Advise,
        },
    )
}

/// The history before the claim: a prompt, a test, and the next prompt, which closes the interval.
fn before() -> Vec<Event> {
    vec![
        agent(Body::PromptSubmit),
        bash("cargo test", Some(true)),
        agent(Body::PromptSubmit),
    ]
}

/// FR60: the claim is aborted, and the state it leaves is the state it was given.
#[test]
fn an_aborted_claim_leaves_the_state_as_it_was() {
    let catalog = guarded();
    let state = catalog.fold(Origin::Genesis, &before());
    let report = catalog
        .admit(&state, &aborted(), &TxPolicy::standard())
        .unwrap();
    assert_eq!(report.decision, TxDecision::Abort);
    let after = catalog.apply(state.clone(), &aborted()).unwrap();
    assert_eq!(after, state);
}

/// FR60: a history whose last event is an aborted claim folds to the state of the history
/// without it.
#[test]
fn a_fold_ending_in_an_aborted_claim_is_the_fold_without_it() {
    let catalog = guarded();
    let mut with = before();
    with.push(aborted());
    assert_eq!(
        catalog.fold(Origin::Genesis, &with),
        catalog.fold(Origin::Genesis, &before()),
    );
}

/// FR60: an aborted claim in the middle of a history changes nothing after it either: the carry
/// of the next event settles what the claim's carry would have.
#[test]
fn a_fold_with_an_aborted_claim_inside_is_the_fold_without_it() {
    let catalog = guarded();
    let mut without = before();
    without.push(agent(Body::Stop));
    let mut with = before();
    with.push(aborted());
    with.push(agent(Body::Stop));
    assert_eq!(
        catalog.fold(Origin::Genesis, &with),
        catalog.fold(Origin::Genesis, &without),
    );
}
