//! The generation of a catalog and the states it made: a state is used only by the catalog that
//! started it, in its generation. A change goes one generation on in the same lineage, a catalog
//! accepted from nothing starts a lineage the caller names, and every entry that takes a state
//! refuses one of another generation, saying which way it differs. What the domain does not do is
//! stated at `Generation`: a lineage kept a single line is the store's.
//!
//! `GenerationsExhausted` is not here: the number of a generation cannot be set through the
//! public API, so the spent number is checked where it is made (`Generation::next`, in the unit
//! tests of `state`).

use std::cell::RefCell;
use std::rc::Rc;

use agent_caps_core::domain::adjust::{Lifetime, Temporary, TemporaryBinding};
use agent_caps_core::domain::catalog::{
    Capabilities, Catalog, Effect, Effective, StaleState, Staleness,
};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::judge;
use agent_caps_core::domain::policy::Level;
use agent_caps_core::domain::predicate::{EventFilter, Scope};
use agent_caps_core::domain::schema::EventKind;
use agent_caps_core::domain::state::{Lineage, Origin, State};
use agent_caps_core::domain::tx::checks::AllOk;
use agent_caps_core::domain::tx::{AdjustmentCheck, CheckFinding, TxDecision, TxInput, TxPolicy};

use super::common::{
    GUARD, adjustment, agent, anyone, at, authority, by_author, catalog, graph_of, id, judgeable,
    lineage, test_guard, the_user, user, violated,
};

/// The catalog of the test guard at Force, and the same sources changed by the root: the next
/// generation of the same lineage.
fn two_generations() -> (Catalog, Catalog) {
    let first = catalog(vec![test_guard(Level::Force)], vec![]);
    let second = first
        .change(first.sources().clone(), &the_user())
        .expect("the same sources are no loosening");
    (first, second)
}

/// A history the guard judges.
fn history() -> Vec<Event> {
    vec![agent(Body::TaskStart), agent(Body::Stop)]
}

/// FR56: a catalog accepted from nothing is at generation 0 of the lineage the caller named, and a
/// change keeps the lineage and goes one on, each time; a state carries the generation of the
/// catalog that started it, and an empty lineage is refused.
#[test]
fn a_change_goes_one_generation_on_in_the_same_lineage() {
    let (first, second) = two_generations();
    assert_eq!(first.generation().lineage(), &lineage());
    assert_eq!(first.generation().n(), 0);
    assert_eq!(second.generation().lineage(), &lineage());
    assert_eq!(second.generation().n(), 1);
    let third = second
        .change(second.sources().clone(), &the_user())
        .unwrap();
    assert_eq!(third.generation().n(), 2);

    assert_eq!(
        first.start(Origin::Genesis).generation(),
        first.generation()
    );
    assert_eq!(
        second.fold(Origin::Unknown, &history()).generation(),
        second.generation()
    );
    assert!(Lineage::new("").is_err());
}

/// FR56: a state from before a change is behind the changed catalog and is refused with both
/// generations; folding the same history again under the changed catalog is accepted, and judged.
#[test]
fn a_state_from_before_a_change_is_behind_and_folded_again_it_is_accepted() {
    let (first, second) = two_generations();
    let old = first.fold(Origin::Genesis, &history());
    let refused = second.owns(&old).unwrap_err();
    assert_eq!(refused.kind(), Staleness::Behind);
    assert_eq!(refused.state(), first.generation());
    assert_eq!(refused.catalog(), second.generation());
    let said = refused.to_string();
    assert!(said.contains("behind"), "{said}");

    let again = second.fold(Origin::Genesis, &history());
    assert_eq!(second.owns(&again), Ok(()));
    let outcome = judge(
        &second,
        &again,
        &judgeable(&history()[1]),
        &Capabilities::full(),
    )
    .unwrap();
    assert_eq!(outcome.verdict, violated());
}

/// FR56: a state of a newer catalog given to the older one is ahead of it, so the catalog is the
/// old one.
#[test]
fn a_state_from_a_newer_catalog_is_ahead_of_the_older_one() {
    let (first, second) = two_generations();
    let newer = second.fold(Origin::Genesis, &history());
    let refused = first.owns(&newer).unwrap_err();
    assert_eq!(refused.kind(), Staleness::Ahead);
    assert_eq!(refused.state(), second.generation());
    assert_eq!(refused.catalog(), first.generation());
    assert!(refused.to_string().contains("ahead"));
}

/// FR56: a state of another lineage is refused whatever its number is, even the same one: two
/// catalogs accepted apart are both at generation 0.
#[test]
fn a_state_of_another_lineage_is_the_wrong_catalog() {
    let first = catalog(vec![test_guard(Level::Force)], vec![]);
    let elsewhere = Catalog::accept(
        by_author(graph_of(vec![test_guard(Level::Force)], vec![])),
        authority(),
        Lineage::new("elsewhere").unwrap(),
    )
    .unwrap();
    assert_eq!(first.generation().n(), elsewhere.generation().n());

    let foreign = elsewhere.fold(Origin::Genesis, &history());
    let refused = first.owns(&foreign).unwrap_err();
    assert_eq!(refused.kind(), Staleness::OtherLineage);
    assert!(refused.to_string().contains("another lineage"));
    // The other way round too.
    let own = first.fold(Origin::Genesis, &history());
    assert_eq!(
        elsewhere.owns(&own).unwrap_err().kind(),
        Staleness::OtherLineage
    );
}

/// FR56: a refused `apply` gives the state back as it was, so a caller that has no other copy has
/// not lost it; `apply_with` does the same, and neither folds the event.
#[test]
fn a_refused_apply_returns_the_state() {
    let (first, second) = two_generations();
    let old = first.fold(Origin::Genesis, [&agent(Body::TaskStart)]);
    let event = agent(Body::Stop);

    let refused = second.apply(old.clone(), &event).unwrap_err();
    assert_eq!(*refused.state, old);
    assert_eq!(refused.stale.kind(), Staleness::Behind);
    assert_eq!(refused.to_string(), refused.stale.to_string());

    let refused = second
        .apply_with(old.clone(), &event, &TxPolicy::standard())
        .unwrap_err();
    assert_eq!(*refused.state, old);

    // The state that comes back is the caller's again: folded again, it is accepted.
    let again = second.fold(Origin::Genesis, [&agent(Body::TaskStart)]);
    assert!(second.apply(again, &event).is_ok());
}

/// FR56: every entry that takes a state refuses one of another generation, with the same answer
/// as `owns`.
#[test]
fn every_entry_that_takes_a_state_refuses_a_stale_one() {
    let (first, second) = two_generations();
    let old = first.fold(Origin::Genesis, &history());
    let event = &history()[1];
    let caps = Capabilities::full();
    let expected: StaleState = second.owns(&old).unwrap_err();

    assert_eq!(second.effective_in(&old).unwrap_err(), expected);
    assert_eq!(second.enforced_in(&old, &caps).unwrap_err(), expected);
    assert_eq!(
        judge(&second, &old, &judgeable(event), &caps).unwrap_err(),
        expected
    );
    assert_eq!(
        second
            .admit(&old, event, &TxPolicy::standard())
            .unwrap_err(),
        expected
    );
    assert_eq!(
        second.apply(old.clone(), event).unwrap_err().stale,
        expected
    );
    assert_eq!(
        second
            .apply_with(old, event, &TxPolicy::standard())
            .unwrap_err()
            .stale,
        expected
    );
}

/// FR56: a state of the catalog's own generation passes every entry: the one it started, one
/// folded, and one an event was applied to.
#[test]
fn a_state_of_the_same_catalog_passes() {
    let (_, second) = two_generations();
    let caps = Capabilities::full();
    let event = &history()[1];
    let started = second.start(Origin::Genesis);
    let applied = second
        .apply(second.fold(Origin::Genesis, [&history()[0]]), event)
        .unwrap();
    for state in [started, applied, second.fold(Origin::Unknown, &history())] {
        assert_eq!(second.owns(&state), Ok(()));
        assert_eq!(state.generation(), second.generation());
        assert!(second.effective_in(&state).is_ok());
        assert!(second.enforced_in(&state, &caps).is_ok());
        assert!(judge(&second, &state, &judgeable(event), &caps).is_ok());
        assert!(second.admit(&state, event, &TxPolicy::standard()).is_ok());
    }
}

/// A check from outside that records, for each claim, the effect of the test guard that
/// `effective_before` and `effective_after` read, and how many adjustments the raw state after the
/// claim still holds.
struct Spy(Rc<RefCell<Vec<(Effect, Effect, usize)>>>);

impl AdjustmentCheck for Spy {
    fn judge(&self, input: &TxInput<'_>) -> Vec<CheckFinding> {
        let guard = |effective: Effective<'_>| {
            effective
                .policies
                .iter()
                .find(|p| p.policy.id() == id(GUARD))
                .map(|p| p.effect)
                .unwrap()
        };
        self.0.borrow_mut().push((
            guard(input.effective_before()),
            guard(input.effective_after()),
            input.after().adjustments().len(),
        ));
        Vec::new()
    }
}

/// FR56, FR55: the effect a check from outside reads after a claim is as the next event finds it:
/// a raise that lasts only within a scope the claim closes is gone from it, though the state after
/// the claim still holds the raise until the next event's carry. The effect before is read as it
/// is.
#[test]
fn a_user_check_reads_the_effect_after_a_claim_without_what_the_claim_ended() {
    let catalog = catalog(vec![test_guard(Level::Advise)], vec![]);
    let until_scored = Lifetime::Within(Scope::Since(anyone(EventFilter {
        kind: EventKind::Measured,
        cond: None,
    })));
    let raised = [
        agent(Body::TaskStart),
        user(adjustment(
            1,
            Temporary::Rebind {
                add: vec![TemporaryBinding {
                    policy: id(GUARD),
                    level: Level::Force,
                }],
                suspend: Vec::new(),
            },
            until_scored,
        )),
    ];
    let score = at(
        the_user(),
        0,
        Body::Measured {
            oracle: "bench".to_owned(),
            score: 0.9,
        },
    );
    let seen = Rc::new(RefCell::new(Vec::new()));
    let policy = TxPolicy {
        extra: vec![Box::new(Spy(Rc::clone(&seen)))],
        combine: Box::new(AllOk),
    };
    let state: State = catalog.fold(Origin::Genesis, &raised);
    let report = catalog.admit(&state, &score, &policy).unwrap();
    assert_eq!(report.decision, TxDecision::Commit);
    assert_eq!(
        *seen.borrow(),
        vec![(Effect::On(Level::Force), Effect::On(Level::Advise), 1)]
    );
}
