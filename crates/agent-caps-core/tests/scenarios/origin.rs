//! What a fold knows of the past when it starts (`Origin`): a fold of a whole history starts as
//! the catalog's first acceptance did, and one that starts in the middle (a transcript of one
//! session, say) knows nothing of what came before, so what has not been seen since is unknown
//! until its period starts again, and an adjustment made before it may only strengthen the rules.
//!
//! The caller says which it is, with every `start` and `fold`, and nothing defaults it.

use agent_caps_core::domain::adjust::Lifetime;
use agent_caps_core::domain::catalog::{Capabilities, Catalog, Effect};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Verdict, judge};
use agent_caps_core::domain::policy::Level;
use agent_caps_core::domain::predicate::{By, Scope, Span};
use agent_caps_core::domain::schema::EventKind;
use agent_caps_core::domain::state::{Holding, Known, Origin};

use super::common::{
    GUARD, agent, bash, catalog, id, test_guard, the_reviewer, the_user, unreadable, violated,
};
use super::limits::{by, leaf, push, pushes_since_review, rebind_guard, review_by, spawn, unknown};

/// The verdict on the last event, with the state folded over all of them from `origin`.
fn verdict_from(catalog: &Catalog, origin: Origin, events: &[Event]) -> Verdict {
    let state = catalog.fold(origin, events);
    judge(
        catalog,
        &state,
        events.last().unwrap(),
        &Capabilities::full(),
    )
    .verdict
}

/// The effect of the test guard after `events` folded from `origin`, and how each adjustment held
/// then is held.
fn guard_from(catalog: &Catalog, origin: Origin, events: &[Event]) -> (Effect, Vec<Holding>) {
    let state = catalog.fold(origin, events);
    let effect = catalog
        .effective_in(&state)
        .policies
        .iter()
        .find(|p| p.policy.id() == id(GUARD))
        .map(|p| p.effect)
        .unwrap();
    (
        effect,
        state.adjustments().iter().map(|h| h.holding).collect(),
    )
}

fn within_the_task() -> Lifetime {
    Lifetime::Within(Scope::Span {
        span: Span::Task,
        by: By::Anyone,
    })
}

/// FR20, UC3: a fold from the middle starts as a record that could not be read leaves it: the
/// mode and every slot are unknown, and a stopping guard that needs a fact it has not seen stops
/// as unknown, where a fold of a whole history finds it violated. A fact seen in the fold is
/// known, and so is one whose period starts in the fold.
#[test]
fn a_fold_from_the_middle_starts_with_the_past_unknown() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let stop = agent(Body::Stop);
    let task = agent(Body::TaskStart);
    let ran = bash("cargo test", Some(true));

    assert_eq!(
        verdict_from(&catalog, Origin::Genesis, std::slice::from_ref(&stop)),
        violated()
    );
    assert_eq!(
        verdict_from(&catalog, Origin::Unknown, std::slice::from_ref(&stop)),
        unknown()
    );
    // What the fold saw is known: the test run was seen.
    assert_eq!(
        verdict_from(&catalog, Origin::Unknown, &[ran, stop.clone()]),
        Verdict::Allow
    );
    // The task starts in the fold, so what is counted within it is known from there.
    assert_eq!(
        verdict_from(&catalog, Origin::Unknown, &[task, stop]),
        violated()
    );

    let from_genesis = catalog.fold(Origin::Genesis, &[]);
    assert_eq!(from_genesis.origin(), Origin::Genesis);
    assert_eq!(from_genesis.mode(), &Known::Known(None));
    let from_the_middle = catalog.fold(Origin::Unknown, &[]);
    assert_eq!(from_the_middle.origin(), Origin::Unknown);
    assert_eq!(from_the_middle.mode(), &Known::Unknown);
    assert_eq!(
        catalog.start(Origin::Unknown),
        from_the_middle,
        "`start` and `fold` of nothing agree"
    );
}

/// FR20: an `Origin::Unknown` is a fact about before the fold, apart from a record lost within
/// it: the marks of a lost record are not set, and `may_hold_unseen` is the one predicate that
/// reads both.
#[test]
fn the_origin_is_its_own_value_apart_from_a_record_lost_in_the_fold() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let whole = catalog.fold(Origin::Genesis, &[]);
    assert!(!whole.may_hold_unseen());
    assert!(!whole.adjustments_lost());

    let middle = catalog.fold(Origin::Unknown, &[]);
    assert!(middle.may_hold_unseen());
    assert!(!middle.adjustments_lost());

    let lost = catalog.fold(Origin::Genesis, &[unreadable(&[EventKind::Adjust])]);
    assert!(lost.may_hold_unseen());
    assert!(lost.adjustments_lost());
}

/// FR20, FR55, UC3: an adjustment made before a fold from the middle may only strengthen, so
/// every rule takes effect at least as strongly as such an adjustment could make it: an Advise
/// guard is at Force. A lowering made within the fold is held as recorded and shows among the
/// adjustments, and the ceiling keeps the effect from going down; a raise made within it holds.
#[test]
fn a_suspension_made_in_a_fold_from_the_middle_holds_while_the_ceiling_keeps_the_effect_up() {
    let lowering = by(
        &the_user(),
        rebind_guard(1, Level::Advise, true, within_the_task()),
    );
    let forced = test_guard(Level::Force);
    let catalog = catalog(vec![forced], vec![]);
    // A whole history: the lowering takes effect.
    assert_eq!(
        guard_from(&catalog, Origin::Genesis, std::slice::from_ref(&lowering)),
        (Effect::On(Level::Advise), vec![Holding::Held])
    );
    // From the middle: it is held as recorded, and the effect does not go down.
    assert_eq!(
        guard_from(&catalog, Origin::Unknown, std::slice::from_ref(&lowering)),
        (Effect::On(Level::Force), vec![Holding::Held])
    );

    // Even an Advise guard is at the ceiling, since an adjustment before the fold could have
    // raised it; the whole history shows what the rules say.
    let advised = self::catalog(vec![test_guard(Level::Advise)], vec![]);
    assert_eq!(
        guard_from(&advised, Origin::Genesis, &[]).0,
        Effect::On(Level::Advise)
    );
    assert_eq!(
        guard_from(&advised, Origin::Unknown, &[]).0,
        Effect::On(Level::Force)
    );

    // What the fold makes stronger holds as it does anywhere.
    let raise = by(
        &the_user(),
        rebind_guard(2, Level::Force, false, within_the_task()),
    );
    assert_eq!(
        guard_from(&advised, Origin::Unknown, &[raise]),
        (Effect::On(Level::Force), vec![Holding::Held])
    );
}

/// FR54, FR20: a fold from the middle does not mark the hierarchy of actors lost: a child spawned
/// within it has a known place, so its review closes a count since the last review, where one
/// placed after a lost spawn record has an unknown place.
#[test]
fn a_child_spawned_in_a_fold_from_the_middle_has_a_known_place() {
    let catalog = pushes_since_review();
    let child = leaf("r1");
    let placed = spawn(&the_user(), &child, &the_reviewer());
    // Known: the child's review closes the interval, and the count starts over from there.
    assert_eq!(
        verdict_from(
            &catalog,
            Origin::Unknown,
            &[placed.clone(), review_by(&child), push(), push()]
        ),
        Verdict::Allow
    );
    assert_eq!(
        verdict_from(
            &catalog,
            Origin::Unknown,
            &[placed.clone(), review_by(&child), push(), push(), push()]
        ),
        violated()
    );
    // Before the review, the count is not known: the fold started in the middle.
    assert_eq!(
        verdict_from(&catalog, Origin::Unknown, &[placed.clone(), push()]),
        unknown()
    );
    // After a lost spawn record, the same child has no known place, and its review closes
    // nothing known.
    let after_a_lost_spawn = [
        unreadable(&[EventKind::Spawn]),
        placed,
        review_by(&child),
        push(),
    ];
    assert_eq!(
        verdict_from(&catalog, Origin::Unknown, &after_a_lost_spawn),
        unknown()
    );
}
