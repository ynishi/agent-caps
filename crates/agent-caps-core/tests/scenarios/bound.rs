//! The bound on a temporary adjustment: the root declares the longest period one may have, and an
//! adjustment states the time it ends by, which may lie no further ahead of the clock than the
//! bound.
//!
//! The root declares the bound in a set it owns; every root that owns a set declares the same
//! value, a declaration anywhere else is refused, and a catalog with none is refused. Changing it
//! is a change of the root's set, judged as any change of a set. An adjustment is refused when the
//! time it ends by lies too far ahead, or when the window it lasts within is longer than the bound,
//! and never rounded. Before the first act there is no clock, so such an adjustment is held, and
//! checked at the first act, where it ends if it lies too far ahead. Whatever its lifetime, an
//! adjustment ends at the time it ends by, or sooner by its lifetime's event.

use agent_caps_core::domain::adjust::{
    BoundError, Inadmissible, Lifetime, Temporary, TemporaryBinding, TemporaryBound,
};
use agent_caps_core::domain::authority::{Authority, Principal};
use agent_caps_core::domain::catalog::{AcceptError, Catalog, Effect, Rejected, Target};
use agent_caps_core::domain::change::{ChangeRejected, Loosening};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::policy::{Level, PolicyGraph};
use agent_caps_core::domain::predicate::{By, Scope, Span, Window};
use agent_caps_core::domain::schema::At;
use agent_caps_core::domain::set::{Source, Sources};
use agent_caps_core::domain::state::{Origin, State};
use agent_caps_core::domain::tx::{TxDecision, TxPolicy, TxReport};

use super::common::{
    DAY, GUARD, adjustment_by, anyone, at, catalog, commit_filter, declaring, default_bound,
    exempt_n_by, graph_of, id, lineage, set, set_id, test_guard, the_agent, the_user, verdict,
    violated,
};

/// The scenarios' bound, in milliseconds.
const BOUND: i64 = 365 * DAY;

/// The test guard at Advise, which a raise puts at Force.
fn advised() -> Catalog {
    catalog(vec![test_guard(Level::Advise)], vec![])
}

/// The start of a task by the agent, at the instant: an act.
fn task_at(millis: i64) -> Event {
    at(the_agent(), millis, Body::TaskStart)
}

/// The end of a turn by the agent, at the instant: an act.
fn stop_at(millis: i64) -> Event {
    at(the_agent(), millis, Body::Stop)
}

/// The test guard raised to Force for `lifetime`, ending by the instant.
fn raise_by(n: u8, lifetime: Lifetime, ends_by: i64) -> Body {
    adjustment_by(
        n,
        Temporary::Rebind {
            add: vec![TemporaryBinding {
                policy: id(GUARD),
                level: Level::Force,
            }],
            suspend: vec![],
        },
        lifetime,
        At::from_millis(ends_by),
    )
}

/// The test guard raised to Force until the instant, ended by nothing else.
fn raise_until(n: u8, ends_by: i64) -> Body {
    raise_by(n, Lifetime::Timed, ends_by)
}

/// The transaction of `event` after `before`, folded from a whole history.
fn admit(catalog: &Catalog, before: &[Event], event: &Event) -> TxReport {
    catalog
        .admit(
            &catalog.fold(Origin::Genesis, before),
            event,
            &TxPolicy::standard(),
        )
        .unwrap()
}

/// The effect of the test guard in the state.
fn effect_in(catalog: &Catalog, state: &State) -> Effect {
    catalog
        .effective_in(state)
        .unwrap()
        .policies
        .iter()
        .find(|p| p.policy.id() == id(GUARD))
        .map(|p| p.effect)
        .unwrap()
}

/// FR55: a time to end by further ahead of the clock than the bound is refused, and not rounded; the
/// instant the bound allows is admitted. The clock is the latest time an act has carried, and the
/// time of the claim itself is not read.
#[test]
fn a_time_to_end_by_beyond_the_bound_is_refused_and_one_at_it_is_not() {
    let catalog = advised();
    let start = task_at(1_000);
    let latest = 1_000 + BOUND;

    let too_late = at(the_agent(), 7 * DAY, raise_until(1, latest + 1));
    let report = admit(&catalog, std::slice::from_ref(&start), &too_late);
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(
        report.inadmissible,
        Some(Inadmissible::EndsTooLate {
            ends_by: At::from_millis(latest + 1),
            latest: At::from_millis(latest),
            bound: default_bound(),
        })
    );
    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert_eq!(
        catalog.fold(Origin::Genesis, [&start, &too_late]),
        catalog.fold(Origin::Genesis, [&start])
    );

    let on_time = at(the_agent(), 0, raise_until(1, latest));
    let report = admit(&catalog, &[start], &on_time);
    assert_eq!(report.decision, TxDecision::Commit);
    assert_eq!(report.inadmissible, None);
}

/// FR55, FR45: a time to end by that the clock has reached is expired, not too late: the bound
/// reads ahead of the clock, and expiry is the clock's.
#[test]
fn a_time_to_end_by_the_clock_has_reached_is_expired() {
    let catalog = advised();
    let start = task_at(500);
    let report = admit(&catalog, &[start], &at(the_agent(), 0, raise_until(1, 500)));
    assert_eq!(report.decision, TxDecision::Abort);
    assert_eq!(report.inadmissible, Some(Inadmissible::Expired));
}

/// FR55: a window of `Every` longer than the bound is refused, with a clock or without one, since
/// it reads no time; one as long as the bound is admitted.
#[test]
fn a_window_longer_than_the_bound_is_refused_with_or_without_a_clock() {
    let catalog = advised();
    let long = Window::from_millis(BOUND + 1).unwrap();
    let just_within = Window::from_millis(BOUND).unwrap();
    let in_window = |window| Lifetime::Within(Scope::Every(window));
    let states = [
        catalog.start(Origin::Genesis),
        catalog.fold(Origin::Genesis, [&task_at(0)]),
    ];
    for state in &states {
        let refused = at(the_agent(), 0, raise_by(1, in_window(long), BOUND));
        let report = catalog
            .admit(state, &refused, &TxPolicy::standard())
            .unwrap();
        assert_eq!(report.decision, TxDecision::Abort);
        assert_eq!(
            report.inadmissible,
            Some(Inadmissible::WindowTooLong {
                window: long,
                bound: default_bound(),
            })
        );

        let admitted = at(the_agent(), 0, raise_by(1, in_window(just_within), BOUND));
        let report = catalog
            .admit(state, &admitted, &TxPolicy::standard())
            .unwrap();
        assert_eq!(report.decision, TxDecision::Commit);
    }
}

/// FR55, FR45: whatever its lifetime, an adjustment ends at the first act at or after the time it
/// ends by: one that lasts within a task, a `since` scope or a mode, and one that nothing else ends.
#[test]
fn every_lifetime_ends_at_the_time_the_adjustment_ends_by() {
    let catalog = advised();
    let lifetimes = [
        ("timed", Lifetime::Timed),
        (
            "task",
            Lifetime::Within(Scope::Span {
                span: Span::Task,
                by: By::Anyone,
            }),
        ),
        ("mode", Lifetime::Within(Scope::Mode)),
        (
            "since",
            Lifetime::Within(Scope::Since(anyone(commit_filter(true)))),
        ),
    ];
    for (name, lifetime) in lifetimes {
        let made = [task_at(0), at(the_agent(), 0, raise_by(1, lifetime, 100))];
        let after = |millis: i64| {
            let mut events = made.to_vec();
            events.push(stop_at(millis));
            let state = catalog.fold(Origin::Genesis, &events);
            (state.adjustments().len(), effect_in(&catalog, &state))
        };
        assert_eq!(after(99), (1, Effect::On(Level::Force)), "{name} at 99");
        assert_eq!(after(100), (0, Effect::On(Level::Advise)), "{name} at 100");
    }
}

/// FR55, FR45: an exemption for the next judgment ends at the time it ends by as well, when no
/// judgment has used it up.
#[test]
fn an_exemption_for_the_next_judgment_ends_at_the_time_it_ends_by() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let exemption = at(
        the_user(),
        0,
        exempt_n_by(1, GUARD, None, Lifetime::Next, At::from_millis(100)),
    );
    let judged = |millis| verdict(&catalog, &[task_at(0), exemption.clone(), stop_at(millis)]);
    assert_eq!(judged(99), agent_caps_core::domain::judge::Verdict::Allow);
    assert_eq!(judged(100), violated());
}

/// FR55: the end by an event and the end by time are both ends: whichever comes first ends the
/// adjustment. A task that starts again ends one within the task, and a mode switch one within the
/// mode, long before the time they end by.
#[test]
fn an_end_by_an_event_that_comes_first_ends_the_adjustment_before_its_time() {
    let catalog = advised();
    let within_the_task = Lifetime::Within(Scope::Span {
        span: Span::Task,
        by: By::Anyone,
    });
    let events = [
        task_at(0),
        at(the_agent(), 0, raise_by(1, within_the_task, 1_000)),
        task_at(10),
    ];
    let state = catalog.fold(Origin::Genesis, &events);
    assert!(state.adjustments().is_empty());
    assert_eq!(effect_in(&catalog, &state), Effect::On(Level::Advise));

    let events = [
        task_at(0),
        at(
            the_agent(),
            0,
            raise_by(1, Lifetime::Within(Scope::Mode), 1_000),
        ),
        at(
            the_user(),
            5,
            Body::ModeSwitch {
                to: "fix".parse().unwrap(),
            },
        ),
        stop_at(10),
    ];
    let state = catalog.fold(Origin::Genesis, &events);
    assert!(state.adjustments().is_empty());
    assert_eq!(effect_in(&catalog, &state), Effect::On(Level::Advise));
}

/// FR55, FR45: an adjustment made before the first act has no clock to be checked against, so it
/// is held; at the first act it is checked with that act's time, and ends there if it lies too far
/// ahead. The same adjustment stays when the first act is late enough for it to be within the bound.
#[test]
fn an_adjustment_made_before_the_first_act_is_checked_at_the_first_act() {
    let catalog = advised();
    let ends_by = BOUND + 1_000;
    let raise = at(the_user(), 0, raise_until(1, ends_by));

    // Held, not refused, though it lies further ahead than the bound could allow from time zero.
    let report = admit(&catalog, &[], &raise);
    assert_eq!(report.decision, TxDecision::Commit);
    let held = catalog.fold(Origin::Genesis, [&raise]);
    assert_eq!(held.adjustments().len(), 1);
    assert_eq!(effect_in(&catalog, &held), Effect::On(Level::Force));

    // The first act is at 500: the latest it could end by is BOUND + 500, so it ends there.
    let early = catalog.fold(Origin::Genesis, [&raise, &task_at(500)]);
    assert!(early.adjustments().is_empty());
    assert_eq!(effect_in(&catalog, &early), Effect::On(Level::Advise));

    // The first act is at 1000: the latest is exactly where it ends by, so it holds, and keeps
    // holding until that time, as one admitted with a clock does.
    let on_time = catalog.fold(Origin::Genesis, [&raise, &task_at(1_000)]);
    assert_eq!(on_time.adjustments().len(), 1);
    assert_eq!(effect_in(&catalog, &on_time), Effect::On(Level::Force));
    let later = catalog.fold(
        Origin::Genesis,
        [&raise, &task_at(1_000), &stop_at(ends_by - 1)],
    );
    assert_eq!(later.adjustments().len(), 1);
    let ended = catalog.fold(
        Origin::Genesis,
        [&raise, &task_at(1_000), &stop_at(ends_by)],
    );
    assert!(ended.adjustments().is_empty());
}

/// FR55, FR20: the ceiling a fold from the middle puts on every rule (an adjustment made before it
/// may have raised it) lifts when the bound has passed since the fold's first act, since an
/// adjustment made before the fold ends by then at the latest. Until the first act it holds, and a
/// claim's time does not lift it.
#[test]
fn an_unknown_folds_ceiling_lifts_after_the_bound_since_its_first_act() {
    let catalog = advised();
    let first = 1_000;
    let state_at = |events: &[Event]| catalog.fold(Origin::Unknown, events);

    let no_act = state_at(&[]);
    assert!(no_act.may_hold_unseen());
    assert_eq!(effect_in(&catalog, &no_act), Effect::On(Level::Force));

    // A claim dated far ahead moves no clock.
    let claim = at(
        the_user(),
        first + 2 * BOUND,
        Body::ModeSwitch {
            to: "fix".parse().unwrap(),
        },
    );
    assert!(state_at(&[task_at(first), claim]).may_hold_unseen());

    let just_before = state_at(&[task_at(first), stop_at(first + BOUND - 1)]);
    assert!(just_before.may_hold_unseen());
    assert_eq!(effect_in(&catalog, &just_before), Effect::On(Level::Force));

    let lifted = state_at(&[task_at(first), stop_at(first + BOUND)]);
    assert!(!lifted.may_hold_unseen());
    assert_eq!(effect_in(&catalog, &lifted), Effect::On(Level::Advise));
    // What the fold started from is still said.
    assert_eq!(lifted.origin(), Origin::Unknown);
    // A whole history never had it.
    assert!(
        !catalog
            .fold(Origin::Genesis, &[task_at(first)])
            .may_hold_unseen()
    );
}

/// The graph of the user's guard, with no declaration.
fn guard_graph() -> PolicyGraph {
    graph_of(vec![test_guard(Level::Force)], vec![])
}

/// A set of the owner holding `graph`, which declares `bound` when one is given.
fn declared(
    name: &str,
    owner: Principal,
    graph: PolicyGraph,
    bound: Option<TemporaryBound>,
) -> Source {
    set(name, owner, declaring(graph, bound))
}

fn accept(sets: Vec<Source>, authority: Authority) -> Result<Catalog, Vec<AcceptError>> {
    Catalog::accept(Sources::new(sets).unwrap(), authority, lineage())
        .map_err(|rejected| rejected.0)
}

/// The bound is a positive length.
fn millis(millis: i64) -> TemporaryBound {
    TemporaryBound::from_millis(millis).unwrap()
}

/// FR55: a bound is more than zero long; zero and negative lengths are refused.
#[test]
fn a_bound_refuses_zero_and_negative_lengths() {
    assert_eq!(
        TemporaryBound::from_millis(0),
        Err(BoundError::NotPositive(0))
    );
    assert_eq!(
        TemporaryBound::from_millis(-1),
        Err(BoundError::NotPositive(-1))
    );
    assert_eq!(
        TemporaryBound::from_millis(1).map(TemporaryBound::millis),
        Ok(1)
    );
}

/// FR55: the root declares the bound in the graph of a set it owns, and the catalog keeps it; the
/// parts of the graph give it back, so a graph made again from them declares it still.
#[test]
fn the_root_declares_the_bound_and_the_catalog_keeps_it() {
    let sets = vec![declared(
        "user",
        the_user(),
        guard_graph(),
        Some(millis(DAY)),
    )];
    let catalog = accept(sets.clone(), super::common::authority()).unwrap();
    assert_eq!(catalog.temporary_bound(), millis(DAY));

    let graph = sets[0].graph.clone();
    assert_eq!(graph.temporary_bound(), Some(millis(DAY)));
    let (policies, bindings, classifiers, bound) = graph.clone().into_parts();
    assert_eq!(
        PolicyGraph::parse_with(policies, bindings, classifiers, bound).unwrap(),
        graph
    );
    // The graph the sets compose to declares none: the catalog's bound is the catalog's.
    assert_eq!(catalog.graph().temporary_bound(), None);
}

/// FR55: only a root decides the bound. A declaration in a set whose owner is not a root is
/// refused, whatever the root declares: a bound from below could cut off a raise the root permits.
#[test]
fn a_bound_in_a_set_a_root_does_not_own_is_refused() {
    let sets = vec![
        declared("user", the_user(), guard_graph(), Some(default_bound())),
        declared(
            "agent",
            the_agent(),
            PolicyGraph::default(),
            Some(millis(DAY)),
        ),
    ];
    assert_eq!(
        accept(sets, super::common::authority()).unwrap_err(),
        vec![AcceptError::BoundNotRoot {
            set: set_id("agent")
        }]
    );
}

/// FR55: every root that owns a set declares the same value. Two that declare different values, or
/// one that declares none beside one that does, are refused; the same value is accepted.
#[test]
fn the_roots_that_own_a_set_declare_the_same_bound() {
    let (a, b) = (Principal::new("a"), Principal::new("b"));
    let two_roots = || Authority::new([(a.clone(), None), (b.clone(), None)]).unwrap();
    let sets = |bound_a, bound_b| {
        vec![
            declared("a", a.clone(), PolicyGraph::default(), bound_a),
            declared("b", b.clone(), PolicyGraph::default(), bound_b),
        ]
    };

    let same = accept(sets(Some(millis(DAY)), Some(millis(DAY))), two_roots()).unwrap();
    assert_eq!(same.temporary_bound(), millis(DAY));

    assert_eq!(
        accept(sets(Some(millis(DAY)), Some(millis(2 * DAY))), two_roots()).unwrap_err(),
        vec![AcceptError::BoundConflict]
    );
    assert_eq!(
        accept(sets(Some(millis(DAY)), None), two_roots()).unwrap_err(),
        vec![AcceptError::BoundConflict]
    );
    assert_eq!(
        accept(sets(None, Some(millis(DAY))), two_roots()).unwrap_err(),
        vec![AcceptError::BoundConflict]
    );
    // A root declares once, in one of its sets: its other sets need not repeat it, and may only
    // with the same value.
    let one_root = || Authority::new([(a.clone(), None)]).unwrap();
    let split = |bound_second| {
        vec![
            declared("a", a.clone(), PolicyGraph::default(), Some(millis(DAY))),
            declared("a2", a.clone(), PolicyGraph::default(), bound_second),
        ]
    };
    assert_eq!(
        accept(split(None), one_root()).unwrap().temporary_bound(),
        millis(DAY)
    );
    assert_eq!(
        accept(split(Some(millis(2 * DAY))), one_root()).unwrap_err(),
        vec![AcceptError::BoundConflict]
    );
    // A root that owns no set has nothing to declare.
    let one = vec![declared(
        "a",
        a.clone(),
        PolicyGraph::default(),
        Some(millis(DAY)),
    )];
    assert!(accept(one, two_roots()).is_ok());
}

/// FR55: a catalog with no declaration at all is refused, so a period nobody chose is never
/// assumed; so is one with no set a root owns, which has no place to declare it.
#[test]
fn a_catalog_with_no_bound_is_refused() {
    let none = vec![declared("user", the_user(), guard_graph(), None)];
    assert_eq!(
        accept(none, super::common::authority()).unwrap_err(),
        vec![AcceptError::NoTemporaryBound]
    );

    let below_the_root = vec![declared("agent", the_agent(), PolicyGraph::default(), None)];
    assert_eq!(
        accept(below_the_root, super::common::authority()).unwrap_err(),
        vec![AcceptError::NoTemporaryBound]
    );
}

/// FR55: the order of what is found: a declaration in a set no root owns first, then the want of
/// one in a set a root owns.
#[test]
fn a_misplaced_bound_is_reported_before_the_missing_one() {
    let sets = vec![
        declared("user", the_user(), guard_graph(), None),
        declared(
            "agent",
            the_agent(),
            PolicyGraph::default(),
            Some(default_bound()),
        ),
    ];
    assert_eq!(
        accept(sets, super::common::authority()).unwrap_err(),
        vec![
            AcceptError::BoundNotRoot {
                set: set_id("agent")
            },
            AcceptError::NoTemporaryBound,
        ]
    );
}

/// FR55, FR49: changing the bound is a change of the root's set, judged as any change of it. The
/// agent, who does not cover the root, may change it in neither direction; the root may.
#[test]
fn a_bound_is_changed_by_one_who_covers_the_root() {
    let before = catalog(vec![test_guard(Level::Force)], vec![]);
    let user_set = before.sources().get(&set_id("user")).unwrap().clone();
    let with_bound = |bound| {
        let changed = Source {
            graph: declaring(user_set.graph.clone(), Some(bound)),
            ..user_set.clone()
        };
        before.sources().replaced(changed).unwrap()
    };

    for bound in [millis(BOUND + DAY), millis(DAY)] {
        match before.change(with_bound(bound), &the_agent()).unwrap_err() {
            ChangeRejected::Loosens(found) => assert!(
                found.contains(&Loosening::Uncovered {
                    target: Target::Set(set_id("user"))
                }),
                "{found:?}"
            ),
            other => panic!("rejected, but not for loosening: {other:?}"),
        }
        let after = before.change(with_bound(bound), &the_user()).unwrap();
        assert_eq!(after.temporary_bound(), bound);
    }
}

/// FR55, FR49: with several roots one cannot change the bound alone: the others declare the old
/// value, so the catalog would no longer be accepted. It changes when the sources are accepted
/// again, all of them with the new value.
#[test]
fn with_several_roots_a_bound_changes_only_when_the_catalog_is_accepted_again() {
    let (a, b) = (Principal::new("a"), Principal::new("b"));
    let hierarchy = Authority::new([(a.clone(), None), (b.clone(), None)]).unwrap();
    let sets = |bound_a, bound_b| {
        vec![
            declared("a", a.clone(), PolicyGraph::default(), Some(bound_a)),
            declared("b", b.clone(), PolicyGraph::default(), Some(bound_b)),
        ]
    };
    let before = accept(sets(millis(DAY), millis(DAY)), hierarchy.clone()).unwrap();

    let only_a = before
        .sources()
        .replaced(declared(
            "a",
            a.clone(),
            PolicyGraph::default(),
            Some(millis(2 * DAY)),
        ))
        .unwrap();
    assert_eq!(
        before.change(only_a, &a).unwrap_err(),
        ChangeRejected::Invalid(Rejected(vec![AcceptError::BoundConflict]))
    );

    let again = accept(sets(millis(2 * DAY), millis(2 * DAY)), hierarchy).unwrap();
    assert_eq!(again.temporary_bound(), millis(2 * DAY));
}
