//! Time as the acts tell it: a clock that only acts advance, the lifetimes that end by it, and
//! the windows of time a limit counts within (`Scope::Every`).
//!
//! The state's clock is the latest time an act has carried, and no time before the first act. A
//! claim's time never moves it, and an act dated earlier never moves it back. A claim's time
//! never ends what loosens when it ends: a raise for a while, a suspension, a window, or an
//! adjustment refused as expired are read by the clock alone. It may end an exemption's cover,
//! which is read at the later of the clock and the judged event's time, since an exemption that
//! ends sooner only tightens.
//!
//! A window of `Every(w)` is aligned to the Unix epoch and starts again when the clock crosses a
//! boundary. A session does not start it again, and an adjustment that lasts `Within(Every(w))`
//! ends at the boundary.

use agent_caps_core::domain::adjust::{Lifetime, Temporary, TemporaryBinding};
use agent_caps_core::domain::catalog::{Catalog, Effect};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::policy::{Expect, Level, Rule};
use agent_caps_core::domain::predicate::{
    By, Cmp, Cond, EventFilter, Pred, Scope, Span, Window, WindowError,
};
use agent_caps_core::domain::schema::{At, EventKind, Field, KindSet};
use agent_caps_core::domain::state::Origin;
use agent_caps_core::domain::tx::{TxDecision, TxPolicy};

use super::common::{
    GUARD, Written, adjustment_by, anyone, at, catalog, ends_by, exempt_n, exempt_n_by, fixture,
    id, mode, test_guard, tested_in, the_agent, the_user, verdict, violated, words,
};

const HOUR: i64 = 3_600_000;

fn hour() -> Window {
    Window::from_millis(HOUR).unwrap()
}

/// The guard warned, not stopped.
fn warned() -> Verdict {
    Verdict::Warn(vec![Cause::Violated(id(GUARD))])
}

/// The `n`th adjustment of the agent's: the test guard raised to Force for `lifetime`, within the
/// scenarios' bound.
fn raise(n: u8, lifetime: Lifetime) -> Body {
    raise_by(n, lifetime, ends_by())
}

/// The `n`th adjustment of the agent's: the test guard raised to Force until the instant, which
/// nothing but a cancel and the time ends before.
fn raise_until(n: u8, millis: i64) -> Body {
    raise_by(n, Lifetime::Timed, At::from_millis(millis))
}

/// The test guard raised to Force for `lifetime`, ending by `ends_by`.
fn raise_by(n: u8, lifetime: Lifetime, ends_by: At) -> Body {
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
        ends_by,
    )
}

/// The test guard at Advise, which a raise puts at Force.
fn advised() -> Catalog {
    catalog(vec![test_guard(Level::Advise)], vec![])
}

/// The effect of the test guard after `events`.
fn effect_after(catalog: &Catalog, events: &[Event]) -> Effect {
    catalog
        .effective_in(&catalog.fold(Origin::Genesis, events))
        .unwrap()
        .policies
        .iter()
        .find(|p| p.policy.id() == id(GUARD))
        .map(|p| p.effect)
        .unwrap()
}

/// The end of a turn by the agent, at the instant: an act.
fn stop_at(millis: i64) -> Event {
    at(the_agent(), millis, Body::Stop)
}

/// The start of a task by the agent, at the instant: an act.
fn task_at(millis: i64) -> Event {
    at(the_agent(), millis, Body::TaskStart)
}

/// The user's switch to a mode, at the instant: a claim.
fn switch_at(millis: i64) -> Event {
    at(the_user(), millis, Body::ModeSwitch { to: mode("fix") })
}

/// FR45, FR55: a claim dated in the future does not end a raise that ends by a time, since a
/// claim's time does not advance the clock; the next act at or after the time does.
#[test]
fn a_claim_dated_in_the_future_does_not_end_a_raise() {
    let catalog = advised();
    let raised = [
        task_at(0),
        at(the_agent(), 0, raise_until(1, 100)),
        switch_at(500),
    ];
    assert_eq!(effect_after(&catalog, &raised), Effect::On(Level::Force));
    assert_eq!(
        catalog.fold(Origin::Genesis, &raised).adjustments().len(),
        1
    );

    let mut events = raised.to_vec();
    events.push(stop_at(50));
    assert_eq!(verdict(&catalog, &events), violated());
    events.push(stop_at(100));
    assert_eq!(verdict(&catalog, &events), warned());
    assert!(
        catalog
            .fold(Origin::Genesis, &events)
            .adjustments()
            .is_empty()
    );
}

/// FR45, FR55: a raise claimed at a time after the time it ends by, while the clock is still
/// before it, is admitted, and ends at the first act past that time.
#[test]
fn a_raise_claimed_after_its_end_by_its_own_time_is_admitted_by_the_clock() {
    let catalog = advised();
    let start = task_at(0);
    let late = at(the_agent(), 200, raise_until(1, 100));
    let report = catalog
        .admit(
            &catalog.fold(Origin::Genesis, [&start]),
            &late,
            &TxPolicy::standard(),
        )
        .unwrap();
    assert_eq!(report.decision, TxDecision::Commit);
    assert_eq!(report.inadmissible, None);

    assert_eq!(
        verdict(&catalog, &[start.clone(), late.clone(), stop_at(50)]),
        violated()
    );
    let ended = [start, late, stop_at(50), stop_at(150)];
    assert_eq!(verdict(&catalog, &ended), warned());
    assert!(
        catalog
            .fold(Origin::Genesis, &ended)
            .adjustments()
            .is_empty()
    );
}

/// FR45, FR34: before any act there is no time yet, and a raise that ends by a time holds,
/// however late the claims around it are dated; the first act past that time ends it.
#[test]
fn before_any_act_a_raise_that_ends_by_a_time_holds() {
    let catalog = advised();
    let claims = [at(the_agent(), 500, raise_until(1, 100)), switch_at(1_000)];
    assert_eq!(effect_after(&catalog, &claims), Effect::On(Level::Force));
    let mut events = claims.to_vec();
    events.push(task_at(150));
    assert_eq!(effect_after(&catalog, &events), Effect::On(Level::Advise));
}

/// A guard on a mode switch: one needs `cargo test` to have passed within the session.
fn switch_guard() -> Written {
    let mut guard = test_guard(Level::Force);
    guard.subject = EventKind::ModeSwitch;
    guard.rule = Rule::Structural(tested_in(Scope::Span {
        span: Span::Session,
        by: By::Anyone,
    }));
    guard.fixtures = vec![
        fixture("untested", vec![switch_at(0)], Expect::Violated),
        fixture(
            "tested",
            vec![
                at(
                    the_agent(),
                    0,
                    Body::ToolUse {
                        tool: "Bash".to_owned(),
                        command: Some(words("cargo test")),
                        path: None,
                        ok: Some(true),
                    },
                ),
                switch_at(0),
            ],
            Expect::Satisfied,
        ),
    ];
    guard
}

/// FR45, FR34, UC25: a guard that judges a mode switch, a claim, is not exempted by an exemption
/// whose time to end by the switch's own time has passed, with no act in between: the cover is
/// read at the later of the clock and the switch's time, since an exemption that ends sooner only
/// tightens. A switch dated before that time is exempted.
#[test]
fn an_exemption_past_its_end_by_the_claims_time_does_not_cover_the_claim() {
    let catalog = catalog(vec![switch_guard()], vec![]);
    let exempted = [
        task_at(0),
        at(
            the_user(),
            0,
            exempt_n_by(1, GUARD, None, Lifetime::Timed, At::from_millis(100)),
        ),
    ];
    let judged = |switch: Event| {
        let mut events = exempted.to_vec();
        events.push(switch);
        verdict(&catalog, &events)
    };
    assert_eq!(judged(switch_at(50)), Verdict::Allow);
    assert_eq!(judged(switch_at(150)), violated());
    // The exemption is still held: no act has carried the clock past the time it ends by.
    assert_eq!(
        catalog.fold(Origin::Genesis, &exempted).adjustments().len(),
        1
    );
}

/// FR45, FR34: an exemption that lasts `Within(Every(1h))` does not cover a claim dated past
/// the hour's boundary, with no act in between: its cover is read at the later of the clock and
/// the claim's time, as the time an exemption ends by is. A switch dated inside the hour is
/// exempted.
#[test]
fn an_exemption_within_a_window_does_not_cover_a_claim_dated_past_it() {
    let catalog = catalog(vec![switch_guard()], vec![]);
    let exempted = [
        task_at(0),
        at(
            the_user(),
            10,
            exempt_n(1, GUARD, None, Lifetime::Within(Scope::Every(hour()))),
        ),
    ];
    let judged = |switch: Event| {
        let mut events = exempted.to_vec();
        events.push(switch);
        verdict(&catalog, &events)
    };
    assert_eq!(judged(switch_at(HOUR - 1)), Verdict::Allow);
    assert_eq!(judged(switch_at(HOUR)), violated());
    assert_eq!(
        catalog.fold(Origin::Genesis, &exempted).adjustments().len(),
        1
    );
}

/// The user's guard on a push: at most `n` pushes, of anyone, within each hour.
fn pushes_per_hour(n: u32) -> Catalog {
    let mut guard = test_guard(Level::Force);
    guard.subject = EventKind::ToolUse;
    guard.when = Some(Pred::Now(Cond::Words(Field::Command, words("git push"))));
    guard.rule = Rule::Structural(Pred::Count {
        select: anyone(EventFilter {
            kind: EventKind::ToolUse,
            cond: Some(Cond::Words(Field::Command, words("git push"))),
        }),
        scope: Scope::Every(hour()),
        cmp: Cmp::Le,
        n,
    });
    guard.fixtures = vec![
        fixture(
            "one push too many",
            (0..=n).map(|_| push_at(0)).collect(),
            Expect::Violated,
        ),
        fixture("one push", vec![push_at(0)], Expect::Satisfied),
    ];
    catalog(vec![guard], vec![])
}

/// A push by the agent, at the instant: an act.
fn push_at(millis: i64) -> Event {
    at(
        the_agent(),
        millis,
        Body::ToolUse {
            tool: "Bash".to_owned(),
            command: Some(words("git push")),
            path: None,
            ok: Some(true),
        },
    )
}

/// UC26, FR45: a count within `Every(1h)` starts again at the hour's boundary, and not at a
/// session's start inside the hour: the window is the clock's, not the session's.
#[test]
fn a_count_per_hour_starts_again_at_the_boundary_and_not_at_a_session() {
    let catalog = pushes_per_hour(1);
    assert_eq!(
        verdict(&catalog, &[push_at(0), push_at(HOUR - 1)]),
        violated()
    );
    assert_eq!(
        verdict(&catalog, &[push_at(0), push_at(HOUR)]),
        Verdict::Allow
    );
    let session = at(the_agent(), 10 * 60_000, Body::SessionStart);
    assert_eq!(
        verdict(&catalog, &[push_at(0), session, push_at(20 * 60_000)]),
        violated()
    );
}

/// UC26, FR45: an act dated earlier than the clock does not move it back, so the window does not
/// go back and start again.
#[test]
fn an_act_dated_earlier_does_not_move_the_window_back() {
    let catalog = pushes_per_hour(1);
    assert_eq!(
        verdict(&catalog, &[push_at(0), push_at(HOUR), push_at(10)]),
        violated()
    );
}

/// FR45, FR55: an adjustment that lasts `Within(Every(1h))` ends at the hour's boundary, at the
/// first act past it.
#[test]
fn an_adjustment_within_a_window_ends_at_the_boundary() {
    let catalog = advised();
    let raised = [
        task_at(0),
        at(
            the_agent(),
            10,
            raise(1, Lifetime::Within(Scope::Every(hour()))),
        ),
    ];
    let mut events = raised.to_vec();
    events.push(stop_at(HOUR - 1));
    assert_eq!(verdict(&catalog, &events), violated());
    events.push(stop_at(HOUR));
    assert_eq!(verdict(&catalog, &events), warned());
    assert!(
        catalog
            .fold(Origin::Genesis, &events)
            .adjustments()
            .is_empty()
    );
}

/// The user's switch to a mode recorded unreadably, at the instant: a record that may only
/// have been a claim.
fn lost_switch_at(millis: i64) -> Event {
    at(
        the_user(),
        millis,
        Body::Unreadable {
            may_have_been: KindSet::new([EventKind::ModeSwitch]),
        },
    )
}

/// A record that could not be read, at the instant, that may have been a tool use: an act.
fn lost_tool_use_at(millis: i64) -> Event {
    at(
        the_agent(),
        millis,
        Body::Unreadable {
            may_have_been: KindSet::new([EventKind::ToolUse]),
        },
    )
}

/// FR45, FR55, FR20: a record that could not be read and may only have been a mode switch, a
/// claim, carries a claim's time: dated far ahead, it neither starts a window again nor ends a
/// raise that ends by a time. One that may have been a tool use, an act, does both.
#[test]
fn an_unreadable_record_advances_the_clock_only_when_it_may_have_been_an_act() {
    let far = 10 * HOUR;
    // Had the lost switch moved the clock to `far`, the window would have started again there,
    // and the push after it (dated earlier, so the clock stays) would be the first of its window.
    let pushes = pushes_per_hour(1);
    assert_eq!(
        verdict(&pushes, &[push_at(0), lost_switch_at(far), push_at(10)]),
        violated()
    );

    let raised = advised();
    let after = |raise: Body, lost: Event| {
        let events = [task_at(0), at(the_agent(), 0, raise), lost];
        effect_after(&raised, &events)
    };
    let until = || raise_until(1, 100);
    let window = || raise(1, Lifetime::Within(Scope::Every(hour())));
    assert_eq!(
        after(until(), lost_switch_at(far)),
        Effect::On(Level::Force)
    );
    assert_eq!(
        after(window(), lost_switch_at(far)),
        Effect::On(Level::Force)
    );
    assert_eq!(
        after(until(), lost_tool_use_at(far)),
        Effect::On(Level::Advise)
    );
    assert_eq!(
        after(window(), lost_tool_use_at(far)),
        Effect::On(Level::Advise)
    );
}

/// FR45: a window is more than zero long; zero and negative lengths are refused.
#[test]
fn a_window_refuses_zero_and_negative_lengths() {
    assert_eq!(Window::from_millis(0), Err(WindowError::NotPositive(0)));
    assert_eq!(Window::from_millis(-1), Err(WindowError::NotPositive(-1)));
    assert_eq!(Window::from_millis(1).map(Window::millis), Ok(1));
}
