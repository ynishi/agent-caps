//! Budgets: a limit on the sum of an amount used, such as the tokens of a task, that the agent
//! cannot start over by its own acts.
//!
//! The platform measures what was used and the adapter carries it as an act, `Body::Used`, with
//! its meter and its amount. `Pred::Spent` sums the amounts of one meter whose actor its `Whose`
//! chooses, within a scope, and compares the sum with a bound by an `Order`. A sum chooses by
//! place only (`Whose` has no `Only`): with `Whose::Under(agent)` the use of a sub agent spawned
//! below the agent counts toward it, so the agent cannot escape its budget by delegating. With
//! `Scope::Span { span: Span::Task, by: By::Only(user) }` only the user's `TaskStart` starts the budget again.
//!
//! An amount is known after the use, so a sum can pass its bound by one event: the act whose use
//! passes it has already run, and the next act is the one stopped. An amount that was measured
//! but could not be read makes the sum unknown, and a stopping guard stops.

use agent_caps_core::domain::authority::Principal;
use agent_caps_core::domain::catalog::Catalog;
use agent_caps_core::domain::event::{Body, Event, Seen};
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::name::Meter;
use agent_caps_core::domain::policy::{Expect, Level, Rule};
use agent_caps_core::domain::predicate::{
    Amount, AmountError, By, Cmp, Cond, EventFilter, Lit, Order, Pred, Scope, Span, Whose, Window,
};
use agent_caps_core::domain::schema::{EventKind, Field, KindSet};

use super::common::{
    GUARD, Written, anyone, at, catalog, fixture, id, test_guard, the_agent, the_user, verdict,
    violated,
};

const HOUR: i64 = 3_600_000;

fn tokens() -> Meter {
    "tokens".parse().unwrap()
}

fn amount(value: f64) -> Amount {
    Amount::new(value).unwrap()
}

/// What the platform measured `actor` used of `meter`, at the instant.
fn used_of(actor: &Principal, millis: i64, meter: &str, value: Option<f64>) -> Event {
    at(
        actor.clone(),
        millis,
        Body::Used {
            meter: meter.parse().unwrap(),
            amount: value.map(amount),
        },
    )
}

/// The agent used `value` tokens.
fn used(value: f64) -> Event {
    used_of(&the_agent(), 0, "tokens", Some(value))
}

/// A tool use by the agent, at the instant: the act a budget stops.
fn tool_at(millis: i64) -> Event {
    at(
        the_agent(),
        millis,
        Body::ToolUse {
            tool: "Read".to_owned(),
            command: Seen::Absent,
            path: Seen::Value("a.rs".to_owned()),
            ok: None,
        },
    )
}

fn tool() -> Event {
    tool_at(0)
}

fn task_by(actor: &Principal) -> Event {
    at(actor.clone(), 0, Body::TaskStart)
}

fn unknown() -> Verdict {
    Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
}

/// The user's Force guard on every tool use: the agent and the actors below it have used fewer
/// than 100 tokens within `scope`.
fn token_budget(scope: Scope) -> Written {
    let mut guard = test_guard(Level::Force);
    guard.subject = EventKind::ToolUse;
    guard.when = None;
    guard.rule = Rule::Structural(Pred::Spent {
        meter: tokens(),
        by: Whose::Under(the_agent()),
        scope,
        order: Order::Lt,
        n: amount(100.0),
    });
    guard.fixtures = vec![
        fixture("over budget", vec![used(100.0), tool()], Expect::Violated),
        fixture("within budget", vec![used(99.0), tool()], Expect::Satisfied),
    ];
    guard
}

/// A budget of 100 tokens per task, which only the user's `TaskStart` starts again.
fn per_task() -> Catalog {
    catalog(
        vec![token_budget(Scope::Span {
            span: Span::Task,
            by: By::Only(the_user()),
        })],
        vec![],
    )
}

/// UC26, FR47: within a task, the tool uses go through while the sum of the tokens used is below
/// the budget, and the next tool use is stopped once it reaches it.
#[test]
fn a_token_budget_per_task_stops_the_next_tool_use_once_the_sum_reaches_it() {
    let catalog = per_task();
    let mut events = vec![task_by(&the_user()), used(60.0), tool()];
    assert_eq!(verdict(&catalog, &events), Verdict::Allow);
    events.extend([used(40.0), tool()]);
    assert_eq!(verdict(&catalog, &events), violated());
}

/// UC26, FR47: the use of a sub agent the agent spawned below itself counts toward the agent's
/// budget under `Whose::Under(agent)`; the user's own use, which is not below the agent, does
/// not.
#[test]
fn a_sub_agents_use_counts_toward_its_parent() {
    let catalog = per_task();
    let child = Principal::new("s1");
    let spawn = spawn_by(&the_agent(), &child);
    assert_eq!(
        verdict(
            &catalog,
            &[
                spawn,
                used(50.0),
                used_of(&child, 0, "tokens", Some(50.0)),
                tool()
            ]
        ),
        violated()
    );
    assert_eq!(
        verdict(
            &catalog,
            &[used_of(&the_user(), 0, "tokens", Some(500.0)), tool()]
        ),
        Verdict::Allow
    );
}

/// `spawner` starts the sub agent `child`, placed directly under itself.
fn spawn_by(spawner: &Principal, child: &Principal) -> Event {
    at(
        spawner.clone(),
        0,
        Body::Spawn {
            child: child.clone(),
            under: spawner.clone(),
        },
    )
}

/// UC26, FR47: delegating further does not escape the budget: the use of a sub agent that the
/// agent's sub agent spawned counts toward the agent as well.
#[test]
fn a_use_delegated_two_levels_down_still_counts() {
    let catalog = per_task();
    let (child, grandchild) = (Principal::new("s1"), Principal::new("s2"));
    assert_eq!(
        verdict(
            &catalog,
            &[
                spawn_by(&the_agent(), &child),
                spawn_by(&child, &grandchild),
                used_of(&grandchild, 0, "tokens", Some(100.0)),
                tool()
            ]
        ),
        violated()
    );
}

/// UC26, FR47: what was used of another meter is not summed with the tokens.
#[test]
fn a_use_of_another_meter_does_not_count() {
    let catalog = per_task();
    assert_eq!(
        verdict(
            &catalog,
            &[used_of(&the_agent(), 0, "cost-usd", Some(1000.0)), tool()]
        ),
        Verdict::Allow
    );
}

/// UC26, FR47, FR20: a use whose amount could not be read makes the sum unknown, so the stopping
/// guard stops; a count of the same `Used` events, which reads no amount, still reads it.
#[test]
fn an_amount_that_could_not_be_read_makes_the_sum_unknown() {
    let budget = per_task();
    let unread = used_of(&the_agent(), 0, "tokens", None);
    assert_eq!(verdict(&budget, &[unread.clone(), tool()]), unknown());
    // Until the scope starts again.
    assert_eq!(
        verdict(&budget, &[unread.clone(), task_by(&the_user()), tool()]),
        Verdict::Allow
    );

    let mut count = test_guard(Level::Force);
    count.subject = EventKind::ToolUse;
    count.rule = Rule::Structural(Pred::Count {
        select: anyone(EventFilter {
            kind: EventKind::Used,
            cond: Some(Cond::Eq(Field::Meter, Lit::Text("tokens".to_owned()))),
        }),
        scope: Scope::Span {
            span: Span::Session,
            by: By::Anyone,
        },
        cmp: Cmp::Eq,
        n: 0,
    });
    count.fixtures = vec![
        fixture("a use", vec![used(1.0), tool()], Expect::Violated),
        fixture("no use", vec![tool()], Expect::Satisfied),
    ];
    let counting = catalog(vec![count], vec![]);
    assert_eq!(verdict(&counting, &[unread, tool()]), violated());
}

/// UC26, FR47, FR20: a record that could not be read and may have been a `Used` makes the sum
/// unknown, so the stopping guard stops; one that cannot have been a `Used` leaves it known.
#[test]
fn a_record_that_may_have_been_a_use_makes_the_sum_unknown() {
    let catalog = per_task();
    let lost = |kind: EventKind| {
        at(
            the_agent(),
            0,
            Body::Unreadable {
                may_have_been: KindSet::new([kind]),
            },
        )
    };
    assert_eq!(
        verdict(&catalog, &[used(10.0), lost(EventKind::Used), tool()]),
        unknown()
    );
    assert_eq!(
        verdict(&catalog, &[used(10.0), lost(EventKind::Stop), tool()]),
        Verdict::Allow
    );
}

/// UC26, FR47, FR54: the agent's own `TaskStart` does not start the budget again under
/// `Span { Task, Only(user) }`; the user's does.
#[test]
fn only_the_users_task_start_starts_the_budget_again() {
    let catalog = per_task();
    let mut events = vec![
        task_by(&the_user()),
        used(100.0),
        task_by(&the_agent()),
        tool(),
    ];
    assert_eq!(verdict(&catalog, &events), violated());
    events.extend([task_by(&the_user()), tool()]);
    assert_eq!(verdict(&catalog, &events), Verdict::Allow);
}

/// UC26, FR47, FR45: a budget within `Every(1h)` starts again when the clock crosses the
/// boundary of the hour.
#[test]
fn a_budget_per_hour_starts_again_at_the_boundary() {
    let hour = Window::from_millis(HOUR).unwrap();
    let catalog = catalog(vec![token_budget(Scope::Every(hour))], vec![]);
    let spent = used_of(&the_agent(), 10, "tokens", Some(100.0));
    assert_eq!(
        verdict(&catalog, &[spent.clone(), tool_at(HOUR - 1)]),
        violated()
    );
    assert_eq!(verdict(&catalog, &[spent, tool_at(HOUR)]), Verdict::Allow);
}

/// UC26, FR47: an amount is a finite number, zero or more: NaN, the infinities and negative
/// numbers are refused.
#[test]
fn an_amount_refuses_nan_infinities_and_negatives() {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert!(matches!(Amount::new(bad), Err(AmountError::NotFinite(_))));
    }
    assert_eq!(Amount::new(-0.5), Err(AmountError::Negative(-0.5)));
    assert_eq!(Amount::new(0.0).map(Amount::get), Ok(0.0));
    assert_eq!(Amount::new(12.5).map(Amount::get), Ok(12.5));
}

/// UC26, FR47: an amount is known after the use, so the use that takes the sum past the budget
/// is not stopped, and the next act is.
#[test]
fn a_sum_may_pass_its_bound_by_one_event_and_the_next_act_is_stopped() {
    let catalog = per_task();
    let mut events = vec![task_by(&the_user()), used(99.0), tool()];
    assert_eq!(verdict(&catalog, &events), Verdict::Allow);
    // The use that passes the budget is no tool use: the guard does not judge it.
    events.push(used(50.0));
    assert_eq!(verdict(&catalog, &events), Verdict::Allow);
    events.push(tool());
    assert_eq!(verdict(&catalog, &events), violated());
}
