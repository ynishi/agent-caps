//! A mode switch is a claim (#17): it takes effect when it only tightens, from anyone, and when it
//! loosens only from one who covers the authors of what it loosens. It loosens when a policy
//! takes effect less strongly after it, when a policy reads the mode it leaves or enters (such a
//! rule's direction cannot be read), and when it starts the mode's scope again over a slot that
//! moves. A switch to the mode already in effect starts the mode's scope again, as any switch
//! does.

use agent_caps_core::domain::catalog::Catalog;
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::name::Mode;
use agent_caps_core::domain::policy::{Change, Level, PolicyDef, Rule};
use agent_caps_core::domain::predicate::{Cond, Pred, Scope};
use agent_caps_core::domain::schema::{EventKind, Field};
use agent_caps_core::domain::state::Known;

use super::common::{
    GUARD, OTHER, agent, bash, catalog, id, in_mode, mode, mode_switch, test_guard, tested_in,
    verdict, words,
};

/// The principal below the root switches to the mode.
fn switch_below(name: &str) -> Event {
    agent(Body::ModeSwitch { to: mode(name) })
}

/// The mode after the events.
fn mode_after(catalog: &Catalog, events: &[Event]) -> Known<Option<Mode>> {
    catalog.fold(events).mode().clone()
}

/// The root's advising guard on the end of a turn, Force in `fix` and Inform in `explore`, with
/// `rule` in place of its own.
fn levelled(rule: Pred) -> Catalog {
    let mut guard = test_guard(Level::Advise);
    guard.rule = Rule::Structural(rule);
    catalog(
        vec![guard],
        vec![
            in_mode("fix", GUARD, Change::Level(Level::Force)),
            in_mode("explore", GUARD, Change::Level(Level::Inform)),
        ],
    )
}

/// The root's guard that holds only in the `strict` mode: no shell call while it is in effect.
fn strict_guard() -> PolicyDef {
    let mut guard = test_guard(Level::Advise);
    guard.id = id(OTHER);
    guard.name = "strict-no-shell".parse().unwrap();
    guard.subject = EventKind::ToolUse;
    guard.when = Some(Pred::ModeIs(mode("strict")));
    guard.rule = Rule::Structural(Pred::Now(Cond::Not(Box::new(Cond::Words(
        Field::Command,
        words("cargo"),
    )))));
    guard.fixtures = vec![];
    guard
}

/// FR11, UC21, UC25: a switch from below that raises the root's guard takes effect; one that
/// lowers it does not, and the mode stays where it was.
#[test]
fn a_switch_from_below_takes_effect_when_it_tightens_and_not_when_it_lowers() {
    let catalog = levelled(tested_in(Scope::Task));
    let start = agent(Body::TaskStart);
    assert_eq!(
        mode_after(&catalog, &[start.clone(), switch_below("fix")]),
        Known::Known(Some(mode("fix")))
    );
    assert_eq!(
        mode_after(&catalog, &[start.clone(), switch_below("explore")]),
        Known::Known(None)
    );
    // The guard is still Advise: the lowering switch did not take effect, and the guard warns.
    assert_eq!(
        verdict(
            &catalog,
            &[start, switch_below("explore"), agent(Body::Stop)]
        ),
        Verdict::Warn(vec![Cause::Violated(id(GUARD))])
    );
}

/// FR11, UC21, UC25: a switch starts the mode's scope again. From below, it does not when that
/// would move a slot the root's guard reads, here a test already seen within the mode; when the
/// slot is at its start value, nothing moves and the tightening switch takes effect.
#[test]
fn a_switch_from_below_does_not_start_the_mode_again_over_a_slot_that_moves() {
    let catalog = levelled(tested_in(Scope::Mode));
    let start = agent(Body::TaskStart);
    let tested = || bash("cargo test", Some(true));
    // Nothing seen yet within the mode: the slot does not move, and the switch takes effect.
    assert_eq!(
        mode_after(&catalog, &[start.clone(), switch_below("fix")]),
        Known::Known(Some(mode("fix")))
    );
    // A test seen within the mode: starting it again would forget the test.
    assert_eq!(
        mode_after(&catalog, &[start.clone(), tested(), switch_below("fix")]),
        Known::Known(None)
    );
    let root_fix = mode_switch("fix");
    assert_eq!(
        verdict(
            &catalog,
            &[
                root_fix.clone(),
                start.clone(),
                tested(),
                switch_below("fix"),
                agent(Body::Stop)
            ]
        ),
        Verdict::Allow
    );
}

/// FR11, UC8: the root's switch to the mode already in effect starts the mode's scope again, so
/// a test seen before it no longer counts.
#[test]
fn the_roots_switch_to_the_same_mode_starts_the_mode_again() {
    let catalog = levelled(tested_in(Scope::Mode));
    let fix = mode_switch("fix");
    assert_eq!(
        verdict(
            &catalog,
            &[
                fix.clone(),
                agent(Body::TaskStart),
                bash("cargo test", Some(true)),
                fix,
                agent(Body::Stop)
            ]
        ),
        Verdict::Deny(vec![Cause::Violated(id(GUARD))])
    );
}

/// FR11, UC21, UC25: a guard of the root's that holds only in `strict` reads the mode, so a
/// switch from below out of `strict` does not take effect, even one that raises the other guard.
/// A switch from below between two modes that guard does not read, and that only raises, does.
#[test]
fn a_switch_from_below_does_not_leave_a_mode_the_roots_guard_reads() {
    let mut guard = test_guard(Level::Advise);
    guard.rule = Rule::Structural(tested_in(Scope::Task));
    let catalog = catalog(
        vec![guard, strict_guard()],
        vec![
            in_mode("fix", GUARD, Change::Level(Level::Force)),
            in_mode("explore", GUARD, Change::Level(Level::Inform)),
        ],
    );
    let start = agent(Body::TaskStart);
    for to in ["explore", "fix"] {
        assert_eq!(
            mode_after(
                &catalog,
                &[mode_switch("strict"), start.clone(), switch_below(to)]
            ),
            Known::Known(Some(mode("strict"))),
            "strict -> {to}"
        );
    }
    assert_eq!(
        mode_after(
            &catalog,
            &[mode_switch("explore"), start, switch_below("fix")]
        ),
        Known::Known(Some(mode("fix")))
    );
}
