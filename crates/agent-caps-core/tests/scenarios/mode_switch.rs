//! A mode switch is a claim (#17): it takes effect when it only tightens, from anyone, and when it
//! loosens only from one who covers the authors of what it loosens. It loosens when a policy
//! takes effect less strongly after it (by the bindings that hold inside or outside a mode, which
//! the rule check reads), when a policy that applies inside a mode it reads sees
//! the mode left (and, where the policy reads the mode in a direction that cannot be told, entered
//! as well), and when it starts the mode's scope again over a slot that moves. A switch into a
//! mode a policy applies inside tightens it. A switch to the mode already in effect starts the
//! mode's scope again, as any switch does.

use agent_caps_core::domain::catalog::Catalog;
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::name::Mode;
use agent_caps_core::domain::policy::{Binding, Level, Rule};
use agent_caps_core::domain::predicate::{Cond, Pred, Scope};
use agent_caps_core::domain::schema::{EventKind, Field};
use agent_caps_core::domain::state::Known;

use agent_caps_core::domain::tx::{
    FindingDetail, TxDecision, TxPolicy, TxReport, Verdict as TxVerdict,
};

use super::common::{
    GUARD, OTHER, Written, agent, bash, bind, catalog, id, inside, mode, mode_switch, outside,
    push_after_allowed, test_guard, tested_in, the_user, unreadable, verdict, words,
};

/// The principal below the root switches to the mode.
fn switch_below(name: &str) -> Event {
    agent(Body::ModeSwitch { to: mode(name) })
}

/// The mode after the events.
fn mode_after(catalog: &Catalog, events: &[Event]) -> Known<Option<Mode>> {
    catalog.fold(events).mode().clone()
}

/// The root's bindings of the guard: Advise outside `explore`, Force in `fix` and Inform in
/// `explore`.
fn levels() -> Vec<Binding> {
    vec![
        bind(GUARD, 1, Level::Advise, outside(&["explore"]), the_user()),
        bind(GUARD, 2, Level::Force, inside("fix"), the_user()),
        bind(GUARD, 3, Level::Inform, inside("explore"), the_user()),
    ]
}

/// The root's guard on the end of a turn, bound by [`levels`], with `rule` in place of its own.
fn levelled(rule: Pred) -> Catalog {
    let mut guard = test_guard(Level::Advise);
    guard.level = None;
    guard.rule = Rule::Structural(rule);
    catalog(vec![guard], levels())
}

/// The root's guard that holds only in the `strict` mode: no shell call while it is in effect.
fn strict_guard() -> Written {
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
    guard.level = None;
    guard.rule = Rule::Structural(tested_in(Scope::Task));
    let catalog = catalog(vec![guard, strict_guard()], levels());
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

/// The root's guard that holds everywhere but in the `strict` mode: it reads the mode under a
/// `not`, so the direction it reads it in cannot be told.
fn outside_strict_guard() -> Written {
    let mut guard = strict_guard();
    guard.when = Some(Pred::Not(Box::new(Pred::ModeIs(mode("strict")))));
    guard
}

/// FR11, UC21, UC25: a guard of the root's that applies inside `strict` is held more by a switch
/// into it, which takes effect from below, and less by one out of it, which does not; a switch
/// between modes it does not read is neither.
#[test]
fn a_switch_from_below_into_a_mode_a_guard_applies_inside_takes_effect_and_out_of_it_does_not() {
    let catalog = catalog(vec![strict_guard()], vec![]);
    let strict = Known::Known(Some(mode("strict")));
    assert_eq!(mode_after(&catalog, &[switch_below("strict")]), strict);
    assert_eq!(
        mode_after(&catalog, &[mode_switch("strict"), switch_below("fix")]),
        strict
    );
    assert_eq!(
        mode_after(&catalog, &[mode_switch("explore"), switch_below("fix")]),
        Known::Known(Some(mode("fix")))
    );
    // The root's switch out of it takes effect.
    assert_eq!(
        mode_after(&catalog, &[mode_switch("strict"), mode_switch("fix")]),
        Known::Known(Some(mode("fix")))
    );
}

/// FR11, UC21, UC25: a guard of the root's that reads `strict` under a `not` cannot be told to
/// hold more or less by a switch into it or out of it, so neither takes effect from below; a
/// switch between modes it does not read does.
#[test]
fn a_switch_from_below_into_a_mode_a_guard_reads_under_a_not_does_not_take_effect() {
    let catalog = catalog(vec![outside_strict_guard()], vec![]);
    assert_eq!(
        mode_after(&catalog, &[switch_below("strict")]),
        Known::Known(None)
    );
    assert_eq!(
        mode_after(&catalog, &[mode_switch("strict"), switch_below("fix")]),
        Known::Known(Some(mode("strict")))
    );
    assert_eq!(
        mode_after(&catalog, &[switch_below("fix")]),
        Known::Known(Some(mode("fix")))
    );
}

/// FR11, FR20, UC25: when the mode before the switch is not known, the mode it goes to is counted
/// as entered and every other mode as left (it may have been there): a switch from below into the
/// mode a guard applies inside takes effect, one to another mode does not, and a guard that reads
/// the mode under a `not` lets neither.
#[test]
fn a_switch_from_below_after_a_lost_mode_switch_counts_the_mode_it_goes_to_as_entered() {
    let lost = || unreadable(&[EventKind::ModeSwitch]);
    let inside = catalog(vec![strict_guard()], vec![]);
    assert_eq!(
        mode_after(&inside, &[lost(), switch_below("strict")]),
        Known::Known(Some(mode("strict")))
    );
    assert_eq!(
        mode_after(&inside, &[lost(), switch_below("fix")]),
        Known::Unknown
    );
    let outside = catalog(vec![outside_strict_guard()], vec![]);
    for to in ["strict", "fix"] {
        assert_eq!(
            mode_after(&outside, &[lost(), switch_below(to)]),
            Known::Unknown,
            "unknown -> {to}"
        );
    }
    // A switch from the root settles it whatever the guards read.
    assert_eq!(
        mode_after(&outside, &[lost(), mode_switch("fix")]),
        Known::Known(Some(mode("fix")))
    );
}

/// The root's advising guard on the end of a turn that holds only in the `strict` mode.
fn strict_stop_guard() -> Written {
    let mut guard = test_guard(Level::Advise);
    guard.when = Some(Pred::ModeIs(mode("strict")));
    guard.fixtures = vec![];
    guard
}

/// The transaction of `event` from the start.
fn admit_first(catalog: &Catalog, event: &Event) -> TxReport {
    catalog.admit(&catalog.start(), event, &TxPolicy::standard())
}

/// FR11, UC21, UC25, FR41: a switch into the mode a guard applies inside makes it apply to more
/// events, and so writes more judgments of it. A root rule that reads that guard's judgments (its
/// last judgment within the session) is moved by that, so the switch from below, which would
/// otherwise only tighten, does not take effect; the root's does.
#[test]
fn a_switch_from_below_does_not_take_effect_when_a_root_rule_reads_the_judgments_of_a_guard_it_widens()
 {
    let catalog = catalog(vec![strict_stop_guard(), push_after_allowed(GUARD)], vec![]);
    let strict = Known::Known(Some(mode("strict")));
    assert_eq!(
        mode_after(&catalog, &[switch_below("strict")]),
        Known::Known(None)
    );
    assert_eq!(mode_after(&catalog, &[mode_switch("strict")]), strict);

    let report = admit_first(&catalog, &switch_below("strict"));
    assert_eq!(report.decision, TxDecision::Abort);
    let [found] = report.findings.as_slice() else {
        panic!("one finding was expected: {report:?}")
    };
    assert_eq!(found.check.as_str(), "mode");
    // The guard that applies to more stays tightened; the rule that reads its judgments loosens.
    assert_eq!(
        found.verdict,
        TxVerdict::Loosens {
            authors: vec![the_user()],
            detail: FindingDetail::Mode {
                reading: vec![id(OTHER)],
            },
        }
    );
    assert_eq!(
        admit_first(&catalog, &mode_switch("strict")).decision,
        TxDecision::Commit
    );
}

/// FR11, UC21, UC25, FR41: with no rule that reads the guard's judgments, the same switch from
/// below tightens and takes effect, whatever else the catalog holds.
#[test]
fn a_switch_from_below_into_a_mode_takes_effect_when_no_rule_reads_the_judgments_of_the_guard() {
    let mut unrelated = push_after_allowed(GUARD);
    unrelated.rule = Rule::Structural(tested_in(Scope::Task));
    let catalog = catalog(vec![strict_stop_guard(), unrelated], vec![]);
    assert_eq!(
        mode_after(&catalog, &[switch_below("strict")]),
        Known::Known(Some(mode("strict")))
    );
    let report = admit_first(&catalog, &switch_below("strict"));
    assert_eq!(report.decision, TxDecision::Commit);
    assert!(matches!(
        report.findings.as_slice(),
        [found] if matches!(found.verdict, TxVerdict::Tightens(_))
    ));
}
