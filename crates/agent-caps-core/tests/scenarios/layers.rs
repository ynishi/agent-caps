//! Scenarios S4, L1, L2 and L3: the bindings of a policy, under every mode or under some, and what
//! operating on them does. What used to be the layers Base, Project and Mode are bindings: the
//! strongest binding that holds under the mode in effect wins.
//!
//! - S4: a binding inside a mode changes the level there, a switch that lowers a guard takes effect
//!   only from one who covers the authors of the bindings that carried its strength, and the
//!   verdict does not depend on the order of the policies. The `mode_switch` module checks the
//!   switch as a claim further.
//! - L2: the strongest binding that holds wins, whoever wrote it; a policy with no binding under
//!   every mode can be put into effect inside a mode; the order of the bindings in the graph does
//!   not matter.
//! - L3: a meta policy has its one binding, by its author, under every mode. `Catalog::accept`
//!   rejects any other, so its level is the same in every mode by construction; the test checks
//!   the rejection.
//! - L1: the policies in effect under a mode, with their levels, are listed by
//!   `Catalog::effective`, without judging any event. That was a gap (#6) and is fixed: a policy
//!   that is off is listed as off, and one the judged event does not reach is still listed. A
//!   judgment lists only the guards the event reaches.
//!
//! The levels are written as literals ("Force under bugfix"), read from `Catalog::effective` or
//! from the outcome of `judge`; no test here computes how the bindings combine.

use agent_caps_core::domain::catalog::{AcceptError, Capabilities, Effect};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Outcome, Verdict, judge};
use agent_caps_core::domain::name::PolicyId;
use agent_caps_core::domain::policy::{DefLayer, Level, ModeScope, Polarity, PolicyDef, Rule};
use agent_caps_core::domain::predicate::{Cond, Lit, Pred};
use agent_caps_core::domain::schema::{EventKind, Field};
use agent_caps_core::domain::state::{Known, Origin};

use super::common::{
    GUARD, OTHER, Written, agent, at, bash, bind, catalog, id, inside, listed, mode, mode_switch,
    outcome, outside, rejected, test_guard, the_agent, the_user, unreadable, verdict, violated,
    written,
};

/// The level the guard had on the last event.
fn level_of(outcome: &Outcome, policy: &str) -> Level {
    outcome
        .guards
        .iter()
        .find(|g| g.policy == id(policy))
        .unwrap_or_else(|| panic!("{policy} did not judge the event"))
        .written
}

/// The test guard with no binding of its author's under every mode: its bindings are the
/// scenario's.
fn unbound_guard() -> Written {
    let mut guard = test_guard(Level::Inform);
    guard.level = None;
    guard
}

/// An advising guard of a tool call: a shell call must have succeeded.
fn bash_guard() -> Written {
    let def = PolicyDef {
        id: id(OTHER),
        name: "bash-ok".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: None,
        rule: Rule::Structural(Pred::Now(Cond::Eq(Field::Ok, Lit::Bool(true)))),
        polarity: Polarity::Guard,
        fixtures: vec![],
        author: the_user(),
    };
    written(def, Level::Advise)
}

/// UC8, FR11: a binding inside a mode, beside one outside it, changes the level of a policy.
/// UC25: a switch that lowers the root's guard is nothing from the principal below it; the root
/// makes it. FR20: a lost record that may have been a switch puts the strongest binding in force.
#[test]
fn a_mode_changes_the_level_and_a_lowering_switch_needs_the_guards_author() {
    let catalog = catalog(
        vec![unbound_guard()],
        vec![
            bind(GUARD, 1, Level::Force, outside(&["modeling"]), the_user()),
            bind(GUARD, 2, Level::Inform, inside("modeling"), the_user()),
        ],
    );
    let switch = |by| {
        at(
            by,
            0,
            Body::ModeSwitch {
                to: mode("modeling"),
            },
        )
    };
    let stop = agent(Body::Stop);
    let warned = Verdict::Warn(vec![Cause::Violated(id(GUARD))]);
    assert_eq!(
        verdict(&catalog, &[switch(the_user()), stop.clone()]),
        warned
    );
    // One below the guard's author cannot loosen it.
    assert!(matches!(
        verdict(&catalog, &[switch(the_agent()), stop.clone()]),
        Verdict::Deny(_)
    ));
    // A lost record may have been a switch: the strongest binding applies.
    let state = catalog.fold(
        Origin::Genesis,
        &[switch(the_user()), unreadable(&[EventKind::ModeSwitch])],
    );
    assert_eq!(state.mode(), &Known::Unknown);
    assert!(matches!(
        judge(&catalog, &state, &stop, &Capabilities::full())
            .unwrap()
            .verdict,
        Verdict::Deny(_)
    ));
}

/// FR29: with several policies in effect on one event, the strongest decides, whatever their
/// order.
#[test]
fn the_verdict_takes_the_strongest_and_ignores_the_order() {
    let mut warn = test_guard(Level::Advise);
    warn.id = id(OTHER);
    warn.name = "advice".parse().unwrap();
    let deny = test_guard(Level::Force);
    let events = [agent(Body::TaskStart), agent(Body::Stop)];
    let one = catalog(vec![warn.clone(), deny.clone()], vec![]);
    let other = catalog(vec![deny, warn], vec![]);
    assert_eq!(verdict(&one, &events), violated());
    assert_eq!(verdict(&other, &events), violated());
}

/// L2, UC27, UC8, FR42: the base binds Inform, the project Advise, the bugfix mode Force; the
/// strongest that holds wins. The guard has its fixtures, so it may be bound at a stopping level.
#[test]
fn the_strongest_binding_that_holds_wins() {
    let catalog = catalog(
        vec![test_guard(Level::Inform)],
        vec![
            bind(GUARD, 1, Level::Advise, ModeScope::Any, the_user()),
            bind(GUARD, 2, Level::Force, inside("bugfix"), the_user()),
        ],
    );
    let stop = [agent(Body::TaskStart), agent(Body::Stop)];
    // No mode: the project's Advise over the base's Inform.
    assert_eq!(level_of(&outcome(&catalog, &stop), GUARD), Level::Advise);
    // The bugfix mode: Force over the project's Advise.
    let bugfix = [mode_switch("bugfix"), stop[0].clone(), stop[1].clone()];
    assert_eq!(level_of(&outcome(&catalog, &bugfix), GUARD), Level::Force);
    // A mode that no binding names leaves the project's level.
    let other = [mode_switch("modeling"), stop[0].clone(), stop[1].clone()];
    assert_eq!(level_of(&outcome(&catalog, &other), GUARD), Level::Advise);
}

/// L2, UC27, UC8, FR42: the project leaves the guard no binding under every mode, so it is off;
/// a binding inside the bugfix mode puts it into effect there.
#[test]
fn a_binding_inside_a_mode_turns_on_a_policy_with_no_other() {
    let catalog = catalog(
        vec![unbound_guard()],
        vec![bind(GUARD, 1, Level::Force, inside("bugfix"), the_user())],
    );
    let stop = [agent(Body::TaskStart), agent(Body::Stop)];
    let off = outcome(&catalog, &stop);
    assert!(off.guards.is_empty());
    assert_eq!(off.verdict, Verdict::Allow);

    let bugfix = [mode_switch("bugfix"), stop[0].clone(), stop[1].clone()];
    let on = outcome(&catalog, &bugfix);
    assert_eq!(level_of(&on, GUARD), Level::Force);
    assert_eq!(on.verdict, violated());
}

/// L2, UC27, UC8: the bindings are combined by what they say, not by where they stand in the graph.
#[test]
fn the_order_of_the_bindings_in_the_graph_does_not_matter() {
    let project_first = vec![
        bind(GUARD, 1, Level::Advise, ModeScope::Any, the_user()),
        bind(GUARD, 2, Level::Force, inside("bugfix"), the_user()),
    ];
    let mode_first = vec![project_first[1].clone(), project_first[0].clone()];
    let bugfix = [
        mode_switch("bugfix"),
        agent(Body::TaskStart),
        agent(Body::Stop),
    ];
    let one = outcome(
        &catalog(vec![test_guard(Level::Inform)], project_first),
        &bugfix,
    );
    let other = outcome(
        &catalog(vec![test_guard(Level::Inform)], mode_first),
        &bugfix,
    );
    assert_eq!(one, other);
    assert_eq!(level_of(&one, GUARD), Level::Force);
}

/// L3, FR14, UC10: no binding but its own reaches a meta policy: not one more under every mode,
/// not one inside a mode, and its own cannot be taken away.
#[test]
fn no_binding_but_its_own_reaches_a_meta_policy() {
    let mut meta = test_guard(Level::Force);
    meta.layer = DefLayer::Meta;
    for extra in [
        bind(GUARD, 1, Level::Inform, ModeScope::Any, the_user()),
        bind(GUARD, 1, Level::Inform, inside("bugfix"), the_user()),
    ] {
        assert_eq!(
            rejected(vec![meta.clone()], vec![extra.clone()]),
            vec![AcceptError::MetaBinding(id(GUARD))],
            "{extra:?}"
        );
    }
    let mut unbound = meta;
    unbound.level = None;
    assert_eq!(
        rejected(
            vec![unbound],
            vec![bind(
                GUARD,
                1,
                Level::Force,
                outside(&["bugfix"]),
                the_user()
            )],
        ),
        vec![AcceptError::MetaBinding(id(GUARD))]
    );
}

/// L1, UC17, FR12: the policies in effect under each mode are listed with their effect, without
/// judging any event: Base Inform, the project Advise, bugfix Force, and none in explore. Not
/// knowing the mode takes the strongest binding.
#[test]
fn the_effective_policies_are_listed_under_each_mode() {
    let catalog = catalog(
        vec![unbound_guard()],
        vec![
            bind(GUARD, 1, Level::Inform, outside(&["explore"]), the_user()),
            bind(GUARD, 2, Level::Advise, outside(&["explore"]), the_user()),
            bind(GUARD, 3, Level::Force, inside("bugfix"), the_user()),
        ],
    );
    let under = |name: Option<&str>| listed(&catalog, Known::Known(name.map(mode)));
    assert_eq!(under(None), vec![(id(GUARD), Effect::On(Level::Advise))]);
    assert_eq!(
        under(Some("bugfix")),
        vec![(id(GUARD), Effect::On(Level::Force))]
    );
    assert_eq!(under(Some("explore")), vec![(id(GUARD), Effect::Off)]);
    // A mode that no binding names leaves the project's level.
    assert_eq!(
        under(Some("modeling")),
        vec![(id(GUARD), Effect::On(Level::Advise))]
    );
    // With the mode unknown the strongest binding applies.
    assert_eq!(
        listed(&catalog, Known::Unknown),
        vec![(id(GUARD), Effect::On(Level::Force))]
    );
}

/// L1, UC17: the effective list has every policy, the judgment of an event lists only the guards
/// the event reaches.
#[test]
fn a_judgment_lists_only_the_guards_the_event_reaches() {
    let catalog = catalog(vec![test_guard(Level::Force), bash_guard()], vec![]);
    let reached = |events: &[Event]| -> Vec<PolicyId> {
        outcome(&catalog, events)
            .guards
            .iter()
            .map(|g| g.policy)
            .collect()
    };
    assert_eq!(
        reached(&[agent(Body::TaskStart), agent(Body::Stop)]),
        vec![id(GUARD)]
    );
    assert_eq!(
        reached(&[agent(Body::TaskStart), bash("cargo build", Some(true))]),
        vec![id(OTHER)]
    );
    // Both are in effect, whichever event comes.
    assert_eq!(
        listed(&catalog, Known::Known(None)),
        vec![
            (id(GUARD), Effect::On(Level::Force)),
            (id(OTHER), Effect::On(Level::Advise)),
        ]
    );
}

/// L1, UC17, FR12: a guard that is off is told apart from one the event does not reach. The
/// effective list has the off guard as off, and the one not reached as in effect; the judgment
/// of an event lists neither.
#[test]
fn an_off_guard_is_listed_as_off_and_not_taken_for_one_the_event_does_not_reach() {
    let on = catalog(vec![test_guard(Level::Force)], vec![]);
    let off = catalog(vec![unbound_guard()], vec![]);
    let tool_call = [agent(Body::TaskStart), bash("cargo build", Some(true))];
    let stop = [agent(Body::TaskStart), agent(Body::Stop)];
    // Not reached: a Stop guard on a tool call. It is in effect.
    assert!(outcome(&on, &tool_call).guards.is_empty());
    assert_eq!(
        listed(&on, Known::Known(None)),
        vec![(id(GUARD), Effect::On(Level::Force))]
    );
    // Off: reached by the Stop, but not judged. It is listed as off.
    assert_eq!(outcome(&on, &stop).guards.len(), 1);
    assert!(outcome(&off, &stop).guards.is_empty());
    assert_eq!(
        listed(&off, Known::Known(None)),
        vec![(id(GUARD), Effect::Off)]
    );
}
