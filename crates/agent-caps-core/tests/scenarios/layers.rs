//! Scenarios S4, L1, L2 and L3: the layers Base, Project and Mode, and what operating on them does.
//!
//! - S4: a mode's override changes the level, a switch that lowers a guard takes effect only from
//!   one who covers the guard's author, and the verdict does not depend on the order of the
//!   policies. The `mode_switch` module checks the switch as a claim further.
//! - L2: the order is Base, then Project, then Mode; a policy the project turns off can be turned
//!   on again by a mode; the order of the overrides in the graph does not matter.
//! - L3: a meta policy takes no override. `Catalog::accept` rejects one in any layer, so its level
//!   is the same in every mode by construction; the test checks the rejection.
//! - L1: the policies in effect under a mode, with their levels, are listed by
//!   `Catalog::effective`, without judging any event. That was a gap (#6) and is fixed: a policy
//!   that is off is listed as off, and one the judged event does not reach is still listed. A
//!   judgment lists only the guards the event reaches.
//!
//! The levels are written as literals ("Force under bugfix"), read from `Catalog::effective` or
//! from the outcome of `judge`; no test here computes how the layers stack.

use agent_caps_core::domain::catalog::{AcceptError, Effect};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Outcome, Verdict, judge};
use agent_caps_core::domain::name::PolicyId;
use agent_caps_core::domain::policy::{
    Change, DefLayer, Level, Override, Polarity, PolicyDef, Rule,
};
use agent_caps_core::domain::predicate::{Cond, Lit, Pred};
use agent_caps_core::domain::schema::{EventKind, Field};
use agent_caps_core::domain::state::Known;

use super::common::{
    GUARD, OTHER, agent, at, bash, catalog, id, in_mode, listed, mode, mode_switch, outcome,
    project, rejected, test_guard, the_agent, the_user, unreadable, verdict, violated,
};

/// The level the guard had on the last event.
fn level_of(outcome: &Outcome, policy: &str) -> Level {
    outcome
        .guards
        .iter()
        .find(|g| g.policy == id(policy))
        .unwrap_or_else(|| panic!("{policy} did not judge the event"))
        .level
}

/// An advising guard of a tool call: a shell call must have succeeded.
fn bash_guard() -> PolicyDef {
    PolicyDef {
        id: id(OTHER),
        name: "bash-ok".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: None,
        rule: Rule::Structural(Pred::Now(Cond::Eq(Field::Ok, Lit::Bool(true)))),
        polarity: Polarity::Guard {
            level: Level::Advise,
        },
        enabled: true,
        fixtures: vec![],
        author: the_user(),
    }
}

/// UC8, FR11: a mode changes the level of a policy. UC25: a switch that lowers the root's guard
/// is nothing from the principal below it; the root makes it. FR20: a lost record that may have
/// been a switch puts the strictest mode in force.
#[test]
fn a_mode_overrides_the_level_and_a_lowering_switch_needs_the_guards_author() {
    let catalog = catalog(
        vec![test_guard(Level::Force)],
        vec![in_mode("modeling", GUARD, Change::Level(Level::Inform))],
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
    // A lost record may have been a switch: the strictest mode applies.
    let state = catalog.fold(&[switch(the_user()), unreadable(&[EventKind::ModeSwitch])]);
    assert_eq!(state.mode(), &Known::Unknown);
    assert!(matches!(
        judge(&catalog, &state, &stop).verdict,
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

/// L2, UC7, UC8: Base Inform, the project says Advise, the bugfix mode says Force. The guard has
/// its fixtures, so a layer may raise it to a stopping level.
#[test]
fn a_mode_overrides_the_project_which_overrides_the_base() {
    let catalog = catalog(
        vec![test_guard(Level::Inform)],
        vec![
            project(GUARD, Change::Level(Level::Advise)),
            in_mode("bugfix", GUARD, Change::Level(Level::Force)),
        ],
    );
    let stop = [agent(Body::TaskStart), agent(Body::Stop)];
    // No mode: the project's Advise over the base's Inform.
    assert_eq!(level_of(&outcome(&catalog, &stop), GUARD), Level::Advise);
    // The bugfix mode: Force over the project's Advise.
    let bugfix = [mode_switch("bugfix"), stop[0].clone(), stop[1].clone()];
    assert_eq!(level_of(&outcome(&catalog, &bugfix), GUARD), Level::Force);
    // A mode that overrides nothing leaves the project's level.
    let other = [mode_switch("modeling"), stop[0].clone(), stop[1].clone()];
    assert_eq!(level_of(&outcome(&catalog, &other), GUARD), Level::Advise);
}

/// L2, UC7, UC8: the project turns the guard off; the bugfix mode turns it on again, at its base
/// level.
#[test]
fn a_mode_turns_on_what_the_project_turned_off() {
    let catalog = catalog(
        vec![test_guard(Level::Force)],
        vec![
            project(GUARD, Change::Off),
            in_mode("bugfix", GUARD, Change::On),
        ],
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

/// L2, UC7, UC8: the layers are applied by what they are, not by where their overrides stand in
/// the graph.
#[test]
fn the_order_of_the_overrides_in_the_graph_does_not_matter() {
    let project_first = vec![
        project(GUARD, Change::Level(Level::Advise)),
        in_mode("bugfix", GUARD, Change::Level(Level::Force)),
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

/// L3, FR14, UC10: no layer overrides a meta policy: not the project's, not a mode's.
#[test]
fn no_layer_overrides_a_meta_policy() {
    let mut meta = test_guard(Level::Force);
    meta.layer = DefLayer::Meta;
    let overrides: [Override; 3] = [
        project(GUARD, Change::Level(Level::Inform)),
        in_mode("bugfix", GUARD, Change::Level(Level::Inform)),
        in_mode("bugfix", GUARD, Change::Off),
    ];
    for one in overrides {
        assert_eq!(
            rejected(vec![meta.clone()], vec![one.clone()]),
            vec![AcceptError::MetaOverride(id(GUARD))],
            "{one:?}"
        );
    }
}

/// L1, UC17, FR12: the policies in effect under each mode are listed with their effect, without
/// judging any event: Base Inform, the project Advise, bugfix Force, explore Off. Not knowing
/// the mode takes the strictest of them.
#[test]
fn the_effective_policies_are_listed_under_each_mode() {
    let catalog = catalog(
        vec![test_guard(Level::Inform)],
        vec![
            project(GUARD, Change::Level(Level::Advise)),
            in_mode("bugfix", GUARD, Change::Level(Level::Force)),
            in_mode("explore", GUARD, Change::Off),
        ],
    );
    let under = |name: Option<&str>| listed(&catalog, Known::Known(name.map(mode)));
    assert_eq!(under(None), vec![(id(GUARD), Effect::On(Level::Advise))]);
    assert_eq!(
        under(Some("bugfix")),
        vec![(id(GUARD), Effect::On(Level::Force))]
    );
    assert_eq!(under(Some("explore")), vec![(id(GUARD), Effect::Off)]);
    // A mode that overrides nothing leaves the project's level.
    assert_eq!(
        under(Some("modeling")),
        vec![(id(GUARD), Effect::On(Level::Advise))]
    );
    // With the mode unknown the strictest of the modes applies.
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
    let off = catalog(
        vec![test_guard(Level::Force)],
        vec![project(GUARD, Change::Off)],
    );
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
