//! Scenario S5: a record that could not be read. A guard that has not seen what it needs cannot
//! tell; a stopping guard denies and an advising one warns. The adapter says which kinds of event
//! the record may have been, and only what an event of those kinds may have changed becomes
//! unknown.

use agent_caps_core::domain::adjust::Lifetime;
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::policy::{Level, Rule};
use agent_caps_core::domain::predicate::{By, Scope};
use agent_caps_core::domain::schema::{EventKind, KindSet};
use agent_caps_core::domain::state::Known;

use super::common::{
    GUARD, agent, bash, catalog, edit, exemption, id, lost_line, mode_switch, src_edit_guard,
    test_guard, tested_in, unreadable, verdict,
};

/// FR20, UC3: a lost line makes an unseen fact unknown and a stopping guard denies; a seen fact
/// stays seen.
#[test]
fn an_unreadable_record_makes_an_unseen_once_unknown_but_not_a_seen_one() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let start = agent(Body::TaskStart);
    let stop = agent(Body::Stop);
    let lost = lost_line();
    // The lost line may have been the test run: the guard cannot tell, and a stopping guard denies.
    assert_eq!(
        verdict(&catalog, &[start.clone(), lost.clone(), stop.clone()]),
        Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
    );
    // The run was seen; a later lost line cannot unsee it.
    assert_eq!(
        verdict(
            &catalog,
            &[
                start.clone(),
                bash("cargo test", Some(true)),
                lost.clone(),
                stop.clone()
            ]
        ),
        Verdict::Allow
    );
    // Seeing the run after the lost line settles it too.
    assert_eq!(
        verdict(
            &catalog,
            &[start, lost, bash("cargo test", Some(true)), stop]
        ),
        Verdict::Allow
    );
}

/// FR20, UC3: a record of which nothing is known may have been any kind (`KindSet::any`), so the
/// guard cannot tell and a stopping guard denies; a record the adapter knows was none of the kinds
/// the guard reads changes nothing for it.
#[test]
fn a_record_that_may_have_been_anything_makes_an_unseen_fact_unknown() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let any = agent(Body::Unreadable {
        may_have_been: KindSet::any(),
    });
    assert_eq!(
        verdict(&catalog, &[agent(Body::TaskStart), any, agent(Body::Stop)]),
        Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
    );
    let not_a_tool_use = unreadable(&[EventKind::PromptSubmit]);
    assert_eq!(
        verdict(
            &catalog,
            &[agent(Body::TaskStart), not_a_tool_use, agent(Body::Stop)]
        ),
        Verdict::Deny(vec![Cause::Violated(id(GUARD))])
    );
}

/// FR20, UC3: when a fact cannot be seen, an advising guard warns where a stopping one denies.
#[test]
fn an_advising_guard_warns_where_a_stopping_one_denies() {
    let catalog = catalog(vec![test_guard(Level::Advise)], vec![]);
    let events = [agent(Body::TaskStart), lost_line(), agent(Body::Stop)];
    assert_eq!(
        verdict(&catalog, &events),
        Verdict::Warn(vec![Cause::Unknown(id(GUARD))])
    );
}

/// FR20, UC3: a record that may have been a mode switch makes the mode unknown, and a `once`
/// within the mode's scope unknown too, a true one included, since the scope may have started
/// again. A record that cannot have been a tool use leaves what tool uses told as it was.
#[test]
fn a_record_that_may_have_been_a_mode_switch_makes_the_mode_and_its_scope_unknown() {
    let mut guard = test_guard(Level::Force);
    guard.rule = Rule::Structural(tested_in(Scope::Mode));
    let catalog = catalog(vec![guard], vec![]);
    let tested = [
        mode_switch("fix"),
        agent(Body::TaskStart),
        bash("cargo test", Some(true)),
    ];
    let lost = unreadable(&[EventKind::ModeSwitch]);
    let state = catalog.fold(tested.iter().chain([&lost]));
    assert_eq!(state.mode(), &Known::Unknown);
    let mut events = tested.to_vec();
    events.extend([lost, agent(Body::Stop)]);
    assert_eq!(
        verdict(&catalog, &events),
        Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
    );
    // Without the mode switch among what it may have been, the test stays seen.
    let mut events = tested.to_vec();
    events.extend([unreadable(&[EventKind::Adjust]), agent(Body::Stop)]);
    assert_eq!(verdict(&catalog, &events), Verdict::Allow);
}

/// FR20, FR34, UC3: a record that may have been a judgment may have used up an exemption for the
/// next judgment, so that one ends; an exemption that lasts within a scope is not used up by a
/// judgment and stays.
#[test]
fn a_record_that_may_have_been_a_judgment_ends_an_exemption_for_the_next_judgment() {
    let catalog = catalog(vec![src_edit_guard()], vec![]);
    let start = agent(Body::TaskStart);
    let lost = unreadable(&[EventKind::Judged]);
    assert!(matches!(
        verdict(
            &catalog,
            &[
                start.clone(),
                exemption(None, Lifetime::Next),
                lost.clone(),
                edit("src/a.rs")
            ]
        ),
        Verdict::Deny(_)
    ));
    assert_eq!(
        verdict(
            &catalog,
            &[
                start,
                exemption(None, Lifetime::Within(Scope::Task(By::Anyone))),
                lost,
                edit("src/a.rs")
            ]
        ),
        Verdict::Allow
    );
}
