//! Scenario S5b: a field of an event that could not be read. The event keeps its kind, its tool
//! and the fields that were read; only a condition that reads the field cannot tell. A guard that
//! reads the field stops (a stopping guard denies, an advising one warns); one that does not
//! judges the event as it is. This is the case apart from a record whose kind could not be read
//! (S5, `unreadable.rs`), which only the fold sees.

use agent_caps_core::domain::adjust::Lifetime;
use agent_caps_core::domain::catalog::{Cap, Capabilities, Catalog, Lowering};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, Outcome, Recognition, Verdict, judge};
use agent_caps_core::domain::name::GlobPattern;
use agent_caps_core::domain::policy::{Expect, Level, Polarity, Rule};
use agent_caps_core::domain::predicate::{By, Cond, EventFilter, Lit, Pred, Scope, Span};
use agent_caps_core::domain::schema::{EventKind, Field};
use agent_caps_core::domain::state::Origin;

use super::common::{
    GUARD, OTHER, REWARD, Written, agent, anyone, bash, bash_path_unreadable, catalog,
    clippy_reward, commit_after_test_guard, edit, edit_path_unreadable, exemption, fixture, id,
    judgeable, outcome, src_edit_guard, test_guard, verdict, words,
};

fn start() -> Event {
    agent(Body::TaskStart)
}

fn under_src() -> Cond {
    Cond::Glob(Field::Path, GlobPattern::new("src/*").unwrap())
}

/// FR71, FR20: a guard whose condition reads the path cannot tell when the path could not be read,
/// and a stopping guard denies with the reason unknown, whether or not the tests ran; the same
/// edit with its path read is judged as it always was. An advising guard warns.
#[test]
fn a_guard_over_the_path_cannot_tell_when_the_path_could_not_be_read() {
    let stopping = catalog(vec![src_edit_guard()], vec![]);
    let unknown = Verdict::Deny(vec![Cause::Unknown(id(GUARD))]);
    assert_eq!(
        verdict(&stopping, &[start(), edit_path_unreadable()]),
        unknown
    );
    assert_eq!(
        verdict(
            &stopping,
            &[
                start(),
                bash("cargo test", Some(true)),
                edit_path_unreadable()
            ]
        ),
        unknown
    );
    // With the path read, the same events are judged by the rule.
    assert_eq!(
        verdict(&stopping, &[start(), edit("src/a.rs")]),
        Verdict::Deny(vec![Cause::Violated(id(GUARD))])
    );
    assert_eq!(
        verdict(
            &stopping,
            &[start(), bash("cargo test", Some(true)), edit("src/a.rs")]
        ),
        Verdict::Allow
    );

    let mut advising = src_edit_guard();
    advising.level = Some(Level::Advise);
    let advising = catalog(vec![advising], vec![]);
    assert_eq!(
        verdict(&advising, &[start(), edit_path_unreadable()]),
        Verdict::Warn(vec![Cause::Unknown(id(GUARD))])
    );
}

/// FR71: a guard that does not read the path judges a tool use whose path could not be read by
/// what was read of it: the command of a commit is known, so the guard on a commit stops it before
/// any test and lets it through after one, and a command that is no commit is not its concern.
#[test]
fn a_guard_that_does_not_read_the_path_judges_the_tool_use_as_it_is() {
    let catalog = catalog(vec![commit_after_test_guard()], vec![]);
    let commit = bash_path_unreadable("git commit -m x", None);
    assert_eq!(
        verdict(&catalog, &[start(), commit.clone()]),
        Verdict::Deny(vec![Cause::Violated(id(GUARD))])
    );
    assert_eq!(
        verdict(
            &catalog,
            &[start(), bash("cargo test", Some(true)), commit.clone()]
        ),
        Verdict::Allow
    );
    assert_eq!(
        verdict(&catalog, &[start(), bash_path_unreadable("ls", None)]),
        Verdict::Allow
    );
}

/// FR71: the kind of the tool use is kept, so a guard over the end of a turn does not judge it:
/// the unreadable path is not mistaken for a record of any kind.
#[test]
fn a_guard_over_the_end_of_a_turn_does_not_judge_a_tool_use_whose_path_could_not_be_read() {
    let catalog = catalog(vec![test_guard(Level::Force)], vec![]);
    let out = outcome(&catalog, &[start(), edit_path_unreadable()]);
    assert_eq!(out.verdict, Verdict::Allow);
    assert!(out.guards.is_empty());
}

fn judged_on(catalog: &Catalog, events: &[Event], caps: &Capabilities) -> Outcome {
    let state = catalog.fold(Origin::Genesis, events);
    judge(catalog, &state, &judgeable(events.last().unwrap()), caps).unwrap()
}

/// FR71, FR40: on a platform that stops a tool use only by a condition on its path, a tool use
/// whose path could not be read may or may not be one it stops, so it is held at the lower level:
/// a Force guard warns, with the reason unknown, and the judgment reports it as lowered. The
/// same platform stops the edit whose path was read.
#[test]
fn a_platform_that_stops_by_the_path_holds_a_path_that_could_not_be_read_at_the_lower_level() {
    let catalog = catalog(vec![src_edit_guard()], vec![]);
    let caps = Capabilities::new(
        vec![(
            EventFilter {
                kind: EventKind::ToolUse,
                cond: Some(under_src()),
            },
            Level::Force,
        )],
        Level::Advise,
    )
    .unwrap();

    let out = judged_on(&catalog, &[start(), edit_path_unreadable()], &caps);
    assert_eq!(out.verdict, Verdict::Warn(vec![Cause::Unknown(id(GUARD))]));
    assert_eq!(out.guards[0].written, Level::Force);
    assert_eq!(out.guards[0].enforced, Level::Advise);
    assert_eq!(
        out.lowered,
        vec![Lowering::BeyondCapability {
            policy: id(GUARD),
            written: Level::Force,
            enforced: Cap::Fixed(Level::Advise),
        }]
    );

    let held = judged_on(&catalog, &[start(), edit("src/a.rs")], &caps);
    assert_eq!(
        held.verdict,
        Verdict::Deny(vec![Cause::Violated(id(GUARD))])
    );
    assert!(held.lowered.is_empty());
}

/// A reward on an edit, bound to the guard on an edit, that is met when the condition holds.
fn edit_reward(policy: &str, cond: Cond) -> Written {
    let mut reward = clippy_reward(Level::Advise);
    reward.id = id(policy);
    reward.name = format!("reward-{}", &policy[30..]).parse().unwrap();
    reward.subject = EventKind::ToolUse;
    reward.rule = Rule::Structural(Pred::Now(cond));
    reward.polarity = Polarity::Reward {
        bound_by: id(GUARD),
    };
    reward
}

/// FR71, FR13: a reward that reads the path is not met by a tool use whose path could not be
/// read, as it cannot tell; one that does not read it is met by the tool use that was read.
#[test]
fn a_reward_over_the_path_is_not_met_when_the_path_could_not_be_read() {
    let catalog = catalog(
        vec![
            src_edit_guard(),
            edit_reward(REWARD, under_src()),
            edit_reward(OTHER, Cond::Eq(Field::Tool, Lit::Text("Edit".to_owned()))),
        ],
        vec![],
    );
    let recognition = |out: &Outcome, reward: &str| {
        out.rewards
            .iter()
            .find(|r| r.policy == id(reward))
            .map(|r| r.recognition)
    };
    let unreadable = outcome(&catalog, &[start(), edit_path_unreadable()]);
    assert_eq!(recognition(&unreadable, REWARD), Some(Recognition::None));
    assert_eq!(recognition(&unreadable, OTHER), Some(Recognition::Hit));
    let read = outcome(&catalog, &[start(), edit("src/a.rs")]);
    assert_eq!(recognition(&read, REWARD), Some(Recognition::Hit));
    assert_eq!(recognition(&read, OTHER), Some(Recognition::Hit));
}

/// FR71, FR34: an exemption with a cover that does not read the path covers a tool use whose path
/// could not be read, and one with a cover that reads the path does not, as the cover cannot
/// tell: the guard judges the event. An exemption with no cover does not cover a guard that reads
/// the path either, as the guard's own condition cannot tell before the exemption is reached.
#[test]
fn an_exemption_covers_by_what_was_read_of_the_tool_use() {
    let commit_guard = catalog(vec![commit_after_test_guard()], vec![]);
    let commit = bash_path_unreadable("git commit -m x", None);
    let exempt = |cover| exemption(cover, Lifetime::Next);
    let by_command = Some(Cond::Words(Field::Command, words("git commit")));
    assert_eq!(
        verdict(
            &commit_guard,
            &[start(), exempt(by_command), commit.clone()]
        ),
        Verdict::Allow
    );
    assert_eq!(
        verdict(
            &commit_guard,
            &[start(), exempt(Some(under_src())), commit.clone()]
        ),
        Verdict::Deny(vec![Cause::Violated(id(GUARD))])
    );
    assert_eq!(
        verdict(&commit_guard, &[start(), exempt(None), commit]),
        Verdict::Allow
    );

    let src_guard = catalog(vec![src_edit_guard()], vec![]);
    assert_eq!(
        verdict(&src_guard, &[start(), exempt(None), edit_path_unreadable()]),
        Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
    );
}

/// FR71, FR20: in the history, a tool use whose path could not be read is counted by a selector that
/// does not read the path, and is unknown to one that does: the test run it was counts for the
/// guard on the end of a turn, and the stop guard whose rule asks for an edit under `src/` cannot
/// tell whether it was one.
#[test]
fn a_selector_over_the_history_counts_a_tool_use_by_what_was_read_of_it() {
    let tested = catalog(vec![test_guard(Level::Force)], vec![]);
    let ran_tests = bash_path_unreadable("cargo test", Some(true));
    assert_eq!(
        verdict(&tested, &[start(), ran_tests, agent(Body::Stop)]),
        Verdict::Allow
    );

    let mut after_a_src_edit = test_guard(Level::Force);
    after_a_src_edit.rule = Rule::Structural(Pred::Once {
        select: anyone(EventFilter {
            kind: EventKind::ToolUse,
            cond: Some(under_src()),
        }),
        scope: Scope::Span {
            span: Span::Task,
            by: By::Anyone,
        },
    });
    after_a_src_edit.fixtures = vec![
        fixture(
            "no edit",
            vec![start(), agent(Body::Stop)],
            Expect::Violated,
        ),
        fixture(
            "an edit under src",
            vec![start(), edit("src/a.rs"), agent(Body::Stop)],
            Expect::Satisfied,
        ),
    ];
    let catalog = catalog(vec![after_a_src_edit], vec![]);
    assert_eq!(
        verdict(
            &catalog,
            &[start(), edit_path_unreadable(), agent(Body::Stop)]
        ),
        Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
    );
    assert_eq!(
        verdict(&catalog, &[start(), edit("src/a.rs"), agent(Body::Stop)]),
        Verdict::Allow
    );
}
