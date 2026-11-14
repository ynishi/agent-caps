//! Scenario S5c: a guard whose condition (`when`) cannot be told. The guard is judged as if it
//! applied: what it would stop counts as failing, and what it would let through, by its rule or by
//! an exemption, is let through, as it is whether or not the guard applies. Such a pass is
//! recorded as a judgment whose result cannot be read (`Judgment::Uncertain`), so a rule that
//! reads the judgment of the guard cannot tell (FR20); an exemption that lets the event through
//! is also used up. A reward whose condition cannot be told recognizes nothing, and a fixture
//! whose last event leaves the condition unknown expects `Uncertain` when the policy passes
//! either way.
//!
//! The guard of these scenarios stops an edit under `src/` before the tests pass, so its `when`
//! reads the path, and a tool use whose path could not be read is one it cannot tell for. The
//! second kind of guard reads the result of a tool use (`ok`), which an act judged ahead has not
//! got yet.

use agent_caps_core::domain::adjust::Lifetime;
use agent_caps_core::domain::catalog::{AcceptError, Catalog};
use agent_caps_core::domain::event::{Body, Event};
use agent_caps_core::domain::judge::{Cause, GuardResult, Outcome, Recognition, Verdict};
use agent_caps_core::domain::name::GlobPattern;
use agent_caps_core::domain::policy::{Expect, Finding, Level, Pass, Rule};
use agent_caps_core::domain::predicate::{Cond, Lit, Pred};
use agent_caps_core::domain::schema::{At, EventKind, Field, Judgment};

use super::common::{
    GUARD, OTHER, REWARD, Written, agent, bash, catalog, clippy_reward, edit, edit_path_unreadable,
    exemption, fixture, id, outcome, push_after_allowed, rejected, src_edit_guard, step, verdict,
};

fn start() -> Event {
    agent(Body::TaskStart)
}

fn under_src() -> Cond {
    Cond::Glob(Field::Path, GlobPattern::new("src/*").unwrap())
}

/// The guard that stops an edit under `src/` before the tests pass, but whose condition reads the
/// result of the tool use instead of the path: an edit judged ahead has no result yet.
fn after_a_result_guard() -> Written {
    let mut guard = src_edit_guard();
    guard.when = Some(Pred::Now(Cond::Eq(Field::Ok, Lit::Bool(true))));
    guard.fixtures = vec![
        fixture(
            "untested, with a result",
            vec![start(), bash("ls", Some(true))],
            Expect::Violated,
        ),
        fixture(
            "tested, with a result",
            vec![
                start(),
                bash("cargo test", Some(true)),
                bash("ls", Some(true)),
            ],
            Expect::Satisfied,
        ),
    ];
    guard
}

/// The one guard that judged the event.
fn the_guard(out: &Outcome) -> &GuardResult {
    let [only] = out.guards.as_slice() else {
        panic!("one guard was expected: {out:?}")
    };
    assert_eq!(only.policy, id(GUARD));
    only
}

/// How many records of the guard with the judgment the evidence of the judgment holds.
fn records(out: &Outcome, judgment: Judgment) -> usize {
    out.evidence(At::from_millis(0))
        .iter()
        .filter(|e| {
            matches!(
                &e.body,
                Body::Judged { policy, judgment: j, .. }
                    if *policy == id(GUARD) && *j == judgment
            )
        })
        .count()
}

/// FR72, FR20: an exemption with no cover lets through a tool use that a guard cannot tell it
/// applies to: the guard is judged as if it applied and is exempted. The judgment of the guard is
/// `Uncertain(Exempted)`, it has no cause, and its record uses the exemption up, so the next such
/// tool use is stopped as unknown.
#[test]
fn an_exemption_with_no_cover_lets_through_a_guard_that_cannot_tell_if_it_applies_and_is_used_up() {
    let catalog = catalog(vec![src_edit_guard()], vec![]);
    let mut log = vec![start(), exemption(None, Lifetime::Next)];

    let first = step(&catalog, &mut log, edit_path_unreadable());
    assert_eq!(first.verdict, Verdict::Allow);
    let guard = the_guard(&first);
    assert_eq!(guard.finding, Finding::Uncertain(Pass::Exempted));
    assert_eq!(guard.judgment(), Judgment::Uncertain(Pass::Exempted));
    assert_eq!(
        records(&first, Judgment::Uncertain(Pass::Exempted)),
        1,
        "{first:?}"
    );

    let second = step(&catalog, &mut log, edit_path_unreadable());
    assert_eq!(
        second.verdict,
        Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
    );
    assert_eq!(the_guard(&second).finding, Finding::Unknown);
}

/// FR72, FR20: a guard that cannot tell whether it applies, and whose rule holds without reading
/// what was not read, lets the tool use through at every level it may be written at. The guard
/// is in the outcome as `Uncertain(Satisfied)`, it has no cause, and one record of that
/// judgment is written.
#[test]
fn a_guard_whose_rule_holds_lets_through_what_it_cannot_tell_it_applies_to_and_records_it_uncertain()
 {
    let ran_tests = [start(), bash("cargo test", Some(true))];
    let mut log = ran_tests.to_vec();
    log.push(edit_path_unreadable());

    for level in [Level::Force, Level::Advise] {
        let mut guard = src_edit_guard();
        guard.level = Some(level);
        let catalog = catalog(vec![guard], vec![]);
        let out = outcome(&catalog, &log);
        assert_eq!(out.verdict, Verdict::Allow);
        let found = the_guard(&out);
        assert_eq!(found.finding, Finding::Uncertain(Pass::Satisfied));
        assert_eq!(found.judgment(), Judgment::Uncertain(Pass::Satisfied));
        assert_eq!(
            records(&out, Judgment::Uncertain(Pass::Satisfied)),
            1,
            "{out:?}"
        );
    }
}

/// FR72, FR20: the same guard, whose rule does not hold, would stop the tool use if it applied,
/// so it stops it as unknown.
#[test]
fn a_guard_whose_rule_does_not_hold_stops_what_it_cannot_tell_it_applies_to() {
    let catalog = catalog(vec![src_edit_guard()], vec![]);
    let out = outcome(&catalog, &[start(), edit_path_unreadable()]);
    assert_eq!(out.verdict, Verdict::Deny(vec![Cause::Unknown(id(GUARD))]));
    assert_eq!(the_guard(&out).finding, Finding::Unknown);
    assert_eq!(records(&out, Judgment::Denied), 1, "{out:?}");
}

/// FR72, FR20: an exemption whose cover reads the path does not cover a tool use whose path could
/// not be read, as the cover cannot tell, so the guard is judged by its rule: it stops as unknown
/// when the rule does not hold.
#[test]
fn an_exemption_whose_cover_reads_the_path_does_not_cover_a_path_that_could_not_be_read() {
    let catalog = catalog(vec![src_edit_guard()], vec![]);
    let events = [
        start(),
        exemption(Some(under_src()), Lifetime::Next),
        edit_path_unreadable(),
    ];
    assert_eq!(
        verdict(&catalog, &events),
        Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
    );
}

/// FR72, FR20: a guard whose condition reads the result of the tool use cannot tell on an act
/// judged ahead, which has none yet, and is judged as the guard of the path is: an exemption with
/// no cover lets it through and is used up, a rule that holds lets it through and is recorded as
/// uncertain, and a rule that does not hold stops it as unknown.
#[test]
fn a_guard_over_the_result_of_a_tool_use_is_judged_ahead_as_if_it_applied() {
    let catalog = catalog(vec![after_a_result_guard()], vec![]);

    let mut log = vec![start(), exemption(None, Lifetime::Next)];
    let exempted = step(&catalog, &mut log, edit("src/a.rs"));
    assert_eq!(exempted.verdict, Verdict::Allow);
    assert_eq!(
        the_guard(&exempted).finding,
        Finding::Uncertain(Pass::Exempted)
    );
    assert_eq!(
        records(&exempted, Judgment::Uncertain(Pass::Exempted)),
        1,
        "{exempted:?}"
    );
    assert_eq!(
        step(&catalog, &mut log, edit("src/a.rs")).verdict,
        Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
    );

    let tested = outcome(
        &catalog,
        &[start(), bash("cargo test", Some(true)), edit("src/a.rs")],
    );
    assert_eq!(tested.verdict, Verdict::Allow);
    assert_eq!(
        the_guard(&tested).finding,
        Finding::Uncertain(Pass::Satisfied)
    );
    assert_eq!(
        records(&tested, Judgment::Uncertain(Pass::Satisfied)),
        1,
        "{tested:?}"
    );

    assert_eq!(
        verdict(&catalog, &[start(), edit("src/a.rs")]),
        Verdict::Deny(vec![Cause::Unknown(id(GUARD))])
    );
}

/// A reward on an edit, bound to the guard on an edit, that is met by an edit and applies to an
/// edit under `src/`.
fn src_reward() -> Written {
    let mut reward = clippy_reward(Level::Advise);
    reward.subject = EventKind::ToolUse;
    reward.when = Some(Pred::Now(under_src()));
    reward.rule = Rule::Structural(Pred::Now(Cond::Eq(
        Field::Tool,
        Lit::Text("Edit".to_owned()),
    )));
    reward
}

/// FR72: a reward whose condition cannot be told recognizes nothing, and writes no record of a
/// hit, though its rule is met; with the path read, the same reward is a hit.
#[test]
fn a_reward_whose_condition_cannot_be_told_recognizes_nothing() {
    let catalog = catalog(vec![src_edit_guard(), src_reward()], vec![]);
    let recognition = |out: &Outcome| {
        out.rewards
            .iter()
            .find(|r| r.policy == id(REWARD))
            .map(|r| r.recognition)
    };
    let unreadable = outcome(&catalog, &[start(), edit_path_unreadable()]);
    assert_eq!(recognition(&unreadable), Some(Recognition::None));
    assert!(
        !unreadable
            .evidence(At::from_millis(0))
            .iter()
            .any(|e| matches!(
                &e.body,
                Body::Judged {
                    judgment: Judgment::Hit,
                    ..
                }
            ))
    );

    let read = outcome(&catalog, &[start(), edit("src/a.rs")]);
    assert_eq!(recognition(&read), Some(Recognition::Hit));
}

/// A guard on a `git push` whose rule reads the last judgment of `GUARD`: with `stops_on_denied`
/// it holds unless that judgment was `denied`, and otherwise it holds only if it was `allowed`.
fn reading_the_last_judgment(stops_on_denied: bool) -> Written {
    let mut reader = push_after_allowed(GUARD);
    if stops_on_denied {
        let Rule::Structural(Pred::Last { select, scope, .. }) = &reader.rule else {
            panic!("a rule that reads the last judgment was expected")
        };
        reader.rule = Rule::Structural(Pred::Not(Box::new(Pred::Last {
            select: select.clone(),
            scope: scope.clone(),
            test: Cond::Eq(Field::Judgment, Lit::Text("denied".to_owned())),
        })));
    }
    reader
}

/// What the guard that reads the judgments of `GUARD` finds on a `git push`.
fn read_finding(catalog: &Catalog, log: &mut Vec<Event>) -> Finding {
    let out = step(catalog, log, bash("git push", None));
    out.guards
        .iter()
        .find(|g| g.policy == id(OTHER))
        .unwrap_or_else(|| panic!("the reader was not judged: {out:?}"))
        .finding
}

/// FR72, FR20: a rule that reads the last judgment of a guard cannot tell it after the guard
/// recorded that it could not tell whether it applied: the record is one of `Uncertain`, whose
/// result is unknown, so the rule is neither held by what the guard recorded before nor loosened
/// by it. "Stop unless the last was denied" was violated by a `denied` and is unknown after;
/// "pass if the last was allowed" held by an `allowed` and is unknown after.
#[test]
fn a_rule_that_reads_the_last_judgment_of_a_guard_cannot_tell_after_an_uncertain_record() {
    // The judgment that is read first: the guard denied an edit before the tests, or allowed it
    // after.
    for (stops_on_denied, before, tests_first) in [
        (true, Finding::Violated, false),
        (false, Finding::Satisfied, true),
    ] {
        let catalog = catalog(
            vec![src_edit_guard(), reading_the_last_judgment(stops_on_denied)],
            vec![],
        );
        let mut log = vec![start()];
        if tests_first {
            log.push(bash("cargo test", Some(true)));
        }
        step(&catalog, &mut log, edit("src/a.rs"));
        assert_eq!(
            read_finding(&catalog, &mut log),
            before,
            "stops_on_denied: {stops_on_denied}"
        );

        // The guard now cannot tell whether it applies; it passes, tests having run.
        if !tests_first {
            log.push(bash("cargo test", Some(true)));
        }
        let passed = step(&catalog, &mut log, edit_path_unreadable());
        assert_eq!(
            the_guard(&passed).finding,
            Finding::Uncertain(Pass::Satisfied)
        );
        assert_eq!(
            read_finding(&catalog, &mut log),
            Finding::Unknown,
            "stops_on_denied: {stops_on_denied}"
        );
    }
}

/// FR72: a fixture that ends with an event the policy cannot tell it applies to, and that it
/// passes either way, expects `Uncertain`; one that expects `Unknown` is refused as failing, with
/// what the policy found. The same holds for a reward, whose fixture ends the same way.
#[test]
fn a_fixture_that_ends_where_the_condition_cannot_be_told_and_the_policy_passes_expects_uncertain()
{
    let ending = |expect| {
        fixture(
            "tests ran, then an edit of a path that could not be read",
            vec![
                start(),
                bash("cargo test", Some(true)),
                edit_path_unreadable(),
            ],
            expect,
        )
    };
    let with = |expect| {
        let mut guard = src_edit_guard();
        guard.fixtures.push(ending(expect));
        guard
    };
    // Accepted: `catalog` refuses a rejected catalog by panicking.
    catalog(vec![with(Expect::Uncertain)], vec![]);

    assert_eq!(
        rejected(vec![with(Expect::Unknown)], vec![]),
        vec![AcceptError::FixtureFailed {
            policy: id(GUARD),
            fixture: "tests ran, then an edit of a path that could not be read".to_owned(),
            expected: Expect::Unknown,
            found: Expect::Uncertain,
        }]
    );

    let reward_ending = |expect| {
        let mut reward = src_reward();
        reward.fixtures = vec![fixture(
            "an edit of a path that could not be read",
            vec![start(), edit_path_unreadable()],
            expect,
        )];
        vec![src_edit_guard(), reward]
    };
    catalog(reward_ending(Expect::Uncertain), vec![]);
    assert_eq!(
        rejected(reward_ending(Expect::Satisfied), vec![]),
        vec![AcceptError::FixtureFailed {
            policy: id(REWARD),
            fixture: "an edit of a path that could not be read".to_owned(),
            expected: Expect::Satisfied,
            found: Expect::Uncertain,
        }]
    );
}
