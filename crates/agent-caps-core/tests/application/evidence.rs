//! Scenarios of the evidence: what an observation judges and writes, by its watch; what the
//! rules fold of it; a racing writer taken in; tries that run out or go on; a store that reports
//! no progress; and what is not taken from the platform.

use agent_caps_core::application::{
    ActEntry, ActSource, Broken, ClaimEntry, ClaimSource, GenerationMark, Len, NotRun, Observed,
    ObservedError, Record, RecordError, RequestEntry, Response, ServiceError, SetEdit, Verb,
    VerbName, Via, Watch, Why, WorkRecord,
};
use agent_caps_core::domain::event::{Body, Seen};
use agent_caps_core::domain::judge::{Cause, Verdict};
use agent_caps_core::domain::name::ClassifierName;
use agent_caps_core::domain::policy::Level;
use agent_caps_core::domain::schema::{At, EventKind, Judgment, KindSet};
use agent_caps_core::domain::tx::TxDecision;

use super::common::{
    AGENT_SET, GATE, MemoryLog, SRC_GUARD, STOP_GUARD, after, agent, agent_set, bash, block_on,
    build, caps, edit, event, id, initialized, instruction, loaded, observe, observed, policy, run,
    service, start_task, stop, task_start, user, work, work_records, work_stream,
};

/// The records of the worktree's stream after the request that started the lineage (the first
/// record of every stream here), by id and kind.
fn kinds(log: &MemoryLog) -> Vec<(String, &'static str)> {
    work_records(log)
        .into_iter()
        .skip(1)
        .map(|(id, record)| {
            let kind = match record {
                WorkRecord::Act(_) => "act",
                WorkRecord::Claim(claim) => match (claim.source(), claim.decision()) {
                    (ClaimSource::Judge, TxDecision::Commit) => "judged",
                    (ClaimSource::Judge, TxDecision::Abort) => "judged, aborted",
                    (ClaimSource::Platform, _) => "claim",
                },
                WorkRecord::Lost(_) => "lost",
                WorkRecord::Request(_) => "request",
            };
            (id.to_string(), kind)
        })
        .collect()
}

fn denied(policy_id: &str) -> Response {
    Response::Block(Why::Verdict(Verdict::Deny(vec![Cause::Violated(policy(
        policy_id,
    ))])))
}

fn unknown(policy_id: &str) -> Response {
    Response::Block(Why::Verdict(Verdict::Deny(vec![Cause::Unknown(policy(
        policy_id,
    ))])))
}

/// A request that the rules do not fold: what a racing writer appends in these scenarios when
/// only its being there matters.
fn noise() -> Record {
    Record::Work(WorkRecord::Request(RequestEntry::new(
        VerbName::Task,
        agent(),
        At::from_millis(0),
        Via::ToolCall,
    )))
}

/// FR63: an act judged ahead is stopped by a guard's deny; the judgment is written as the judge's
/// claim that took effect, and the act is not written, as it has not happened.
#[test]
fn before_writes_the_judgment_and_not_the_act() {
    let log = initialized();
    start_task(&log, "t");
    assert_eq!(
        observe(&log, "pre", edit("src/a.rs"), Watch::Before),
        Ok(denied(SRC_GUARD))
    );
    assert_eq!(
        kinds(&log),
        [
            ("t".to_owned(), "request"),
            ("t#1".to_owned(), "act"),
            ("pre#1".to_owned(), "judged")
        ]
    );
}

/// FR63: the end of a turn that passes is written with its judgments; one that is stopped writes
/// only its judgments.
#[test]
fn a_gate_writes_the_act_unless_it_stops_it() {
    let log = initialized();
    start_task(&log, "t");
    assert_eq!(observe(&log, "s1", stop(), GATE), Ok(denied(STOP_GUARD)));
    after(&log, "test", bash("cargo test", Some(true)));
    assert_eq!(observe(&log, "s2", stop(), GATE), Ok(Response::Pass));
    assert_eq!(
        kinds(&log),
        [
            ("t".to_owned(), "request"),
            ("t#1".to_owned(), "act"),
            ("s1#1".to_owned(), "judged"),
            ("test".to_owned(), "act"),
            ("s2".to_owned(), "act"),
            ("s2#1".to_owned(), "judged"),
        ]
    );
}

/// FR63: a claim that did not take effect is kept as such and not folded, nor is a request: the
/// answer is the one of the same history without them.
#[test]
fn an_aborted_claim_and_a_request_are_not_folded() {
    let with = initialized();
    let without = initialized();
    for log in [&with, &without] {
        start_task(log, "t");
    }
    let under = GenerationMark::of(loaded(&with).catalog().generation());
    // A record of the guard's judgment in the agent's name, which is never admitted.
    let theirs = event(
        agent(),
        Body::Judged {
            policy: policy(STOP_GUARD),
            judgment: Judgment::Allowed,
            written: Level::Force,
            enforced: Level::Force,
        },
    );
    let aborted = ClaimEntry::judged(under, theirs, TxDecision::Abort).unwrap();
    with.put(
        work_stream(),
        id("x").child(std::num::NonZeroU16::MIN),
        Record::Work(WorkRecord::Claim(aborted)),
    );
    with.put(work_stream(), id("r").entry(), noise());
    // After the request that started the lineage, and the request and start of the task.
    for (_, record) in &work_records(&with)[3..] {
        assert_eq!(record.folded(), None);
    }
    assert_eq!(
        observe(&with, "s", stop(), GATE),
        observe(&without, "s", stop(), GATE)
    );
}

/// FR63: a writer that got in first is taken in: the end of a turn that would have been stopped
/// is judged again after the test run another process wrote, and passes.
#[test]
fn a_racing_writer_is_taken_in_and_judged_again() {
    let log = initialized();
    start_task(&log, "t");
    let under = GenerationMark::of(loaded(&log).catalog().generation());
    let test_run = ActEntry::observed(under, bash("cargo test", Some(true))).unwrap();
    log.race(
        work_stream(),
        vec![(id("test").entry(), Record::Work(WorkRecord::Act(test_run)))],
    );
    assert_eq!(observe(&log, "s", stop(), GATE), Ok(Response::Pass));
    let ids: Vec<String> = kinds(&log).into_iter().map(|(id, _)| id).collect();
    assert_eq!(ids, ["t", "t#1", "test", "s", "s#1"]);
}

/// FR63: an act judged ahead, and a request, stop when their tries run out; an act read back
/// goes on past as many refusals as it takes.
#[test]
fn tries_run_out_ahead_and_not_after() {
    let log = initialized();
    log.race_always(work_stream(), noise());
    assert_eq!(
        observe(&log, "pre", edit("src/a.rs"), Watch::Before),
        Ok(Response::Block(Why::Contended { attempts: 8 }))
    );
    let change = instruction(
        "c",
        agent(),
        Via::ToolCall,
        Verb::Change(SetEdit::Add(agent_set(AGENT_SET))),
    );
    assert_eq!(
        run(&log, change),
        Ok(Err(NotRun::Contended { attempts: 8 }))
    );
    let log = initialized();
    log.race_n(work_stream(), 20, noise());
    after(&log, "b", build());
    let written: Vec<String> = kinds(&log)
        .into_iter()
        .filter(|(_, kind)| *kind == "act")
        .map(|(id, _)| id)
        .collect();
    assert_eq!(written, ["b"]);
    // The request that started the lineage, the 20 records of the racing writer, and the act.
    assert_eq!(work_records(&log).len(), 22);
}

/// FR70: a tool use whose path is not in the one form is written as the tool use it is, with its
/// tool and command kept and only its path one that could not be read, so the guard over the end
/// of a turn, which does not read a path, knows the edit was no test run and stops with a deny,
/// not with an unknown.
#[test]
fn a_path_not_in_the_one_form_is_written_as_a_tool_use_with_an_unreadable_path() {
    let log = initialized();
    start_task(&log, "t");
    let odd = observed("e", edit("../x"), Watch::After);
    assert_eq!(odd.replaced_path(), Some("../x"));
    assert_eq!(
        block_on(service(&log).observe(&work(), odd, &caps())),
        Ok(Response::Pass)
    );
    let written = work_records(&log).pop().unwrap().1;
    let WorkRecord::Act(act) = written else {
        panic!("not an act: {written:?}");
    };
    assert_eq!(
        act.event().body,
        Body::ToolUse {
            tool: "Edit".to_owned(),
            command: Seen::Absent,
            path: Seen::Unreadable,
            ok: None,
        }
    );
    assert_eq!(observe(&log, "s", stop(), GATE), Ok(denied(STOP_GUARD)));
}

/// FR70, FR69: a tool use whose path is not in the one form is judged ahead, as the tool use it is:
/// the guard over edits under `src/` reads the path, so it cannot tell and stops the edit; the
/// same edit in the form outside `src/` is let through.
#[test]
fn a_path_not_in_the_one_form_is_stopped_ahead_by_a_guard_over_paths() {
    let log = initialized();
    start_task(&log, "t");
    assert_eq!(
        observe(&log, "pre", edit("../x"), Watch::Before),
        Ok(unknown(SRC_GUARD))
    );
    assert_eq!(
        observe(&log, "pre2", edit("../x"), GATE),
        Ok(unknown(SRC_GUARD))
    );
    assert_eq!(
        observe(&log, "pre3", edit("docs/x"), Watch::Before),
        Ok(Response::Pass)
    );
}

/// FR70: a record whose kind could not be read is not judged ahead, whatever the watch that
/// judges ahead; one read back after the act is taken as it always was.
#[test]
fn a_record_of_no_kind_is_refused_when_it_is_judged_ahead() {
    let lost = event(
        agent(),
        Body::Unreadable {
            may_have_been: KindSet::any(),
        },
    );
    for watch in [Watch::Before, GATE] {
        assert_eq!(
            Observed::new(id("lost"), lost.clone(), watch),
            Err(ObservedError::UnreadableAhead)
        );
    }
    assert!(Observed::new(id("lost"), lost, Watch::After).is_ok());
}

/// FR63: a record the store cannot read back is folded as one that could not be read, and falls
/// to the stopping side.
#[test]
fn a_lost_record_is_folded_as_unreadable() {
    let log = initialized();
    start_task(&log, "t");
    after(&log, "test", bash("cargo test", Some(true)));
    assert_eq!(observe(&log, "s1", stop(), GATE), Ok(Response::Pass));
    // The test run: after the request that started the lineage, and the request and start of
    // the task.
    log.undecodable(work_stream(), 4);
    let response = observe(&log, "s2", stop(), GATE).unwrap();
    let Response::Block(Why::Verdict(Verdict::Deny(causes))) = response else {
        panic!("not stopped: {response:?}");
    };
    assert!(
        causes.contains(&Cause::Unknown(policy(STOP_GUARD))),
        "{causes:?}"
    );
}

/// FR63: a record of a judgment, a classifier's answer and a score are not taken from the
/// platform, judged ahead or read back, and a claim from the platform refuses them the same way.
#[test]
fn judgments_answers_and_scores_are_not_taken_from_the_platform() {
    let log = initialized();
    let under = GenerationMark::of(loaded(&log).catalog().generation());
    let claims = [
        event(
            user(),
            Body::Judged {
                policy: policy(STOP_GUARD),
                judgment: Judgment::Allowed,
                written: Level::Force,
                enforced: Level::Force,
            },
        ),
        event(
            user(),
            Body::Classified {
                classifier: "risk@1".parse::<ClassifierName>().unwrap(),
                answer: 0.1,
            },
        ),
        event(
            user(),
            Body::Measured {
                oracle: "coverage".to_owned(),
                score: 0.9,
            },
        ),
    ];
    for claim in claims {
        let kind = claim.body.kind();
        for watch in [Watch::After, Watch::Before] {
            assert_eq!(
                Observed::new(id("x"), claim.clone(), watch),
                Err(ObservedError::NotFromPlatform(kind))
            );
        }
        assert_eq!(
            ClaimEntry::observed(under.clone(), claim, TxDecision::Commit),
            Err(RecordError::NotFromPlatform(kind))
        );
    }
}

/// FR63, FR64: the start of a task is not taken from the platform, whatever the watch, nor as an
/// act a store gives back: only the request to start one makes it, and what a rule counts within
/// a task is not restarted by what the platform reports of its task lists.
#[test]
fn the_start_of_a_task_is_not_taken_from_the_platform() {
    let log = initialized();
    let under = GenerationMark::of(loaded(&log).catalog().generation());
    for watch in [Watch::After, GATE, Watch::Before] {
        assert_eq!(
            Observed::new(id("x"), task_start(), watch),
            Err(ObservedError::NotFromPlatform(EventKind::TaskStart))
        );
    }
    assert_eq!(
        ActEntry::observed(under, task_start()),
        Err(RecordError::NotFromPlatform(EventKind::TaskStart))
    );
    start_task(&log, "t");
    let started = work_records(&log).pop().unwrap().1;
    let WorkRecord::Act(act) = started else {
        panic!("not an act: {started:?}");
    };
    assert_eq!(act.source(), &ActSource::Instructed { request: id("t") });
}

/// FR63: a store that refuses an append with no growth is caught at once, by an act read back
/// and by a request, and neither goes round.
#[test]
fn a_refusal_that_reports_no_growth_is_an_error() {
    let log = initialized();
    log.break_conflict(work_stream());
    // The stream holds the request that started the lineage.
    let len = Len::new(1);
    assert_eq!(
        observe(&log, "b", build(), Watch::After),
        Err(ServiceError::Broken(Broken::ConflictNotLonger {
            expected: len,
            len
        }))
    );
    let change = instruction(
        "c",
        agent(),
        Via::ToolCall,
        Verb::Change(SetEdit::Add(agent_set(AGENT_SET))),
    );
    assert!(matches!(
        run(&log, change),
        Err(ServiceError::Broken(Broken::ConflictNotLonger { .. }))
    ));
}

/// FR63: a read after a refused append that is shorter than the refusal reported is an error.
#[test]
fn a_read_shorter_than_the_refusal_is_an_error() {
    let log = initialized();
    log.break_reread(work_stream());
    log.race(work_stream(), vec![(id("other").entry(), noise())]);
    let refused = observe(&log, "b", build(), Watch::After);
    assert!(
        matches!(
            refused,
            Err(ServiceError::Broken(Broken::RereadShorter { .. }))
        ),
        "{refused:?}"
    );
    // What the stream holds is what the racing writer wrote, and nothing else.
    assert_eq!(kinds(&log), [("other".to_owned(), "request")]);
}
