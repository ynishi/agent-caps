//! Scenarios of the operations that write: a change and the proposal a loosening becomes, two
//! changes from one read, who may ask for what from where, a proposal settled, and the result of
//! a request read back the same way whatever has happened since.

use std::num::NonZeroU16;

use agent_caps_core::application::{
    ActEntry, Broken, CatalogRecord, Changed, ClaimEntry, CoreVersion, EntryId, GenerationMark,
    NotRun, Ran, Record, Refused, ResultError, ServiceError, SetEdit, StreamKey, Verb, VerbName,
    Via, WorkRecord,
};
use agent_caps_core::domain::change::ChangeRejected;
use agent_caps_core::domain::event::Body;
use agent_caps_core::domain::policy::Level;
use agent_caps_core::domain::schema::{At, Judgment};
use agent_caps_core::domain::set::SourcesError;
use agent_caps_core::domain::tx::TxDecision;

use super::common::{
    AGENT_SET, EXTRA_SET, MemoryLog, STOP_GUARD, agent, agent_set, block_on, event, founding,
    helper, id, initialized, instruction, loaded, policy, ran, result, run, service, set_id,
    sources, stranger, user, user_set, work_records, work_stream,
};

fn add(set: &str) -> Verb {
    Verb::Change(SetEdit::Add(agent_set(set)))
}

/// Lowers the user's guard on the end of a turn (and, with `src`, the one on an edit): a
/// loosening of the user's work.
fn lower(src: Level) -> Verb {
    Verb::Change(SetEdit::Replace(user_set(Level::Advise, src)))
}

fn catalog_len(log: &MemoryLog) -> usize {
    log.records(&StreamKey::Catalog).len()
}

/// FR62, FR64: a change the agent covers takes effect as the next generation; one that loosens
/// the user's work becomes a proposal with every way it loosens, as the domain judged it.
#[test]
fn a_change_takes_effect_and_a_loosening_is_proposed() {
    let log = initialized();
    let changed = ran(
        &log,
        instruction("c", agent(), Via::ToolCall, add(AGENT_SET)),
    );
    assert_eq!(
        changed,
        Ran::Changed {
            record: result("c")
        }
    );
    let catalog = loaded(&log);
    assert_eq!(catalog.catalog().generation().n(), 1);
    let after = catalog
        .catalog()
        .sources()
        .replaced(user_set(Level::Advise, Level::Force))
        .unwrap();
    let Err(ChangeRejected::Loosens(loosens)) = catalog.catalog().change(after, &agent()) else {
        panic!("not a loosening");
    };
    assert!(!loosens.is_empty());
    let proposed = ran(
        &log,
        instruction("p", agent(), Via::ToolCall, lower(Level::Force)),
    );
    assert_eq!(
        proposed,
        Ran::Proposed {
            record: result("p"),
            loosens
        }
    );
    assert_eq!(loaded(&log).catalog().generation().n(), 1);
}

/// FR62: of two changes made from the same read, the one written second is refused, reads what
/// the first wrote and is judged again from it: as the next generation, or refused when the
/// domain refuses it there.
#[test]
fn two_changes_from_one_read_are_written_one_after_the_other() {
    let log = initialized();
    let first = Changed::new(
        sources().with(agent_set(AGENT_SET)).unwrap(),
        agent(),
        At::from_millis(0),
        CoreVersion::running(),
    );
    log.race(
        StreamKey::Catalog,
        vec![(
            result("other"),
            Record::Catalog(CatalogRecord::Changed(first.clone())),
        )],
    );
    let second = ran(
        &log,
        instruction("c", agent(), Via::ToolCall, add(EXTRA_SET)),
    );
    assert_eq!(
        second,
        Ran::Changed {
            record: result("c")
        }
    );
    let catalog = loaded(&log);
    assert_eq!(catalog.catalog().generation().n(), 2);
    assert!(
        catalog
            .catalog()
            .sources()
            .get(&set_id(AGENT_SET))
            .is_some()
    );
    assert!(
        catalog
            .catalog()
            .sources()
            .get(&set_id(EXTRA_SET))
            .is_some()
    );
    // The same set added from the same read: judged again, the domain refuses it.
    let log = initialized();
    log.race(
        StreamKey::Catalog,
        vec![(
            result("other"),
            Record::Catalog(CatalogRecord::Changed(first)),
        )],
    );
    assert_eq!(
        run(
            &log,
            instruction("c", agent(), Via::ToolCall, add(AGENT_SET))
        ),
        Ok(Err(NotRun::Refused(Refused::Sources(
            SourcesError::Duplicate(set_id(AGENT_SET))
        ))))
    );
}

/// FR63: an observation and a request given twice are written once and answered the same; a
/// request that was refused leaves no result and is judged again.
#[test]
fn the_same_act_or_request_is_written_once() {
    let log = initialized();
    super::common::start_task(&log, "t");
    let pre = || {
        super::common::observe(
            &log,
            "pre",
            super::common::edit("src/a.rs"),
            agent_caps_core::application::Watch::Before,
        )
    };
    let first = pre();
    let written = work_records(&log).len();
    assert_eq!(pre(), first);
    assert_eq!(work_records(&log).len(), written);

    let change = || instruction("c", agent(), Via::ToolCall, add(AGENT_SET));
    let changed = ran(&log, change());
    let proposal = || instruction("p", agent(), Via::ToolCall, lower(Level::Force));
    let proposed = ran(&log, proposal());
    let (catalog, work) = (catalog_len(&log), work_records(&log).len());
    assert_eq!(ran(&log, change()), changed);
    assert_eq!(ran(&log, proposal()), proposed);
    assert_eq!(
        (catalog_len(&log), work_records(&log).len()),
        (catalog, work)
    );

    let remove = || {
        instruction(
            "rm",
            agent(),
            Via::ToolCall,
            Verb::Change(SetEdit::Remove(set_id(EXTRA_SET))),
        )
    };
    assert_eq!(
        run(&log, remove()),
        Ok(Err(NotRun::Refused(Refused::Sources(
            SourcesError::Unknown(set_id(EXTRA_SET))
        ))))
    );
    ran(
        &log,
        instruction("x", agent(), Via::ToolCall, add(EXTRA_SET)),
    );
    assert_eq!(
        run(&log, remove()),
        Ok(Ok(Ran::Changed {
            record: result("rm")
        }))
    );
}

/// FR64: from a prompt the platform cannot show the user typed, a loosening, an approval and the
/// start of a task are refused and a change the agent covers is taken; from an attested prompt,
/// an approval is taken, from the generation its proposal was made from only.
#[test]
fn what_a_prompt_may_ask_for() {
    let log = initialized();
    assert_eq!(
        run(
            &log,
            instruction("l", user(), Via::Prompt, lower(Level::Force))
        ),
        Ok(Err(NotRun::Refused(Refused::NeedsAttestedPrompt(
            VerbName::Change
        ))))
    );
    ran(
        &log,
        instruction("p", agent(), Via::ToolCall, lower(Level::Force)),
    );
    assert_eq!(
        run(
            &log,
            instruction("a1", user(), Via::Prompt, Verb::Approve(result("p")))
        ),
        Ok(Err(NotRun::Refused(Refused::NeedsAttestedPrompt(
            VerbName::Approve
        ))))
    );
    assert_eq!(
        ran(
            &log,
            instruction(
                "a2",
                user(),
                Via::AttestedPrompt,
                Verb::Approve(result("p"))
            )
        ),
        Ran::Approved {
            record: result("a2"),
            proposal: result("p")
        }
    );
    ran(
        &log,
        instruction("q", agent(), Via::ToolCall, lower(Level::Advise)),
    );
    let base = GenerationMark::of(loaded(&log).catalog().generation());
    assert_eq!(
        ran(&log, instruction("c", user(), Via::Prompt, add(AGENT_SET))),
        Ran::Changed {
            record: result("c")
        }
    );
    let current = GenerationMark::of(loaded(&log).catalog().generation());
    assert_eq!(
        run(
            &log,
            instruction(
                "a3",
                user(),
                Via::AttestedPrompt,
                Verb::Approve(result("q"))
            )
        ),
        Ok(Err(NotRun::Refused(Refused::Outdated {
            proposal: result("q"),
            base,
            current
        })))
    );
    assert_eq!(
        run(&log, instruction("t", user(), Via::Prompt, Verb::Task)),
        Ok(Err(NotRun::Refused(Refused::NeedsAttestedPrompt(
            VerbName::Task
        ))))
    );
}

/// FR64: a proposal is rejected by its maker, not by one below the maker, and is settled after.
#[test]
fn a_proposal_is_rejected_by_its_maker_or_one_above() {
    let log = initialized();
    ran(
        &log,
        instruction("p", agent(), Via::ToolCall, lower(Level::Force)),
    );
    let pending = block_on(service(&log).proposals()).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].entry().id(), &result("p"));
    assert_eq!(
        run(
            &log,
            instruction("n1", helper(), Via::ToolCall, Verb::Reject(result("p")))
        ),
        Ok(Err(NotRun::Refused(Refused::NotMakerOrAbove {
            proposal: result("p")
        })))
    );
    assert_eq!(
        ran(
            &log,
            instruction("n2", agent(), Via::ToolCall, Verb::Reject(result("p")))
        ),
        Ran::Declined {
            record: result("n2"),
            proposal: result("p")
        }
    );
    assert!(block_on(service(&log).proposals()).unwrap().is_empty());
    assert_eq!(
        run(
            &log,
            instruction("n3", user(), Via::AttestedPrompt, Verb::Reject(result("p")))
        ),
        Ok(Err(NotRun::Refused(Refused::Settled(result("p")))))
    );
}

/// FR63: when another process wrote the result of the same request first, the second finds it
/// after its append is refused, writes nothing and answers with the same result; the same holds
/// for an observation.
#[test]
fn a_second_writer_of_the_same_request_writes_nothing() {
    let log = initialized();
    let (one, two) = (service(&log), service(&log));
    let theirs = Changed::new(
        sources().with(agent_set(AGENT_SET)).unwrap(),
        agent(),
        At::from_millis(0),
        CoreVersion::running(),
    );
    log.race(
        StreamKey::Catalog,
        vec![(result("c"), Record::Catalog(CatalogRecord::Changed(theirs)))],
    );
    let change = || instruction("c", agent(), Via::ToolCall, add(AGENT_SET));
    let expected = Ran::Changed {
        record: result("c"),
    };
    assert_eq!(block_on(two.run(change())), Ok(Ok(expected.clone())));
    assert_eq!(block_on(one.run(change())), Ok(Ok(expected)));
    let changes = log
        .records(&StreamKey::Catalog)
        .into_iter()
        .filter(|(_, record)| matches!(record, Record::Catalog(CatalogRecord::Changed(_))))
        .count();
    assert_eq!(changes, 1);

    let under = GenerationMark::of(loaded(&log).catalog().generation());
    let build = ActEntry::observed(under, super::common::build()).unwrap();
    log.race(
        work_stream(),
        vec![(id("b").entry(), Record::Work(WorkRecord::Act(build)))],
    );
    super::common::after(&log, "b", super::common::build());
    let acts = work_records(&log)
        .into_iter()
        .filter(|(entry, _)| entry == &id("b").entry())
        .count();
    assert_eq!(acts, 1);
}

/// FR63: a request whose result was written is answered with that result again, whatever the
/// catalog has become since: unreplayable, or a new lineage.
#[test]
fn a_result_is_the_same_whatever_the_catalog_has_become() {
    for rebase in [false, true] {
        let log = initialized();
        let change = || instruction("c", agent(), Via::ToolCall, add(AGENT_SET));
        let proposal = || instruction("p", agent(), Via::ToolCall, lower(Level::Force));
        let (changed, proposed) = (ran(&log, change()), ran(&log, proposal()));
        if rebase {
            ran(
                &log,
                instruction("r", user(), Via::AttestedPrompt, Verb::Rebase(founding())),
            );
        } else {
            log.put(
                StreamKey::Catalog,
                result("old"),
                Record::Catalog(CatalogRecord::Changed(Changed::new(
                    sources(),
                    stranger(),
                    At::from_millis(0),
                    CoreVersion::running(),
                ))),
            );
        }
        let (catalog, work) = (catalog_len(&log), work_records(&log).len());
        assert_eq!(run(&log, change()), Ok(Ok(changed)), "rebase {rebase}");
        assert_eq!(run(&log, proposal()), Ok(Ok(proposed)), "rebase {rebase}");
        assert_eq!(
            (catalog_len(&log), work_records(&log).len()),
            (catalog, work),
            "rebase {rebase}"
        );
    }
}

/// FR64: the id of a stored proposal, read back from its text, is what an approval names.
#[test]
fn a_proposal_is_approved_by_the_text_of_its_id() {
    let log = initialized();
    let Ran::Proposed { record, .. } = ran(
        &log,
        instruction("p", agent(), Via::ToolCall, lower(Level::Force)),
    ) else {
        panic!("not proposed");
    };
    let text = record.to_string();
    assert_eq!(text, "p#1");
    let named: EntryId = text.parse().unwrap();
    assert_eq!(
        ran(
            &log,
            instruction("a", user(), Via::AttestedPrompt, Verb::Approve(named))
        ),
        Ran::Approved {
            record: result("a"),
            proposal: record
        }
    );
}

/// FR63: a record at a request's result id that is not its result is reported, not taken for
/// none.
#[test]
fn a_record_that_is_not_the_result_is_an_error() {
    let log = initialized();
    let under = GenerationMark::of(loaded(&log).catalog().generation());
    let judged = event(
        user(),
        Body::Judged {
            policy: policy(STOP_GUARD),
            judgment: Judgment::Allowed,
            written: Level::Force,
            enforced: Level::Force,
        },
    );
    log.put(
        work_stream(),
        result("t"),
        Record::Work(WorkRecord::Claim(
            ClaimEntry::judged(under, judged, TxDecision::Commit).unwrap(),
        )),
    );
    assert_eq!(
        run(
            &log,
            instruction("t", user(), Via::AttestedPrompt, Verb::Task)
        ),
        Err(ServiceError::Broken(Broken::Result(
            ResultError::NotAResult { id: result("t") }
        )))
    );
}

/// FR63: a result the store cannot read back is reported as one.
#[test]
fn a_result_that_cannot_be_read_back_is_an_error() {
    let log = initialized();
    let task = || instruction("t", user(), Via::AttestedPrompt, Verb::Task);
    assert_eq!(
        ran(&log, task()),
        Ran::TaskStarted {
            record: result("t")
        }
    );
    let seq = work_records(&log)
        .iter()
        .position(|(entry, _)| entry == &result("t"))
        .unwrap() as u64
        + 1;
    log.undecodable(work_stream(), seq);
    assert_eq!(
        run(&log, task()),
        Err(ServiceError::Broken(Broken::Result(
            ResultError::ResultUnreadable { id: result("t") }
        )))
    );
}

/// FR63: a result names its record and holds no generation; the generation is read from the
/// catalog in effect.
#[test]
fn a_result_names_its_record_and_the_catalog_has_the_generation() {
    let log = initialized();
    let results = [
        Ran::Initialized {
            record: result("init"),
        },
        ran(
            &log,
            instruction("c1", agent(), Via::ToolCall, add(AGENT_SET)),
        ),
        {
            ran(
                &log,
                instruction("p", agent(), Via::ToolCall, lower(Level::Force)),
            );
            ran(
                &log,
                instruction("a", user(), Via::AttestedPrompt, Verb::Approve(result("p"))),
            )
        },
        ran(
            &log,
            instruction("r", user(), Via::AttestedPrompt, Verb::Rebase(founding())),
        ),
        ran(
            &log,
            instruction("c2", agent(), Via::ToolCall, add(AGENT_SET)),
        ),
    ];
    let ids: Vec<EntryId> = log
        .records(&StreamKey::Catalog)
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    for ran in &results {
        let record = match ran {
            Ran::Initialized { record }
            | Ran::Rebased { record }
            | Ran::Changed { record }
            | Ran::Approved { record, .. } => record,
            other => panic!("{other:?}"),
        };
        assert_eq!(record.child(), NonZeroU16::new(1));
        assert!(ids.contains(record), "{record}");
    }
    let catalog = loaded(&log);
    assert_eq!(catalog.catalog().generation().lineage().as_str(), "r");
    assert_eq!(catalog.catalog().generation().n(), 1);
}
