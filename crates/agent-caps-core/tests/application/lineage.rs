//! Scenarios of the catalog's line: a lineage started once and by a root, the replay of the
//! records from the last genesis, a catalog the running version cannot replay, a broken stream,
//! and what an empty store answers.

use agent_caps_core::application::{
    Broken, CatalogRecord, CatalogState, Changed, CoreVersion, Fallback, Founding, LogError,
    NotReady, NotRun, PlatformActors, Ran, Record, Refused, Response, ServiceError, SetEdit,
    StreamKey, Verb, VerbName, Via, Watch, Why, WorkRecord,
};
use agent_caps_core::domain::authority::Authority;
use agent_caps_core::domain::catalog::Catalog;
use agent_caps_core::domain::policy::Level;
use agent_caps_core::domain::schema::At;
use agent_caps_core::domain::set::Sources;

use super::common::{
    AGENT_SET, GATE, MemoryLog, agent, agent_set, authority, block_on, build, declaring, edit,
    empty_agent_set, founding, id, initialized, instruction, loaded, observe, ran, result, run,
    service, set_id, sources, stop, stranger, user, user_set, work_records,
};

/// FR62: an acceptance starts a lineage only in an empty line; a second is refused.
#[test]
fn init_starts_the_first_lineage_once() {
    let log = MemoryLog::new();
    let first = run(
        &log,
        instruction("init", user(), Via::AttestedPrompt, Verb::Init(founding())),
    );
    assert_eq!(
        first,
        Ok(Ok(Ran::Initialized {
            record: result("init")
        }))
    );
    let catalog = loaded(&log);
    assert_eq!(catalog.catalog().generation().lineage().as_str(), "init");
    assert_eq!(catalog.catalog().generation().n(), 0);
    let again = run(
        &log,
        instruction(
            "init-2",
            user(),
            Via::AttestedPrompt,
            Verb::Init(founding()),
        ),
    );
    assert_eq!(again, Ok(Err(NotRun::Refused(Refused::AlreadyInitialized))));
    assert_eq!(log.records(&StreamKey::Catalog).len(), 1);
}

/// FR62, FR64: an acceptance is made by a root of its hierarchy, and not from a tool call.
#[test]
fn init_by_one_below_the_root_or_from_a_tool_call_is_refused() {
    let log = MemoryLog::new();
    let below = run(
        &log,
        instruction("init", agent(), Via::AttestedPrompt, Verb::Init(founding())),
    );
    assert_eq!(below, Ok(Err(NotRun::Refused(Refused::NotRoot))));
    let tool = run(
        &log,
        instruction("init-2", user(), Via::ToolCall, Verb::Init(founding())),
    );
    assert_eq!(
        tool,
        Ok(Err(NotRun::Refused(Refused::NotFromToolCall(
            VerbName::Init
        ))))
    );
    assert!(matches!(
        block_on(service(&log).catalog()),
        Ok(CatalogState::Empty { .. })
    ));
}

/// FR62: the catalog is the replay of the records from the last acceptance: a change and an
/// approval change it, a proposal and a rejection do not, and the replay comes to the catalog
/// the domain makes from the same changes.
#[test]
fn the_catalog_is_the_replay_of_its_records() {
    let log = initialized();
    let add = Verb::Change(SetEdit::Add(agent_set(AGENT_SET)));
    ran(&log, instruction("add", agent(), Via::ToolCall, add));
    let lower = || Verb::Change(SetEdit::Replace(user_set(Level::Advise, Level::Force)));
    ran(&log, instruction("p1", agent(), Via::ToolCall, lower()));
    ran(
        &log,
        instruction("no", agent(), Via::ToolCall, Verb::Reject(result("p1"))),
    );
    ran(&log, instruction("p2", agent(), Via::ToolCall, lower()));
    let approved = ran(
        &log,
        instruction(
            "yes",
            user(),
            Via::AttestedPrompt,
            Verb::Approve(result("p2")),
        ),
    );
    assert_eq!(
        approved,
        Ran::Approved {
            record: result("yes"),
            proposal: result("p2")
        }
    );
    let kinds: Vec<&str> = log
        .records(&StreamKey::Catalog)
        .iter()
        .map(|(_, record)| match record {
            Record::Catalog(CatalogRecord::Genesis(_)) => "genesis",
            Record::Catalog(CatalogRecord::Changed(_)) => "changed",
            Record::Catalog(CatalogRecord::Proposed(_)) => "proposed",
            Record::Catalog(CatalogRecord::Declined(_)) => "declined",
            Record::Catalog(CatalogRecord::Approved(_)) => "approved",
            Record::Work(_) => "work",
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "genesis", "changed", "proposed", "declined", "proposed", "approved"
        ]
    );
    let replayed = loaded(&log);
    assert_eq!(replayed.catalog().generation().n(), 2);
    let expected = Catalog::accept(sources(), authority(), id("init").lineage())
        .unwrap()
        .change(sources().with(agent_set(AGENT_SET)).unwrap(), &agent())
        .unwrap()
        .change(
            sources()
                .with(agent_set(AGENT_SET))
                .unwrap()
                .replaced(user_set(Level::Advise, Level::Force))
                .unwrap(),
            &user(),
        )
        .unwrap();
    assert_eq!(replayed.catalog().graph(), expected.graph());
    assert_eq!(replayed.catalog().generation(), expected.generation());
}

/// FR62: after a new lineage, only its records are replayed: a change before it does not hold.
#[test]
fn a_rebase_replays_only_the_new_lineage() {
    let log = initialized();
    let add = Verb::Change(SetEdit::Add(agent_set(AGENT_SET)));
    ran(&log, instruction("add", agent(), Via::ToolCall, add));
    assert!(
        loaded(&log)
            .catalog()
            .sources()
            .get(&set_id(AGENT_SET))
            .is_some()
    );
    let rebased = ran(
        &log,
        instruction(
            "rebase",
            user(),
            Via::AttestedPrompt,
            Verb::Rebase(founding()),
        ),
    );
    assert_eq!(
        rebased,
        Ran::Rebased {
            record: result("rebase")
        }
    );
    let catalog = loaded(&log);
    assert_eq!(catalog.catalog().generation().lineage().as_str(), "rebase");
    assert_eq!(catalog.catalog().generation().n(), 0);
    assert!(
        catalog
            .catalog()
            .sources()
            .get(&set_id(AGENT_SET))
            .is_none()
    );
    let genesis = block_on(service(&log).genesis()).unwrap().unwrap();
    assert_eq!(genesis.id(), &result("rebase"));
}

/// FR62: a record the running domain refuses makes the catalog unreplayable: an act judged ahead
/// is stopped, a root of the last acceptance may start a new lineage even from a prompt the
/// platform cannot show the user typed, and one who is not a root may not.
#[test]
fn an_unreplayable_catalog_stops_acts_and_opens_a_rebase_to_its_root() {
    let log = initialized();
    log.put(
        StreamKey::Catalog,
        result("old"),
        Record::Catalog(CatalogRecord::Changed(Changed::new(
            sources(),
            stranger(),
            At::from_millis(0),
            CoreVersion::new("0.0.1").unwrap(),
        ))),
    );
    let state = block_on(service(&log).catalog()).unwrap();
    let CatalogState::Unreplayable(unreplayable) = &state else {
        panic!("replayed: {state:?}");
    };
    assert_eq!(unreplayable.seq().get(), 2);
    assert_eq!(unreplayable.recorded().as_str(), "0.0.1");
    assert_eq!(unreplayable.running(), &CoreVersion::running());
    assert_eq!(
        observe(&log, "pre", edit("src/a.rs"), Watch::Before),
        Ok(Response::Block(Why::NotReady(NotReady::Unreplayable(
            unreplayable.clone()
        ))))
    );
    let below = run(
        &log,
        instruction("r1", agent(), Via::AttestedPrompt, Verb::Rebase(founding())),
    );
    assert_eq!(below, Ok(Err(NotRun::Refused(Refused::NotRoot))));
    let rebased = run(
        &log,
        instruction("r2", user(), Via::Prompt, Verb::Rebase(founding())),
    );
    assert_eq!(
        rebased,
        Ok(Ok(Ran::Rebased {
            record: result("r2")
        }))
    );
    assert_eq!(loaded(&log).catalog().generation().lineage().as_str(), "r2");
}

/// FR62: until the line has an acceptance, an act judged ahead is stopped, the end of a turn
/// passes when the adapter says it need not stop, and nothing is written.
#[test]
fn an_empty_store_stops_what_is_judged_ahead_and_writes_nothing() {
    let log = MemoryLog::new();
    let empty = Response::Block(Why::NotReady(NotReady::Empty));
    assert_eq!(
        observe(&log, "a", edit("src/a.rs"), Watch::Before),
        Ok(empty.clone())
    );
    assert_eq!(
        observe(
            &log,
            "b",
            stop(),
            Watch::Gate {
                fallback: Fallback::Pass
            }
        ),
        Ok(Response::Pass)
    );
    assert_eq!(observe(&log, "c", stop(), GATE), Ok(empty));
    assert_eq!(
        observe(&log, "d", build(), Watch::After),
        Ok(Response::Pass)
    );
    assert!(work_records(&log).is_empty());
}

/// FR62, FR64: with two roots that do not cover each other, a change from a prompt the platform
/// cannot show the user typed is judged and recorded as the agent's, the request keeps that the
/// user asked from a prompt, and the replay judges the change the same way.
#[test]
fn a_change_from_an_unattested_prompt_is_the_agents_and_replays() {
    let authority = Authority::new([(user(), None), (agent(), None)]).unwrap();
    let sources = Sources::new(vec![
        user_set(Level::Force, Level::Force),
        declaring(empty_agent_set()),
    ])
    .unwrap();
    let actors = PlatformActors::new(user(), agent(), &authority).unwrap();
    let founding = Founding::new(sources, authority, actors).unwrap();
    let log = MemoryLog::new();
    ran(
        &log,
        instruction("init", user(), Via::AttestedPrompt, Verb::Init(founding)),
    );
    let tighter = declaring(agent_set(AGENT_SET));
    let changed = ran(
        &log,
        instruction(
            "c",
            user(),
            Via::Prompt,
            Verb::Change(SetEdit::Replace(tighter)),
        ),
    );
    assert_eq!(
        changed,
        Ran::Changed {
            record: result("c")
        }
    );
    let records = log.records(&StreamKey::Catalog);
    let Some((_, Record::Catalog(CatalogRecord::Changed(written)))) = records.last() else {
        panic!("no change: {records:?}");
    };
    assert_eq!(written.by(), &agent());
    let request = work_records(&log)
        .into_iter()
        .find(|(entry, _)| entry == &id("c").entry())
        .map(|(_, record)| record);
    let Some(WorkRecord::Request(request)) = request else {
        panic!("no request: {request:?}");
    };
    assert_eq!(request.by(), &user());
    assert_eq!(request.via(), Via::Prompt);
    assert_eq!(loaded(&log).catalog().generation().n(), 1);
}

/// The three ways a store is broken: a catalog's stream that does not start with a genesis, a
/// record of it that cannot be read back, a store that cannot be reached.
fn broken_stores() -> Vec<(&'static str, MemoryLog)> {
    let unrooted = MemoryLog::new();
    unrooted.put(
        StreamKey::Catalog,
        result("first"),
        Record::Catalog(CatalogRecord::Changed(Changed::new(
            sources(),
            user(),
            At::from_millis(0),
            CoreVersion::running(),
        ))),
    );
    let undecodable = initialized();
    undecodable.undecodable(StreamKey::Catalog, 1);
    let unreachable = initialized();
    unreachable.unavailable();
    vec![
        ("unrooted", unrooted),
        ("undecodable", undecodable),
        ("unreachable", unreachable),
    ]
}

/// FR62: a broken stream is an error, not a catalog that cannot be replayed, so it opens no new
/// lineage from an unattested prompt: what is judged ahead stops with the failure, what passes
/// returns it, and an operation that writes is a stop for the hook.
#[test]
fn a_broken_store_opens_no_rebase_and_falls_to_the_stopping_side() {
    for (name, log) in broken_stores() {
        let catalog = block_on(service(&log).catalog());
        match (name, &catalog) {
            ("unrooted", Err(ServiceError::Broken(Broken::NotRooted { seq }))) => {
                assert_eq!(seq.get(), 1)
            }
            ("undecodable", Err(ServiceError::Log(LogError::Undecodable { .. }))) => {}
            ("unreachable", Err(ServiceError::Log(LogError::Unavailable { .. }))) => {}
            _ => panic!("{name}: {catalog:?}"),
        }
        let before = log.records(&StreamKey::Catalog);
        let rebase = || instruction("r", user(), Via::Prompt, Verb::Rebase(founding()));
        assert!(run(&log, rebase()).is_err(), "{name}");
        assert_eq!(log.records(&StreamKey::Catalog), before, "{name}");
        let failed = |response: Result<Response, ServiceError>| {
            matches!(response, Ok(Response::Block(Why::Failed(_))))
        };
        assert!(
            failed(observe(&log, "a", edit("src/a.rs"), Watch::Before)),
            "{name}"
        );
        assert!(failed(observe(&log, "b", stop(), GATE)), "{name}");
        let pass = Watch::Gate {
            fallback: Fallback::Pass,
        };
        assert!(observe(&log, "c", stop(), pass).is_err(), "{name}");
        assert!(observe(&log, "d", build(), Watch::After).is_err(), "{name}");
        let change = instruction(
            "x",
            agent(),
            Via::ToolCall,
            Verb::Change(SetEdit::Add(agent_set(AGENT_SET))),
        );
        for request in [rebase(), change] {
            let response = block_on(service(&log).respond(request));
            assert!(
                matches!(response, Response::Block(Why::Failed(_))),
                "{name}: {response:?}"
            );
        }
    }
}
