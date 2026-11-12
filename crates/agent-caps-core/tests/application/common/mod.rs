//! Helpers shared by the application's scenarios: the hierarchy and the platform's actors, the
//! sets of policies, events, observations and requests, and the way every scenario runs a use
//! case ([`block_on`] over a [`MemoryLog`]). Nothing here decides anything the application or the
//! domain decides.
//!
//! The user is the root; the agent is below it, and the helper below the agent. The user's set
//! holds two guards at Force: the end of a turn needs `cargo test` to have passed within the task,
//! and so does an edit under `src/`. The agent's sets hold an advising guard of the agent's own,
//! so adding one tightens and is the agent's to make; lowering a guard of the user's loosens.

pub mod log;

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use agent_caps_core::application::{
    BaseId, CatalogState, EntryId, Fallback, Founding, Instruction, Loaded, NotRun, Observed,
    PlatformActors, Ran, Record, Response, Service, ServiceError, StreamKey, Verb, Via, Watch,
    WorkKey, WorkRecord,
};
use agent_caps_core::domain::adjust::TemporaryBound;
use agent_caps_core::domain::authority::{Authority, Principal};
use agent_caps_core::domain::catalog::Capabilities;
use agent_caps_core::domain::event::{Body, Event, Seen};
use agent_caps_core::domain::name::{BindingId, CommandWords, GlobPattern, PolicyId};
use agent_caps_core::domain::policy::{
    Binding, DefLayer, Expect, Fixture, Level, ModeScope, Polarity, PolicyDef, PolicyGraph, Rule,
};
use agent_caps_core::domain::predicate::{By, Cond, EventFilter, Lit, Pred, Scope, Selector, Span};
use agent_caps_core::domain::schema::{At, EventKind, Field};
use agent_caps_core::domain::set::{SetId, Source, Sources};

pub use log::MemoryLog;

/// Runs a use case to its end. The memory store never waits, so its futures are ready at the
/// first poll; one that is not is a bug of the test, and fails it.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("a use case over the memory store waited"),
    }
}

pub fn user() -> Principal {
    Principal::new("user")
}

pub fn agent() -> Principal {
    Principal::new("agent")
}

/// Below the agent.
pub fn helper() -> Principal {
    Principal::new("helper")
}

/// Not in the hierarchy.
pub fn stranger() -> Principal {
    Principal::new("stranger")
}

pub fn authority() -> Authority {
    Authority::new([
        (user(), None),
        (agent(), Some(user())),
        (helper(), Some(agent())),
    ])
    .unwrap()
}

pub fn actors() -> PlatformActors {
    PlatformActors::new(user(), agent(), &authority()).unwrap()
}

pub fn id(text: &str) -> BaseId {
    BaseId::new(text).unwrap()
}

/// The first derived id of the request `text`: where its result is.
pub fn result(text: &str) -> EntryId {
    format!("{text}#1").parse().unwrap()
}

pub fn work() -> WorkKey {
    WorkKey::new("wt").unwrap()
}

pub fn work_stream() -> StreamKey {
    StreamKey::Work(work())
}

pub fn caps() -> Capabilities {
    Capabilities::full()
}

pub fn words(text: &str) -> CommandWords {
    CommandWords::new(text.split_whitespace().map(str::to_owned).collect()).unwrap()
}

pub fn event(by: Principal, body: Body) -> Event {
    Event {
        at: At::from_millis(0),
        by,
        body,
    }
}

/// The start of a task, for the domain's fixtures and for a record a scenario writes straight
/// into the store: the platform's is not taken ([`start_task`] makes one).
pub fn task_start() -> Event {
    event(agent(), Body::TaskStart)
}

/// An act read back from the platform that no guard of the scenarios reads.
pub fn build() -> Event {
    bash("cargo build", Some(true))
}

pub fn stop() -> Event {
    event(agent(), Body::Stop)
}

pub fn bash(command: &str, ok: Option<bool>) -> Event {
    event(
        agent(),
        Body::ToolUse {
            tool: "Bash".to_owned(),
            command: Seen::Value(words(command)),
            path: Seen::Absent,
            ok,
        },
    )
}

pub fn edit(path: &str) -> Event {
    event(
        agent(),
        Body::ToolUse {
            tool: "Edit".to_owned(),
            command: Seen::Absent,
            path: Seen::Value(path.to_owned()),
            ok: None,
        },
    )
}

pub const STOP_GUARD: &str = "00000000-0000-7000-8000-000000000001";
pub const SRC_GUARD: &str = "00000000-0000-7000-8000-000000000002";
pub const AGENT_GUARD: &str = "00000000-0000-7000-8000-000000000003";

pub fn policy(text: &str) -> PolicyId {
    text.parse().unwrap()
}

fn binding(policy_id: &str, level: Level, author: Principal) -> Binding {
    let text = policy_id.to_owned();
    Binding {
        id: format!("b0000000{}", &text[8..])
            .parse::<BindingId>()
            .unwrap(),
        policy: policy(policy_id),
        level,
        mode: ModeScope::Any,
        author,
    }
}

fn fixture(name: &str, events: Vec<Event>, expect: Expect) -> Fixture {
    Fixture {
        name: name.to_owned(),
        events,
        expect,
        known_gap: false,
    }
}

/// `cargo test` passed within the task.
fn tested() -> Pred {
    Pred::Once {
        select: Selector {
            filter: EventFilter {
                kind: EventKind::ToolUse,
                cond: Some(Cond::All(vec![
                    Cond::Words(Field::Command, words("cargo test")),
                    Cond::Eq(Field::Ok, Lit::Bool(true)),
                ])),
            },
            by: By::Anyone,
        },
        scope: Scope::Span {
            span: Span::Task,
            by: By::Anyone,
        },
    }
}

/// The end of a turn needs `cargo test` to have passed within the task.
fn stop_guard() -> PolicyDef {
    PolicyDef {
        id: policy(STOP_GUARD),
        name: "test-before-stop".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::Stop,
        when: None,
        rule: Rule::Structural(tested()),
        polarity: Polarity::Guard,
        fixtures: vec![
            fixture("untested", vec![task_start(), stop()], Expect::Violated),
            fixture(
                "tested",
                vec![task_start(), bash("cargo test", Some(true)), stop()],
                Expect::Satisfied,
            ),
        ],
        author: user(),
    }
}

/// An edit under `src/` needs `cargo test` to have passed within the task.
fn src_guard() -> PolicyDef {
    PolicyDef {
        id: policy(SRC_GUARD),
        name: "test-before-src-edit".parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::ToolUse,
        when: Some(Pred::Now(Cond::Glob(
            Field::Path,
            GlobPattern::new("src/*").unwrap(),
        ))),
        rule: Rule::Structural(tested()),
        polarity: Polarity::Guard,
        fixtures: vec![
            fixture(
                "untested edit",
                vec![task_start(), edit("src/a.rs")],
                Expect::Violated,
            ),
            fixture(
                "tested edit",
                vec![
                    task_start(),
                    bash("cargo test", Some(true)),
                    edit("src/a.rs"),
                ],
                Expect::Satisfied,
            ),
        ],
        author: user(),
    }
}

/// The agent's own advice: run clippy before the end of a turn.
fn agent_guard(id: &str) -> PolicyDef {
    PolicyDef {
        id: policy(id),
        name: format!("clippy-before-stop-{}", &id[30..]).parse().unwrap(),
        layer: DefLayer::Base,
        subject: EventKind::Stop,
        when: None,
        rule: Rule::Structural(Pred::Once {
            select: Selector {
                filter: EventFilter {
                    kind: EventKind::ToolUse,
                    cond: Some(Cond::Words(Field::Command, words("cargo clippy"))),
                },
                by: By::Anyone,
            },
            scope: Scope::Span {
                span: Span::Task,
                by: By::Anyone,
            },
        }),
        polarity: Polarity::Guard,
        fixtures: vec![],
        author: agent(),
    }
}

pub const USER_SET: &str = "5e700000-0000-7000-8000-000000000001";
pub const AGENT_SET: &str = "5e700000-0000-7000-8000-000000000002";
pub const EXTRA_SET: &str = "5e700000-0000-7000-8000-000000000003";

pub fn set_id(text: &str) -> SetId {
    text.parse().unwrap()
}

fn bound() -> TemporaryBound {
    TemporaryBound::from_millis(365 * 86_400_000).unwrap()
}

/// The user's set, with the guard on the end of a turn at `stop` and the guard on an edit at
/// `src`. It declares the bound on a temporary adjustment, as a root's set does.
pub fn user_set(stop: Level, src: Level) -> Source {
    let graph = PolicyGraph::parse_with(
        vec![stop_guard(), src_guard()],
        vec![
            binding(STOP_GUARD, stop, user()),
            binding(SRC_GUARD, src, user()),
        ],
        vec![],
        Some(bound()),
    )
    .unwrap();
    Source {
        id: set_id(USER_SET),
        name: "user".parse().unwrap(),
        owner: user(),
        graph,
    }
}

/// A set of the agent's, with its own advising guard: `AGENT_SET` with `AGENT_GUARD`, or
/// `EXTRA_SET` with another.
pub fn agent_set(set: &str) -> Source {
    let (guard, name) = if set == AGENT_SET {
        (AGENT_GUARD, "agent")
    } else {
        ("00000000-0000-7000-8000-000000000004", "extra")
    };
    let graph = PolicyGraph::parse_with(
        vec![agent_guard(guard)],
        vec![binding(guard, Level::Advise, agent())],
        vec![],
        None,
    )
    .unwrap();
    Source {
        id: set_id(set),
        name: name.parse().unwrap(),
        owner: agent(),
        graph,
    }
}

/// The set, declaring the bound on a temporary adjustment as a root's set does.
pub fn declaring(source: Source) -> Source {
    let (policies, bindings, classifiers, _) = source.graph.into_parts();
    Source {
        graph: PolicyGraph::parse_with(policies, bindings, classifiers, Some(bound())).unwrap(),
        ..source
    }
}

/// `AGENT_SET` with nothing in it.
pub fn empty_agent_set() -> Source {
    Source {
        graph: PolicyGraph::parse_with(vec![], vec![], vec![], None).unwrap(),
        ..agent_set(AGENT_SET)
    }
}

/// The sets a lineage starts from: the user's, with both guards at Force.
pub fn sources() -> Sources {
    Sources::new(vec![user_set(Level::Force, Level::Force)]).unwrap()
}

pub fn founding() -> Founding {
    Founding::new(sources(), authority(), actors()).unwrap()
}

/// The request `request` by `by` from `via`, for the worktree.
pub fn instruction(request: &str, by: Principal, via: Via, verb: Verb) -> Instruction {
    Instruction::new(id(request), by, At::from_millis(0), via, work(), verb)
}

pub fn service(log: &MemoryLog) -> Service<MemoryLog> {
    Service::new(log.clone())
}

/// Runs the request.
pub fn run(log: &MemoryLog, instruction: Instruction) -> Result<Result<Ran, NotRun>, ServiceError> {
    block_on(service(log).run(instruction))
}

/// Runs the request and expects it done.
pub fn ran(log: &MemoryLog, instruction: Instruction) -> Ran {
    run(log, instruction).unwrap().unwrap()
}

/// A store whose lineage the user started from an attested prompt, by the request `init`.
pub fn initialized() -> MemoryLog {
    let log = MemoryLog::new();
    ran(
        &log,
        instruction("init", user(), Via::AttestedPrompt, Verb::Init(founding())),
    );
    log
}

/// Starts a task, as only a request does: the user's, from an attested prompt, by the request
/// `text`. It writes the request at `text` and the start at `text#1`.
pub fn start_task(log: &MemoryLog, text: &str) {
    assert_eq!(
        ran(
            log,
            instruction(text, user(), Via::AttestedPrompt, Verb::Task)
        ),
        Ran::TaskStarted {
            record: result(text)
        }
    );
}

pub fn observed(text: &str, event: Event, watch: Watch) -> Observed {
    Observed::new(id(text), event, watch).unwrap()
}

/// Observes the event with the watch.
pub fn observe(
    log: &MemoryLog,
    text: &str,
    event: Event,
    watch: Watch,
) -> Result<Response, ServiceError> {
    block_on(service(log).observe(&work(), observed(text, event, watch), &caps()))
}

/// Writes the act read back from the platform.
pub fn after(log: &MemoryLog, text: &str, event: Event) {
    assert_eq!(observe(log, text, event, Watch::After), Ok(Response::Pass));
}

pub const GATE: Watch = Watch::Gate {
    fallback: Fallback::Block,
};

/// The catalog in effect.
pub fn loaded(log: &MemoryLog) -> Loaded {
    match block_on(service(log).catalog()).unwrap() {
        CatalogState::Ready(loaded) => *loaded,
        other => panic!("no catalog in effect: {other:?}"),
    }
}

/// The records of the worktree's stream.
pub fn work_records(log: &MemoryLog) -> Vec<(EntryId, WorkRecord)> {
    log.records(&work_stream())
        .into_iter()
        .map(|(id, record)| match record {
            Record::Work(record) => (id, record),
            Record::Catalog(_) => panic!("a catalog record in the worktree's stream"),
        })
        .collect()
}
