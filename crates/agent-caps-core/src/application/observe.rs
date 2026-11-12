//! An observation of the platform: what to judge, what to write, and the answer for the hook.
//!
//! ```text
//! Observed { id, event, watch } ─ catalog().ready() ─▶ NotReady: watch.fallback() (Block | Pass)
//!   fold(Act, Claim(Commit), Lost)                 ─▶ prior(id)? the same answer, nothing written
//!   Before: judge a copy with the act ─▶ [Claim(Judged)…]            answer: of_outcome
//!   Gate:   judge a copy with the act ─▶ [Act, Claim(Judged)…] or, on Deny, [Claim(Judged)…]
//!   After:  ─▶ [Act] or [Claim]                                      answer: Pass, or Aborted
//!   append(work, len, records) ── Conflict { len' } ─▶ read after len, fold it in, judge again
//! ```
//!
//! Every record of a worktree's stream, the start of a task included, is made by one function
//! (`record`), so a claim is admitted after the state of what comes before it, and its decision
//! is kept with it.

use std::fmt;
use std::num::{NonZeroU8, NonZeroU16};

use crate::domain::catalog::{Capabilities, Catalog, StaleState};
use crate::domain::event::{Body, Event, Judgeable, Seen};
use crate::domain::judge::{Cause, Outcome, Verdict, judge};
use crate::domain::schema::{EventKind, Nature};
use crate::domain::state::State;
use crate::domain::tx::{TxDecision, TxPolicy, TxReport};

use super::load::NotReady;
use super::port::{BaseId, Broken, EntryId, LogError};
use super::record::{
    ActEntry, ActSource, ClaimEntry, ClaimSource, GenerationMark, RecordError, WorkRecord,
    accepts_from_platform,
};
use super::run::{NotRun, Ran, Refused};

/// How an observation is taken: judged ahead or not, and whether the act is written now. The
/// adapter chooses it for each hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Watch {
    /// Judged ahead, and the act is not written: it is written when it is read back after it
    /// happened (a tool use before the call).
    Before,
    /// Judged ahead, and the act is written unless it is stopped (the end of a turn, of a sub
    /// agent's turn, a prompt).
    Gate {
        /// What to answer when it cannot be judged.
        fallback: Fallback,
    },
    /// Written after it happened, and not judged (a tool use read back, a session start, a
    /// spawn).
    After,
}

impl Watch {
    /// Whether to stop when the observation cannot be judged: the one place that says it. A
    /// watch judged ahead with nothing to answer stops; one that ends a turn stops only when the
    /// adapter says so, as stopping it only keeps the agent working; one taken after the act
    /// cannot stop anything.
    pub fn fallback(&self) -> Fallback {
        match self {
            Self::Before => Fallback::Block,
            Self::Gate { fallback } => *fallback,
            Self::After => Fallback::Pass,
        }
    }

    /// Whether the act is judged ahead, and so whether a run of refused appends is cut short.
    pub(super) fn bounded(&self) -> bool {
        match self {
            Self::Before | Self::Gate { .. } => true,
            Self::After => false,
        }
    }
}

/// What an observation answers when it cannot be judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallback {
    /// Stop the act.
    Block,
    /// Let it through.
    Pass,
}

/// The event of an observation, held as the watch needs it: one that is judged ahead is a
/// [`Judgeable`], so [`decide`] gives it to [`judge`] without checking its kind again; one that is
/// read back is the [`Event`] it is. Each variant is one [`Watch`], so no watch is held with an
/// event it cannot be judged with.
#[derive(Debug, Clone, PartialEq)]
enum Observation {
    Before(Judgeable),
    Gate(Judgeable, Fallback),
    After(Event),
}

/// One observation: its id on the platform, the event, and how it is taken.
#[derive(Debug, Clone, PartialEq)]
pub struct Observed {
    id: BaseId,
    observation: Observation,
    replaced_path: Option<String>,
}

impl Observed {
    /// The observation. Refused when the event is of a kind not taken from the platform
    /// ([`accepts_from_platform`]), whatever the watch, and when a claim is to be judged ahead
    /// (only an act is), and when a record whose kind could not be read is to be judged ahead
    /// ([`ObservedError::UnreadableAhead`]). A tool use whose path is not in the one form
    /// ([`Observed::replaced_path`]) is taken as a tool use whose path could not be read
    /// ([`Seen::Unreadable`]), with its tool and command kept: a path in another form would let a
    /// rule over paths miss it (FR70).
    pub fn new(id: BaseId, mut event: Event, watch: Watch) -> Result<Self, ObservedError> {
        let kind = event.body.kind();
        if !accepts_from_platform(kind) {
            return Err(ObservedError::NotFromPlatform(kind));
        }
        if watch.bounded() && kind.nature() == Nature::Claim {
            return Err(ObservedError::ClaimBefore(kind));
        }
        let mut replaced_path = None;
        if let Body::ToolUse { path, .. } = &mut event.body
            && let Seen::Value(written) = path
            && !in_form(written)
        {
            replaced_path = Some(std::mem::take(written));
            *path = Seen::Unreadable;
        }
        let ahead =
            |event: Event| Judgeable::try_from(event).map_err(|_| ObservedError::UnreadableAhead);
        let observation = match watch {
            Watch::Before => Observation::Before(ahead(event)?),
            Watch::Gate { fallback } => Observation::Gate(ahead(event)?, fallback),
            Watch::After => Observation::After(event),
        };
        Ok(Self {
            id,
            observation,
            replaced_path,
        })
    }

    /// The id on the platform.
    pub fn id(&self) -> &BaseId {
        &self.id
    }

    /// The event as it is judged and written.
    pub fn event(&self) -> &Event {
        match &self.observation {
            Observation::Before(ahead) | Observation::Gate(ahead, _) => ahead.event(),
            Observation::After(event) => event,
        }
    }

    /// How it is taken.
    pub fn watch(&self) -> Watch {
        match &self.observation {
            Observation::Before(_) => Watch::Before,
            Observation::Gate(_, fallback) => Watch::Gate {
                fallback: *fallback,
            },
            Observation::After(_) => Watch::After,
        }
    }

    /// The path of a tool use that was not in the one form, when it was made unreadable for it.
    pub fn replaced_path(&self) -> Option<&str> {
        self.replaced_path.as_deref()
    }
}

/// Whether a path is in the one form a judgment reads: segments separated by `/`, none of them
/// empty, `.` or `..`, either relative to the worktree's root or absolute. Nothing is resolved:
/// the path is read as written.
fn in_form(path: &str) -> bool {
    let relative = path.strip_prefix('/').unwrap_or(path);
    !relative.is_empty()
        && relative
            .split('/')
            .all(|segment| !matches!(segment, "" | "." | ".."))
}

/// Why an observation was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservedError {
    /// The event is of a kind not taken from the platform ([`accepts_from_platform`]).
    NotFromPlatform(EventKind),
    /// A claim cannot be judged ahead.
    ClaimBefore(EventKind),
    /// A record whose kind could not be read ([`Body::Unreadable`]) cannot be judged ahead: it is
    /// no [`Judgeable`], and nothing can be said of it but that it is unknown. An event judged
    /// ahead has its kind, as the hook that reports it says what it is, so this is an error of
    /// the adapter that made the observation. The adapter is the one that calls
    /// [`Observed::new`]; the answer for its hook, when it is refused, is [`Watch::fallback`].
    UnreadableAhead,
}

impl fmt::Display for ObservedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFromPlatform(kind) => {
                write!(
                    f,
                    "an event of kind {kind:?} is not taken from the platform"
                )
            }
            Self::ClaimBefore(kind) => {
                write!(
                    f,
                    "an event of kind {kind:?} is a claim and is not judged ahead"
                )
            }
            Self::UnreadableAhead => {
                write!(
                    f,
                    "a record whose kind could not be read is not judged ahead"
                )
            }
        }
    }
}

impl std::error::Error for ObservedError {}

/// The answer for a hook, with why. Named apart from the answer of a classifier.
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    /// Let it through.
    Pass,
    /// Stop it.
    Block(Why),
    /// Let it through, and show why.
    Context(Why),
}

impl Response {
    /// The answer to a judgment: the one place a verdict becomes an answer. A deny stops, a
    /// warning is shown, an allow passes.
    pub fn of_outcome(outcome: &Outcome) -> Self {
        match &outcome.verdict {
            Verdict::Allow => Self::Pass,
            Verdict::Warn(_) => Self::Context(Why::Verdict(outcome.verdict.clone())),
            Verdict::Deny(_) => Self::Block(Why::Verdict(outcome.verdict.clone())),
        }
    }

    /// The answer to an operation that writes: always a stop, as the prompt that asked for it is
    /// not passed on to the model, whether it was done, refused, given up on or failed.
    pub fn of_run(result: Result<Result<Ran, NotRun>, ServiceError>) -> Self {
        Self::Block(match result {
            Ok(Ok(ran)) => Why::Ran(ran),
            Ok(Err(NotRun::Refused(refused))) => Why::Refused(refused),
            Ok(Err(NotRun::Contended { attempts })) => Why::Contended { attempts },
            Err(error) => Why::Failed(Box::new(error)),
        })
    }

    /// The answer to an observation that failed, in the direction [`Watch::fallback`] gives: a
    /// stop, with the failure, for a watch that stops; the failure itself for one that passes,
    /// so its caller sees that the evidence was not written. A hook stops only on a stop, so
    /// leaving the direction to how the caller reports an error would let a tool use through.
    pub fn of_error(watch: &Watch, error: ServiceError) -> Result<Self, ServiceError> {
        match watch.fallback() {
            Fallback::Block => Ok(Self::Block(Why::Failed(Box::new(error)))),
            Fallback::Pass => Err(error),
        }
    }
}

/// Why an answer is what it is, kept apart so that an adapter and a test read the kind and not
/// a text. The text is [`Display`](fmt::Display), the one place it is written.
#[derive(Debug, Clone, PartialEq)]
pub enum Why {
    /// The verdict of the guards that warned or denied.
    Verdict(Verdict),
    /// A claim was written and did not take effect.
    Aborted(TxReport),
    /// There is no catalog to judge by.
    NotReady(NotReady),
    /// The appends were refused as many times as the observation or request may try.
    Contended {
        /// How many times it tried.
        attempts: u8,
    },
    /// It could not be judged or done, for the failure.
    Failed(Box<ServiceError>),
    /// An operation that writes was done.
    Ran(Ran),
    /// An operation that writes was refused.
    Refused(Refused),
}

/// The causes of a verdict, as text.
fn causes(f: &mut fmt::Formatter<'_>, causes: &[Cause]) -> fmt::Result {
    causes.iter().try_for_each(|cause| match cause {
        Cause::Violated(policy) => write!(f, "\n- policy {policy} is not met"),
        Cause::Unknown(policy) => write!(
            f,
            "\n- policy {policy} cannot tell, as something it reads was not seen"
        ),
    })
}

impl fmt::Display for Why {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verdict(Verdict::Deny(list)) => {
                f.write_str("stopped by agent-caps:")?;
                causes(f, list)
            }
            Self::Verdict(Verdict::Warn(list)) => {
                f.write_str("agent-caps warns:")?;
                causes(f, list)
            }
            Self::Verdict(Verdict::Allow) => f.write_str("allowed by agent-caps"),
            Self::Aborted(report) => {
                f.write_str("the claim was recorded and did not take effect")?;
                if let Some(inadmissible) = &report.inadmissible {
                    write!(f, ": {inadmissible}")?;
                }
                report
                    .uncovered
                    .iter()
                    .try_for_each(|uncovered| write!(f, "\n- {uncovered}"))
            }
            Self::NotReady(not_ready) => not_ready.fmt(f),
            Self::Contended { attempts } => write!(
                f,
                "the store was written by others {attempts} times in a row; try again"
            ),
            Self::Failed(error) => match error.as_ref() {
                ServiceError::Log(LogError::Unavailable { reason }) => {
                    write!(f, "agent-caps cannot reach its store: {reason}")
                }
                ServiceError::Log(error @ LogError::Undecodable { .. }) => {
                    write!(f, "{error}; the store needs repair outside agent-caps")
                }
                ServiceError::Log(LogError::Broken(broken)) => {
                    write!(f, "the store broke its promise: {broken}")
                }
                ServiceError::Broken(broken) => {
                    write!(f, "the store broke its promise: {broken}")
                }
                ServiceError::Stale(stale) => {
                    write!(f, "an internal error of agent-caps: {stale}")
                }
                ServiceError::Record(error) => {
                    write!(f, "an internal error of agent-caps: {error}")
                }
            },
            Self::Ran(ran) => ran.fmt(f),
            Self::Refused(refused) => refused.fmt(f),
        }
    }
}

/// How many times an observation judged ahead, or a request, appends before it gives up. The
/// application does not wait between tries: a refused append means another writer's append
/// went in, so the whole goes on without waiting. Waiting belongs to the store (its lock) and
/// to the caller (its deadline). An observation taken after the act is not cut short at all: it
/// tries until it is written or its caller drops it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retry {
    attempts: NonZeroU8,
}

impl Retry {
    /// `attempts` tries.
    pub fn new(attempts: NonZeroU8) -> Self {
        Self { attempts }
    }

    /// The number of tries.
    pub fn attempts(&self) -> NonZeroU8 {
        self.attempts
    }
}

impl Default for Retry {
    /// Eight tries.
    fn default() -> Self {
        Self {
            attempts: NonZeroU8::new(8).unwrap_or(NonZeroU8::MIN),
        }
    }
}

/// A failure of an observation or a request, which both return.
///
/// An observation returns its refusals and its giving up as the answer, and a failure as this
/// (or, for a watch that stops, as a stop with it: [`Response::of_error`]). A request has a
/// result and a reason it was not done ([`NotRun`]), neither a failure, so it returns
/// `Result<Result<Ran, NotRun>, ServiceError>`. The shapes differ by what succeeds; the failure
/// is the same.
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceError {
    /// The store failed.
    Log(LogError),
    /// A state was judged under a catalog of another generation. The catalog and the state come
    /// from one load, so the domain's apply, admit and judge under an observation or the start of
    /// a task meet this only through a bug of the application: it is returned, not hidden.
    Stale(StaleState),
    /// A promise the application checks was broken ([`Broken`]).
    Broken(Broken),
    /// A record the application made was refused by its own constructor. The application gives
    /// each constructor only what it takes, so this is met only through a bug of the
    /// application, and is returned, as [`ServiceError::Stale`] is.
    Record(RecordError),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Log(error) => error.fmt(f),
            Self::Stale(stale) => stale.fmt(f),
            Self::Broken(broken) => broken.fmt(f),
            Self::Record(error) => error.fmt(f),
        }
    }
}

impl From<RecordError> for ServiceError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

impl std::error::Error for ServiceError {}

impl From<LogError> for ServiceError {
    fn from(error: LogError) -> Self {
        Self::Log(error)
    }
}

impl From<Broken> for ServiceError {
    fn from(broken: Broken) -> Self {
        Self::Broken(broken)
    }
}

impl From<StaleState> for ServiceError {
    fn from(stale: StaleState) -> Self {
        Self::Stale(stale)
    }
}

/// One record to write: an act, or a claim whose decision [`record`] gives.
pub(super) enum Item {
    /// An act.
    Act {
        id: EntryId,
        event: Event,
        source: ActSource,
    },
    /// A claim.
    Claim {
        id: EntryId,
        event: Event,
        source: ClaimSource,
    },
}

/// What [`record`] made: the records, and the report of each claim's transaction, in order, so
/// the answer to a claim that did not take effect is not admitted a second time.
pub(super) struct Recorded {
    pub(super) records: Vec<(EntryId, WorkRecord)>,
    pub(super) reports: Vec<TxReport>,
}

/// The records of `items`, after `state`, judged under `under`: the one function every record of
/// a worktree's stream is made by. In order: an act is applied; a claim is admitted after the
/// state of every item before it, keeps the decision, and is then applied. The transaction's
/// policy is made here and used up here: it is not `Send`, so it is never held across an await,
/// and this function has none.
pub(super) fn record(
    catalog: &Catalog,
    state: State,
    under: &GenerationMark,
    items: Vec<Item>,
) -> Result<Recorded, ServiceError> {
    let policy = TxPolicy::standard();
    let mut state = state;
    let mut records = Vec::with_capacity(items.len());
    let mut reports = Vec::new();
    for item in items {
        // The constructors check each record, as they do for a store: the callers give an act
        // from the platform only for an act, a request's act only for the start of a task, the
        // judge's claims from its evidence, and a claim from the platform through
        // `Observed::new`. A refusal is a bug of the application, and is returned.
        let (id, event, record) = match item {
            Item::Act { id, event, source } => {
                let entry = match source {
                    ActSource::Platform => ActEntry::observed(under.clone(), event.clone()),
                    ActSource::Instructed { request } => {
                        ActEntry::instructed(under.clone(), event.clone(), request)
                    }
                }?;
                (id, event, WorkRecord::Act(entry))
            }
            Item::Claim { id, event, source } => {
                let report = catalog.admit(&state, &event, &policy)?;
                let decision = report.decision;
                reports.push(report);
                let entry = match source {
                    ClaimSource::Judge => {
                        ClaimEntry::judged(under.clone(), event.clone(), decision)
                    }
                    ClaimSource::Platform => {
                        ClaimEntry::observed(under.clone(), event.clone(), decision)
                    }
                }?;
                (id, event, WorkRecord::Claim(entry))
            }
        };
        state = catalog
            .apply_with(state, &event, &policy)
            .map_err(|stale| stale.stale)?;
        records.push((id, record));
    }
    Ok(Recorded { records, reports })
}

/// The answer to `observed` after `state`, and the records to write for it.
pub(super) fn decide(
    catalog: &Catalog,
    state: State,
    observed: &Observed,
    caps: &Capabilities,
    under: &GenerationMark,
) -> Result<(Response, Vec<(EntryId, WorkRecord)>), ServiceError> {
    let id = observed.id();
    let judged = |state: &State, ahead: &Judgeable| -> Result<(Outcome, Vec<Item>), StaleState> {
        let copy = catalog
            .apply(state.clone(), ahead.event())
            .map_err(|stale| stale.stale)?;
        let outcome = judge(catalog, &copy, ahead, caps)?;
        let claims = outcome
            .evidence(ahead.event().at)
            .into_iter()
            .zip(1u16..)
            .filter_map(|(judgment, k)| {
                NonZeroU16::new(k).map(|k| Item::Claim {
                    id: id.child(k),
                    event: judgment,
                    source: ClaimSource::Judge,
                })
            })
            .collect();
        Ok((outcome, claims))
    };
    match &observed.observation {
        Observation::Before(ahead) => {
            let (outcome, claims) = judged(&state, ahead)?;
            let recorded = record(catalog, state, under, claims)?;
            Ok((Response::of_outcome(&outcome), recorded.records))
        }
        Observation::Gate(ahead, _) => {
            let (outcome, claims) = judged(&state, ahead)?;
            let response = Response::of_outcome(&outcome);
            let items = match response {
                Response::Block(_) => claims,
                Response::Pass | Response::Context(_) => {
                    let act = Item::Act {
                        id: id.entry(),
                        event: ahead.event().clone(),
                        source: ActSource::Platform,
                    };
                    std::iter::once(act).chain(claims).collect()
                }
            };
            let recorded = record(catalog, state, under, items)?;
            Ok((response, recorded.records))
        }
        Observation::After(event) => {
            let item = match event.body.kind().nature() {
                Nature::Act => Item::Act {
                    id: id.entry(),
                    event: event.clone(),
                    source: ActSource::Platform,
                },
                Nature::Claim => Item::Claim {
                    id: id.entry(),
                    event: event.clone(),
                    source: ClaimSource::Platform,
                },
            };
            let recorded = record(catalog, state, under, vec![item])?;
            let response = match recorded.reports.into_iter().next() {
                Some(report) if report.decision == TxDecision::Abort => {
                    Response::Context(Why::Aborted(report))
                }
                Some(_) | None => Response::Pass,
            };
            Ok((response, recorded.records))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::port::{Len, Seq};
    use crate::application::record::RecordError;
    use crate::domain::authority::Principal;
    use crate::domain::name::ClassifierName;
    use crate::domain::policy::Level;
    use crate::domain::schema::{At, Judgment};
    use crate::domain::state::Lineage;

    fn event(body: Body) -> Event {
        Event {
            at: At::from_millis(0),
            by: Principal::new("agent"),
            body,
        }
    }

    fn edit(path: &str) -> Event {
        event(Body::ToolUse {
            tool: "Edit".to_owned(),
            command: Seen::Absent,
            path: Seen::Value(path.to_owned()),
            ok: None,
        })
    }

    fn id() -> BaseId {
        BaseId::new("tool-1").unwrap()
    }

    fn error() -> ServiceError {
        ServiceError::Log(LogError::Unavailable {
            reason: "down".to_owned(),
        })
    }

    const WATCHES: [Watch; 4] = [
        Watch::Before,
        Watch::Gate {
            fallback: Fallback::Block,
        },
        Watch::Gate {
            fallback: Fallback::Pass,
        },
        Watch::After,
    ];

    #[test]
    fn the_fallback_of_a_watch() {
        let fallbacks: Vec<Fallback> = WATCHES.iter().map(Watch::fallback).collect();
        assert_eq!(
            fallbacks,
            [
                Fallback::Block,
                Fallback::Block,
                Fallback::Pass,
                Fallback::Pass
            ]
        );
    }

    #[test]
    fn a_failure_stops_a_watch_that_stops_and_is_returned_by_one_that_passes() {
        let stop = Ok(Response::Block(Why::Failed(Box::new(error()))));
        let results: Vec<_> = WATCHES
            .iter()
            .map(|watch| Response::of_error(watch, error()))
            .collect();
        assert_eq!(results, [stop.clone(), stop, Err(error()), Err(error())]);
    }

    #[test]
    fn an_operation_that_writes_is_always_stopped() {
        let ran = Ran::TaskStarted {
            record: id().entry(),
        };
        assert_eq!(
            Response::of_run(Ok(Ok(ran.clone()))),
            Response::Block(Why::Ran(ran))
        );
        assert_eq!(
            Response::of_run(Ok(Err(NotRun::Refused(Refused::NotRoot)))),
            Response::Block(Why::Refused(Refused::NotRoot))
        );
        assert_eq!(
            Response::of_run(Ok(Err(NotRun::Contended { attempts: 8 }))),
            Response::Block(Why::Contended { attempts: 8 })
        );
        assert_eq!(
            Response::of_run(Err(error())),
            Response::Block(Why::Failed(Box::new(error())))
        );
    }

    #[test]
    fn a_failure_is_told_by_its_kind() {
        let text = |error: ServiceError| Why::Failed(Box::new(error)).to_string();
        let texts = [
            text(error()),
            text(ServiceError::Log(LogError::Undecodable {
                stream: super::super::port::StreamKey::Catalog,
                seq: Seq::FIRST,
                reason: "bad".to_owned(),
            })),
            text(ServiceError::Broken(Broken::ConflictNotLonger {
                expected: Len::ZERO,
                len: Len::ZERO,
            })),
            text(ServiceError::Log(LogError::Broken(
                super::super::port::BrokenSlice::Short {
                    last: Seq::FIRST,
                    len: Len::ZERO,
                },
            ))),
        ];
        assert!(texts[0].contains("cannot reach"));
        assert!(texts[1].contains("repair outside"));
        assert!(texts[2].contains("broke its promise"));
        assert!(texts[3].contains("broke its promise"));
        assert_ne!(texts[0], texts[1]);
    }

    #[test]
    fn the_same_kinds_are_refused_from_the_platform_by_an_observation_and_a_claim() {
        let under = GenerationMark {
            lineage: Lineage::new("l").unwrap(),
            n: 0,
        };
        let claims = [
            event(Body::Judged {
                policy: "00000000-0000-7000-8000-000000000001".parse().unwrap(),
                judgment: Judgment::Allowed,
                written: Level::Force,
                enforced: Level::Force,
            }),
            event(Body::Classified {
                classifier: "c@1".parse::<ClassifierName>().unwrap(),
                answer: 0.5,
            }),
            event(Body::Measured {
                oracle: "o".to_owned(),
                score: 1.0,
            }),
        ];
        for claim in claims {
            let kind = claim.body.kind();
            for watch in WATCHES {
                assert_eq!(
                    Observed::new(id(), claim.clone(), watch),
                    Err(ObservedError::NotFromPlatform(kind))
                );
            }
            assert_eq!(
                ClaimEntry::observed(under.clone(), claim, TxDecision::Commit),
                Err(RecordError::NotFromPlatform(kind))
            );
        }
        // The start of a task is an act, refused by an observation and by an act the same way.
        let start = event(Body::TaskStart);
        for watch in WATCHES {
            assert_eq!(
                Observed::new(id(), start.clone(), watch),
                Err(ObservedError::NotFromPlatform(EventKind::TaskStart))
            );
        }
        assert_eq!(
            ActEntry::observed(under, start),
            Err(RecordError::NotFromPlatform(EventKind::TaskStart))
        );
    }

    #[test]
    fn a_path_not_in_the_one_form_is_an_unreadable_path_of_the_same_tool_use() {
        for path in ["src/a.rs", "a", "/abs/b", ".hidden/x"] {
            assert!(in_form(path), "{path}");
            let observed = Observed::new(id(), edit(path), Watch::After).unwrap();
            assert_eq!(observed.replaced_path(), None);
            assert_eq!(observed.event(), &edit(path));
        }
        for path in ["", "/", "./a", "a/../b", "a//b", "a/", "..", "/a/./b"] {
            assert!(!in_form(path), "{path}");
            let observed = Observed::new(id(), edit(path), Watch::Before).unwrap();
            assert_eq!(observed.replaced_path(), Some(path));
            assert_eq!(
                observed.event().body,
                Body::ToolUse {
                    tool: "Edit".to_owned(),
                    command: Seen::Absent,
                    path: Seen::Unreadable,
                    ok: None,
                }
            );
        }
    }
}
