//! The use cases around the model: keeping the catalog and the evidence in a store, judging what
//! the platform reports, and the operations that write.
//!
//! Pure as the domain is: no file system, process, environment, network, clock, randomness,
//! runtime or shared mutable state. The store is behind the one port, [`Log`]; times and ids come
//! in as values. The application uses the domain and the domain knows nothing of it;
//! `arch-lint.toml` keeps both so.
//!
//! ```text
//!  caller (an adapter)        Observed { id, event, watch }   Instruction { request, by, at, via, work, verb }
//!        │                               │                               │
//!        ▼                               ▼                               ▼
//!  Service<L: Log>   catalog(): read ─ load::replay ─▶ CatalogState { Empty | Ready | Unreplayable }
//!                    observe(): fold ─ judge, admit ─ record ─▶ append(work) ─▶ Response
//!                    respond() / run(): admission ─ accept, change, is_root, covers
//!                                       ─▶ append(work, Request) + append(catalog | work, result) ─▶ Ran
//!                    every turn: Slice::prior(id) ─▶ written already? the same answer, nothing written
//!                    Conflict { len' } ─▶ read what came after, judge again (no waiting)
//!        │ read(stream, from) ─▶ Slice { entries, len }     append(stream, expected, entries) ─▶ Len
//!        ▼
//!  Log    CatalogStream ─▶ CatalogRecord     WorkStream(WorkKey) ─▶ WorkRecord
//! ```
//!
//! # Invariants
//!
//! - The catalog's stream is one line. A record is appended only when the stream is as long as
//!   when it was read, so two changes made from the same read cannot both be written; the loser
//!   reads what was written meanwhile and is judged again, never merged.
//! - The catalog in effect is the replay of the records from the last genesis
//!   ([`load::replay`]). Its generation is the domain's alone
//!   ([`Catalog::generation`](crate::domain::catalog::Catalog::generation)): no record and no
//!   result keeps one of its own. A record keeps the generation it was judged under only as a
//!   copy read from the catalog ([`GenerationMark`]).
//! - A record's id comes from the act's or the request's id, and a retry carries the same one.
//!   Whether an act or a request was written already is decided in one place
//!   ([`Slice::prior`]), on every turn of a loop, the reads after a refused append included. A
//!   request whose result was written is answered with that result again, read from the record
//!   ([`Ran::of_catalog`], [`Ran::of_task`]), whatever the catalog has become since.
//! - Every record of a worktree's stream is made by one function, in order, a claim admitted
//!   after the state of what comes before it. An act is told from a claim by its kind; a claim
//!   keeps whether it took effect ([`WorkRecord`]). The rules fold the acts, the claims that took
//!   effect and the records that could not be read back ([`WorkRecord::folded`]), never a
//!   request.
//! - A record of a judgment, the answer of a classifier, a score and the start of a task are not
//!   taken from the platform ([`accepts_from_platform`]); a record of a judgment enters only from
//!   the judge, and the start of a task only from a request to start one.
//! - Who may ask for what from where is one table ([`run`]). A prompt the platform cannot show
//!   the user typed is judged as the platform's agent, and recorded so.
//!
//! # Answers and errors
//!
//! The entries a hook goes through, [`Service::observe`] and [`Service::respond`], both answer
//! with a [`Response`], and decide its direction here: the caller passes it to the platform and
//! decides nothing. A hook stops only on a stop, so leaving the direction of a failure to the
//! caller would let an act through.
//!
//! - An observation answers its refusals and its giving up as the [`Response`]. A failure is a
//!   stop with it for a watch that stops, and the error for one that passes
//!   ([`Response::of_error`], [`Watch::fallback`]); with no catalog to judge by, the same watch
//!   stops or passes and writes nothing.
//! - An operation that writes is always a stop, done, refused, given up on or failed
//!   ([`Response::of_run`]): the prompt that asked for it is not passed on to the model. The
//!   raw [`Service::run`] returns `Result<Result<Ran, NotRun>, ServiceError>`, for tests and for
//!   a caller that reads the result: a refusal ([`Refused`]) and giving up
//!   ([`NotRun::Contended`]) are answers, not failures.
//! - [`ServiceError`] is the failure of both. [`LogError`] is what a store reports;
//!   [`Broken`] is a broken promise that the application finds itself (an append refused with a
//!   length that did not grow, a read after it that is shorter, a catalog's stream that does not
//!   start with a genesis, a record found as a result that is not one), which a store cannot
//!   return; [`ServiceError::Stale`] is a bug of the application. A catalog the running version
//!   cannot replay is not a failure but [`Unreplayable`], whose way out is a new lineage; a
//!   broken stream does not open it.
//!
//! # Retries
//!
//! A refused append means another writer's went in, so the whole goes on without waiting, and
//! the application keeps no clock. An observation judged ahead and a request try as many times
//! as [`Retry`] says, then stop ([`Why::Contended`], [`NotRun::Contended`]). An observation
//! taken after the act is not cut short: dropping an act would make a count of acts loosen. It
//! tries until it is written or its caller drops the future, and on every turn checks that the
//! store kept its promise, so it never goes round on a broken one. Waiting belongs to the store
//! (its lock) and the caller (its deadline).
//!
//! # Known limitations
//!
//! - An observation reads the catalog once. A change of the catalog between that read and the
//!   append of the evidence is not detected; the record keeps the generation it was judged
//!   under.
//! - A change from a prompt the platform cannot show the user typed is recorded in the agent's
//!   name, the one it was judged as; that the user typed it is in the request at its first
//!   derived id.
//! - A sub agent is a leaf of the hierarchy of actors, not of the authority, so a change it asks
//!   for is refused as by an unknown principal.
//! - While the store is empty or cannot be replayed, an observation taken after the act writes
//!   nothing. A watch judged ahead stops meanwhile, so few acts are missed, but the history is
//!   not strictly whole.
//! - An observation taken after the act that its caller drops at its deadline is not written,
//!   as when the hook's process is killed; a count of acts may then loosen by it.
//! - A claim that did not take effect is not folded again, even when a later catalog would let
//!   it: whoever made it makes it again.
//! - A classifier's answer and a score cannot be written yet: they are not taken from the
//!   platform, and no other way in exists.
//! - A claim is judged with [`TxPolicy::standard`](crate::domain::tx::TxPolicy::standard) only:
//!   a transaction's policy is not `Send`, so the service does not hold one.
//! - A record of the catalog's stream that cannot be read back, or a stream that does not start
//!   with a genesis, has no way out inside agent-caps: a rebase reads the same stream. Watches
//!   that stop keep stopping until the store is repaired or replaced outside it.
//! - Every hook replays the catalog and folds the worktree's stream from the start.

pub mod load;
pub mod observe;
pub mod port;
pub mod record;
pub mod run;
mod service;

pub use load::{CatalogState, Loaded, NotReady, Pending, ReplayError, Unreplayable};
pub use observe::{Fallback, Observed, ObservedError, Response, Retry, ServiceError, Watch, Why};
pub use port::{
    AppendError, BaseId, Broken, BrokenSlice, CatalogStream, Entry, EntryId, EntryIdError, IdError,
    KeyError, Len, Log, LogError, Prior, Record, ResultError, Seq, Slice, Stream, StreamKey,
    WorkKey, WorkStream,
};
pub use record::{
    ActEntry, ActSource, ActorsError, Approved, CatalogRecord, Changed, ClaimEntry, ClaimSource,
    CoreVersion, Declined, EmptyVersion, GenerationMark, Genesis, LostEntry, PlatformActors,
    Proposed, RecordError, RequestEntry, VerbName, Via, WorkRecord, accepts_from_platform,
};
pub use run::{
    CatalogKind, CatalogVerb, Founding, Instruction, NotRun, Ran, Refused, SetEdit, Target, Verb,
    WorkKind,
};
pub use service::Service;
