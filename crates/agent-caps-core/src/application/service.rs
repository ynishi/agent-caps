//! The use cases: [`Service`], over one [`Log`].

use std::num::NonZeroU16;

use crate::domain::catalog::Capabilities;
use crate::domain::event::{Body, Event};
use crate::domain::state::Origin;

use super::load::{self, CatalogState, Pending};
use super::observe::{
    Fallback, Item, Observed, Response, Retry, ServiceError, Watch, Why, decide, record,
};
use super::port::{
    AppendError, BaseId, Broken, CatalogStream, Entry, Len, Log, ResultError, Seq, Slice, Stream,
    WorkKey, WorkStream,
};
use super::record::{ActSource, CatalogRecord, GenerationMark, Genesis, RequestEntry, WorkRecord};
use super::run::{Instruction, NotRun, Ran, Refused, Target, admission, judged_catalog, result_id};

/// The use cases of the application over a store. It holds no state of its own beyond the store
/// and how many times to try, so one value serves requests at once (`&self`), and each method's
/// future is `Send` when the store's are.
///
/// A hook goes in through [`Service::observe`] and [`Service::respond`], which both answer with
/// a [`Response`] whose direction (stop or pass) is decided here: the caller hands it to the
/// platform and decides nothing.
#[derive(Debug, Clone)]
pub struct Service<L> {
    log: L,
    retry: Retry,
}

/// Which stream an append was refused on, so the read after it is checked against the refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Catalog,
    Work,
}

impl<L: Log> Service<L> {
    /// The use cases over `log`, with the default number of tries ([`Retry::default`]).
    pub fn new(log: L) -> Self {
        Self {
            log,
            retry: Retry::default(),
        }
    }

    /// With `retry` tries.
    pub fn with_retry(self, retry: Retry) -> Self {
        Self { retry, ..self }
    }

    /// The store, given back. Closing it is the caller's: nothing here does I/O on drop.
    pub fn into_log(self) -> L {
        self.log
    }

    /// The last genesis, without replaying anything: who the roots of the lineage in effect are.
    pub async fn genesis(&self) -> Result<Option<Entry<Genesis>>, ServiceError> {
        let slice = self.log.read(&CatalogStream, Seq::FIRST).await?;
        load::rooted(&slice)?;
        Ok(load::last_genesis_entry(&slice))
    }

    /// The catalog as the store holds it ([`load::replay`]).
    pub async fn catalog(&self) -> Result<CatalogState, ServiceError> {
        let slice = self.log.read(&CatalogStream, Seq::FIRST).await?;
        Ok(load::replay(&slice)?)
    }

    /// The proposals of the lineage in effect that are neither approved nor rejected.
    pub async fn proposals(&self) -> Result<Vec<Pending>, ServiceError> {
        let slice = self.log.read(&CatalogStream, Seq::FIRST).await?;
        load::rooted(&slice)?;
        Ok(load::pending(&slice))
    }

    /// Judges and writes an observation of the worktree `work` on a platform with `caps`
    /// ([`super::observe`]). A failure is answered in the direction of the watch
    /// ([`Response::of_error`]): a stop for a watch that stops, the error for one that passes.
    pub async fn observe(
        &self,
        work: &WorkKey,
        observed: Observed,
        caps: &Capabilities,
    ) -> Result<Response, ServiceError> {
        let watch = observed.watch();
        match self.observed(work, &observed, caps).await {
            Ok(response) => Ok(response),
            Err(error) => Response::of_error(&watch, error),
        }
    }

    async fn observed(
        &self,
        work: &WorkKey,
        observed: &Observed,
        caps: &Capabilities,
    ) -> Result<Response, ServiceError> {
        let state = self.catalog().await?;
        let loaded = match state.ready() {
            Ok(loaded) => loaded,
            // Before a genesis there is no history to write to: the watch says only whether to
            // stop.
            Err(not_ready) => {
                return Ok(match observed.watch().fallback() {
                    Fallback::Block => Response::Block(Why::NotReady(not_ready)),
                    Fallback::Pass => Response::Pass,
                });
            }
        };
        let catalog = loaded.catalog();
        let under = GenerationMark::of(catalog.generation());
        let stream = WorkStream::new(work.clone());
        let mut slice = self.log.read(&stream, Seq::FIRST).await?;
        let mut folded = catalog.fold(
            Origin::Genesis,
            slice.entries().iter().filter_map(|e| e.record().folded()),
        );
        let mut attempts: u8 = 0;
        loop {
            // Written already: the same answer, judged after what came before it. An act read
            // back writes its own record (the base id); the judgments written for it ahead, under
            // the same id, do not stand for it.
            let prior = slice
                .prior(observed.id())
                .filter(|prior| match observed.watch() {
                    Watch::After => prior.base().is_some(),
                    Watch::Before | Watch::Gate { .. } => true,
                });
            if let Some(prior) = prior {
                let before = catalog.fold(
                    Origin::Genesis,
                    slice
                        .entries()
                        .iter()
                        .take_while(|e| e.seq() < prior.first())
                        .filter_map(|e| e.record().folded()),
                );
                return Ok(decide(catalog, before, observed, caps, &under)?.0);
            }
            if observed.watch().bounded() && attempts >= self.retry.attempts().get() {
                return Ok(Response::Block(Why::Contended { attempts }));
            }
            attempts = attempts.saturating_add(1);
            let (response, records) = decide(catalog, folded.clone(), observed, caps, &under)?;
            let expected = slice.len();
            match self.log.append(&stream, expected, records).await {
                Ok(_) => return Ok(response),
                Err(AppendError::Log(error)) => return Err(error.into()),
                Err(AppendError::Conflict { len }) => {
                    let more = self.reread(&stream, expected, len).await?;
                    for entry in more.entries() {
                        if let Some(event) = entry.record().folded() {
                            folded = catalog.apply(folded, event).map_err(|stale| stale.stale)?;
                        }
                    }
                    slice = slice.joined(more);
                }
            }
        }
    }

    /// The records written after `expected` by others, as an append refused with `len` found:
    /// checked to have grown, and to be read back at least as long.
    async fn reread<S: Stream>(
        &self,
        stream: &S,
        expected: Len,
        len: Len,
    ) -> Result<Slice<S::Record>, ServiceError> {
        let from = grown(expected, len)?;
        let more = self.log.read(stream, from).await?;
        if more.len() < len {
            return Err(Broken::RereadShorter {
                conflict: len,
                len: more.len(),
            }
            .into());
        }
        Ok(more)
    }

    /// Does the request and answers for the hook: always a stop ([`Response::of_run`]). The one
    /// way a hook makes an operation that writes.
    pub async fn respond(&self, instruction: Instruction) -> Response {
        Response::of_run(self.run(instruction).await)
    }

    /// Does the request ([`super::run`]): what it did, why it was not done, or the failure. For
    /// tests and for a caller that reads the result; a hook goes through [`Service::respond`].
    pub async fn run(&self, instruction: Instruction) -> Result<Result<Ran, NotRun>, ServiceError> {
        let request = instruction.request();
        let name = instruction.verb().name();
        let target = instruction.verb().target();
        let work = WorkStream::new(instruction.work().clone());
        let mut refused_at: Option<(Which, Len)> = None;
        let mut attempts: u8 = 0;
        loop {
            let catalog_slice = self.log.read(&CatalogStream, Seq::FIRST).await?;
            reread_at(refused_at, Which::Catalog, catalog_slice.len())?;
            let state = load::replay(&catalog_slice)?;
            let work_slice = self.log.read(&work, Seq::FIRST).await?;
            reread_at(refused_at, Which::Work, work_slice.len())?;
            // Done already, whatever the catalog has become since: the same result.
            if let Some(result) = done(target, request, &catalog_slice, &work_slice) {
                return result.map(Ok);
            }
            if attempts >= self.retry.attempts().get() {
                return Ok(Err(NotRun::Contended { attempts }));
            }
            attempts = attempts.saturating_add(1);
            let asked = work_slice
                .prior(request)
                .and_then(|prior| prior.base())
                .is_none()
                .then(|| {
                    let entry = RequestEntry::new(
                        name,
                        instruction.by().clone(),
                        instruction.at(),
                        instruction.via(),
                    );
                    (request.entry(), WorkRecord::Request(entry))
                });
            let admitted = admission(name, instruction.via(), &state);
            match target {
                Target::Catalog { verb, .. } => {
                    let judged = admitted.and_then(|standing| {
                        judged_catalog(&instruction, verb, standing, &state, &catalog_slice)
                    });
                    if let Some(asked) = asked {
                        let at = work_slice.len();
                        match self.log.append(&work, at, vec![asked]).await {
                            Ok(_) => {}
                            Err(AppendError::Log(error)) => return Err(error.into()),
                            Err(AppendError::Conflict { len }) => {
                                grown(at, len)?;
                                refused_at = Some((Which::Work, len));
                                continue;
                            }
                        }
                    }
                    let record = match judged {
                        Ok(record) => record,
                        Err(refused) => return Ok(Err(NotRun::Refused(refused))),
                    };
                    let id = result_id(request);
                    let at = catalog_slice.len();
                    let written = vec![(id, record)];
                    match self.log.append(&CatalogStream, at, written.clone()).await {
                        // Read as a later retry reads it. It is there, as `extended` checked the
                        // length; were it not, the next turn reads the store again.
                        Ok(len) => {
                            let catalog_slice = catalog_slice.extended(written, len)?;
                            if let Some(result) = done(target, request, &catalog_slice, &work_slice)
                            {
                                return result.map(Ok);
                            }
                        }
                        Err(AppendError::Log(error)) => return Err(error.into()),
                        Err(AppendError::Conflict { len }) => {
                            grown(at, len)?;
                            refused_at = Some((Which::Catalog, len));
                        }
                    }
                }
                Target::Work { .. } => {
                    let judged = admitted
                        .and_then(|_| state.ready().map_err(Refused::NotReady))
                        .map(|loaded| {
                            let catalog = loaded.catalog();
                            let folded = catalog.fold(
                                Origin::Genesis,
                                work_slice
                                    .entries()
                                    .iter()
                                    .filter_map(|e| e.record().folded()),
                            );
                            let start = Item::Act {
                                id: result_id(request),
                                event: Event {
                                    at: instruction.at(),
                                    by: instruction.by().clone(),
                                    body: Body::TaskStart,
                                },
                                source: ActSource::Instructed {
                                    request: request.clone(),
                                },
                            };
                            let under = GenerationMark::of(catalog.generation());
                            record(catalog, folded, &under, vec![start])
                        });
                    let (started, refused) = match judged {
                        Ok(recorded) => (recorded?.records, None),
                        Err(refused) => (Vec::new(), Some(refused)),
                    };
                    let written: Vec<_> = asked.into_iter().chain(started).collect();
                    // Refused, with the request written already: nothing to write.
                    if written.is_empty()
                        && let Some(refused) = refused
                    {
                        return Ok(Err(NotRun::Refused(refused)));
                    }
                    let at = work_slice.len();
                    match self.log.append(&work, at, written.clone()).await {
                        Ok(len) => {
                            if let Some(refused) = refused {
                                return Ok(Err(NotRun::Refused(refused)));
                            }
                            let work_slice = work_slice.extended(written, len)?;
                            if let Some(result) = done(target, request, &catalog_slice, &work_slice)
                            {
                                return result.map(Ok);
                            }
                        }
                        Err(AppendError::Log(error)) => return Err(error.into()),
                        Err(AppendError::Conflict { len }) => {
                            grown(at, len)?;
                            refused_at = Some((Which::Work, len));
                        }
                    }
                }
            }
        }
    }
}

/// The position to read from after an append that expected `expected` was refused with `len`:
/// refused when `len` is not greater, as the stream is only appended to.
fn grown(expected: Len, len: Len) -> Result<Seq, ServiceError> {
    match expected.next() {
        Some(from) if len > expected => Ok(from),
        _ => Err(Broken::ConflictNotLonger { expected, len }.into()),
    }
}

/// Checks the length read from `which` against the append refused on it, if it was.
fn reread_at(refused_at: Option<(Which, Len)>, which: Which, len: Len) -> Result<(), ServiceError> {
    match refused_at {
        Some((stream, conflict)) if stream == which && len < conflict => {
            Err(Broken::RereadShorter { conflict, len }.into())
        }
        _ => Ok(()),
    }
}

/// The result recorded for `request`, if any: the record at its first derived id, in the stream
/// its verb writes to, read as a result. The first time (just written) and every later time go
/// through here.
fn done(
    target: Target<'_>,
    request: &BaseId,
    catalog: &Slice<CatalogRecord>,
    work: &Slice<WorkRecord>,
) -> Option<Result<Ran, ServiceError>> {
    let first = NonZeroU16::MIN;
    let read = |result: Result<Ran, ResultError>| result.map_err(|e| Broken::Result(e).into());
    match target {
        Target::Catalog { expected, .. } => catalog
            .prior(request)
            .and_then(|prior| prior.child(first))
            .map(|entry| read(Ran::of_catalog(catalog, entry, expected))),
        Target::Work { expected } => work
            .prior(request)
            .and_then(|prior| prior.child(first))
            .map(|entry| read(Ran::of_task(entry, expected))),
    }
}
