//! An operation that writes: the request, who may make it from where, the domain's judgment, and
//! its result.
//!
//! ```text
//! Instruction { request, by, at, via, work, verb }
//!   read catalog, work ─▶ prior(request)#1? ─▶ Ran::of_catalog / of_task (the same result again)
//!   append Request (once) ─▶ admission(verb, via) ─▶ accept · change · is_root · covers
//!   append the result at request#1 ─▶ Ran::of_catalog / of_task
//!   Conflict ─▶ from the top: judged again on what was written meanwhile
//! ```
//!
//! Who may ask for what from where is one table, kept in one function (`admission`):
//!
//! | verb | tool call | prompt | attested prompt |
//! |---|---|---|---|
//! | init | refused | taken | taken |
//! | rebase | refused | taken only when the catalog cannot be replayed | taken |
//! | change, import | taken | judged as the agent | taken |
//! | approve | taken | refused | taken |
//! | reject | taken | taken | taken |
//! | task | refused | refused | taken |
//!
//! A prompt the platform cannot show the user typed is judged as the platform's agent: the
//! weakest one who could have written it, so it opens nothing the agent could not do from a tool
//! call. Who asked, and how, is kept in the request. Then the domain judges: an init only in an
//! empty store and by the root the actors name as the user; a rebase by a root of the last
//! genesis, read without replaying; a change or an import by
//! [`Catalog::change`](crate::domain::catalog::Catalog::change), a loosening kept as a proposal
//! (or refused, for one judged as the agent); an approval from the generation its proposal was
//! made from; a rejection by the maker or one who covers the maker.

use std::fmt;
use std::num::NonZeroU16;

use crate::domain::authority::{Authority, Principal};
use crate::domain::catalog::{Catalog, Rejected};
use crate::domain::change::{ChangeRejected, Loosening};
use crate::domain::schema::At;
use crate::domain::set::{SetId, Source, Sources, SourcesError};
use crate::domain::state::Lineage;

use super::load::{self, CatalogState, Loaded, NotReady};
use super::port::{BaseId, Entry, EntryId, ResultError, Slice, WorkKey};
use super::record::{
    ActSource, ActorsError, Approved, CatalogRecord, Changed, CoreVersion, Declined,
    GenerationMark, Genesis, PlatformActors, Proposed, VerbName, Via, WorkRecord,
};

/// A request to write, as the adapter reads it: its id, who asked as the platform reports, when,
/// from where, for which worktree, and what.
#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    request: BaseId,
    by: Principal,
    at: At,
    via: Via,
    work: WorkKey,
    verb: Verb,
}

impl Instruction {
    /// The request.
    pub fn new(
        request: BaseId,
        by: Principal,
        at: At,
        via: Via,
        work: WorkKey,
        verb: Verb,
    ) -> Self {
        Self {
            request,
            by,
            at,
            via,
            work,
            verb,
        }
    }

    /// The id of the request: a retry carries the same one.
    pub fn request(&self) -> &BaseId {
        &self.request
    }

    /// Who asked, as the platform reports.
    pub fn by(&self) -> &Principal {
        &self.by
    }

    /// When.
    pub fn at(&self) -> At {
        self.at
    }

    /// From where.
    pub fn via(&self) -> Via {
        self.via
    }

    /// The worktree whose stream keeps the request.
    pub fn work(&self) -> &WorkKey {
        &self.work
    }

    /// What is asked.
    pub fn verb(&self) -> &Verb {
        &self.verb
    }
}

/// What a request asks for.
#[derive(Debug, Clone, PartialEq)]
pub enum Verb {
    /// Start the first lineage of an empty store.
    Init(Founding),
    /// Start a new lineage over the catalog. This is also how the hierarchy changes; it is not
    /// judged as a change.
    Rebase(Founding),
    /// Change the sets.
    Change(SetEdit),
    /// Bring in a set: it is added, or replaces the set with its id.
    Import(Source),
    /// Approve the proposal.
    Approve(EntryId),
    /// Reject the proposal.
    Reject(EntryId),
    /// Start a task.
    Task,
}

impl Verb {
    /// Its name.
    pub fn name(&self) -> VerbName {
        match self {
            Self::Init(_) => VerbName::Init,
            Self::Rebase(_) => VerbName::Rebase,
            Self::Change(_) => VerbName::Change,
            Self::Import(_) => VerbName::Import,
            Self::Approve(_) => VerbName::Approve,
            Self::Reject(_) => VerbName::Reject,
            Self::Task => VerbName::Task,
        }
    }

    /// Where the verb's result is written, of which kind, and, for the catalog's stream, the
    /// verb with what it holds: the one table, which writing a result and matching one found
    /// later both read. Split by the stream, so the judgment of the catalog's verbs takes only
    /// those, and each result is matched against the records of its own stream's type.
    pub fn target(&self) -> Target<'_> {
        let catalog = |verb, expected| Target::Catalog { verb, expected };
        match self {
            Self::Init(founding) => catalog(CatalogVerb::Init(founding), CatalogKind::FirstGenesis),
            Self::Rebase(founding) => {
                catalog(CatalogVerb::Rebase(founding), CatalogKind::LaterGenesis)
            }
            Self::Change(edit) => {
                catalog(CatalogVerb::Change(edit), CatalogKind::ChangedOrProposed)
            }
            Self::Import(source) => {
                catalog(CatalogVerb::Import(source), CatalogKind::ChangedOrProposed)
            }
            Self::Approve(id) => catalog(CatalogVerb::Approve(id), CatalogKind::Approved),
            Self::Reject(id) => catalog(CatalogVerb::Reject(id), CatalogKind::Declined),
            Self::Task => Target::Work {
                expected: WorkKind::TaskStarted,
            },
        }
    }
}

/// Where a verb's result is written ([`Verb::target`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Target<'a> {
    /// A record of the catalog's stream.
    Catalog {
        /// The verb.
        verb: CatalogVerb<'a>,
        /// The kind of its result.
        expected: CatalogKind,
    },
    /// A record of the worktree's stream: the start of a task.
    Work {
        /// The kind of its result.
        expected: WorkKind,
    },
}

/// A verb whose result is a record of the catalog's stream, with what it holds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CatalogVerb<'a> {
    /// [`Verb::Init`].
    Init(&'a Founding),
    /// [`Verb::Rebase`].
    Rebase(&'a Founding),
    /// [`Verb::Change`].
    Change(&'a SetEdit),
    /// [`Verb::Import`].
    Import(&'a Source),
    /// [`Verb::Approve`].
    Approve(&'a EntryId),
    /// [`Verb::Reject`].
    Reject(&'a EntryId),
}

/// What a new lineage starts from: the sets, the hierarchy, and the platform's actors in it.
#[derive(Debug, Clone, PartialEq)]
pub struct Founding {
    sources: Sources,
    authority: Authority,
    actors: PlatformActors,
}

impl Founding {
    /// The founding, when the actors are in `authority` as [`PlatformActors::new`] says.
    pub fn new(
        sources: Sources,
        authority: Authority,
        actors: PlatformActors,
    ) -> Result<Self, ActorsError> {
        let (user, agent) = (actors.user().clone(), actors.agent().clone());
        let actors = PlatformActors::new(user, agent, &authority)?;
        Ok(Self {
            sources,
            authority,
            actors,
        })
    }

    /// The sets.
    pub fn sources(&self) -> &Sources {
        &self.sources
    }

    /// The hierarchy.
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// The platform's actors.
    pub fn actors(&self) -> &PlatformActors {
        &self.actors
    }
}

/// A change of the sets, as the domain makes it from the catalog's sets.
#[derive(Debug, Clone, PartialEq)]
pub enum SetEdit {
    /// Add a set ([`Sources::with`]).
    Add(Source),
    /// Remove the set ([`Sources::without`]).
    Remove(SetId),
    /// Swap the set with the id for this one ([`Sources::replaced`]).
    Replace(Source),
}

impl SetEdit {
    /// The sets after the edit.
    fn applied(&self, sources: &Sources) -> Result<Sources, SourcesError> {
        match self {
            Self::Add(source) => sources.with(source.clone()),
            Self::Remove(id) => sources.without(id),
            Self::Replace(source) => sources.replaced(source.clone()),
        }
    }
}

/// The sets after importing `source`: it replaces the set with its id, or is added.
fn imported(sources: &Sources, source: &Source) -> Result<Sources, SourcesError> {
    match sources.get(&source.id) {
        Some(_) => sources.replaced(source.clone()),
        None => sources.with(source.clone()),
    }
}

/// The kind of a record of the catalog's stream, as a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogKind {
    /// The first genesis of the stream.
    FirstGenesis,
    /// A genesis after another.
    LaterGenesis,
    /// A change, or the proposal a change became.
    ChangedOrProposed,
    /// An approval.
    Approved,
    /// A rejection.
    Declined,
}

impl CatalogKind {
    /// The kind of `entry`, a record of `slice`, as a result: the one place that says it. Every
    /// record of the catalog's stream has one, so this never fails. A genesis is the first or a
    /// later one by whether a genesis comes before it in `slice`: where it is, not what it holds.
    pub fn of(slice: &Slice<CatalogRecord>, entry: &Entry<CatalogRecord>) -> Self {
        match entry.record() {
            CatalogRecord::Genesis(_) => {
                let earlier = slice.entries().iter().any(|other| {
                    other.seq() < entry.seq() && matches!(other.record(), CatalogRecord::Genesis(_))
                });
                if earlier {
                    Self::LaterGenesis
                } else {
                    Self::FirstGenesis
                }
            }
            CatalogRecord::Changed(_) | CatalogRecord::Proposed(_) => Self::ChangedOrProposed,
            CatalogRecord::Approved(_) => Self::Approved,
            CatalogRecord::Declined(_) => Self::Declined,
        }
    }
}

/// The kind of a record of a worktree's stream, as a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkKind {
    /// The start of a task, made by a request.
    TaskStarted,
}

impl WorkKind {
    /// The kind of `entry` as a result: the start of a task made by a request is one; any other
    /// record is none. A record that could not be read back is told apart by
    /// [`Ran::of_task`].
    pub fn of(entry: &Entry<WorkRecord>) -> Option<Self> {
        match entry.record() {
            WorkRecord::Act(act) => match (act.source(), &act.event().body) {
                (ActSource::Instructed { .. }, crate::domain::event::Body::TaskStart) => {
                    Some(Self::TaskStarted)
                }
                _ => None,
            },
            WorkRecord::Claim(_) | WorkRecord::Lost(_) | WorkRecord::Request(_) => None,
        }
    }
}

/// What an operation that writes did, read from the record of its result: the record's id
/// (the request's first derived id), and what of the record the caller needs. It holds no
/// generation: a caller that wants it reads the catalog's
/// [`generation()`](crate::domain::catalog::Catalog::generation). The generation is the
/// domain's, kept in one place, and the application neither counts nor copies it here.
#[derive(Debug, Clone, PartialEq)]
pub enum Ran {
    /// The first lineage started.
    Initialized {
        /// The genesis.
        record: EntryId,
    },
    /// A new lineage started.
    Rebased {
        /// The genesis.
        record: EntryId,
    },
    /// The change took effect.
    Changed {
        /// The change.
        record: EntryId,
    },
    /// The change loosens what its maker does not cover, and was kept as a proposal.
    Proposed {
        /// The proposal: the id an approval or a rejection names.
        record: EntryId,
        /// How it loosens, as the domain judged it.
        loosens: Vec<Loosening>,
    },
    /// The proposal was approved and took effect.
    Approved {
        /// The approval.
        record: EntryId,
        /// The proposal it settles.
        proposal: EntryId,
    },
    /// The proposal was rejected.
    Declined {
        /// The rejection.
        record: EntryId,
        /// The proposal it settles.
        proposal: EntryId,
    },
    /// The task started.
    TaskStarted {
        /// The start of the task.
        record: EntryId,
    },
}

impl Ran {
    /// The result that `entry`, a record of `slice`, is, when it is of the `expected` kind: the
    /// one way a result of the catalog's stream is read, the first time (just written) and every
    /// later time (found again). It replays nothing, judges nothing again and counts no
    /// generation: it reads the record's kind ([`CatalogKind::of`]) and copies its id and what it
    /// holds. A record of another kind is not a result.
    pub fn of_catalog(
        slice: &Slice<CatalogRecord>,
        entry: &Entry<CatalogRecord>,
        expected: CatalogKind,
    ) -> Result<Ran, ResultError> {
        let record = entry.id().clone();
        let not_a_result = || ResultError::NotAResult { id: record.clone() };
        if CatalogKind::of(slice, entry) != expected {
            return Err(not_a_result());
        }
        match (expected, entry.record()) {
            (CatalogKind::FirstGenesis, _) => Ok(Ran::Initialized { record }),
            (CatalogKind::LaterGenesis, _) => Ok(Ran::Rebased { record }),
            (CatalogKind::ChangedOrProposed, CatalogRecord::Proposed(proposed)) => {
                Ok(Ran::Proposed {
                    loosens: proposed.loosens().to_vec(),
                    record,
                })
            }
            (CatalogKind::ChangedOrProposed, _) => Ok(Ran::Changed { record }),
            (CatalogKind::Approved, CatalogRecord::Approved(approved)) => Ok(Ran::Approved {
                proposal: approved.proposal().clone(),
                record,
            }),
            (CatalogKind::Declined, CatalogRecord::Declined(declined)) => Ok(Ran::Declined {
                proposal: declined.proposal().clone(),
                record,
            }),
            (CatalogKind::Approved | CatalogKind::Declined, _) => Err(not_a_result()),
        }
    }

    /// The result that `entry`, a record of a worktree's stream, is, when it is of the
    /// `expected` kind ([`WorkKind::of`]). A record that could not be read back is reported as
    /// one; any other record is not a result.
    pub fn of_task(entry: &Entry<WorkRecord>, expected: WorkKind) -> Result<Ran, ResultError> {
        let record = entry.id().clone();
        if WorkKind::of(entry) == Some(expected) {
            return match expected {
                WorkKind::TaskStarted => Ok(Ran::TaskStarted { record }),
            };
        }
        match entry.record() {
            WorkRecord::Lost(_) => Err(ResultError::ResultUnreadable { id: record }),
            WorkRecord::Act(_) | WorkRecord::Claim(_) | WorkRecord::Request(_) => {
                Err(ResultError::NotAResult { id: record })
            }
        }
    }
}

impl fmt::Display for Ran {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initialized { record } => write!(f, "the catalog was started ({record})"),
            Self::Rebased { record } => {
                write!(f, "a new lineage of the catalog was started ({record})")
            }
            Self::Changed { record } => write!(f, "the change took effect ({record})"),
            Self::Proposed { record, loosens } => {
                write!(
                    f,
                    "the change loosens what its maker does not cover, and was kept as the proposal {record}:"
                )?;
                loosens
                    .iter()
                    .try_for_each(|loosening| write!(f, "\n- {loosening}"))
            }
            Self::Approved { record, proposal } => {
                write!(f, "the proposal {proposal} was approved ({record})")
            }
            Self::Declined { record, proposal } => {
                write!(f, "the proposal {proposal} was rejected ({record})")
            }
            Self::TaskStarted { record } => write!(f, "the task started ({record})"),
        }
    }
}

/// Why an operation that writes was refused. A refused request leaves no result, so a retry of it
/// is judged again.
#[derive(Debug, Clone, PartialEq)]
pub enum Refused {
    /// There is no catalog to judge by: the store is empty (for any verb but init), or it cannot
    /// be replayed (for any verb but rebase).
    NotReady(NotReady),
    /// A lineage has started already.
    AlreadyInitialized,
    /// The one who asks is not a root of the hierarchy (of the last genesis, for a rebase), or,
    /// for an init, not the root the actors name as the user.
    NotRoot,
    /// Not taken from a prompt the platform cannot show the user typed.
    NeedsAttestedPrompt(VerbName),
    /// Not taken from an agent's tool call.
    NotFromToolCall(VerbName),
    /// The sets are not accepted as a catalog.
    Invalid(Rejected),
    /// The edit does not make sets.
    Sources(SourcesError),
    /// The domain refused the change. A change or an import that loosens becomes a proposal
    /// instead, so a loosening here is an approval's, or one of a prompt judged as the agent.
    Change(ChangeRejected),
    /// No proposal has the id.
    UnknownProposal(EntryId),
    /// The proposal was approved or rejected already.
    Settled(EntryId),
    /// The proposal was made from another generation than the one in effect.
    Outdated {
        /// The proposal.
        proposal: EntryId,
        /// The generation it was made from.
        base: GenerationMark,
        /// The generation in effect.
        current: GenerationMark,
    },
    /// The one who rejects is neither the proposal's maker nor one who covers the maker.
    NotMakerOrAbove {
        /// The proposal.
        proposal: EntryId,
    },
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReady(not_ready) => not_ready.fmt(f),
            Self::AlreadyInitialized => f.write_str("the catalog was started already"),
            Self::NotRoot => f.write_str("only a root of the hierarchy may do this"),
            Self::NeedsAttestedPrompt(verb) => write!(
                f,
                "{verb} is not taken from a prompt the platform cannot show the user typed"
            ),
            Self::NotFromToolCall(verb) => {
                write!(f, "{verb} is not taken from an agent's tool call")
            }
            Self::Invalid(rejected) => rejected.fmt(f),
            Self::Sources(error) => error.fmt(f),
            Self::Change(rejected) => rejected.fmt(f),
            Self::UnknownProposal(id) => write!(f, "no proposal has the id {id}"),
            Self::Settled(id) => write!(f, "the proposal {id} was settled already"),
            Self::Outdated {
                proposal,
                base,
                current,
            } => write!(
                f,
                "the proposal {proposal} was made from {base}, and {current} is in effect"
            ),
            Self::NotMakerOrAbove { proposal } => write!(
                f,
                "only the maker of the proposal {proposal}, or one who covers the maker, may reject it"
            ),
        }
    }
}

/// Why an operation that writes was not done. A failure of the store is not one: it is the
/// outer error ([`ServiceError`](super::observe::ServiceError)).
#[derive(Debug, Clone, PartialEq)]
pub enum NotRun {
    /// Refused.
    Refused(Refused),
    /// The appends were refused as many times as the request may try.
    Contended {
        /// How many times it tried.
        attempts: u8,
    },
}

/// Whose judgment a request admitted from where is made as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Standing {
    /// The one the platform reports.
    Requester,
    /// The platform's agent: a change from a prompt the platform cannot show the user typed.
    Agent,
}

/// Whether a request is taken from where it came, and as whom: the one table, as the module doc
/// shows it.
pub(super) fn admission(
    verb: VerbName,
    via: Via,
    state: &CatalogState,
) -> Result<Standing, Refused> {
    use VerbName::{Approve, Change, Import, Init, Rebase, Reject, Task};
    use Via::{AttestedPrompt, Prompt, ToolCall};
    match (verb, via) {
        (Init | Rebase | Task, ToolCall) => Err(Refused::NotFromToolCall(verb)),
        (Rebase, Prompt) => match state {
            CatalogState::Unreplayable(_) => Ok(Standing::Requester),
            CatalogState::Empty { .. } | CatalogState::Ready(_) => {
                Err(Refused::NeedsAttestedPrompt(verb))
            }
        },
        (Approve | Task, Prompt) => Err(Refused::NeedsAttestedPrompt(verb)),
        (Change | Import, Prompt) => Ok(Standing::Agent),
        (Init, Prompt)
        | (Reject, _)
        | (Change | Import | Approve, ToolCall)
        | (Init | Rebase | Change | Import | Approve | Task, AttestedPrompt) => {
            Ok(Standing::Requester)
        }
    }
}

/// The record of the result of `verb`, a request on the catalog's stream, or why it is refused.
/// The catalog's state and stream are one read.
pub(super) fn judged_catalog(
    instruction: &Instruction,
    verb: CatalogVerb<'_>,
    standing: Standing,
    state: &CatalogState,
    slice: &Slice<CatalogRecord>,
) -> Result<CatalogRecord, Refused> {
    let by = instruction.by();
    let at = instruction.at();
    let core = CoreVersion::running();
    match verb {
        CatalogVerb::Init(founding) => {
            match state {
                CatalogState::Empty { .. } => {}
                CatalogState::Ready(_) | CatalogState::Unreplayable(_) => {
                    return Err(Refused::AlreadyInitialized);
                }
            }
            if !founding.authority.is_root(by) || founding.actors.user() != by {
                return Err(Refused::NotRoot);
            }
            founded(founding, instruction.request().lineage(), by, at, core)
        }
        CatalogVerb::Rebase(founding) => {
            let last = match state {
                CatalogState::Empty { .. } => return Err(Refused::NotReady(NotReady::Empty)),
                CatalogState::Ready(_) | CatalogState::Unreplayable(_) => {
                    load::last_genesis_entry(slice).ok_or(Refused::NotReady(NotReady::Empty))?
                }
            };
            // Read from the last genesis itself, not from a replay: a catalog that cannot be
            // replayed still says who its roots are.
            if !last.record().authority().is_root(by) {
                return Err(Refused::NotRoot);
            }
            founded(founding, instruction.request().lineage(), by, at, core)
        }
        CatalogVerb::Change(edit) => {
            let loaded = state.ready().map_err(Refused::NotReady)?;
            let after = edit
                .applied(loaded.catalog().sources())
                .map_err(Refused::Sources)?;
            changed(instruction, standing, loaded, after, core)
        }
        CatalogVerb::Import(source) => {
            let loaded = state.ready().map_err(Refused::NotReady)?;
            let after = imported(loaded.catalog().sources(), source).map_err(Refused::Sources)?;
            changed(instruction, standing, loaded, after, core)
        }
        CatalogVerb::Approve(id) => {
            let loaded = state.ready().map_err(Refused::NotReady)?;
            let catalog = loaded.catalog();
            let proposed = open_proposal(slice, id)?;
            if !proposed.base().is(catalog.generation()) {
                return Err(Refused::Outdated {
                    proposal: id.clone(),
                    base: proposed.base().clone(),
                    current: GenerationMark::of(catalog.generation()),
                });
            }
            catalog
                .change(proposed.after().clone(), by)
                .map_err(Refused::Change)?;
            Ok(CatalogRecord::Approved(Approved::new(
                id.clone(),
                proposed.after().clone(),
                by.clone(),
                at,
                core,
            )))
        }
        CatalogVerb::Reject(id) => {
            let loaded = state.ready().map_err(Refused::NotReady)?;
            let proposed = open_proposal(slice, id)?;
            let maker = proposed.by();
            if by != maker && !loaded.catalog().authority().covers(by, maker) {
                return Err(Refused::NotMakerOrAbove {
                    proposal: id.clone(),
                });
            }
            Ok(CatalogRecord::Declined(Declined::new(
                id.clone(),
                by.clone(),
                at,
            )))
        }
    }
}

/// The genesis of `founding`, when the domain accepts it.
fn founded(
    founding: &Founding,
    lineage: Lineage,
    by: &Principal,
    at: At,
    core: CoreVersion,
) -> Result<CatalogRecord, Refused> {
    Catalog::accept(
        founding.sources.clone(),
        founding.authority.clone(),
        lineage.clone(),
    )
    .map_err(Refused::Invalid)?;
    Ok(CatalogRecord::Genesis(Genesis::founded(
        founding.sources.clone(),
        founding.authority.clone(),
        founding.actors.clone(),
        lineage,
        by.clone(),
        at,
        core,
    )))
}

/// The record of a change to `after`: a change when the domain takes it as the one judged, a
/// proposal when it loosens what a requester does not cover.
fn changed(
    instruction: &Instruction,
    standing: Standing,
    loaded: &Loaded,
    after: Sources,
    core: CoreVersion,
) -> Result<CatalogRecord, Refused> {
    let catalog = loaded.catalog();
    let judged_as = match standing {
        Standing::Requester => instruction.by(),
        Standing::Agent => loaded.actors().agent(),
    };
    match catalog.change(after.clone(), judged_as) {
        Ok(_) => Ok(CatalogRecord::Changed(Changed::new(
            after,
            judged_as.clone(),
            instruction.at(),
            core,
        ))),
        Err(ChangeRejected::Loosens(loosens)) => match standing {
            Standing::Requester => Ok(CatalogRecord::Proposed(Proposed::new(
                GenerationMark::of(catalog.generation()),
                after,
                loosens,
                instruction.by().clone(),
                instruction.at(),
                core,
            ))),
            Standing::Agent => Err(Refused::NeedsAttestedPrompt(instruction.verb().name())),
        },
        Err(rejected) => Err(Refused::Change(rejected)),
    }
}

/// The proposal `id`, when the stream holds one that is not settled.
fn open_proposal<'a>(
    slice: &'a Slice<CatalogRecord>,
    id: &EntryId,
) -> Result<&'a Proposed, Refused> {
    let proposed = load::proposal(slice, id).ok_or_else(|| Refused::UnknownProposal(id.clone()))?;
    if load::settled(slice, id) {
        return Err(Refused::Settled(id.clone()));
    }
    Ok(proposed)
}

/// The id of a request's result: its first derived id.
pub(super) fn result_id(request: &BaseId) -> EntryId {
    request.child(NonZeroU16::MIN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::port::{Len, Seq};
    use crate::application::record::{ActEntry, ClaimEntry, LostEntry, RequestEntry};
    use crate::domain::event::{Body, Event};
    use crate::domain::policy::Level;
    use crate::domain::schema::{Judgment, KindSet};
    use crate::domain::tx::TxDecision;

    fn user() -> Principal {
        Principal::new("user")
    }

    fn at() -> At {
        At::from_millis(0)
    }

    fn mark() -> GenerationMark {
        GenerationMark {
            lineage: Lineage::new("l").unwrap(),
            n: 0,
        }
    }

    fn genesis() -> CatalogRecord {
        let authority =
            Authority::new([(user(), None), (Principal::new("agent"), Some(user()))]).unwrap();
        let actors = PlatformActors::new(user(), Principal::new("agent"), &authority).unwrap();
        CatalogRecord::Genesis(Genesis::founded(
            Sources::default(),
            authority,
            actors,
            Lineage::new("l").unwrap(),
            user(),
            at(),
            CoreVersion::running(),
        ))
    }

    fn proposal() -> EntryId {
        BaseId::new("p").unwrap().child(NonZeroU16::MIN)
    }

    fn records() -> Vec<CatalogRecord> {
        vec![
            genesis(),
            CatalogRecord::Changed(Changed::new(
                Sources::default(),
                user(),
                at(),
                CoreVersion::running(),
            )),
            CatalogRecord::Proposed(Proposed::new(
                mark(),
                Sources::default(),
                vec![],
                user(),
                at(),
                CoreVersion::running(),
            )),
            CatalogRecord::Approved(Approved::new(
                proposal(),
                Sources::default(),
                user(),
                at(),
                CoreVersion::running(),
            )),
            CatalogRecord::Declined(Declined::new(proposal(), user(), at())),
            genesis(),
        ]
    }

    fn slice<R>(records: Vec<R>) -> Slice<R> {
        let len = records.len() as u64;
        let entries = records
            .into_iter()
            .enumerate()
            .map(|(i, record)| {
                let n = i as u64 + 1;
                Entry::new(
                    Seq::new(n).unwrap(),
                    result_id(&BaseId::new(&format!("r{n}")).unwrap()),
                    record,
                )
            })
            .collect();
        Slice::new(Seq::FIRST, entries, Len::new(len)).unwrap()
    }

    #[test]
    fn a_verb_names_where_its_result_is_and_of_which_kind() {
        use crate::domain::policy::PolicyGraph;
        let CatalogRecord::Genesis(start) = genesis() else {
            unreachable!()
        };
        let founding = Founding::new(
            Sources::default(),
            start.authority().clone(),
            start.actors().clone(),
        )
        .unwrap();
        let set: SetId = "5e700000-0000-7000-8000-000000000001".parse().unwrap();
        let source = Source {
            id: set,
            name: "s".parse().unwrap(),
            owner: user(),
            graph: PolicyGraph::parse_with(vec![], vec![], vec![], None).unwrap(),
        };
        let edit = SetEdit::Remove(set);
        let id = proposal();
        let catalog = |verb, expected| Target::Catalog { verb, expected };
        let table = [
            (
                Verb::Init(founding.clone()),
                catalog(CatalogVerb::Init(&founding), CatalogKind::FirstGenesis),
            ),
            (
                Verb::Rebase(founding.clone()),
                catalog(CatalogVerb::Rebase(&founding), CatalogKind::LaterGenesis),
            ),
            (
                Verb::Change(edit.clone()),
                catalog(CatalogVerb::Change(&edit), CatalogKind::ChangedOrProposed),
            ),
            (
                Verb::Import(source.clone()),
                catalog(CatalogVerb::Import(&source), CatalogKind::ChangedOrProposed),
            ),
            (
                Verb::Approve(id.clone()),
                catalog(CatalogVerb::Approve(&id), CatalogKind::Approved),
            ),
            (
                Verb::Reject(id.clone()),
                catalog(CatalogVerb::Reject(&id), CatalogKind::Declined),
            ),
            (
                Verb::Task,
                Target::Work {
                    expected: WorkKind::TaskStarted,
                },
            ),
        ];
        for (verb, target) in &table {
            assert_eq!(&verb.target(), target, "{}", verb.name());
        }
    }

    #[test]
    fn the_kind_of_each_catalog_record_and_a_genesis_by_where_it_is() {
        let slice = slice(records());
        let kinds: Vec<CatalogKind> = slice
            .entries()
            .iter()
            .map(|entry| CatalogKind::of(&slice, entry))
            .collect();
        assert_eq!(
            kinds,
            [
                CatalogKind::FirstGenesis,
                CatalogKind::ChangedOrProposed,
                CatalogKind::ChangedOrProposed,
                CatalogKind::Approved,
                CatalogKind::Declined,
                CatalogKind::LaterGenesis,
            ]
        );
    }

    #[test]
    fn a_catalog_result_copies_the_record_and_holds_no_generation() {
        let slice = slice(records());
        let e = slice.entries();
        let id = |i: usize| e[i].id().clone();
        assert_eq!(
            Ran::of_catalog(&slice, &e[0], CatalogKind::FirstGenesis),
            Ok(Ran::Initialized { record: id(0) })
        );
        assert_eq!(
            Ran::of_catalog(&slice, &e[1], CatalogKind::ChangedOrProposed),
            Ok(Ran::Changed { record: id(1) })
        );
        assert_eq!(
            Ran::of_catalog(&slice, &e[2], CatalogKind::ChangedOrProposed),
            Ok(Ran::Proposed {
                record: id(2),
                loosens: vec![]
            })
        );
        assert_eq!(
            Ran::of_catalog(&slice, &e[3], CatalogKind::Approved),
            Ok(Ran::Approved {
                record: id(3),
                proposal: proposal()
            })
        );
        assert_eq!(
            Ran::of_catalog(&slice, &e[4], CatalogKind::Declined),
            Ok(Ran::Declined {
                record: id(4),
                proposal: proposal()
            })
        );
        assert_eq!(
            Ran::of_catalog(&slice, &e[5], CatalogKind::LaterGenesis),
            Ok(Ran::Rebased { record: id(5) })
        );
    }

    #[test]
    fn a_catalog_record_of_another_kind_is_not_a_result() {
        let slice = slice(records());
        let e = slice.entries();
        let not = |i: usize| {
            Err(ResultError::NotAResult {
                id: e[i].id().clone(),
            })
        };
        // An approval's id holds a genesis; an init's holds the second genesis; a rebase's the
        // first.
        assert_eq!(
            Ran::of_catalog(&slice, &e[0], CatalogKind::Approved),
            not(0)
        );
        assert_eq!(
            Ran::of_catalog(&slice, &e[5], CatalogKind::FirstGenesis),
            not(5)
        );
        assert_eq!(
            Ran::of_catalog(&slice, &e[0], CatalogKind::LaterGenesis),
            not(0)
        );
        assert_eq!(
            Ran::of_catalog(&slice, &e[1], CatalogKind::Declined),
            not(1)
        );
    }

    #[test]
    fn a_task_result_is_only_a_task_start_made_by_a_request() {
        let request = BaseId::new("r").unwrap();
        let event = |body| Event {
            at: at(),
            by: user(),
            body,
        };
        let records = vec![
            WorkRecord::Act(ActEntry::instructed(mark(), event(Body::TaskStart), request).unwrap()),
            WorkRecord::Act(ActEntry::observed(mark(), event(Body::Stop)).unwrap()),
            WorkRecord::Claim(
                ClaimEntry::judged(
                    mark(),
                    event(Body::Judged {
                        policy: "00000000-0000-7000-8000-000000000001".parse().unwrap(),
                        judgment: Judgment::Allowed,
                        written: Level::Force,
                        enforced: Level::Force,
                    }),
                    TxDecision::Commit,
                )
                .unwrap(),
            ),
            WorkRecord::Request(RequestEntry::new(
                VerbName::Task,
                user(),
                at(),
                Via::AttestedPrompt,
            )),
            WorkRecord::Lost(LostEntry::new(at(), user(), KindSet::any())),
        ];
        let slice = slice(records);
        let e = slice.entries();
        let id = |i: usize| e[i].id().clone();
        assert_eq!(WorkKind::of(&e[0]), Some(WorkKind::TaskStarted));
        assert_eq!(
            Ran::of_task(&e[0], WorkKind::TaskStarted),
            Ok(Ran::TaskStarted { record: id(0) })
        );
        for entry in &e[1..4] {
            assert_eq!(WorkKind::of(entry), None);
            assert_eq!(
                Ran::of_task(entry, WorkKind::TaskStarted),
                Err(ResultError::NotAResult {
                    id: entry.id().clone()
                })
            );
        }
        assert_eq!(
            Ran::of_task(&e[4], WorkKind::TaskStarted),
            Err(ResultError::ResultUnreadable { id: id(4) })
        );
    }
}
