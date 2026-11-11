//! Reading the catalog from its stream: the replay of the records from the last genesis.
//!
//! ```text
//! read(catalog, 1) ─ rooted ─▶ last_genesis ─▶ Catalog::accept(sources, authority, lineage)
//!                                              ─▶ Catalog::change(after, by) per Changed, Approved
//!                                              ─▶ CatalogState { Empty | Ready | Unreplayable }
//! ```
//!
//! A proposal and a rejection change nothing, so the replay passes over them. A record the
//! running version of the domain refuses makes the catalog [`Unreplayable`]: not an error, as
//! a new lineage (rebase) is the way out of it. A stream that is broken (it does not start with a
//! genesis, a record of it cannot be read back) is an error, and opens no such way.

use std::fmt;

use crate::domain::catalog::{Catalog, Rejected};
use crate::domain::change::ChangeRejected;

use super::port::{Broken, Entry, EntryId, Len, Seq, Slice};
use super::record::{CatalogRecord, CoreVersion, Genesis, PlatformActors, Proposed};

/// Checks that the catalog's stream, read from its first record, starts with a genesis: the one
/// place that says so. An empty stream passes. Every reading of the catalog's stream goes
/// through it before anything else reads the records.
pub fn rooted(slice: &Slice<CatalogRecord>) -> Result<(), Broken> {
    match slice.entries().first() {
        None => Ok(()),
        Some(entry) => match entry.record() {
            CatalogRecord::Genesis(_) => Ok(()),
            CatalogRecord::Changed(_)
            | CatalogRecord::Proposed(_)
            | CatalogRecord::Approved(_)
            | CatalogRecord::Declined(_) => Err(Broken::NotRooted { seq: entry.seq() }),
        },
    }
}

/// The index of the last genesis among `entries`: the start of the lineage in effect. The one
/// place that finds it.
pub fn last_genesis(entries: &[Entry<CatalogRecord>]) -> Option<usize> {
    found(entries).map(|(i, _)| i)
}

/// The last genesis with its index: what [`last_genesis`] finds, with the record.
fn found(entries: &[Entry<CatalogRecord>]) -> Option<(usize, Entry<Genesis>)> {
    entries
        .iter()
        .enumerate()
        .rev()
        .find_map(|(i, entry)| match entry.record() {
            CatalogRecord::Genesis(genesis) => Some((
                i,
                Entry::new(entry.seq(), entry.id().clone(), genesis.clone()),
            )),
            CatalogRecord::Changed(_)
            | CatalogRecord::Proposed(_)
            | CatalogRecord::Approved(_)
            | CatalogRecord::Declined(_) => None,
        })
}

/// The last genesis of a stream, if any.
pub(super) fn last_genesis_entry(slice: &Slice<CatalogRecord>) -> Option<Entry<Genesis>> {
    found(slice.entries()).map(|(_, genesis)| genesis)
}

/// The catalog as the stream holds it, after checking the stream is rooted ([`rooted`]). The
/// state is decided here once, and everything that reads the catalog takes it from here.
pub fn replay(slice: &Slice<CatalogRecord>) -> Result<CatalogState, Broken> {
    rooted(slice)?;
    let entries = slice.entries();
    let Some((i, genesis)) = found(entries) else {
        return Ok(CatalogState::Empty { len: slice.len() });
    };
    let unreplayable = |seq: Seq, recorded: &CoreVersion, error: ReplayError| {
        CatalogState::Unreplayable(Box::new(Unreplayable {
            seq,
            recorded: recorded.clone(),
            running: CoreVersion::running(),
            error,
            genesis: genesis.clone(),
        }))
    };
    let start = genesis.record();
    let mut catalog = match Catalog::accept(
        start.sources().clone(),
        start.authority().clone(),
        start.lineage().clone(),
    ) {
        Ok(catalog) => catalog,
        Err(rejected) => {
            return Ok(unreplayable(
                genesis.seq(),
                start.core(),
                ReplayError::Accept(rejected),
            ));
        }
    };
    for entry in &entries[i + 1..] {
        let (after, by, core) = match entry.record() {
            CatalogRecord::Changed(changed) => (changed.after(), changed.by(), changed.core()),
            CatalogRecord::Approved(approved) => (approved.after(), approved.by(), approved.core()),
            // A proposal and a rejection change nothing; no genesis follows the last.
            CatalogRecord::Proposed(_) | CatalogRecord::Declined(_) | CatalogRecord::Genesis(_) => {
                continue;
            }
        };
        catalog = match catalog.change(after.clone(), by) {
            Ok(next) => next,
            Err(rejected) => {
                return Ok(unreplayable(
                    entry.seq(),
                    core,
                    ReplayError::Change(rejected),
                ));
            }
        };
    }
    Ok(CatalogState::Ready(Box::new(Loaded {
        catalog,
        actors: start.actors().clone(),
        len: slice.len(),
        genesis_seq: genesis.seq(),
    })))
}

/// The record of the proposal `id`, when the lineage in effect holds one: a proposal of an
/// earlier lineage is no longer one to settle.
pub(super) fn proposal<'a>(slice: &'a Slice<CatalogRecord>, id: &EntryId) -> Option<&'a Proposed> {
    in_effect(slice)
        .iter()
        .find(|entry| entry.id() == id)
        .and_then(|entry| match entry.record() {
            CatalogRecord::Proposed(proposed) => Some(proposed),
            _ => None,
        })
}

/// The entries of the lineage in effect, from its last genesis on: the one place that says where
/// the proposals still to settle are, read by [`proposal`], [`settled`] and [`pending`].
fn in_effect(slice: &Slice<CatalogRecord>) -> &[Entry<CatalogRecord>] {
    let entries = slice.entries();
    let from = last_genesis(entries).unwrap_or(entries.len());
    &entries[from..]
}

/// The proposal a record settles, if it is an approval or a rejection: the one answer to "what
/// settles a proposal".
fn settles(record: &CatalogRecord) -> Option<&EntryId> {
    match record {
        CatalogRecord::Approved(approved) => Some(approved.proposal()),
        CatalogRecord::Declined(declined) => Some(declined.proposal()),
        CatalogRecord::Genesis(_) | CatalogRecord::Changed(_) | CatalogRecord::Proposed(_) => None,
    }
}

/// Whether the lineage in effect holds an approval or a rejection of the proposal `id`.
pub(super) fn settled(slice: &Slice<CatalogRecord>, id: &EntryId) -> bool {
    in_effect(slice)
        .iter()
        .any(|entry| settles(entry.record()) == Some(id))
}

/// The proposals of the lineage in effect that are neither approved nor rejected, in order.
pub(super) fn pending(slice: &Slice<CatalogRecord>) -> Vec<Pending> {
    let entries = in_effect(slice);
    let settled: Vec<&EntryId> = entries
        .iter()
        .filter_map(|entry| settles(entry.record()))
        .collect();
    entries
        .iter()
        .filter_map(|entry| match entry.record() {
            CatalogRecord::Proposed(proposed) if !settled.contains(&entry.id()) => Some(Pending {
                entry: Entry::new(entry.seq(), entry.id().clone(), proposed.clone()),
            }),
            _ => None,
        })
        .collect()
}

/// What the catalog's stream holds, as [`replay`] decides it.
#[derive(Debug, Clone, PartialEq)]
pub enum CatalogState {
    /// No lineage has started.
    Empty {
        /// The length of the stream: 0.
        len: Len,
    },
    /// The catalog in effect. Boxed so the state stays small beside the empty store.
    Ready(Box<Loaded>),
    /// The records cannot be replayed under the running version.
    Unreplayable(Box<Unreplayable>),
}

impl CatalogState {
    /// The catalog in effect, or why there is none: what an observation and a request both read.
    pub fn ready(&self) -> Result<&Loaded, NotReady> {
        match self {
            Self::Ready(loaded) => Ok(loaded),
            Self::Empty { .. } => Err(NotReady::Empty),
            Self::Unreplayable(unreplayable) => Err(NotReady::Unreplayable(unreplayable.clone())),
        }
    }
}

/// The catalog in effect, with the platform's actors of its lineage.
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    catalog: Catalog,
    actors: PlatformActors,
    len: Len,
    genesis_seq: Seq,
}

impl Loaded {
    /// The catalog. Its generation is the domain's ([`Catalog::generation`]): the one place it is
    /// kept.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// The platform's actors of the lineage.
    pub fn actors(&self) -> &PlatformActors {
        &self.actors
    }

    /// The length of the catalog's stream when it was read.
    pub fn len(&self) -> Len {
        self.len
    }

    /// The position of the genesis of the lineage.
    pub fn genesis_seq(&self) -> Seq {
        self.genesis_seq
    }
}

/// Why there is no catalog to judge by. An observation and a request carry the same value, and
/// the way out of each is a verb: init for an empty store, rebase for one that cannot be
/// replayed.
#[derive(Debug, Clone, PartialEq)]
pub enum NotReady {
    /// No lineage has started.
    Empty,
    /// The records cannot be replayed under the running version.
    Unreplayable(Box<Unreplayable>),
}

impl fmt::Display for NotReady {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("no catalog has been started; run init"),
            Self::Unreplayable(unreplayable) => unreplayable.fmt(f),
        }
    }
}

/// A catalog whose records the running version of the domain refuses: only a refusal of the
/// domain makes one ([`ReplayError`]). A broken stream is an error instead, so the rebase that
/// this opens is never opened by one.
#[derive(Debug, Clone, PartialEq)]
pub struct Unreplayable {
    seq: Seq,
    recorded: CoreVersion,
    running: CoreVersion,
    error: ReplayError,
    genesis: Entry<Genesis>,
}

impl Unreplayable {
    /// The position of the record the replay stopped at.
    pub fn seq(&self) -> Seq {
        self.seq
    }

    /// The version that wrote it.
    pub fn recorded(&self) -> &CoreVersion {
        &self.recorded
    }

    /// The running version.
    pub fn running(&self) -> &CoreVersion {
        &self.running
    }

    /// What the domain said.
    pub fn error(&self) -> &ReplayError {
        &self.error
    }

    /// The last genesis: whose roots may start a new lineage.
    pub fn genesis(&self) -> &Entry<Genesis> {
        &self.genesis
    }
}

impl fmt::Display for Unreplayable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the catalog cannot be replayed: the record {} written by {} is refused by {}: {}; run rebase",
            self.seq, self.recorded, self.running, self.error
        )
    }
}

/// What the domain refused in a replay.
#[derive(Debug, Clone, PartialEq)]
pub enum ReplayError {
    /// The genesis is not accepted.
    Accept(Rejected),
    /// A change is not accepted.
    Change(ChangeRejected),
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept(rejected) => rejected.fmt(f),
            Self::Change(rejected) => rejected.fmt(f),
        }
    }
}

/// A proposal neither approved nor rejected.
#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    entry: Entry<Proposed>,
}

impl Pending {
    /// The proposal, at its position, with its id: the id an approval or a rejection names.
    pub fn entry(&self) -> &Entry<Proposed> {
        &self.entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::port::BaseId;
    use crate::application::record::Changed;
    use crate::domain::authority::{Authority, Principal};
    use crate::domain::schema::At;
    use crate::domain::set::Sources;
    use crate::domain::state::Lineage;

    fn changed() -> CatalogRecord {
        CatalogRecord::Changed(Changed::new(
            Sources::default(),
            Principal::new("user"),
            At::from_millis(0),
            CoreVersion::running(),
        ))
    }

    fn genesis() -> CatalogRecord {
        let user = Principal::new("user");
        let agent = Principal::new("agent");
        let authority =
            Authority::new([(user.clone(), None), (agent.clone(), Some(user.clone()))]).unwrap();
        let actors = PlatformActors::new(user.clone(), agent, &authority).unwrap();
        CatalogRecord::Genesis(
            Genesis::new(
                Sources::default(),
                authority,
                actors,
                Lineage::new("l").unwrap(),
                user,
                At::from_millis(0),
                CoreVersion::running(),
            )
            .unwrap(),
        )
    }

    fn slice(records: Vec<CatalogRecord>) -> Slice<CatalogRecord> {
        let len = records.len() as u64;
        let entries = records
            .into_iter()
            .enumerate()
            .map(|(i, record)| {
                let n = i as u64 + 1;
                Entry::new(
                    Seq::new(n).unwrap(),
                    BaseId::new(&format!("r{n}")).unwrap().entry(),
                    record,
                )
            })
            .collect();
        Slice::new(Seq::FIRST, entries, Len::new(len)).unwrap()
    }

    #[test]
    fn a_stream_is_rooted_when_empty_or_when_it_starts_with_a_genesis() {
        assert_eq!(rooted(&slice(vec![])), Ok(()));
        assert_eq!(rooted(&slice(vec![genesis(), changed()])), Ok(()));
        assert_eq!(
            rooted(&slice(vec![changed(), genesis()])),
            Err(Broken::NotRooted { seq: Seq::FIRST })
        );
    }

    #[test]
    fn the_last_genesis_is_the_last_one() {
        assert_eq!(last_genesis(slice(vec![]).entries()), None);
        assert_eq!(last_genesis(slice(vec![changed()]).entries()), None);
        assert_eq!(
            last_genesis(slice(vec![genesis(), changed(), genesis(), changed()]).entries()),
            Some(2)
        );
    }
}
