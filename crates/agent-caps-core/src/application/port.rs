//! The one port of the application, [`Log`]: streams of records that are only appended to, each
//! append made only when the stream is as long as when it was read (compare and swap).
//!
//! The ids and positions a store keeps are here too. A record's id ([`EntryId`]) is made from the
//! platform's or the request's id ([`BaseId`]), so a retry of the same act or request carries the
//! same id and is found again ([`Slice::prior`]); its position ([`Seq`]) is the store's, given
//! without gaps.

use crate::domain::state::Lineage;
use std::fmt;
use std::future::Future;
use std::num::{NonZeroU16, NonZeroU64};
use std::str::FromStr;

use super::record::{CatalogRecord, WorkRecord};

mod sealed {
    /// Keeps the kinds of stream to the two the application defines.
    pub trait Sealed {}
}

/// A kind of stream, and the type of record it holds. This is the one place that ties the two.
///
/// Sealed: what kinds of record exist is the application's decision, not something an
/// implementation of [`Log`] adds. An implementation sees the records as the closed [`Record`]
/// and matches it, so a new kind does not compile until the store handles it.
pub trait Stream: sealed::Sealed + Send + Sync {
    /// The record the stream holds.
    type Record: Clone + Send + Sync + 'static;
    /// The key a store keeps the stream under.
    fn key(&self) -> StreamKey;
    /// The record as one of the closed set of records.
    fn wrap(record: Self::Record) -> Record;
    /// The record of this stream, or the record given back, boxed, when it is of another kind: a
    /// store that gives one back has mixed its streams up ([`BrokenSlice::WrongKind`]).
    fn unwrap(record: Record) -> Result<Self::Record, Box<Record>>;
}

/// Every record a store keeps, closed: an implementation of [`Log`] encodes and decodes this with
/// an exhaustive match, and needs no downcast.
#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    /// A record of the catalog's stream.
    Catalog(CatalogRecord),
    /// A record of a worktree's stream.
    Work(WorkRecord),
}

/// The key of a stream in a store: `catalog`, or `work/<key>` for a worktree.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StreamKey {
    /// The catalog's stream: one line of catalogs.
    Catalog,
    /// The stream of the evidence of one worktree.
    Work(WorkKey),
}

impl fmt::Display for StreamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog => f.write_str("catalog"),
            Self::Work(key) => write!(f, "work/{key}"),
        }
    }
}

/// The catalog's stream. There is one per store, so a lineage is one line: two changes made from
/// the same read cannot both be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CatalogStream;

impl sealed::Sealed for CatalogStream {}

impl Stream for CatalogStream {
    type Record = CatalogRecord;

    fn key(&self) -> StreamKey {
        StreamKey::Catalog
    }

    fn wrap(record: CatalogRecord) -> Record {
        Record::Catalog(record)
    }

    fn unwrap(record: Record) -> Result<CatalogRecord, Box<Record>> {
        match record {
            Record::Catalog(record) => Ok(record),
            other @ Record::Work(_) => Err(Box::new(other)),
        }
    }
}

/// The stream of the evidence of one worktree: what the rules fold for it, and the requests made
/// from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkStream(WorkKey);

impl WorkStream {
    /// The stream of the worktree.
    pub fn new(key: WorkKey) -> Self {
        Self(key)
    }

    /// The worktree.
    pub fn work(&self) -> &WorkKey {
        &self.0
    }
}

impl sealed::Sealed for WorkStream {}

impl Stream for WorkStream {
    type Record = WorkRecord;

    fn key(&self) -> StreamKey {
        StreamKey::Work(self.0.clone())
    }

    fn wrap(record: WorkRecord) -> Record {
        Record::Work(record)
    }

    fn unwrap(record: Record) -> Result<WorkRecord, Box<Record>> {
        match record {
            Record::Work(record) => Ok(record),
            other @ Record::Catalog(_) => Err(Box::new(other)),
        }
    }
}

/// The key of a worktree: 1 to 128 characters of `A-Z`, `a-z`, `0-9`, `.`, `_` and `-`, and not
/// `.` or `..`. The caller makes it from the worktree; the form is narrow so that a store can put
/// it in a name of its own (a file, a key) without escaping.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WorkKey(String);

/// The longest key of a worktree, in characters.
const WORK_KEY_MAX: usize = 128;

impl WorkKey {
    /// The key, when it is of the form.
    pub fn new(text: &str) -> Result<Self, KeyError> {
        if text.is_empty() {
            return Err(KeyError::Empty);
        }
        if text.len() > WORK_KEY_MAX {
            return Err(KeyError::TooLong { len: text.len() });
        }
        if let Some(c) = text
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        {
            return Err(KeyError::Forbidden(c));
        }
        if text == "." || text == ".." {
            return Err(KeyError::Dots);
        }
        Ok(Self(text.to_owned()))
    }

    /// The text of the key.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a key of a worktree was not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The key is empty.
    Empty,
    /// The key is longer than 128 characters.
    TooLong {
        /// Its length, in bytes (all of its characters are ASCII when it gets this far).
        len: usize,
    },
    /// The key holds a character outside the form.
    Forbidden(char),
    /// The key is `.` or `..`, which a store would read as a directory.
    Dots,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("a worktree key cannot be empty"),
            Self::TooLong { len } => {
                write!(
                    f,
                    "a worktree key is at most {WORK_KEY_MAX} characters, not {len}"
                )
            }
            Self::Forbidden(c) => write!(f, "a worktree key cannot hold {c:?}"),
            Self::Dots => f.write_str("a worktree key cannot be `.` or `..`"),
        }
    }
}

impl std::error::Error for KeyError {}

/// The id of an act on the platform or of a request, as the adapter reads it: not empty, at most
/// 512 bytes, with no `#` and no control character.
///
/// It cannot hold `#`, so an id derived from it ([`BaseId::child`]) never equals an id an adapter
/// gives. A retry of the same act or request carries the same id, which is how the application
/// finds that it was already written ([`Slice::prior`]).
///
/// Its text is kept as the name of a lineage, shared, as every record derived from it keeps it:
/// a request that starts a lineage names it by its id ([`BaseId::lineage`]), and both are text
/// that is not empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BaseId(Lineage);

/// The longest id an adapter gives, in bytes.
const BASE_ID_MAX: usize = 512;

impl BaseId {
    /// The id, when it is of the form.
    pub fn new(text: &str) -> Result<Self, IdError> {
        if text.is_empty() {
            return Err(IdError::Empty);
        }
        if text.len() > BASE_ID_MAX {
            return Err(IdError::TooLong { len: text.len() });
        }
        if let Some(c) = text.chars().find(|&c| c == '#' || c.is_control()) {
            return Err(IdError::Forbidden(c));
        }
        Lineage::new(text).map(Self).map_err(|_| IdError::Empty)
    }

    /// The lineage a request with this id starts: named by the id, which is the request's own.
    pub fn lineage(&self) -> Lineage {
        self.0.clone()
    }

    /// The id of the `k`th record derived from this act or request, in the order they are
    /// written. It cannot fail: the base holds no `#`, and a derived id has no derived id of its
    /// own, as the type has no way to make one.
    pub fn child(&self, k: NonZeroU16) -> EntryId {
        EntryId {
            base: self.clone(),
            child: Some(k),
        }
    }

    /// The id of the record of the act or request itself.
    pub fn entry(&self) -> EntryId {
        EntryId {
            base: self.clone(),
            child: None,
        }
    }

    /// The text of the id.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for BaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// Why an id was not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// The id is empty.
    Empty,
    /// The id is longer than 512 bytes.
    TooLong {
        /// Its length, in bytes.
        len: usize,
    },
    /// The id holds `#`, which separates a derived id, or a control character.
    Forbidden(char),
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("an id cannot be empty"),
            Self::TooLong { len } => {
                write!(f, "an id is at most {BASE_ID_MAX} bytes, not {len}")
            }
            Self::Forbidden(c) => write!(f, "an id cannot hold {c:?}"),
        }
    }
}

impl std::error::Error for IdError {}

/// The id of a record: the act's or request's id, and, for a record derived from it, its number
/// among them. Its text is `<base>` or `<base>#<k>` with `k` from 1 and no leading zero; the
/// [`FromStr`] and [`Display`](fmt::Display) of it are one pair, so an id a command reads back
/// (the proposal an approval names) and an id a store decodes are the id that was written.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntryId {
    base: BaseId,
    child: Option<NonZeroU16>,
}

impl EntryId {
    /// The act's or request's id.
    pub fn base(&self) -> &BaseId {
        &self.base
    }

    /// The number of the derived record; `None` for the record of the act or request itself.
    pub fn child(&self) -> Option<NonZeroU16> {
        self.child
    }
}

impl fmt::Display for EntryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.child {
            None => write!(f, "{}", self.base),
            Some(k) => write!(f, "{}#{k}", self.base),
        }
    }
}

impl FromStr for EntryId {
    type Err = EntryIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let Some((base, k)) = text.split_once('#') else {
            return BaseId::new(text)
                .map(|base| base.entry())
                .map_err(EntryIdError::Base);
        };
        let base = BaseId::new(base).map_err(EntryIdError::Base)?;
        // Digits only, from 1, with no leading zero: `+1` and `01` would read as 1 and not write
        // back as they were read.
        let digits = !k.is_empty() && k.bytes().all(|b| b.is_ascii_digit()) && !k.starts_with('0');
        let child = digits
            .then(|| k.parse::<NonZeroU16>().ok())
            .flatten()
            .ok_or_else(|| EntryIdError::Child(k.to_owned()))?;
        Ok(base.child(child))
    }
}

/// Why the text of a record's id was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryIdError {
    /// The part before `#` is not an id.
    Base(IdError),
    /// The part after `#` is not a number from 1 to 65535 with no leading zero.
    Child(String),
}

impl fmt::Display for EntryIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Base(error) => error.fmt(f),
            Self::Child(text) => write!(f, "{text:?} is not the number of a derived record"),
        }
    }
}

impl std::error::Error for EntryIdError {}

/// The position of a record in its stream: from 1 in each stream, without gaps. The store gives
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Seq(NonZeroU64);

impl Seq {
    /// The first position of a stream.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// The position `n`; none for 0.
    pub fn new(n: u64) -> Option<Self> {
        NonZeroU64::new(n).map(Self)
    }

    /// The number of the position.
    pub fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The length of a stream: the number of its records, and the position of its last. It is what an
/// append expects ([`Log::append`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Len(u64);

impl Len {
    /// The length of an empty stream.
    pub const ZERO: Self = Self(0);

    /// The length `n`.
    pub fn new(n: u64) -> Self {
        Self(n)
    }

    /// The length of a stream whose last record is at `seq`.
    pub fn of(seq: Seq) -> Self {
        Self(seq.get())
    }

    /// The position of the record after the stream's last; none when the numbers are spent.
    pub fn next(self) -> Option<Seq> {
        self.0.checked_add(1).and_then(Seq::new)
    }

    /// The number of records.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Len {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// One record of a stream, at its position, with its id.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry<R> {
    seq: Seq,
    id: EntryId,
    record: R,
}

impl<R> Entry<R> {
    /// The record at `seq` with `id`.
    pub fn new(seq: Seq, id: EntryId, record: R) -> Self {
        Self { seq, id, record }
    }

    /// Its position.
    pub fn seq(&self) -> Seq {
        self.seq
    }

    /// Its id.
    pub fn id(&self) -> &EntryId {
        &self.id
    }

    /// The record.
    pub fn record(&self) -> &R {
        &self.record
    }

    /// The record, given up.
    pub fn into_record(self) -> R {
        self.record
    }
}

/// The records of a stream read from a position, and the length of the stream when they were
/// read, which the next append expects.
///
/// There are two public ways to make one, and both keep the same promise (the positions run from
/// where the read started without a gap, and the length is at least the last of them):
/// [`Slice::new`], by which an implementation of [`Log`] gives what it read, and
/// [`Slice::extended`], by which the application adds what it has just appended. Inside the
/// application, a slice is also joined with the one read after a refused append, which was made
/// by [`Slice::new`] from the position after it. The promise is generic: what a stream must
/// start with is the stream's own rule, checked where it is read
/// ([`load::rooted`](super::load::rooted)).
#[derive(Debug, Clone, PartialEq)]
pub struct Slice<R> {
    entries: Vec<Entry<R>>,
    len: Len,
}

impl<R> Slice<R> {
    /// The records read from `from`, and the length of the stream: refused when the positions do
    /// not run from `from` without a gap, or the length is short of the last of them.
    pub fn new(from: Seq, entries: Vec<Entry<R>>, len: Len) -> Result<Self, BrokenSlice> {
        let mut expected = from;
        for entry in &entries {
            if entry.seq != expected {
                return Err(BrokenSlice::Gap {
                    expected,
                    found: entry.seq,
                });
            }
            expected = Len::of(entry.seq).next().unwrap_or(expected);
        }
        if let Some(last) = entries.last()
            && len < Len::of(last.seq)
        {
            return Err(BrokenSlice::Short {
                last: last.seq,
                len,
            });
        }
        Ok(Self { entries, len })
    }

    /// This slice with `entries` added after it, as `append(stream, self.len(), entries)` wrote
    /// them when it returned `len`: each is given the position after the one before, from
    /// `self.len()`, and the last must be at `len`. So the result of a write is read by the same
    /// function as the result found on a later read ([`Ran::of_catalog`](super::run::Ran::of_catalog)).
    /// A length that does not meet the last position is the store's broken promise.
    pub fn extended(mut self, entries: Vec<(EntryId, R)>, len: Len) -> Result<Self, Broken> {
        let expected = Len::new(self.len.0.saturating_add(entries.len() as u64));
        if len != expected {
            return Err(Broken::AppendedLength { expected, len });
        }
        let mut at = self.len;
        for (id, record) in entries {
            let seq = at.next().ok_or(Broken::AppendedLength { expected, len })?;
            self.entries.push(Entry::new(seq, id, record));
            at = Len::of(seq);
        }
        self.len = len;
        Ok(self)
    }

    /// This slice with `more` after it: `more` was read from the position after this slice's
    /// length, after an append from this slice was refused. `more`'s length is checked against
    /// the refusal before this is called, so the result keeps the promise of both.
    pub(super) fn joined(mut self, more: Slice<R>) -> Self {
        self.entries.extend(more.entries);
        self.len = more.len;
        self
    }

    /// The records read, in order.
    pub fn entries(&self) -> &[Entry<R>] {
        &self.entries
    }

    /// The length of the stream when it was read.
    pub fn len(&self) -> Len {
        self.len
    }

    /// Whether no record was read.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The records already written for the act or request `id`: its own and those derived from
    /// it, in order; none when there are none. This is the one place that tells a retry, or a
    /// second writer of the same request, from a new one. Every turn of the loops that append
    /// calls it, after the first read and after every read that follows a refused append.
    pub fn prior(&self, id: &BaseId) -> Option<Prior<'_, R>> {
        let matched: Vec<&Entry<R>> = self
            .entries
            .iter()
            .filter(|entry| entry.id.base() == id)
            .collect();
        let first = matched.first()?.seq;
        Some(Prior { first, matched })
    }
}

/// The records already written for one act or request ([`Slice::prior`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Prior<'a, R> {
    first: Seq,
    matched: Vec<&'a Entry<R>>,
}

impl<'a, R> Prior<'a, R> {
    /// The position of the first of them: what was written before it is what they were judged
    /// after.
    pub fn first(&self) -> Seq {
        self.first
    }

    /// The record of the act or request itself, when it was written.
    pub fn base(&self) -> Option<&'a Entry<R>> {
        self.matched
            .iter()
            .copied()
            .find(|entry| entry.id.child.is_none())
    }

    /// The `k`th record derived from it, when it was written.
    pub fn child(&self, k: NonZeroU16) -> Option<&'a Entry<R>> {
        self.matched
            .iter()
            .copied()
            .find(|entry| entry.id.child == Some(k))
    }

    /// Every one of them, in order.
    pub fn entries(&self) -> &[&'a Entry<R>] {
        &self.matched
    }
}

/// Where the application keeps its records: streams that are only appended to.
///
/// The methods return a future that is `Send`, so a daemon on a multi-threaded runtime can run a
/// use case on any thread; an implementation writes them as `async fn`. The trait is not made
/// into an object: its methods are generic over the stream.
pub trait Log: Send + Sync {
    /// The records of `stream` from `from` on, in order, with the length of the stream. A stream
    /// never written is empty.
    fn read<S: Stream>(
        &self,
        stream: &S,
        from: Seq,
    ) -> impl Future<Output = Result<Slice<S::Record>, LogError>> + Send;

    /// Writes `entries` after the last record of `stream`, all or none, only when the stream's
    /// length is `expected`, and returns the new length. When the length is not `expected`, it
    /// writes nothing and returns [`AppendError::Conflict`] with the length it found, which is
    /// greater than `expected`: the stream is only appended to, so it grew by what others wrote. A
    /// read from the position after `expected` that follows gives a length at least that one.
    /// With no entries, it only checks the length.
    fn append<S: Stream>(
        &self,
        stream: &S,
        expected: Len,
        entries: Vec<(EntryId, S::Record)>,
    ) -> impl Future<Output = Result<Len, AppendError>> + Send;
}

/// Why an append wrote nothing.
#[derive(Debug, Clone, PartialEq)]
pub enum AppendError {
    /// The stream was not as long as expected: another writer appended since the read.
    Conflict {
        /// The length the store found.
        len: Len,
    },
    /// The store failed.
    Log(LogError),
}

impl fmt::Display for AppendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict { len } => {
                write!(f, "the stream grew to {len} records since it was read")
            }
            Self::Log(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for AppendError {}

/// How a store failed.
#[derive(Debug, Clone, PartialEq)]
pub enum LogError {
    /// The store could not be reached, or its transaction failed.
    Unavailable {
        /// What the store said.
        reason: String,
    },
    /// A record of the catalog's stream could not be read back. The catalog is not read by a
    /// guess, so this is an error; a record of a worktree's stream that cannot be read back is
    /// given as [`WorkRecord::Lost`] instead.
    Undecodable {
        /// The stream.
        stream: StreamKey,
        /// The position of the record.
        seq: Seq,
        /// What the store said.
        reason: String,
    },
    /// What the store read does not keep the promise of a slice or of a stream.
    Broken(BrokenSlice),
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { reason } => write!(f, "the store cannot be reached: {reason}"),
            Self::Undecodable {
                stream,
                seq,
                reason,
            } => write!(
                f,
                "the record {seq} of {stream} cannot be read back: {reason}"
            ),
            Self::Broken(broken) => broken.fmt(f),
        }
    }
}

impl std::error::Error for LogError {}

/// A read that does not keep its promise, as an implementation of [`Log`] finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokenSlice {
    /// A position is not the one after the record before it (a gap or a wrong order).
    Gap {
        /// The position that was due.
        expected: Seq,
        /// The position that came.
        found: Seq,
    },
    /// The length is short of the last position read.
    Short {
        /// The last position read.
        last: Seq,
        /// The length given.
        len: Len,
    },
    /// A record is of another stream's kind ([`Stream::unwrap`]).
    WrongKind {
        /// The stream read.
        stream: StreamKey,
        /// The position of the record.
        seq: Seq,
    },
}

impl fmt::Display for BrokenSlice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gap { expected, found } => {
                write!(
                    f,
                    "the store gave the record {found} where {expected} was due"
                )
            }
            Self::Short { last, len } => {
                write!(
                    f,
                    "the store gave a length of {len} after the record {last}"
                )
            }
            Self::WrongKind { stream, seq } => {
                write!(f, "the record {seq} of {stream} is of another stream")
            }
        }
    }
}

impl std::error::Error for BrokenSlice {}

/// A broken promise that the application finds in its own loops and reads, not one a store
/// reports: an implementation of [`Log`] cannot return it. It is returned as
/// [`ServiceError::Broken`](super::observe::ServiceError::Broken), so a loop that would otherwise
/// go round until its caller gives up stops at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Broken {
    /// A refused append reported a length that is not greater than the one it expected.
    ConflictNotLonger {
        /// The length the append expected.
        expected: Len,
        /// The length it reported.
        len: Len,
    },
    /// The read after a refused append gave a length shorter than the refusal reported.
    RereadShorter {
        /// The length the refusal reported.
        conflict: Len,
        /// The length the read gave.
        len: Len,
    },
    /// The first record of the catalog's stream is not a Genesis
    /// ([`load::rooted`](super::load::rooted)).
    NotRooted {
        /// Its position.
        seq: Seq,
    },
    /// An append returned a length that is not the position of the last record it wrote
    /// ([`Slice::extended`]).
    AppendedLength {
        /// The length the records written come to.
        expected: Len,
        /// The length the append returned.
        len: Len,
    },
    /// The record found as a request's result is not one ([`ResultError`]).
    Result(ResultError),
}

impl fmt::Display for Broken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConflictNotLonger { expected, len } => write!(
                f,
                "a refused append expected {expected} records and reported {len}, which is not more"
            ),
            Self::RereadShorter { conflict, len } => write!(
                f,
                "a refused append reported {conflict} records and the read after it gave {len}"
            ),
            Self::NotRooted { seq } => write!(
                f,
                "the catalog's stream starts with the record {seq}, which is not a genesis"
            ),
            Self::AppendedLength { expected, len } => write!(
                f,
                "an append returned a length of {len} where the records written come to {expected}"
            ),
            Self::Result(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Broken {}

/// Why the record found as a request's result is not one. Only reading a result makes these, so
/// a broken loop cannot be one of them.
///
/// A result that cannot be read back is reported here for a worktree's stream only: a record of
/// that stream that a store cannot decode comes back as
/// [`WorkRecord::Lost`], folded as one that could not be read,
/// while a record of the catalog's stream that cannot be decoded is
/// [`LogError::Undecodable`], as the catalog is never read by a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultError {
    /// The record at the request's first derived id is not the result of its verb.
    NotAResult {
        /// Its id.
        id: EntryId,
    },
    /// The record at the request's first derived id could not be read back.
    ResultUnreadable {
        /// Its id.
        id: EntryId,
    },
}

impl fmt::Display for ResultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAResult { id } => {
                write!(f, "the record {id} is not the result of its request")
            }
            Self::ResultUnreadable { id } => {
                write!(f, "the result {id} of the request cannot be read back")
            }
        }
    }
}

impl std::error::Error for ResultError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(n: u16) -> NonZeroU16 {
        NonZeroU16::new(n).unwrap()
    }

    fn seq(n: u64) -> Seq {
        Seq::new(n).unwrap()
    }

    fn base(text: &str) -> BaseId {
        BaseId::new(text).unwrap()
    }

    fn entry(n: u64, id: EntryId) -> Entry<u8> {
        Entry::new(seq(n), id, 0)
    }

    #[test]
    fn a_base_id_refuses_a_hash_an_empty_text_and_a_long_one() {
        assert_eq!(BaseId::new("a#b"), Err(IdError::Forbidden('#')));
        assert_eq!(BaseId::new("a\nb"), Err(IdError::Forbidden('\n')));
        assert_eq!(BaseId::new(""), Err(IdError::Empty));
        let long = "x".repeat(513);
        assert_eq!(BaseId::new(&long), Err(IdError::TooLong { len: 513 }));
        assert!(BaseId::new(&"x".repeat(512)).is_ok());
    }

    #[test]
    fn a_base_id_derives_ids_that_cannot_fail() {
        let id = base("tool-1");
        assert_eq!(id.entry().base(), &id);
        assert_eq!(id.entry().child(), None);
        assert_eq!(id.child(k(3)).child(), Some(k(3)));
        assert_eq!(id.child(k(3)).base(), &id);
    }

    #[test]
    fn an_entry_id_reads_back_what_it_writes() {
        for text in ["a", "a#3", "a#65535"] {
            let id: EntryId = text.parse().unwrap();
            assert_eq!(id.to_string(), text);
        }
        assert_eq!("a#3".parse::<EntryId>().unwrap(), base("a").child(k(3)));
        for text in ["a#0", "a#", "#1", "a#1#2", "a#01", "a#+1", "a#65536", ""] {
            assert!(text.parse::<EntryId>().is_err(), "{text}");
        }
    }

    #[test]
    fn a_work_key_is_narrow() {
        assert!(WorkKey::new("main_wt-1.x").is_ok());
        assert_eq!(WorkKey::new(""), Err(KeyError::Empty));
        assert_eq!(WorkKey::new("."), Err(KeyError::Dots));
        assert_eq!(WorkKey::new(".."), Err(KeyError::Dots));
        assert_eq!(WorkKey::new("a/b"), Err(KeyError::Forbidden('/')));
        assert_eq!(
            WorkKey::new(&"x".repeat(129)),
            Err(KeyError::TooLong { len: 129 })
        );
        assert!(WorkKey::new(&"x".repeat(128)).is_ok());
    }

    #[test]
    fn a_slice_refuses_a_gap_a_wrong_order_and_a_short_length() {
        let a = base("a");
        assert!(
            Slice::new(
                seq(1),
                vec![entry(1, a.entry()), entry(2, a.entry())],
                Len::new(2)
            )
            .is_ok()
        );
        assert!(Slice::<u8>::new(seq(4), vec![], Len::new(3)).is_ok());
        assert_eq!(
            Slice::new(
                seq(1),
                vec![entry(1, a.entry()), entry(3, a.entry())],
                Len::new(3)
            ),
            Err(BrokenSlice::Gap {
                expected: seq(2),
                found: seq(3)
            })
        );
        assert_eq!(
            Slice::new(
                seq(1),
                vec![entry(2, a.entry()), entry(1, a.entry())],
                Len::new(2)
            ),
            Err(BrokenSlice::Gap {
                expected: seq(1),
                found: seq(2)
            })
        );
        assert_eq!(
            Slice::new(
                seq(1),
                vec![entry(1, a.entry()), entry(2, a.entry())],
                Len::new(1)
            ),
            Err(BrokenSlice::Short {
                last: seq(2),
                len: Len::new(1)
            })
        );
    }

    #[test]
    fn a_prior_finds_the_base_its_children_both_or_none() {
        let (a, b, c, d) = (base("a"), base("b"), base("c"), base("d"));
        let slice = Slice::new(
            seq(1),
            vec![
                entry(1, a.entry()),
                entry(2, b.child(k(1))),
                entry(3, c.entry()),
                entry(4, c.child(k(1))),
                entry(5, c.child(k(2))),
            ],
            Len::new(5),
        )
        .unwrap();
        let only_base = slice.prior(&a).unwrap();
        assert_eq!(only_base.first(), seq(1));
        assert!(only_base.base().is_some());
        assert!(only_base.child(k(1)).is_none());
        let only_child = slice.prior(&b).unwrap();
        assert_eq!(only_child.first(), seq(2));
        assert!(only_child.base().is_none());
        assert_eq!(only_child.child(k(1)).unwrap().seq(), seq(2));
        let both = slice.prior(&c).unwrap();
        assert_eq!(both.first(), seq(3));
        assert_eq!(both.entries().len(), 3);
        assert_eq!(both.child(k(2)).unwrap().seq(), seq(5));
        assert!(slice.prior(&d).is_none());
    }

    #[test]
    fn an_extended_slice_numbers_what_was_appended_after_its_length() {
        let a = base("a");
        let slice = Slice::new(seq(1), vec![entry(1, a.entry())], Len::new(1)).unwrap();
        let extended = slice
            .clone()
            .extended(vec![(a.child(k(1)), 0), (a.child(k(2)), 0)], Len::new(3))
            .unwrap();
        let seqs: Vec<u64> = extended.entries().iter().map(|e| e.seq().get()).collect();
        assert_eq!(seqs, [1, 2, 3]);
        assert_eq!(extended.len(), Len::new(3));
        assert_eq!(
            slice.extended(vec![(a.child(k(1)), 0)], Len::new(5)),
            Err(Broken::AppendedLength {
                expected: Len::new(2),
                len: Len::new(5)
            })
        );
    }
}
