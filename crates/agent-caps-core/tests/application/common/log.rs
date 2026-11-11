//! An in-memory store behind the application's port, for these tests only: it is not part of the
//! library.
//!
//! A clone points at the same store, so two services over two clones are two processes over one
//! store. Writers racing each other are made with no thread and no sleep: a race is queued for a
//! stream, and the next append to it commits the queued records first, so that append is refused
//! the same way every run. The store can also be made to break its promises (a refusal that
//! reports no growth, a read after a refusal that is shorter, a record it cannot read back, a store
//! it cannot reach), so a test sees the application stop on each.
//!
//! The `Mutex` stands for the store's own lock; the application's scope forbids one
//! (`arch-lint.toml`), and this file is outside it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use agent_caps_core::application::{
    AppendError, BaseId, BrokenSlice, Entry, EntryId, Len, Log, LogError, LostEntry, Record, Seq,
    Slice, Stream, StreamKey, WorkRecord,
};
use agent_caps_core::domain::authority::Principal;
use agent_caps_core::domain::schema::{At, KindSet};

/// The store.
#[derive(Debug, Clone, Default)]
pub struct MemoryLog {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    streams: BTreeMap<StreamKey, Vec<(EntryId, Record)>>,
    races: BTreeMap<StreamKey, VecDeque<Race>>,
    raced: u64,
    undecodable: BTreeSet<(StreamKey, u64)>,
    broken_conflict: BTreeSet<StreamKey>,
    broken_reread: BTreeSet<StreamKey>,
    reread_due: BTreeSet<StreamKey>,
    unavailable: bool,
}

/// A writer that gets in before the next append.
#[derive(Debug)]
enum Race {
    /// Commits these records once.
    Once(Vec<(EntryId, Record)>),
    /// Commits one record before each of the next `left` appends; before every one with none.
    Each {
        record: Box<Record>,
        left: Option<usize>,
    },
}

impl MemoryLog {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap()
    }

    /// Writes the record straight into the stream, as a store or another version would have.
    pub fn put(&self, stream: StreamKey, id: EntryId, record: Record) {
        self.lock()
            .streams
            .entry(stream)
            .or_default()
            .push((id, record));
    }

    /// Every record of the stream, in order, as written.
    pub fn records(&self, stream: &StreamKey) -> Vec<(EntryId, Record)> {
        self.lock().streams.get(stream).cloned().unwrap_or_default()
    }

    /// The next append to the stream finds these records committed first.
    pub fn race(&self, stream: StreamKey, entries: Vec<(EntryId, Record)>) {
        self.lock()
            .races
            .entry(stream)
            .or_default()
            .push_back(Race::Once(entries));
    }

    /// Every append to the stream finds one more record committed first.
    pub fn race_always(&self, stream: StreamKey, record: Record) {
        self.lock()
            .races
            .entry(stream)
            .or_default()
            .push_back(Race::Each {
                record: Box::new(record),
                left: None,
            });
    }

    /// Each of the next `n` appends to the stream finds one more record committed first.
    pub fn race_n(&self, stream: StreamKey, n: usize, record: Record) {
        self.lock()
            .races
            .entry(stream)
            .or_default()
            .push_back(Race::Each {
                record: Box::new(record),
                left: Some(n),
            });
    }

    /// Every append to the stream is refused with the length it expected: no growth.
    pub fn break_conflict(&self, stream: StreamKey) {
        self.lock().broken_conflict.insert(stream);
    }

    /// The read after a refused append to the stream gives one record fewer than the refusal
    /// reported.
    pub fn break_reread(&self, stream: StreamKey) {
        self.lock().broken_reread.insert(stream);
    }

    /// The record at `seq` cannot be read back: a worktree's comes back lost, the catalog's is an
    /// error.
    pub fn undecodable(&self, stream: StreamKey, seq: u64) {
        self.lock().undecodable.insert((stream, seq));
    }

    /// The store cannot be reached.
    pub fn unavailable(&self) {
        self.lock().unavailable = true;
    }

    fn read_now<S: Stream>(&self, key: StreamKey, from: Seq) -> Result<Slice<S::Record>, LogError> {
        let mut inner = self.lock();
        if inner.unavailable {
            return Err(down());
        }
        let due = inner.reread_due.remove(&key);
        let all = inner.streams.get(&key).cloned().unwrap_or_default();
        let mut len = all.len() as u64;
        let mut entries = Vec::new();
        for (i, (id, record)) in all.into_iter().enumerate() {
            let n = i as u64 + 1;
            let seq = Seq::new(n).unwrap();
            if seq < from {
                continue;
            }
            let record = if inner.undecodable.contains(&(key.clone(), n)) {
                match &key {
                    StreamKey::Catalog => {
                        return Err(LogError::Undecodable {
                            stream: key,
                            seq,
                            reason: "unknown shape".to_owned(),
                        });
                    }
                    StreamKey::Work(_) => Record::Work(WorkRecord::Lost(LostEntry::new(
                        At::from_millis(0),
                        Principal::new("store"),
                        KindSet::any(),
                    ))),
                }
            } else {
                record
            };
            let record = S::unwrap(record).map_err(|_| {
                LogError::Broken(BrokenSlice::WrongKind {
                    stream: key.clone(),
                    seq,
                })
            })?;
            entries.push(Entry::new(seq, id, record));
        }
        if due {
            len -= 1;
            if entries.last().is_some_and(|e| e.seq().get() > len) {
                entries.pop();
            }
        }
        Slice::new(from, entries, Len::new(len)).map_err(LogError::Broken)
    }

    fn append_now(
        &self,
        key: StreamKey,
        expected: Len,
        entries: Vec<(EntryId, Record)>,
    ) -> Result<Len, AppendError> {
        let mut inner = self.lock();
        if inner.unavailable {
            return Err(AppendError::Log(down()));
        }
        inner.run_race(&key);
        if inner.broken_conflict.contains(&key) {
            return Err(AppendError::Conflict { len: expected });
        }
        let len = Len::new(inner.streams.get(&key).map_or(0, Vec::len) as u64);
        if len != expected {
            if inner.broken_reread.contains(&key) {
                inner.reread_due.insert(key);
            }
            return Err(AppendError::Conflict { len });
        }
        let stream = inner.streams.entry(key).or_default();
        stream.extend(entries);
        Ok(Len::new(stream.len() as u64))
    }
}

impl Inner {
    /// Commits what the first race queued for the stream wants in before this append.
    fn run_race(&mut self, key: &StreamKey) {
        let Some(queue) = self.races.get_mut(key) else {
            return;
        };
        let Some(race) = queue.front_mut() else {
            return;
        };
        let committed = match race {
            Race::Once(entries) => {
                let entries = std::mem::take(entries);
                queue.pop_front();
                entries
            }
            Race::Each { record, left } => {
                let record = Record::clone(record);
                if let Some(n) = left {
                    *n -= 1;
                    if *n == 0 {
                        queue.pop_front();
                    }
                }
                self.raced += 1;
                let id = BaseId::new(&format!("race-{}", self.raced))
                    .unwrap()
                    .entry();
                vec![(id, record)]
            }
        };
        self.streams
            .entry(key.clone())
            .or_default()
            .extend(committed);
    }
}

fn down() -> LogError {
    LogError::Unavailable {
        reason: "the test made the store unreachable".to_owned(),
    }
}

impl Log for MemoryLog {
    async fn read<S: Stream>(&self, stream: &S, from: Seq) -> Result<Slice<S::Record>, LogError> {
        self.read_now::<S>(stream.key(), from)
    }

    async fn append<S: Stream>(
        &self,
        stream: &S,
        expected: Len,
        entries: Vec<(EntryId, S::Record)>,
    ) -> Result<Len, AppendError> {
        let entries = entries
            .into_iter()
            .map(|(id, record)| (id, S::wrap(record)))
            .collect();
        self.append_now(stream.key(), expected, entries)
    }
}
