//! Event pipeline: the in-process channel plus the **durable spool** that backs
//! backend delivery.
//!
//! Every collected event flows through an mpsc channel to a single consumer,
//! which appends it to a [`Spool`].  Online, the spool is **disk-backed**: the
//! transport ships batches from its front and the journal survives an agent
//! crash or restart, so a backend outage no longer means lost telemetry — events
//! accumulate on disk (bounded) and are replayed on the next run.  Offline the
//! spool is purely in-memory (the NDJSON output file is the system of record).
//!
//! Delivery is **at-least-once**: the journal is compacted lazily, so a crash
//! between "shipped" and "compacted" can replay a few already-sent events.  The
//! backend de-duplicates on `event_id`, which every event carries.
//!
//! **Durability**: every appended line is `write()`d immediately, but `write()`
//! alone only lands in the page cache — it does not survive a power loss or
//! kernel panic until `fsync`'d. The journal is fsync'd every [`FSYNC_EVERY`]
//! appends (independent of, and far more often than, the [`COMPACT_EVERY`]
//! rewrite), so at most `FSYNC_EVERY - 1` events are at risk on an unclean
//! shutdown — not up to `COMPACT_EVERY` as before. `FSYNC_EVERY` trades a
//! little throughput (one `fsync(2)` per batch instead of per compaction) for
//! that bound; a smaller value tightens the durability window further at a
//! proportional fsync-rate cost.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::schema::AgentEvent;

pub const CHANNEL_CAPACITY: usize = 1_000;

/// Default in-memory spool capacity (offline, or when disk backing is
/// unavailable).
pub const SPOOL_MAX_MEMORY: usize = 10_000;
/// Default durable (disk-backed) spool capacity — larger because it is bounded
/// by disk, not RAM.  Override with `TRAPD_SPOOL_MAX`.
pub const SPOOL_MAX_DURABLE: usize = 50_000;

/// Rewrite (compact) the on-disk journal after this many appends.  Bounds the
/// journal to roughly the live set plus this many stale lines, and caps how
/// many already-sent events can be replayed after a crash.
const COMPACT_EVERY: usize = 5_000;

/// Fsync the on-disk journal after this many appends, independent of
/// compaction. Bounds how many events can be lost to an unclean shutdown (the
/// previous behaviour bounded this by `COMPACT_EVERY` — 5,000 events — which
/// overstated the durability the doc comment claimed).
const FSYNC_EVERY: usize = 50;

pub fn create_pipeline() -> (mpsc::Sender<AgentEvent>, mpsc::Receiver<AgentEvent>) {
    mpsc::channel(CHANNEL_CAPACITY)
}

/// Resolve the durable spool capacity, honouring `TRAPD_SPOOL_MAX`.
pub fn spool_max_from_env() -> usize {
    std::env::var("TRAPD_SPOOL_MAX")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(SPOOL_MAX_DURABLE)
}

/// A bounded FIFO of events awaiting backend delivery, optionally persisted to
/// an append-only JSON-lines journal so it survives restarts.
///
/// API mirrors a ring buffer (`push` / `peek_batch` / `drain`): the transport
/// peeks a batch, ships it, then drains on success.  When full, the **oldest**
/// event is dropped (and counted) — the same policy as before, but now only
/// reached after the on-disk buffer is exhausted, not after 10k in RAM.
pub struct Spool {
    mem: VecDeque<AgentEvent>,
    max: usize,
    file: Option<SpoolFile>,
    dropped_total: u64,
    appends_since_compact: usize,
    appends_since_fsync: usize,
    fsyncs_total: u64,
    /// Test-only instrumentation: records which OS thread `push()` executed
    /// on, so a test can assert the blocking journal write happened off the
    /// async executor thread (i.e. inside `spawn_blocking`).
    #[cfg(test)]
    last_push_thread: Option<std::thread::ThreadId>,
}

struct SpoolFile {
    path: PathBuf,
    handle: File,
}

impl Spool {
    /// In-memory only (offline / fallback).  Drops the oldest event when full,
    /// exactly like the previous ring buffer.
    pub fn in_memory(max: usize) -> Self {
        Self {
            mem: VecDeque::with_capacity(max.min(1024)),
            max,
            file: None,
            dropped_total: 0,
            appends_since_compact: 0,
            appends_since_fsync: 0,
            fsyncs_total: 0,
            #[cfg(test)]
            last_push_thread: None,
        }
    }

    /// Disk-backed spool persisting to `<state>/spool/queue.ndjson`, replaying
    /// any events left by a previous run.  Falls back to in-memory if the
    /// journal directory/file cannot be opened.
    pub fn durable(max: usize) -> Self {
        let path = crate::paths::state_dir().join("spool").join("queue.ndjson");
        Self::durable_at(path, max)
    }

    pub(crate) fn durable_at(path: PathBuf, max: usize) -> Self {
        let mut spool = Self::in_memory(max);
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!(error = %e, "spool: cannot create journal dir — running in-memory only");
                return spool;
            }
        }
        let replayed = spool.load(&path);
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(handle) => {
                spool.file = Some(SpoolFile {
                    path: path.clone(),
                    handle,
                });
                // Rewrite the journal from the (capped) replayed set, dropping
                // any torn/over-cap lines so we start from a clean file.
                spool.compact();
                if replayed > 0 {
                    info!(
                        events = replayed,
                        "spool: replayed persisted events from a previous run"
                    );
                }
            }
            Err(e) => warn!(
                error = %e,
                path = %path.display(),
                "spool: cannot open journal — running in-memory only"
            ),
        }
        spool
    }

    /// Append an event.  Written to the journal first (so a crash right after
    /// can't lose it once fsync'd — see [`FSYNC_EVERY`]), then enforces the
    /// cap.
    pub fn push(&mut self, event: AgentEvent) {
        #[cfg(test)]
        {
            self.last_push_thread = Some(std::thread::current().id());
        }
        if let Some(f) = self.file.as_mut() {
            match serde_json::to_string(&event) {
                Ok(mut line) => {
                    line.push('\n');
                    if let Err(e) = f.handle.write_all(line.as_bytes()) {
                        warn!(error = %e, "spool: journal append failed");
                    }
                }
                Err(e) => warn!(error = %e, "spool: event serialise failed"),
            }
            self.appends_since_compact += 1;
            self.appends_since_fsync += 1;

            // Fsync on a short, fixed cadence — independent of compaction —
            // so durability does not depend on reaching COMPACT_EVERY.
            if self.appends_since_fsync >= FSYNC_EVERY {
                if let Err(e) = f.handle.sync_all() {
                    warn!(error = %e, "spool: periodic journal fsync failed");
                }
                self.fsyncs_total += 1;
                self.appends_since_fsync = 0;
            }
        }

        self.mem.push_back(event);
        if self.mem.len() > self.max {
            self.mem.pop_front();
            self.dropped_total += 1;
            if self.dropped_total % 1_000 == 1 {
                warn!(
                    dropped_total = self.dropped_total,
                    max = self.max,
                    "spool full — dropping oldest events (backend unreachable?)"
                );
            }
        }

        if self.file.is_some() && self.appends_since_compact >= COMPACT_EVERY {
            self.compact();
        }
    }

    /// Up to `n` events from the front, without removing them.
    pub fn peek_batch(&self, n: usize) -> Vec<AgentEvent> {
        self.mem.iter().take(n).cloned().collect()
    }

    /// Remove the first `n` events from the front (after a successful ship).
    ///
    /// The journal is reconciled at the next append-triggered compaction; until
    /// then it may still hold these (already-sent) events.  This is the
    /// at-least-once trade-off — harmless, since the backend dedupes by
    /// `event_id`.
    pub fn drain(&mut self, n: usize) {
        let count = n.min(self.mem.len());
        self.mem.drain(..count);
    }

    /// Total events dropped because the spool was full (observability).
    pub fn dropped_total(&self) -> u64 {
        self.dropped_total
    }

    /// Total periodic fsyncs performed on the journal (observability / test
    /// hook — proves durability does not wait for compaction). Not yet wired
    /// into a metrics/heartbeat consumer, unlike `dropped_total`.
    #[allow(dead_code)]
    pub fn fsyncs_total(&self) -> u64 {
        self.fsyncs_total
    }

    /// Replay a journal file into memory; returns the number of events read.
    fn load(&mut self, path: &Path) -> usize {
        let data = match std::fs::read_to_string(path) {
            Ok(d) => d,
            Err(_) => return 0,
        };
        let mut n = 0;
        for line in data.lines() {
            if line.is_empty() {
                continue;
            }
            // A torn final line from a crash mid-append simply fails to parse
            // and is skipped.
            if let Ok(event) = serde_json::from_str::<AgentEvent>(line) {
                self.mem.push_back(event);
                if self.mem.len() > self.max {
                    self.mem.pop_front();
                    self.dropped_total += 1;
                }
                n += 1;
            }
        }
        n
    }

    /// Atomically rewrite the journal from the current in-memory set
    /// (temp file + fsync + rename), then reopen the append handle.
    fn compact(&mut self) {
        let path = match &self.file {
            Some(f) => f.path.clone(),
            None => return,
        };
        let tmp = path.with_extension("ndjson.tmp");
        let mut buf = String::new();
        for event in &self.mem {
            if let Ok(line) = serde_json::to_string(event) {
                buf.push_str(&line);
                buf.push('\n');
            }
        }
        let result = (|| -> std::io::Result<()> {
            let mut f = File::create(&tmp)?;
            f.write_all(buf.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)?;
            Ok(())
        })();
        match result {
            Ok(()) => match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(handle) => {
                    self.file = Some(SpoolFile { path, handle });
                    self.appends_since_compact = 0;
                    // Compaction just fsync'd the rewritten journal, so the
                    // periodic-fsync clock also resets here.
                    self.appends_since_fsync = 0;
                }
                Err(e) => {
                    warn!(error = %e, "spool: reopen after compaction failed — in-memory only");
                    self.file = None;
                }
            },
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                warn!(error = %e, "spool: compaction failed");
            }
        }
    }
}

#[cfg(test)]
impl Spool {
    pub fn len(&self) -> usize {
        self.mem.len()
    }

    /// Thread the most recent `push()` executed on (test-only instrumentation).
    pub fn last_push_thread(&self) -> Option<std::thread::ThreadId> {
        self.last_push_thread
    }
}

#[cfg(test)]
mod tests;
