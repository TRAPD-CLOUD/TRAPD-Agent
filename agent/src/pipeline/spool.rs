//! The persistent queue.
//!
//! Every event the pipeline accepts lands here and stays until the backend
//! acknowledges it. The queue is the reason an agent can answer "what happened
//! to event X" after a crash: it is an append-only, checksummed journal that is
//! replayed on startup, so an unacknowledged event survives an agent restart, a
//! backend outage and an unclean shutdown.
//!
//! ## Delivery semantics
//!
//! **At-least-once.** The journal is compacted lazily, so a crash between
//! "shipped" and "compacted" replays a few already-delivered events. That is
//! the deliberate trade: the alternative (compact synchronously on every ack)
//! costs an fsync per batch, and duplicates are cheap for the backend to
//! discard because `event_id` is stable across retries and restarts. Exactly-once
//! would require distributed consensus for no operational gain.
//!
//! **Durability window.** Compaction rewrites and fsyncs the whole journal
//! every [`COMPACT_EVERY`] appends (5,000) — a `write()` alone only lands in
//! the kernel page cache, so an unclean shutdown (power loss, kernel panic,
//! `SIGKILL`) between two compactions could otherwise lose up to that many
//! already-accepted events. A separate, much shorter [`FSYNC_EVERY`] cadence
//! fsyncs just the open journal file (no rewrite) far more often than
//! compaction runs, bounding that window without paying compaction's cost on
//! every batch.
//!
//! ## Overflow policy
//!
//! When the queue is full the **oldest** event is evicted, counted as
//! [`DropReason::PersistentQueueFull`] and logged. Newest-wins is the right
//! direction for security telemetry during an outage: an operator investigating
//! a live incident needs the last few minutes, and the alternative (refusing new
//! events) would blind the agent for the entire remainder of the outage.
//!
//! ## Failure handling
//!
//! A full disk or a read-only filesystem does not stop the agent. The journal is
//! marked *degraded*, the queue continues in memory, and the condition is
//! counted and logged — losing durability is bad, but stopping collection is
//! worse, and a silent switch to in-memory would be worst of all.
//!
//! ## Emergency disk reserve
//!
//! To ride out a *short* disk-full period without losing durability, the
//! durable spool pre-allocates a reserve file (`journal.reserve`, 64 MiB by
//! default, `TRAPD_SPOOL_RESERVE_MB`) next to the journal. The bytes are really
//! written, not a sparse `set_len`, because a sparse file frees nothing when it
//! is deleted. On a disk-full error the reserve is deleted and the failed write
//! is retried once; only if that also fails does the journal degrade as
//! described above. The reserve is re-created after a compaction (or every few
//! minutes) once free space allows it with headroom, and never at the cost of
//! filling the disk itself.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use tokio::sync::Notify;

use tracing::{info, warn};

use super::backoff;
use super::journal::{self, JournalRecord, LineRead, RecordOutcome};
use crate::schema::{AgentEvent, EventClass};
use crate::telemetry::limits::{MAX_BATCH_BYTES, MAX_EVENT_BYTES, MAX_RECORD_BYTES};
use crate::telemetry::metrics::ReserveState;
use crate::telemetry::{metrics::metrics, DropReason};

/// Default in-memory capacity (offline, or when the journal is unavailable).
pub const SPOOL_MAX_MEMORY: usize = 10_000;

/// Default durable capacity — larger, because it is bounded by disk not RAM.
pub const SPOOL_MAX_DURABLE: usize = 50_000;

/// Default byte ceiling for the queue. Enforced alongside the event count
/// because the two constrain different things: 50 000 tiny events are fine,
/// 50 000 events carrying 16 KiB command lines are 800 MiB.
pub const SPOOL_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Compact the journal after this many appends.
const COMPACT_EVERY: usize = 5_000;

/// Fsync the open journal file after this many appends, independent of (and
/// far more often than) [`COMPACT_EVERY`] — see the module-level durability
/// note above.
const FSYNC_EVERY: usize = 50;

/// Default size of the emergency disk reserve.
pub const SPOOL_RESERVE_DEFAULT_MB: u64 = 64;

/// Upper bound for `TRAPD_SPOOL_RESERVE_MB`: a reserve is dead weight on the
/// disk, so a typo must not claim gigabytes.
const SPOOL_RESERVE_MAX_MB: u64 = 1024;

/// File name of the reserve, always next to the journal.
const RESERVE_FILE_NAME: &str = "journal.reserve";

/// Allocation is written in chunks of this size.
const RESERVE_CHUNK: usize = 1024 * 1024;

/// Upper bound on how long allocating the reserve may take. A slow or hung
/// disk must delay startup by at most this, never indefinitely.
const RESERVE_ALLOC_BUDGET: Duration = Duration::from_secs(10);

/// Minimum spacing between attempts to re-create the reserve.
const RESERVE_REARM_INTERVAL: Duration = Duration::from_secs(300);

/// Free space required before re-creating the reserve, as a multiple of its
/// size, so re-arming itself cannot push the disk back to full.
const RESERVE_REARM_HEADROOM: u64 = 2;

/// A queued event and its delivery state.
#[derive(Debug, Clone)]
pub struct SpoolEntry {
    /// Acknowledgement handle, unique within this spool.
    pub seq: u64,
    pub event: AgentEvent,
    /// Delivery attempts so far.
    pub attempts: u32,
    /// Serialized size, tracked so the byte cap does not require re-encoding.
    pub bytes: usize,
    /// Earliest time this entry may be retried; `None` means immediately.
    pub not_before: Option<Instant>,
}

/// Events the backend should see ahead of bulk telemetry: what the agent
/// itself concluded (detections) and what it did about it (prevention).
fn is_priority(event: &AgentEvent) -> bool {
    matches!(event.class, EventClass::Detection | EventClass::Prevention)
}

impl SpoolEntry {
    fn is_eligible(&self, now: Instant) -> bool {
        self.not_before.is_none_or(|t| now >= t)
    }
}

struct JournalFile {
    path: PathBuf,
    handle: File,
    /// Length of the journal after the last fully written record, or `None`
    /// if it could not be determined. Used to cut a half-written record off
    /// the tail before a retry (see [`Spool::write_journal`]).
    len: Option<u64>,
}

impl JournalFile {
    fn new(path: PathBuf, handle: File) -> Self {
        let len = handle.metadata().ok().map(|m| m.len());
        Self { path, handle, len }
    }
}

/// The emergency reserve of a durable spool.
struct Reserve {
    path: PathBuf,
    size: u64,
    state: ReserveState,
    consumed_total: u64,
    /// Last allocation attempt after start-up, to throttle re-arming.
    last_attempt: Option<Instant>,
}

/// A bounded, durable FIFO of events awaiting delivery.
pub struct Spool {
    mem: VecDeque<SpoolEntry>,
    max_events: usize,
    max_bytes: u64,
    bytes: u64,
    next_seq: u64,
    file: Option<JournalFile>,
    /// Set when the journal became unusable (disk full, read-only mount) and
    /// the queue fell back to memory. Surfaced so the condition is visible
    /// rather than inferred from a missing file.
    degraded: bool,
    reserve: Option<Reserve>,
    dropped_total: u64,
    corrupt_records: u64,
    appends_since_compact: usize,
    appends_since_fsync: usize,
    fsyncs_total: u64,
    /// Signalled when a priority event is enqueued, so the transport flushes
    /// within milliseconds instead of waiting for its next tick.
    priority_wake: Arc<Notify>,
    /// Test-only instrumentation: records which OS thread `push()` executed
    /// on, so a test can assert the blocking journal write happened off the
    /// async executor thread (i.e. inside `spawn_blocking`).
    #[cfg(test)]
    last_push_thread: Option<std::thread::ThreadId>,
    /// Test-only: number of upcoming journal writes to fail with disk-full,
    /// after writing half of the record (a torn write).
    #[cfg(test)]
    inject_write_disk_full: u32,
    /// Test-only: number of upcoming fsyncs to fail with disk-full.
    #[cfg(test)]
    inject_sync_disk_full: u32,
    /// Test-only: pretend this many bytes are free instead of asking the OS.
    #[cfg(test)]
    free_space_override: Option<u64>,
}

impl Spool {
    /// In-memory only. Used offline, where the local NDJSON file is the system
    /// of record and durability is not this queue's job.
    pub fn in_memory(max_events: usize) -> Self {
        let spool = Self {
            mem: VecDeque::with_capacity(max_events.min(1024)),
            max_events,
            max_bytes: SPOOL_MAX_BYTES,
            bytes: 0,
            next_seq: 1,
            file: None,
            degraded: false,
            reserve: None,
            dropped_total: 0,
            corrupt_records: 0,
            appends_since_compact: 0,
            appends_since_fsync: 0,
            fsyncs_total: 0,
            priority_wake: Arc::new(Notify::new()),
            #[cfg(test)]
            last_push_thread: None,
            #[cfg(test)]
            inject_write_disk_full: 0,
            #[cfg(test)]
            inject_sync_disk_full: 0,
            #[cfg(test)]
            free_space_override: None,
        };
        // Publish immediately: a capacity of zero in the diagnostics report
        // would make every utilization reading meaningless.
        spool.publish_capacity();
        spool.publish();
        spool
    }

    /// Disk-backed queue at `<state>/spool/queue.journal`, replaying whatever a
    /// previous run left behind.
    pub fn durable(max_events: usize) -> Self {
        let path = crate::paths::state_dir()
            .join("spool")
            .join("queue.journal");
        Self::durable_at(path, max_events).with_reserve_bytes(spool_reserve_bytes_from_env())
    }

    /// Byte ceiling override, for tests and for `TRAPD_SPOOL_MAX_BYTES`.
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self.publish_capacity();
        self
    }

    /// Allocate the emergency disk reserve next to the journal (`0` disables
    /// it). A no-op for in-memory and degraded spools. Failing to allocate is
    /// logged and surfaced as `unavailable`, never an error: the spool then
    /// behaves exactly as it did before the reserve existed.
    pub(crate) fn with_reserve_bytes(mut self, bytes: u64) -> Self {
        let Some(journal_path) = self.file.as_ref().map(|f| f.path.clone()) else {
            return self;
        };
        let path = journal_path.with_file_name(RESERVE_FILE_NAME);
        if bytes == 0 {
            // Turning the reserve off must give its disk space back.
            let _ = std::fs::remove_file(&path);
            self.reserve = Some(Reserve {
                path,
                size: 0,
                state: ReserveState::Disabled,
                consumed_total: 0,
                last_attempt: None,
            });
            self.publish();
            return self;
        }
        let state = match std::fs::metadata(&path) {
            // Left by a previous run: reuse it rather than rewriting 64 MiB on
            // every start.
            Ok(m) if m.is_file() && m.len() == bytes => ReserveState::Armed,
            _ => match allocate_reserve(&path, bytes, RESERVE_ALLOC_BUDGET) {
                Ok(()) => ReserveState::Armed,
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %path.display(),
                        "spool: cannot allocate the disk-full reserve — journal runs without it"
                    );
                    ReserveState::Unavailable
                }
            },
        };
        self.reserve = Some(Reserve {
            path,
            size: bytes,
            state,
            consumed_total: 0,
            last_attempt: Some(Instant::now()),
        });
        self.publish();
        self
    }

    pub(crate) fn durable_at(path: PathBuf, max_events: usize) -> Self {
        let mut spool = Self::in_memory(max_events);

        if let Some(parent) = path.parent() {
            if let Err(e) = create_private_dir(parent) {
                warn!(
                    error = %e,
                    path = %parent.display(),
                    "spool: cannot create journal directory — continuing in memory only"
                );
                spool.degraded = true;
                spool.publish();
                return spool;
            }
        }

        let replayed = spool.replay(&path);

        match open_private_append(&path) {
            Ok(handle) => {
                spool.file = Some(JournalFile::new(path.clone(), handle));
                // Rewrite from the recovered set so the file starts clean:
                // corrupt lines and over-cap records are not carried forward.
                spool.compact();
                if replayed > 0 {
                    info!(
                        events = replayed,
                        corrupt = spool.corrupt_records,
                        "spool: recovered persisted events from a previous run"
                    );
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    path = %path.display(),
                    "spool: cannot open journal — continuing in memory only"
                );
                spool.degraded = true;
            }
        }
        spool.publish();
        spool
    }

    // ── Producer side ────────────────────────────────────────────────────────

    /// Enqueue an event.
    ///
    /// Returns the acknowledgement handle, or the reason the event could not be
    /// accepted. An `Err` here is always counted — there is no path that
    /// discards an event without naming why.
    pub fn push(&mut self, event: AgentEvent) -> Result<u64, DropReason> {
        #[cfg(any(windows, test))]
        let receipt_id = event.event_id;
        #[cfg(any(windows, test))]
        let wants_receipt = super::receipt::requested(receipt_id);
        // A checkpoint retry refers to the same accepted event. Keep its
        // delivery state and capacity slot rather than evicting other evidence.
        #[cfg(any(windows, test))]
        if wants_receipt
            || event
                .origin
                .as_ref()
                .and_then(|origin| origin.source.as_deref())
                .is_some_and(|source| {
                    (matches!(event.class, EventClass::Log)
                        && source.starts_with("windows_eventlog:"))
                        || (matches!(event.class, EventClass::Registry)
                            && source == "windows_registry_snapshot")
                })
        {
            if let Some(seq) = self
                .mem
                .iter()
                .find(|entry| entry.event.event_id == receipt_id)
                .map(|entry| entry.seq)
            {
                if wants_receipt {
                    self.sync_for_checkpoint();
                    self.publish();
                    super::receipt::complete(receipt_id, self.is_durable());
                }
                return Ok(seq);
            }
        }
        #[cfg(test)]
        {
            self.last_push_thread = Some(std::thread::current().id());
        }
        let seq = self.next_seq;

        let record = JournalRecord {
            v: journal::RECORD_VERSION,
            seq,
            attempts: 0,
            event,
        };

        let encoded = match journal::encode(&record) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "spool: event could not be serialized");
                metrics().event_dropped(DropReason::SerializationFailed);
                #[cfg(any(windows, test))]
                if wants_receipt {
                    super::receipt::complete(receipt_id, false);
                }
                return Err(DropReason::SerializationFailed);
            }
        };

        // An event that cannot fit a batch would block the queue head forever,
        // so it is refused at the door rather than poisoning delivery.
        if encoded.len() > MAX_EVENT_BYTES {
            warn!(
                bytes = encoded.len(),
                limit = MAX_EVENT_BYTES,
                event_id = %record.event.event_id,
                "spool: event exceeds the size limit — dropping"
            );
            metrics().event_dropped(DropReason::EventTooLarge);
            #[cfg(any(windows, test))]
            if wants_receipt {
                super::receipt::complete(receipt_id, false);
            }
            return Err(DropReason::EventTooLarge);
        }

        self.next_seq += 1;
        self.append_to_journal(&encoded);

        // Checkpointing sources must not advance their durable baseline/cursor
        // until this particular record has reached stable journal storage.
        #[cfg(any(windows, test))]
        if wants_receipt {
            self.sync_for_checkpoint();
        }

        let entry = SpoolEntry {
            seq,
            event: record.event,
            attempts: 0,
            bytes: encoded.len(),
            not_before: None,
        };
        self.bytes += entry.bytes as u64;
        let priority = is_priority(&entry.event);
        self.mem.push_back(entry);
        metrics().spool_event_accepted();

        self.enforce_caps();

        if self.file.is_some() && self.appends_since_compact >= COMPACT_EVERY {
            self.compact();
        }
        self.maybe_rearm(false);
        self.publish();
        #[cfg(any(windows, test))]
        if wants_receipt {
            let retained = self.mem.back().is_some_and(|entry| entry.seq == seq);
            super::receipt::complete(receipt_id, retained && self.is_durable());
        }
        if priority {
            // Stores one permit if the transport is not waiting yet, so a
            // wake-up between two flushes is never lost.
            self.priority_wake.notify_one();
        }
        Ok(seq)
    }

    #[cfg(any(windows, test))]
    fn sync_for_checkpoint(&mut self) {
        if self.appends_since_fsync == 0 {
            return;
        }
        if self.file.is_some() {
            match self.sync_journal() {
                Ok(()) => {
                    self.fsyncs_total += 1;
                    self.appends_since_fsync = 0;
                }
                Err(error) => {
                    warn!(%error, "spool: checkpoint handoff sync failed — durability lost, continuing in memory");
                    self.file = None;
                    self.degraded = true;
                }
            }
        }
    }

    /// Handle the transport waits on to learn that a priority event arrived.
    pub fn priority_wake(&self) -> Arc<Notify> {
        Arc::clone(&self.priority_wake)
    }

    /// Evict from the front until both caps are satisfied.
    fn enforce_caps(&mut self) {
        let mut evicted = 0u64;
        let mut priority_evicted = 0u64;
        while self.mem.len() > self.max_events || self.bytes > self.max_bytes {
            let Some(old) = self.mem.pop_front() else {
                break;
            };
            if is_priority(&old.event) {
                priority_evicted += 1;
            }
            self.bytes = self.bytes.saturating_sub(old.bytes as u64);
            evicted += 1;
        }
        if priority_evicted > 0 {
            metrics().spool_priority_evicted(priority_evicted);
        }
        if evicted > 0 {
            self.dropped_total += evicted;
            metrics().events_dropped(DropReason::PersistentQueueFull, evicted);
            // Log the first overflow and then every thousandth, so a sustained
            // outage does not itself become a log flood.
            if self.dropped_total - evicted == 0 || self.dropped_total % 1_000 < evicted {
                warn!(
                    dropped_total = self.dropped_total,
                    priority_evicted,
                    max_events = self.max_events,
                    max_bytes = self.max_bytes,
                    "spool at capacity — evicting oldest events (backend unreachable?)"
                );
            }
        }
    }

    fn append_to_journal(&mut self, encoded: &[u8]) {
        if self.file.is_none() {
            return;
        }
        let mut result = self.write_journal(encoded);
        if let Err(e) = &result {
            if is_disk_full(e) && self.release_reserve() {
                result = self.write_journal(encoded);
            }
        }
        if let Err(e) = result {
            // Disk full or a read-only remount. Keep collecting in memory and
            // make the loss of durability explicit.
            warn!(
                error = %e,
                "spool: journal append failed — durability lost, continuing in memory"
            );
            self.file = None;
            self.degraded = true;
            return;
        }
        self.appends_since_compact += 1;
        self.appends_since_fsync += 1;

        // `write()` alone only reaches the page cache — fsync on a short,
        // fixed cadence independent of compaction so durability does not wait
        // for COMPACT_EVERY (see the module-level durability note).
        if self.appends_since_fsync >= FSYNC_EVERY {
            if let Err(e) = self.sync_journal() {
                warn!(error = %e, "spool: periodic journal fsync failed — durability lost, continuing in memory");
                self.file = None;
                self.degraded = true;
                return;
            }
            self.fsyncs_total += 1;
            self.appends_since_fsync = 0;
        }
    }

    /// Append one encoded record to the open journal.
    ///
    /// Torn-write safety: the journal is line-oriented and the reader only
    /// tolerates a torn record at the very *end* of the file. A failed
    /// `write_all` may still have written a prefix of the record (no trailing
    /// newline). Appending the retry directly behind that prefix would glue
    /// both into one line that fails its checksum, destroying the retried
    /// record too. So on any failure the file is cut back to the length of the
    /// last complete record before the caller may retry. The shrink needs no
    /// free space. If the length is unknown or the shrink fails, the error is
    /// returned as a plain failure and the caller degrades instead of retrying.
    fn write_journal(&mut self, encoded: &[u8]) -> std::io::Result<()> {
        #[cfg(test)]
        let injected = self.inject_write_disk_full > 0;
        #[cfg(test)]
        if injected {
            self.inject_write_disk_full -= 1;
        }
        let Some(f) = self.file.as_mut() else {
            return Ok(());
        };
        #[cfg(test)]
        let result = if injected {
            f.handle
                .write_all(&encoded[..encoded.len() / 2])
                .and_then(|()| Err(std::io::Error::from(std::io::ErrorKind::StorageFull)))
        } else {
            f.handle.write_all(encoded)
        };
        #[cfg(not(test))]
        let result = f.handle.write_all(encoded);

        match result {
            Ok(()) => {
                f.len = f.len.map(|l| l + encoded.len() as u64);
                Ok(())
            }
            Err(e) => {
                let Some(len) = f.len else {
                    return Err(e);
                };
                // A separate write handle: the append handle may lack
                // `FILE_WRITE_DATA` (Windows), which truncation needs.
                let cut = OpenOptions::new()
                    .write(true)
                    .open(&f.path)
                    .and_then(|h| h.set_len(len));
                if let Err(cut_err) = cut {
                    warn!(error = %cut_err, "spool: cannot trim a partial journal record");
                    f.len = None;
                }
                Err(e)
            }
        }
    }

    /// `fsync` the journal. On a disk-full error (delayed allocation can
    /// surface ENOSPC only here) the reserve is released and the sync retried
    /// once. Caveat: after a failed `fsync` some kernels drop the dirty pages,
    /// so a successful retry is best-effort evidence, not proof; the journal's
    /// per-record checksums still catch whatever did not reach the disk.
    fn sync_journal(&mut self) -> std::io::Result<()> {
        let mut result = self.sync_once();
        if let Err(e) = &result {
            if is_disk_full(e) && self.release_reserve() {
                result = self.sync_once();
            }
        }
        result
    }

    fn sync_once(&mut self) -> std::io::Result<()> {
        #[cfg(test)]
        if self.inject_sync_disk_full > 0 {
            self.inject_sync_disk_full -= 1;
            return Err(std::io::Error::from(std::io::ErrorKind::StorageFull));
        }
        match self.file.as_ref() {
            Some(f) => f.handle.sync_all(),
            None => Ok(()),
        }
    }

    // ── Emergency reserve ────────────────────────────────────────────────────

    /// Delete the armed reserve to make room. Returns whether space was freed
    /// and the failed write is worth retrying; `false` means "behave as before".
    fn release_reserve(&mut self) -> bool {
        let Some(r) = self.reserve.as_mut() else {
            return false;
        };
        if r.state != ReserveState::Armed {
            return false;
        }
        match std::fs::remove_file(&r.path) {
            Ok(()) => {
                r.state = ReserveState::InUse;
                r.consumed_total += 1;
                warn!(
                    reserve_bytes = r.size,
                    consumed_total = r.consumed_total,
                    "spool: disk full — released the emergency reserve to keep the journal durable"
                );
                self.publish();
                true
            }
            Err(e) => {
                warn!(error = %e, "spool: cannot release the emergency reserve");
                r.state = ReserveState::Unavailable;
                self.publish();
                false
            }
        }
    }

    /// Re-create a consumed or missing reserve if the disk allows it.
    ///
    /// `after_compaction` skips the interval throttle once (compaction just
    /// freed space), but never the free-space check.
    fn maybe_rearm(&mut self, after_compaction: bool) {
        if self.file.is_none() {
            return;
        }
        let Some(r) = self.reserve.as_ref() else {
            return;
        };
        if !matches!(r.state, ReserveState::InUse | ReserveState::Unavailable) {
            return;
        }
        if !after_compaction
            && r.last_attempt
                .is_some_and(|t| t.elapsed() < RESERVE_REARM_INTERVAL)
        {
            return;
        }
        let (path, size) = (r.path.clone(), r.size);
        if let Some(r) = self.reserve.as_mut() {
            r.last_attempt = Some(Instant::now());
        }

        // Without a free-space API the allocation itself is the probe; it
        // deletes its partial file on failure.
        if let Some(free) = self.free_space(&path) {
            if free < size.saturating_mul(RESERVE_REARM_HEADROOM) {
                return;
            }
        }
        match allocate_reserve(&path, size, RESERVE_ALLOC_BUDGET) {
            Ok(()) => {
                if let Some(r) = self.reserve.as_mut() {
                    r.state = ReserveState::Armed;
                }
                info!(
                    reserve_bytes = size,
                    "spool: emergency disk reserve re-armed"
                );
                self.publish();
            }
            Err(e) => {
                warn!(error = %e, "spool: cannot re-arm the emergency reserve — will retry later");
            }
        }
    }

    fn free_space(&self, path: &Path) -> Option<u64> {
        #[cfg(test)]
        if let Some(v) = self.free_space_override {
            return Some(v);
        }
        free_space_bytes(path)
    }

    // ── Consumer side ────────────────────────────────────────────────────────

    /// Up to `n` entries eligible for delivery, without removing them.
    ///
    /// Entries still inside their retry backoff are skipped, and the batch is
    /// additionally capped at [`MAX_BATCH_BYTES`] so one batch of large events
    /// cannot exceed what the backend will accept.
    pub fn peek_batch(&self, n: usize) -> Vec<SpoolEntry> {
        self.peek_batch_at(n, Instant::now())
    }

    pub(crate) fn peek_batch_at(&self, n: usize, now: Instant) -> Vec<SpoolEntry> {
        // Priority events go first, but never take more than three quarters of a
        // batch while bulk telemetry is waiting: a detection storm must delay
        // process/network events, not starve them. Slots a class cannot fill are
        // handed to the other, so a batch is only short when the queue is.
        let priority_cap = n - n / 4;
        let mut chosen = vec![false; self.mem.len()];
        let mut count = 0usize;
        let mut bytes = 0usize;

        let mut take = |want_priority: Option<bool>, limit: usize, chosen: &mut Vec<bool>| {
            for (i, entry) in self.mem.iter().enumerate() {
                if count >= limit {
                    break;
                }
                if chosen[i] || !entry.is_eligible(now) {
                    continue;
                }
                if want_priority.is_some_and(|w| w != is_priority(&entry.event)) {
                    continue;
                }
                if count > 0 && bytes + entry.bytes > MAX_BATCH_BYTES {
                    break;
                }
                bytes += entry.bytes;
                chosen[i] = true;
                count += 1;
            }
        };
        take(Some(true), priority_cap, &mut chosen);
        take(Some(false), n, &mut chosen);
        take(Some(true), n, &mut chosen);

        self.mem
            .iter()
            .zip(chosen)
            .filter(|(_, c)| *c)
            .map(|(entry, _)| entry.clone())
            .collect()
    }

    /// Remove acknowledged entries.
    ///
    /// Idempotent and order-independent: acknowledging a `seq` that is already
    /// gone is a no-op, so a duplicated or out-of-order acknowledgement from the
    /// backend cannot remove the wrong event. Returns how many entries this call
    /// actually removed.
    pub fn ack(&mut self, seqs: &[u64]) -> usize {
        if seqs.is_empty() {
            return 0;
        }
        let ackset: std::collections::HashSet<u64> = seqs.iter().copied().collect();
        let before = self.mem.len();
        let mut freed = 0u64;
        self.mem.retain(|e| {
            let keep = !ackset.contains(&e.seq);
            if !keep {
                freed += e.bytes as u64;
            }
            keep
        });
        self.bytes = self.bytes.saturating_sub(freed);
        let removed = before - self.mem.len();
        if removed > 0 {
            self.appends_since_compact += removed;
        }
        self.publish();
        removed
    }

    /// Mark entries as failed: bump their attempt count and push their next
    /// eligible time out by a jittered exponential backoff.
    pub fn nack(&mut self, seqs: &[u64]) {
        self.nack_at(seqs, Instant::now());
    }

    pub(crate) fn nack_at(&mut self, seqs: &[u64], now: Instant) {
        if seqs.is_empty() {
            return;
        }
        let nackset: std::collections::HashSet<u64> = seqs.iter().copied().collect();
        let mut retried = 0u64;
        for entry in self.mem.iter_mut() {
            if nackset.contains(&entry.seq) {
                entry.attempts = entry.attempts.saturating_add(1);
                entry.not_before = Some(now + backoff::jittered_delay(entry.attempts));
                retried += 1;
            }
        }
        if retried > 0 {
            metrics().transport_events_retried(retried);
        }
    }

    /// Force an entry's next attempt time, for deterministic tests.
    #[cfg(test)]
    pub(crate) fn set_not_before(&mut self, seq: u64, when: Option<Instant>) {
        for e in self.mem.iter_mut() {
            if e.seq == seq {
                e.not_before = when;
            }
        }
    }

    fn publish(&self) {
        metrics().set_spool_state(self.mem.len() as u64, self.bytes);
        metrics().set_spool_durability_lost(self.degraded);
        let (reserve_state, reserve_consumed) = self
            .reserve
            .as_ref()
            .map_or((ReserveState::Disabled, 0), |r| (r.state, r.consumed_total));
        metrics().set_spool_reserve(reserve_state, reserve_consumed);
        let age = self.mem.front().map_or(0, |entry| {
            chrono::Utc::now()
                .signed_duration_since(entry.event.timestamp)
                .num_milliseconds()
                .max(0) as u64
        });
        metrics().set_spool_oldest_age_ms(age);
    }

    fn publish_capacity(&self) {
        metrics().set_spool_capacity(self.max_events as u64, self.max_bytes);
    }

    // ── Recovery ─────────────────────────────────────────────────────────────

    /// Replay a journal into memory, classifying every line.
    ///
    /// Returns the number of valid records recovered. Corrupt and unsupported
    /// records are counted (and surfaced as `recovery_required` health) rather
    /// than silently skipped: a checksum failure means telemetry was destroyed,
    /// and that has to reach an operator.
    fn replay(&mut self, path: &Path) -> usize {
        let file = match File::open(path) {
            Ok(f) => f,
            // No journal yet is the normal first-run case.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
            Err(e) => {
                warn!(error = %e, path = %path.display(), "spool: cannot read journal");
                self.degraded = true;
                return 0;
            }
        };

        let mut reader = BufReader::new(file);
        let mut line = Vec::with_capacity(4096);
        let mut recovered = 0usize;
        let mut corrupt = 0u64;
        let mut torn = 0u64;
        let mut unsupported = 0u64;
        let mut first_line = true;
        let mut max_seq = 0u64;

        loop {
            let outcome = match journal::read_line_bounded(&mut reader, MAX_RECORD_BYTES, &mut line)
            {
                Ok(o) => o,
                Err(e) => {
                    warn!(error = %e, "spool: journal read failed — stopping recovery here");
                    self.degraded = true;
                    break;
                }
            };

            match outcome {
                LineRead::Eof => break,
                LineRead::Overlong => {
                    corrupt += 1;
                    continue;
                }
                LineRead::Complete | LineRead::Unterminated => {}
            }
            let terminated = outcome == LineRead::Complete;

            // The header identifies the format; skip it rather than parsing it
            // as a record.
            if first_line {
                first_line = false;
                if line == journal::JOURNAL_HEADER.as_bytes() {
                    continue;
                }
            }

            match journal::decode(&line, terminated) {
                RecordOutcome::Valid(rec) => {
                    max_seq = max_seq.max(rec.seq);
                    let bytes = line.len() + 1;
                    self.bytes += bytes as u64;
                    self.mem.push_back(SpoolEntry {
                        seq: rec.seq,
                        event: rec.event,
                        attempts: rec.attempts,
                        bytes,
                        // Records that already failed resume their backoff at
                        // the level they left off at, rather than stampeding
                        // the backend on every restart.
                        not_before: (rec.attempts > 0)
                            .then(|| Instant::now() + backoff::jittered_delay(rec.attempts)),
                    });
                    recovered += 1;
                    self.enforce_caps();
                }
                RecordOutcome::TruncatedTail => torn += 1,
                RecordOutcome::UnsupportedVersion(v) => {
                    warn!(
                        version = v,
                        "spool: journal record from a newer agent — skipping"
                    );
                    unsupported += 1;
                }
                RecordOutcome::Corrupt(why) => {
                    warn!(reason = why, "spool: corrupt journal record discarded");
                    corrupt += 1;
                }
                RecordOutcome::Blank => {}
            }
        }

        // Continue the sequence past anything recovered so a restart cannot
        // reissue a handle that is still in flight.
        self.next_seq = max_seq + 1;

        self.corrupt_records += corrupt;
        if corrupt > 0 {
            metrics().spool_corrupt_record(corrupt);
            metrics().events_dropped(DropReason::PersistentQueueCorrupt, corrupt);
            warn!(
                corrupt,
                "spool: journal records failed checksum validation — telemetry was lost to \
                 corruption; agent health is now recovery_required"
            );
        }
        if unsupported > 0 {
            metrics().events_dropped(DropReason::UnsupportedEventVersion, unsupported);
        }
        if torn > 0 {
            // Expected after an unclean stop: the last append never completed.
            metrics().spool_truncated_tail_record(torn);
            info!(
                records = torn,
                "spool: discarded torn tail record(s) from an interrupted append"
            );
        }
        if recovered > 0 {
            metrics().spool_recovered_records(recovered as u64);
        }
        recovered
    }

    /// Rewrite the journal from the live set: temp file, fsync, atomic rename.
    ///
    /// The rename is what makes this crash-safe — a reader (this agent on its
    /// next start) sees either the old complete journal or the new one, never a
    /// partially rewritten file.
    pub(crate) fn compact(&mut self) {
        let Some(path) = self.file.as_ref().map(|f| f.path.clone()) else {
            return;
        };

        let tmp = path.with_extension(format!("journal.tmp.{}", std::process::id()));
        let mut buf = Vec::with_capacity(self.bytes as usize + 64);
        buf.extend_from_slice(journal::JOURNAL_HEADER.as_bytes());
        buf.push(b'\n');
        for entry in &self.mem {
            let rec = JournalRecord {
                v: journal::RECORD_VERSION,
                seq: entry.seq,
                attempts: entry.attempts,
                event: entry.event.clone(),
            };
            match journal::encode(&rec) {
                Ok(line) => buf.extend_from_slice(&line),
                Err(e) => {
                    warn!(error = %e, "spool: skipping unserializable entry during compaction")
                }
            }
        }

        let result = (|| -> std::io::Result<()> {
            let mut f = open_private_write(&tmp)?;
            f.write_all(&buf)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)
        })();

        match result {
            Ok(()) => match open_private_append(&path) {
                Ok(handle) => {
                    self.file = Some(JournalFile::new(path, handle));
                    self.appends_since_compact = 0;
                    // Compaction just fsync'd the rewritten journal, so the
                    // periodic-fsync clock also resets here.
                    self.appends_since_fsync = 0;
                    self.maybe_rearm(true);
                }
                Err(e) => {
                    warn!(error = %e, "spool: reopen after compaction failed — memory only");
                    self.file = None;
                    self.degraded = true;
                }
            },
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                warn!(error = %e, "spool: compaction failed — journal left as-is");
                // The existing journal is still valid, so durability is intact;
                // only the space reclamation was lost.
            }
        }
    }

    /// Flush and compact — called on a clean shutdown so the next start replays
    /// exactly the un-acknowledged set.
    pub fn checkpoint(&mut self) {
        if self.file.is_some() {
            if let Err(e) = self.sync_journal() {
                warn!(error = %e, "spool: final journal fsync failed — durability lost, continuing in memory");
                self.file = None;
                self.degraded = true;
                self.publish();
                return;
            }
        }
        self.compact();
        self.publish();
    }
}

/// Observability accessors.
///
/// The agent reads live queue state through the metric registry, which the
/// queue publishes to on every mutation; these exist so the queue's state is
/// assertable from tests without reaching into private fields, and so shutdown
/// can report what is still pending. Configured ceilings deliberately have no
/// accessor — they are published to the registry, which is the one place the
/// diagnostics command reads them from.
///
/// Several are read only from `#[cfg(test)]` code, hence the conditional allow:
/// they are assertions about queue behaviour, not production call sites.
#[cfg_attr(not(test), allow(dead_code))]
impl Spool {
    /// Events currently awaiting acknowledgement.
    pub fn len(&self) -> usize {
        self.mem.len()
    }

    /// Bytes currently held, matching what the journal would occupy.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Events evicted because the queue was at capacity.
    pub fn dropped_total(&self) -> u64 {
        self.dropped_total
    }

    /// Journal records that failed checksum validation during recovery.
    pub fn corrupt_records(&self) -> u64 {
        self.corrupt_records
    }

    /// Successful journal fsyncs performed independent of compaction — proves
    /// durability does not wait for [`COMPACT_EVERY`] (see the module-level
    /// durability note and [`FSYNC_EVERY`]).
    pub fn fsyncs_total(&self) -> u64 {
        self.fsyncs_total
    }

    /// Thread the most recent `push()` executed on (test-only instrumentation
    /// for asserting blocking journal I/O runs off the async executor).
    #[cfg(test)]
    pub fn last_push_thread(&self) -> Option<std::thread::ThreadId> {
        self.last_push_thread
    }

    /// True when the queue lost its on-disk backing and is running in memory.
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// State of the emergency disk reserve.
    pub fn reserve_state(&self) -> ReserveState {
        self.reserve
            .as_ref()
            .map_or(ReserveState::Disabled, |r| r.state)
    }

    /// True when the queue is durable — writes are reaching the journal.
    pub fn is_durable(&self) -> bool {
        self.file.is_some()
    }
}

/// Create a directory only the agent user can enter (`0700`).
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Open the journal for appending, `0600`.
///
/// `create_new`-style private mode is set at open time rather than chmod-ed
/// afterwards: the journal holds full command lines and file paths, and a
/// world-readable window between creation and chmod would leak them on a
/// multi-user host.
fn open_private_append(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    set_private_mode(&mut opts);
    opts.open(path)
}

/// Create a new file `0600`, failing if anything (including a symlink) is
/// already at `path` — `O_EXCL` does not follow a planted link.
fn open_private_create_new(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    set_private_mode(&mut opts);
    opts.open(path)
}

/// Really allocate `size` bytes at `path`: zeros are written and synced, a
/// sparse `set_len` would free nothing when the file is later deleted. Bounded
/// by `budget`; a partial file is removed on any failure.
fn allocate_reserve(path: &Path, size: u64, budget: Duration) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut file = open_private_create_new(path)?;
    let started = Instant::now();
    let result = (|| -> std::io::Result<()> {
        let chunk = vec![0u8; RESERVE_CHUNK];
        let mut left = size;
        while left > 0 {
            if started.elapsed() > budget {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "reserve allocation exceeded its time budget",
                ));
            }
            let n = left.min(RESERVE_CHUNK as u64) as usize;
            file.write_all(&chunk[..n])?;
            left -= n as u64;
        }
        file.sync_all()
    })();
    if result.is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
    }
    result
}

/// True for "no space left" errors: `ErrorKind::StorageFull`, `ENOSPC` on
/// Unix, `ERROR_DISK_FULL` (112) / `ERROR_HANDLE_DISK_FULL` (39) on Windows.
pub(crate) fn is_disk_full(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::StorageFull {
        return true;
    }
    match e.raw_os_error() {
        #[cfg(unix)]
        Some(code) => code == libc::ENOSPC,
        #[cfg(windows)]
        Some(code) => code == 112 || code == 39,
        _ => false,
    }
}

/// Bytes available to the unprivileged agent on the filesystem holding `path`'s
/// directory, or `None` if the platform query is unavailable or fails.
#[cfg(unix)]
fn free_space_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt as _;
    let dir = path.parent()?;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c` is a valid NUL-terminated path and `st` is a properly sized
    // out-parameter that statvfs fully initialises on success.
    let st = unsafe {
        let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if libc::statvfs(c.as_ptr(), st.as_mut_ptr()) != 0 {
            return None;
        }
        st.assume_init()
    };
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

#[cfg(windows)]
fn free_space_bytes(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let dir = path.parent()?;
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut available = 0u64;
    // SAFETY: `wide` is NUL-terminated and `available` is a valid out-pointer;
    // the other two out-parameters are optional and passed as null.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(available)
}

#[cfg(not(any(unix, windows)))]
fn free_space_bytes(_path: &Path) -> Option<u64> {
    None
}

fn open_private_write(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    set_private_mode(&mut opts);
    opts.open(path)
}

#[allow(unused_variables)]
fn set_private_mode(opts: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
}

/// Resolve the durable event capacity, honouring `TRAPD_SPOOL_MAX`.
pub fn spool_max_from_env() -> usize {
    std::env::var("TRAPD_SPOOL_MAX")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(SPOOL_MAX_DURABLE)
}

/// Resolve the durable byte capacity, honouring `TRAPD_SPOOL_MAX_BYTES`.
pub fn spool_max_bytes_from_env() -> u64 {
    std::env::var("TRAPD_SPOOL_MAX_BYTES")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(SPOOL_MAX_BYTES)
}

/// Resolve the emergency reserve size in bytes, honouring
/// `TRAPD_SPOOL_RESERVE_MB` (`0` disables, clamped to a sane maximum).
pub fn spool_reserve_bytes_from_env() -> u64 {
    let mb = std::env::var("TRAPD_SPOOL_RESERVE_MB")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(SPOOL_RESERVE_DEFAULT_MB)
        .min(SPOOL_RESERVE_MAX_MB);
    mb * 1024 * 1024
}

#[cfg(all(test, unix))]
mod sync_failure_tests {
    use super::*;
    use crate::schema::{EventAction, EventData, Severity};

    #[tokio::test]
    async fn retry_sync_failure_keeps_one_record_without_confirming_durability() {
        let dir = std::env::temp_dir().join(format!("trapd-retry-sync-{}", uuid::Uuid::new_v4()));
        let mut spool = Spool::durable_at(dir.join("queue.journal"), 2);
        let event = AgentEvent::new(
            "test".into(),
            "host".into(),
            EventClass::Process,
            EventAction::Create,
            Severity::Info,
            EventData::ProcessExec(Box::default()),
        );
        let seq = spool.push(event.clone()).unwrap();
        spool.file.as_mut().unwrap().handle =
            OpenOptions::new().write(true).open("/dev/null").unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        for _ in 0..3 {
            let tx = tx.clone();
            let retry = event.clone();
            let sender =
                tokio::spawn(async move { super::super::receipt::send_durable(&tx, retry).await });
            assert_eq!(spool.push(rx.recv().await.unwrap()).unwrap(), seq);
            assert!(sender.await.unwrap().is_err());
            assert_eq!(spool.len(), 1);
            assert_eq!(spool.fsyncs_total(), 0);
            assert!(spool.is_degraded());
        }
        assert_eq!(spool.dropped_total(), 0);
        drop(spool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_shutdown_sync_marks_durability_lost() {
        let dir = std::env::temp_dir().join(format!("trapd-sync-{}", uuid::Uuid::new_v4()));
        let mut spool = Spool::durable_at(dir.join("queue.journal"), 100);
        spool.file.as_mut().unwrap().handle =
            OpenOptions::new().write(true).open("/dev/null").unwrap();
        spool.checkpoint();
        assert!(
            spool.is_degraded(),
            "checkpoint must surface a failed final sync"
        );
        assert!(!spool.is_durable());
        drop(spool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_periodic_sync_is_not_successful_durability() {
        let dir = std::env::temp_dir().join(format!("trapd-sync-{}", uuid::Uuid::new_v4()));
        let mut spool = Spool::durable_at(dir.join("queue.journal"), 100);
        // A real OS handle accepts writes but rejects fsync. Unlike a read-only
        // file, this reproduces precisely the write-success/sync-failure path.
        spool.file.as_mut().unwrap().handle =
            OpenOptions::new().write(true).open("/dev/null").unwrap();
        for _ in 0..FSYNC_EVERY {
            spool
                .push(AgentEvent::new(
                    "test".into(),
                    "host".into(),
                    EventClass::Process,
                    EventAction::Exec,
                    Severity::Info,
                    EventData::ProcessExec(Box::default()),
                ))
                .unwrap();
        }
        assert_eq!(
            spool.fsyncs_total(),
            0,
            "failed sync must not count as success"
        );
        assert!(spool.is_degraded(), "durability failure must be visible");
        assert!(!spool.is_durable());
        assert_eq!(
            spool.len(),
            FSYNC_EVERY,
            "collection must continue in memory"
        );
        assert_eq!(
            spool.dropped_total(),
            0,
            "loss of durability is not confirmed event loss"
        );
        drop(spool);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod reserve_tests {
    use super::*;
    use crate::schema::{EventAction, EventData, Severity};

    const MIB: u64 = 1024 * 1024;

    fn event() -> AgentEvent {
        AgentEvent::new(
            "test".into(),
            "host".into(),
            EventClass::Process,
            EventAction::Exec,
            Severity::Info,
            EventData::ProcessExec(Box::default()),
        )
    }

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("trapd-reserve-{}", uuid::Uuid::new_v4()))
    }

    fn reserve_path(dir: &Path) -> PathBuf {
        dir.join(RESERVE_FILE_NAME)
    }

    fn spool_with_reserve(dir: &Path, mb: u64) -> Spool {
        Spool::durable_at(dir.join("queue.journal"), 100).with_reserve_bytes(mb * MIB)
    }

    #[test]
    fn reserve_is_created_fully_allocated_with_configured_size() {
        let dir = temp_dir();
        let spool = spool_with_reserve(&dir, 2);
        assert_eq!(spool.reserve_state(), ReserveState::Armed);
        let meta = std::fs::metadata(reserve_path(&dir)).unwrap();
        assert_eq!(meta.len(), 2 * MIB);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            // Really allocated (not sparse) and private.
            assert!(meta.blocks() * 512 >= 2 * MIB);
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
        drop(spool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reserve_size_zero_disables_and_removes_a_stale_file() {
        let dir = temp_dir();
        drop(spool_with_reserve(&dir, 1));
        assert!(reserve_path(&dir).exists());
        let spool = spool_with_reserve(&dir, 0);
        assert_eq!(spool.reserve_state(), ReserveState::Disabled);
        assert!(!reserve_path(&dir).exists());
        drop(spool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn in_memory_spool_never_creates_a_reserve() {
        let spool = Spool::in_memory(10).with_reserve_bytes(MIB);
        assert_eq!(spool.reserve_state(), ReserveState::Disabled);
        assert!(spool.reserve.is_none());
    }

    #[test]
    fn unallocatable_reserve_is_unavailable_and_leaves_no_file() {
        let dir = temp_dir();
        let mut spool = Spool::durable_at(dir.join("queue.journal"), 100);
        // A directory squatting on the path makes allocation fail.
        std::fs::create_dir(reserve_path(&dir)).unwrap();
        spool = spool.with_reserve_bytes(MIB);
        assert_eq!(spool.reserve_state(), ReserveState::Unavailable);
        assert!(spool.push(event()).is_ok());
        assert!(spool.is_durable());
        drop(spool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn allocation_over_budget_is_aborted_and_cleaned_up() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = reserve_path(&dir);
        let err = allocate_reserve(&path, 4 * MIB, Duration::ZERO).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn env_size_defaults_clamps_and_disables() {
        // Single test owns the variable to avoid races with other tests.
        std::env::remove_var("TRAPD_SPOOL_RESERVE_MB");
        assert_eq!(spool_reserve_bytes_from_env(), 64 * MIB);
        std::env::set_var("TRAPD_SPOOL_RESERVE_MB", "0");
        assert_eq!(spool_reserve_bytes_from_env(), 0);
        std::env::set_var("TRAPD_SPOOL_RESERVE_MB", "999999");
        assert_eq!(spool_reserve_bytes_from_env(), 1024 * MIB);
        std::env::set_var("TRAPD_SPOOL_RESERVE_MB", "garbage");
        assert_eq!(spool_reserve_bytes_from_env(), 64 * MIB);
        std::env::remove_var("TRAPD_SPOOL_RESERVE_MB");
    }

    #[test]
    fn disk_full_classification() {
        use std::io::{Error, ErrorKind};
        assert!(is_disk_full(&Error::from(ErrorKind::StorageFull)));
        assert!(!is_disk_full(&Error::from(ErrorKind::PermissionDenied)));
        assert!(!is_disk_full(&Error::other("x")));
        #[cfg(unix)]
        {
            assert!(is_disk_full(&Error::from_raw_os_error(libc::ENOSPC)));
            assert!(!is_disk_full(&Error::from_raw_os_error(libc::EACCES)));
            assert!(!is_disk_full(&Error::from_raw_os_error(libc::EIO)));
        }
        #[cfg(windows)]
        {
            assert!(is_disk_full(&Error::from_raw_os_error(112)));
            assert!(is_disk_full(&Error::from_raw_os_error(39)));
            assert!(!is_disk_full(&Error::from_raw_os_error(5)));
        }
    }

    #[test]
    fn disk_full_append_consumes_reserve_and_stays_durable_without_corruption() {
        let dir = temp_dir();
        let mut spool = spool_with_reserve(&dir, 1);
        spool.push(event()).unwrap();
        spool.inject_write_disk_full = 1;
        spool.push(event()).unwrap();
        spool.push(event()).unwrap();

        assert!(!spool.is_degraded());
        assert!(spool.is_durable());
        assert_eq!(spool.reserve_state(), ReserveState::InUse);
        assert_eq!(spool.reserve.as_ref().unwrap().consumed_total, 1);
        assert!(!reserve_path(&dir).exists());
        assert_eq!(spool.len(), 3);

        // The half-written first attempt must not have corrupted the journal:
        // all three records replay, none is corrupt.
        drop(spool);
        let replayed = Spool::durable_at(dir.join("queue.journal"), 100);
        assert_eq!(replayed.len(), 3);
        assert_eq!(replayed.corrupt_records(), 0);
        drop(replayed);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn second_disk_full_without_reserve_degrades_as_before() {
        let dir = temp_dir();
        let mut spool = spool_with_reserve(&dir, 1);
        spool.inject_write_disk_full = 1;
        spool.push(event()).unwrap();
        assert!(spool.is_durable());
        assert_eq!(spool.reserve_state(), ReserveState::InUse);

        spool.inject_write_disk_full = 1;
        spool.push(event()).unwrap();
        assert!(spool.is_degraded());
        assert!(!spool.is_durable());
        assert_eq!(spool.len(), 2, "collection continues in memory");
        assert_eq!(spool.dropped_total(), 0);
        drop(spool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_retry_after_reserve_release_degrades() {
        let dir = temp_dir();
        let mut spool = spool_with_reserve(&dir, 1);
        spool.inject_write_disk_full = 2;
        spool.push(event()).unwrap();
        assert!(spool.is_degraded());
        assert_eq!(spool.reserve_state(), ReserveState::InUse);
        drop(spool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn non_disk_full_error_does_not_touch_the_reserve() {
        let dir = temp_dir();
        let mut spool = spool_with_reserve(&dir, 1);
        // A read-only handle fails with EBADF / access denied, not disk-full.
        spool.file.as_mut().unwrap().handle = File::open(dir.join("queue.journal")).unwrap();
        spool.push(event()).unwrap();
        assert!(spool.is_degraded());
        assert_eq!(spool.reserve_state(), ReserveState::Armed);
        assert!(reserve_path(&dir).exists());
        drop(spool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn disk_full_fsync_consumes_reserve_and_retries_once() {
        let dir = temp_dir();
        let mut spool = spool_with_reserve(&dir, 1);
        for _ in 0..FSYNC_EVERY - 1 {
            spool.push(event()).unwrap();
        }
        spool.inject_sync_disk_full = 1;
        spool.push(event()).unwrap();
        assert!(!spool.is_degraded());
        assert_eq!(spool.reserve_state(), ReserveState::InUse);
        assert_eq!(spool.fsyncs_total(), 1);

        // Reserve gone: the next disk-full fsync degrades.
        for _ in 0..FSYNC_EVERY - 1 {
            spool.push(event()).unwrap();
        }
        spool.inject_sync_disk_full = 1;
        spool.push(event()).unwrap();
        assert!(spool.is_degraded());
        drop(spool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reserve_is_rearmed_after_compaction_when_space_allows() {
        let dir = temp_dir();
        let mut spool = spool_with_reserve(&dir, 1);
        spool.inject_write_disk_full = 1;
        spool.push(event()).unwrap();
        assert_eq!(spool.reserve_state(), ReserveState::InUse);

        spool.free_space_override = Some(2 * MIB);
        spool.compact();
        assert_eq!(spool.reserve_state(), ReserveState::Armed);
        assert_eq!(std::fs::metadata(reserve_path(&dir)).unwrap().len(), MIB);
        assert_eq!(
            spool.reserve.as_ref().unwrap().consumed_total,
            1,
            "history of consumption is kept"
        );
        drop(spool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rearm_is_skipped_below_twice_the_reserve_size() {
        let dir = temp_dir();
        let mut spool = spool_with_reserve(&dir, 1);
        spool.inject_write_disk_full = 1;
        spool.push(event()).unwrap();

        spool.free_space_override = Some(2 * MIB - 1);
        spool.compact();
        assert_eq!(spool.reserve_state(), ReserveState::InUse);
        assert!(!reserve_path(&dir).exists());
        drop(spool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn periodic_rearm_is_throttled() {
        let dir = temp_dir();
        let mut spool = spool_with_reserve(&dir, 1);
        spool.inject_write_disk_full = 1;
        spool.push(event()).unwrap();
        spool.free_space_override = Some(10 * MIB);

        // Just attempted: a plain push must not retry yet.
        spool.reserve.as_mut().unwrap().last_attempt = Some(Instant::now());
        spool.push(event()).unwrap();
        assert_eq!(spool.reserve_state(), ReserveState::InUse);

        // Long enough ago: the next push re-arms.
        spool.reserve.as_mut().unwrap().last_attempt =
            Instant::now().checked_sub(RESERVE_REARM_INTERVAL + Duration::from_secs(1));
        spool.push(event()).unwrap();
        assert_eq!(spool.reserve_state(), ReserveState::Armed);
        drop(spool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn free_space_query_reports_something_for_a_real_directory() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        assert!(free_space_bytes(&dir.join("x")).is_some_and(|b| b > 0));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
