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

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

use tracing::{info, warn};

use super::backoff;
use super::journal::{self, JournalRecord, LineRead, RecordOutcome};
use crate::schema::AgentEvent;
use crate::telemetry::limits::{MAX_BATCH_BYTES, MAX_EVENT_BYTES, MAX_RECORD_BYTES};
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

impl SpoolEntry {
    fn is_eligible(&self, now: Instant) -> bool {
        self.not_before.is_none_or(|t| now >= t)
    }
}

struct JournalFile {
    path: PathBuf,
    handle: File,
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
    dropped_total: u64,
    corrupt_records: u64,
    appends_since_compact: usize,
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
            dropped_total: 0,
            corrupt_records: 0,
            appends_since_compact: 0,
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
        Self::durable_at(path, max_events)
    }

    /// Byte ceiling override, for tests and for `TRAPD_SPOOL_MAX_BYTES`.
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self.publish_capacity();
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
                spool.file = Some(JournalFile {
                    path: path.clone(),
                    handle,
                });
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
            return Err(DropReason::EventTooLarge);
        }

        self.next_seq += 1;
        self.append_to_journal(&encoded);

        let entry = SpoolEntry {
            seq,
            event: record.event,
            attempts: 0,
            bytes: encoded.len(),
            not_before: None,
        };
        self.bytes += entry.bytes as u64;
        self.mem.push_back(entry);

        self.enforce_caps();

        if self.file.is_some() && self.appends_since_compact >= COMPACT_EVERY {
            self.compact();
        }
        self.publish();
        Ok(seq)
    }

    /// Evict from the front until both caps are satisfied.
    fn enforce_caps(&mut self) {
        let mut evicted = 0u64;
        while self.mem.len() > self.max_events || self.bytes > self.max_bytes {
            let Some(old) = self.mem.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(old.bytes as u64);
            evicted += 1;
        }
        if evicted > 0 {
            self.dropped_total += evicted;
            metrics().events_dropped(DropReason::PersistentQueueFull, evicted);
            // Log the first overflow and then every thousandth, so a sustained
            // outage does not itself become a log flood.
            if self.dropped_total - evicted == 0 || self.dropped_total % 1_000 < evicted {
                warn!(
                    dropped_total = self.dropped_total,
                    max_events = self.max_events,
                    max_bytes = self.max_bytes,
                    "spool at capacity — evicting oldest events (backend unreachable?)"
                );
            }
        }
    }

    fn append_to_journal(&mut self, encoded: &[u8]) {
        let Some(f) = self.file.as_mut() else {
            return;
        };
        if let Err(e) = f.handle.write_all(encoded) {
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
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for entry in self.mem.iter() {
            if out.len() >= n {
                break;
            }
            if !entry.is_eligible(now) {
                continue;
            }
            if !out.is_empty() && bytes + entry.bytes > MAX_BATCH_BYTES {
                break;
            }
            bytes += entry.bytes;
            out.push(entry.clone());
        }
        out
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
                    self.file = Some(JournalFile { path, handle });
                    self.appends_since_compact = 0;
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
        if let Some(f) = self.file.as_mut() {
            let _ = f.handle.flush();
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

    /// True when the queue lost its on-disk backing and is running in memory.
    pub fn is_degraded(&self) -> bool {
        self.degraded
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
