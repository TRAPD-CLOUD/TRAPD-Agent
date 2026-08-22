//! Persistent-queue tests.
//!
//! The queue's contract is that an accepted event is always in exactly one of
//! three states — acknowledged, still queued, or dropped with a named reason —
//! and these tests exercise the paths where that could silently break: crashes
//! mid-append, corrupted journals, capacity overflow, partial and duplicate
//! acknowledgements, and a filesystem that stops accepting writes.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::journal::{self, JournalRecord};
use super::spool::Spool;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, ExecEventData, Severity, SystemSnapshotData,
};

fn dummy_event() -> AgentEvent {
    AgentEvent::new(
        "agent-test".to_string(),
        "test-host".to_string(),
        EventClass::System,
        EventAction::Snapshot,
        Severity::Info,
        EventData::SystemSnapshot(SystemSnapshotData {
            os: "Linux".to_string(),
            kernel: "6.0.0".to_string(),
            distro: "Test".to_string(),
            cpu_count: 1,
            cpu_usage_pct: 0.0,
            memory_total_mb: 1024,
            memory_used_mb: 512,
            memory_free_mb: 512,
            uptime_secs: 100,
            load_avg: [0.0, 0.0, 0.0],
        }),
    )
}

/// An exec event whose command line is `size` bytes — for size-limit tests.
fn exec_event_with_cmdline(size: usize) -> AgentEvent {
    AgentEvent::new(
        "agent-test".to_string(),
        "test-host".to_string(),
        EventClass::Process,
        EventAction::Exec,
        Severity::Info,
        EventData::ProcessExec(Box::new(ExecEventData {
            cmdline: "a".repeat(size),
            ..Default::default()
        })),
    )
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "trapd_spool_{}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            tag,
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn journal(&self) -> PathBuf {
        self.0.join("queue.journal")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ── In-memory semantics ──────────────────────────────────────────────────────

#[test]
fn accepted_events_get_increasing_handles() {
    let mut s = Spool::in_memory(10);
    let a = s.push(dummy_event()).unwrap();
    let b = s.push(dummy_event()).unwrap();
    assert!(b > a, "acknowledgement handles must be unique and ordered");
    assert_eq!(s.len(), 2);
}

#[test]
fn overflow_evicts_oldest_and_names_the_reason() {
    let mut s = Spool::in_memory(3);
    for _ in 0..4 {
        s.push(dummy_event()).unwrap();
    }
    assert_eq!(s.len(), 3, "capacity must be enforced");
    assert_eq!(
        s.dropped_total(),
        1,
        "the eviction must be counted, not silent"
    );
}

#[test]
fn byte_capacity_is_enforced_independently_of_the_event_count() {
    // 1000 events would fit by count, but not by bytes.
    let mut s = Spool::in_memory(1000).with_max_bytes(4096);
    for _ in 0..50 {
        s.push(exec_event_with_cmdline(512)).unwrap();
    }
    assert!(
        s.bytes() <= 4096,
        "byte ceiling must hold, got {} bytes",
        s.bytes()
    );
    assert!(s.dropped_total() > 0, "evictions must be counted");
    assert!(s.len() < 50);
}

#[test]
fn an_oversized_event_is_refused_with_a_reason() {
    let mut s = Spool::in_memory(10);
    let err = s
        .push(exec_event_with_cmdline(
            crate::telemetry::limits::MAX_EVENT_BYTES + 1,
        ))
        .unwrap_err();
    assert_eq!(
        err,
        crate::telemetry::DropReason::EventTooLarge,
        "an event too large to ever ship must be refused at the door"
    );
    assert_eq!(s.len(), 0, "it must not occupy the queue");
}

#[test]
fn peek_does_not_consume() {
    let mut s = Spool::in_memory(100);
    for _ in 0..5 {
        s.push(dummy_event()).unwrap();
    }
    assert_eq!(s.peek_batch(3).len(), 3);
    assert_eq!(s.len(), 5, "peek must leave the queue intact");
    assert_eq!(s.peek_batch(100).len(), 5, "peek is capped at what exists");
}

#[test]
fn peek_returns_entries_in_fifo_order() {
    let mut s = Spool::in_memory(100);
    let seqs: Vec<u64> = (0..5).map(|_| s.push(dummy_event()).unwrap()).collect();
    let peeked: Vec<u64> = s.peek_batch(5).iter().map(|e| e.seq).collect();
    assert_eq!(peeked, seqs, "delivery order must follow arrival order");
}

// ── Acknowledgement semantics ────────────────────────────────────────────────

#[test]
fn acknowledging_removes_exactly_those_entries() {
    let mut s = Spool::in_memory(100);
    let seqs: Vec<u64> = (0..5).map(|_| s.push(dummy_event()).unwrap()).collect();

    assert_eq!(s.ack(&seqs[1..3]), 2);
    assert_eq!(s.len(), 3);

    let remaining: Vec<u64> = s.peek_batch(10).iter().map(|e| e.seq).collect();
    assert_eq!(remaining, vec![seqs[0], seqs[3], seqs[4]]);
}

#[test]
fn a_partial_acknowledgement_leaves_the_rest_queued() {
    // The backend accepted 3 of 5; the other 2 must stay for redelivery.
    let mut s = Spool::in_memory(100);
    let seqs: Vec<u64> = (0..5).map(|_| s.push(dummy_event()).unwrap()).collect();

    s.ack(&seqs[..3]);
    assert_eq!(s.len(), 2, "unacknowledged events must never be discarded");
    let left: Vec<u64> = s.peek_batch(10).iter().map(|e| e.seq).collect();
    assert_eq!(left, vec![seqs[3], seqs[4]]);
}

#[test]
fn a_duplicate_acknowledgement_is_harmless() {
    let mut s = Spool::in_memory(100);
    let seqs: Vec<u64> = (0..3).map(|_| s.push(dummy_event()).unwrap()).collect();

    assert_eq!(s.ack(&seqs[..2]), 2);
    assert_eq!(
        s.ack(&seqs[..2]),
        0,
        "re-acknowledging must not remove anything else"
    );
    assert_eq!(s.len(), 1);
}

#[test]
fn acknowledging_an_unknown_handle_is_a_noop() {
    let mut s = Spool::in_memory(100);
    s.push(dummy_event()).unwrap();
    assert_eq!(s.ack(&[999_999]), 0);
    assert_eq!(s.len(), 1, "a stale handle must not evict a live event");
}

#[test]
fn acknowledging_out_of_order_works() {
    let mut s = Spool::in_memory(100);
    let seqs: Vec<u64> = (0..4).map(|_| s.push(dummy_event()).unwrap()).collect();
    s.ack(&[seqs[3], seqs[0]]);
    let left: Vec<u64> = s.peek_batch(10).iter().map(|e| e.seq).collect();
    assert_eq!(left, vec![seqs[1], seqs[2]]);
}

#[test]
fn acknowledging_frees_bytes() {
    let mut s = Spool::in_memory(100);
    let seq = s.push(exec_event_with_cmdline(1024)).unwrap();
    assert!(s.bytes() > 1024);
    s.ack(&[seq]);
    assert_eq!(s.bytes(), 0, "byte accounting must not leak on ack");
}

#[test]
fn an_empty_acknowledgement_changes_nothing() {
    let mut s = Spool::in_memory(100);
    s.push(dummy_event()).unwrap();
    assert_eq!(s.ack(&[]), 0);
    assert_eq!(s.len(), 1);
}

// ── Retry / backoff ──────────────────────────────────────────────────────────

#[test]
fn a_failed_entry_is_held_back_then_retried() {
    let mut s = Spool::in_memory(100);
    let seq = s.push(dummy_event()).unwrap();
    let now = Instant::now();

    s.nack_at(&[seq], now);
    assert!(
        s.peek_batch_at(10, now).is_empty(),
        "a just-failed entry must not be retried immediately"
    );

    // Once its backoff elapses it becomes eligible again.
    s.set_not_before(seq, None);
    assert_eq!(s.peek_batch_at(10, now).len(), 1);
}

#[test]
fn repeated_failures_increase_the_attempt_count() {
    let mut s = Spool::in_memory(100);
    let seq = s.push(dummy_event()).unwrap();
    let now = Instant::now();

    for expected in 1..=3 {
        s.nack_at(&[seq], now);
        s.set_not_before(seq, None);
        assert_eq!(s.peek_batch_at(10, now)[0].attempts, expected);
    }
}

#[test]
fn a_backed_off_entry_does_not_block_the_ones_behind_it() {
    // Head-of-line blocking would stall the whole queue on one poison record.
    let mut s = Spool::in_memory(100);
    let first = s.push(dummy_event()).unwrap();
    let second = s.push(dummy_event()).unwrap();
    let now = Instant::now();

    s.nack_at(&[first], now);
    let batch = s.peek_batch_at(10, now);
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].seq, second, "the queue must keep making progress");
}

#[test]
fn nacking_an_unknown_handle_is_a_noop() {
    let mut s = Spool::in_memory(100);
    let seq = s.push(dummy_event()).unwrap();
    s.nack_at(&[999_999], Instant::now());
    assert_eq!(s.peek_batch(10)[0].attempts, 0);
    assert_eq!(s.peek_batch(10)[0].seq, seq);
}

#[test]
fn a_future_deadline_keeps_an_entry_ineligible() {
    let mut s = Spool::in_memory(100);
    let seq = s.push(dummy_event()).unwrap();
    let now = Instant::now();
    s.set_not_before(seq, Some(now + Duration::from_secs(60)));
    assert!(s.peek_batch_at(10, now).is_empty());
    assert_eq!(
        s.peek_batch_at(10, now + Duration::from_secs(61)).len(),
        1,
        "it must become eligible once the deadline passes"
    );
}

// ── Durability & crash recovery ──────────────────────────────────────────────

#[test]
fn periodic_fsync_runs_well_before_compaction_threshold() {
    // Durability must not depend on hitting COMPACT_EVERY (5,000 appends) — a
    // much more frequent periodic fsync (every 50 appends, FSYNC_EVERY in
    // spool.rs) is what actually bounds the crash-loss window. This exercises
    // the fsync counter directly rather than trying to observe crash
    // survival, which a unit test cannot do.
    let dir = TempDir::new("periodic_fsync");
    let mut s = Spool::durable_at(dir.journal(), 1_000);

    assert_eq!(s.fsyncs_total(), 0, "no appends yet — no fsync yet");

    for _ in 0..60 {
        s.push(dummy_event()).unwrap();
    }
    assert!(
        s.fsyncs_total() >= 1,
        "a periodic fsync must have run well before the 5,000-append compaction threshold"
    );
}

#[test]
fn unacknowledged_events_survive_a_restart() {
    let dir = TempDir::new("restart");
    let ids: Vec<_> = {
        let mut s = Spool::durable_at(dir.journal(), 100);
        let events: Vec<AgentEvent> = (0..3).map(|_| dummy_event()).collect();
        let ids: Vec<_> = events.iter().map(|e| e.event_id).collect();
        for e in events {
            s.push(e).unwrap();
        }
        ids
    }; // dropped without a checkpoint — an unclean stop

    let s2 = Spool::durable_at(dir.journal(), 100);
    assert_eq!(s2.len(), 3, "no unacknowledged event may be lost");
    let recovered: Vec<_> = s2.peek_batch(10).iter().map(|e| e.event.event_id).collect();
    assert_eq!(recovered, ids, "and they must be the same events");
}

#[test]
fn event_ids_are_stable_across_recovery() {
    // Backend deduplication depends on this exactly.
    let dir = TempDir::new("stable_ids");
    let original = {
        let mut s = Spool::durable_at(dir.journal(), 100);
        let e = dummy_event();
        let id = e.event_id;
        s.push(e).unwrap();
        id
    };

    let s2 = Spool::durable_at(dir.journal(), 100);
    assert_eq!(
        s2.peek_batch(1)[0].event.event_id,
        original,
        "recovery must never mint a new event_id"
    );
}

#[test]
fn retry_state_survives_a_restart() {
    let dir = TempDir::new("retry_state");
    {
        let mut s = Spool::durable_at(dir.journal(), 100);
        let seq = s.push(dummy_event()).unwrap();
        s.nack_at(&[seq], Instant::now());
        s.nack_at(&[seq], Instant::now());
        s.checkpoint();
    }

    let s2 = Spool::durable_at(dir.journal(), 100);
    let entry = &s2.peek_batch_at(10, Instant::now() + Duration::from_secs(3600))[0];
    assert_eq!(
        entry.attempts, 2,
        "a poison record must not reset its backoff every restart"
    );
}

#[test]
fn acknowledged_events_are_gone_after_a_checkpoint() {
    let dir = TempDir::new("checkpoint");
    {
        let mut s = Spool::durable_at(dir.journal(), 100);
        let seqs: Vec<u64> = (0..3).map(|_| s.push(dummy_event()).unwrap()).collect();
        s.ack(&seqs[..2]);
        s.checkpoint();
    }

    let s2 = Spool::durable_at(dir.journal(), 100);
    assert_eq!(s2.len(), 1, "acknowledged events must not be replayed");
}

#[test]
fn without_a_checkpoint_delivery_is_at_least_once() {
    // The documented trade-off: a crash between "shipped" and "compacted"
    // replays already-delivered events. Duplicates are safe because event_id is
    // stable; losing them would not be.
    let dir = TempDir::new("atleastonce");
    {
        let mut s = Spool::durable_at(dir.journal(), 100);
        let seqs: Vec<u64> = (0..2).map(|_| s.push(dummy_event()).unwrap()).collect();
        s.ack(&seqs[..1]);
        // No checkpoint — simulates a crash right after shipping.
    }

    let s2 = Spool::durable_at(dir.journal(), 100);
    assert_eq!(
        s2.len(),
        2,
        "at-least-once: replaying a delivered event is acceptable, losing one is not"
    );
}

#[test]
fn handles_are_not_reissued_after_recovery() {
    let dir = TempDir::new("seq_continuity");
    let last = {
        let mut s = Spool::durable_at(dir.journal(), 100);
        let mut last = 0;
        for _ in 0..3 {
            last = s.push(dummy_event()).unwrap();
        }
        last
    };

    let mut s2 = Spool::durable_at(dir.journal(), 100);
    let next = s2.push(dummy_event()).unwrap();
    assert!(
        next > last,
        "a recovered spool must not reuse handle {last} (got {next})"
    );
}

#[test]
fn capacity_is_enforced_while_replaying() {
    let dir = TempDir::new("replay_cap");
    {
        let mut s = Spool::durable_at(dir.journal(), 50);
        for _ in 0..20 {
            s.push(dummy_event()).unwrap();
        }
    }
    // Restart with a much smaller cap: recovery must not blow past it.
    let s2 = Spool::durable_at(dir.journal(), 5);
    assert_eq!(s2.len(), 5, "a large journal must not overflow a small cap");
}

// ── Damaged journals ─────────────────────────────────────────────────────────

#[test]
fn a_torn_final_record_is_recovered_around_not_flagged_as_corruption() {
    let dir = TempDir::new("torn_tail");
    {
        let mut s = Spool::durable_at(dir.journal(), 100);
        s.push(dummy_event()).unwrap();
        s.push(dummy_event()).unwrap();
        s.checkpoint();
    }

    // Simulate a crash mid-append: chop the file's last few bytes.
    let mut bytes = std::fs::read(dir.journal()).unwrap();
    bytes.truncate(bytes.len() - 12);
    std::fs::write(dir.journal(), &bytes).unwrap();

    let s2 = Spool::durable_at(dir.journal(), 100);
    assert_eq!(s2.len(), 1, "the intact record must still be recovered");
    assert_eq!(
        s2.corrupt_records(),
        0,
        "an interrupted append is expected, not corruption"
    );
}

#[test]
fn a_corrupt_record_is_counted_and_the_rest_still_recover() {
    let dir = TempDir::new("corrupt");
    {
        let mut s = Spool::durable_at(dir.journal(), 100);
        for _ in 0..3 {
            s.push(dummy_event()).unwrap();
        }
        s.checkpoint();
    }

    // Corrupt the payload of the middle record, leaving its framing intact.
    let text = std::fs::read_to_string(dir.journal()).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let target = lines.len() / 2;
    let line = &mut lines[target];
    let mid = line.len() / 2 + 20;
    line.replace_range(mid..mid + 1, "X");
    std::fs::write(dir.journal(), lines.join("\n") + "\n").unwrap();

    let s2 = Spool::durable_at(dir.journal(), 100);
    assert_eq!(
        s2.corrupt_records(),
        1,
        "corruption must be counted so health escalates to recovery_required"
    );
    assert_eq!(
        s2.len(),
        2,
        "one damaged record must not cost the whole journal"
    );
}

#[test]
fn a_journal_of_pure_garbage_does_not_crash_recovery() {
    let dir = TempDir::new("garbage");
    std::fs::write(
        dir.journal(),
        b"\x00\x01\x02 not a journal at all\n\xff\xfe\nzzzz 9 abc\n",
    )
    .unwrap();

    let s = Spool::durable_at(dir.journal(), 100);
    assert_eq!(s.len(), 0);
    assert!(s.corrupt_records() > 0, "garbage must be reported, not ignored");
}

#[test]
fn an_empty_journal_recovers_cleanly() {
    let dir = TempDir::new("empty");
    std::fs::write(dir.journal(), b"").unwrap();
    let s = Spool::durable_at(dir.journal(), 100);
    assert_eq!(s.len(), 0);
    assert_eq!(s.corrupt_records(), 0);
}

#[test]
fn a_record_with_an_absurd_length_prefix_is_rejected_without_allocating() {
    let dir = TempDir::new("huge_len");
    let line = format!("00000000 {} x\n", u64::MAX);
    std::fs::write(dir.journal(), line.as_bytes()).unwrap();

    // The bound is what stops this from attempting a u64::MAX allocation.
    let s = Spool::durable_at(dir.journal(), 100);
    assert_eq!(s.len(), 0);
    assert!(s.corrupt_records() > 0);
}

#[test]
fn a_record_from_a_newer_agent_is_skipped_not_misread() {
    let dir = TempDir::new("newer_version");
    let mut rec = JournalRecord::new(1, dummy_event());
    rec.v = journal::RECORD_VERSION + 99;
    let mut body = journal::JOURNAL_HEADER.as_bytes().to_vec();
    body.push(b'\n');
    body.extend_from_slice(&journal::encode(&rec).unwrap());
    std::fs::write(dir.journal(), &body).unwrap();

    let s = Spool::durable_at(dir.journal(), 100);
    assert_eq!(s.len(), 0, "an unreadable record must not be guessed at");
    assert_eq!(
        s.corrupt_records(),
        0,
        "a version mismatch is not disk corruption"
    );
}

// ── Filesystem failure ───────────────────────────────────────────────────────

#[test]
fn an_unwritable_location_degrades_to_memory_instead_of_failing() {
    // A read-only filesystem or a full disk must not stop collection.
    let s = Spool::durable_at(PathBuf::from("/proc/trapd-cannot-exist/queue.journal"), 100);
    assert!(s.is_degraded(), "the loss of durability must be visible");
    assert!(!s.is_durable());
}

#[test]
fn a_degraded_spool_still_accepts_and_serves_events() {
    let mut s = Spool::durable_at(PathBuf::from("/proc/trapd-cannot-exist/queue.journal"), 100);
    s.push(dummy_event()).unwrap();
    assert_eq!(
        s.len(),
        1,
        "collection must continue even without durable backing"
    );
    assert_eq!(s.peek_batch(10).len(), 1);
}

#[test]
fn journal_files_are_not_world_readable() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = TempDir::new("perms");
        let mut s = Spool::durable_at(dir.journal(), 100);
        s.push(dummy_event()).unwrap();
        s.checkpoint();

        let mode = std::fs::metadata(dir.journal())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "the journal holds full command lines — it must be owner-only"
        );

        let dir_mode = std::fs::metadata(dir.journal().parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "the spool directory must be owner-only");
    }
}

#[test]
fn compaction_leaves_no_temporary_file_behind() {
    let dir = TempDir::new("no_tmp");
    let mut s = Spool::durable_at(dir.journal(), 100);
    s.push(dummy_event()).unwrap();
    s.checkpoint();

    let leftovers: Vec<_> = std::fs::read_dir(&dir.0)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("tmp"))
        .collect();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}

// ── Whole-cycle invariant ────────────────────────────────────────────────────

#[test]
fn every_accepted_event_is_acknowledged_queued_or_counted_as_dropped() {
    // The pipeline's central promise, checked as arithmetic.
    let dir = TempDir::new("accounting");
    let mut s = Spool::durable_at(dir.journal(), 10);

    let mut accepted = 0u64;
    let mut refused = 0u64;
    for _ in 0..25 {
        match s.push(dummy_event()) {
            Ok(_) => accepted += 1,
            Err(_) => refused += 1,
        }
    }

    // Acknowledge half of what is still queued.
    let batch = s.peek_batch(5);
    let acked = s.ack(&batch.iter().map(|e| e.seq).collect::<Vec<_>>()) as u64;

    let queued = s.len() as u64;
    let evicted = s.dropped_total();

    assert_eq!(
        accepted,
        acked + queued + evicted,
        "accepted={accepted} must equal acked={acked} + queued={queued} + evicted={evicted}"
    );
    assert_eq!(refused, 0, "no event should have been refused in this run");
}
