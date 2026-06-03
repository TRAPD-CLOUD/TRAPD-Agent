use std::path::PathBuf;

use uuid::Uuid;

use super::Spool;
use crate::schema::{AgentEvent, EventAction, EventClass, EventData, Severity, SystemSnapshotData};

fn dummy_event() -> AgentEvent {
    AgentEvent::new(
        Uuid::new_v4().to_string(),
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

fn tmp_journal(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "trapd_spool_{}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        tag,
    ));
    dir.join("queue.ndjson")
}

// ── In-memory semantics (parity with the previous ring buffer) ────────────────

#[test]
fn drops_oldest_when_full() {
    let mut s = Spool::in_memory(3);
    for _ in 0..4 {
        s.push(dummy_event());
    }
    assert_eq!(s.len(), 3, "must not exceed capacity");
    assert_eq!(
        s.dropped_total(),
        1,
        "one oldest event must have been dropped"
    );
}

#[test]
fn peek_batch_does_not_consume_and_is_capped() {
    let mut s = Spool::in_memory(100);
    for _ in 0..5 {
        s.push(dummy_event());
    }
    assert_eq!(s.peek_batch(3).len(), 3);
    assert_eq!(s.len(), 5, "peek must not consume");
    assert_eq!(s.peek_batch(100).len(), 5, "peek is capped at len");
}

#[test]
fn drain_removes_n_and_does_not_underflow() {
    let mut s = Spool::in_memory(100);
    for _ in 0..5 {
        s.push(dummy_event());
    }
    s.drain(3);
    assert_eq!(s.len(), 2);
    s.drain(10);
    assert_eq!(s.len(), 0, "drain beyond len empties the spool");
}

// ── Durability ────────────────────────────────────────────────────────────────

#[test]
fn durable_spool_survives_reopen() {
    let path = tmp_journal("reopen");
    {
        let mut s = Spool::durable_at(path.clone(), 100);
        s.push(dummy_event());
        s.push(dummy_event());
        s.push(dummy_event());
    } // handle dropped — simulates a restart

    let s2 = Spool::durable_at(path.clone(), 100);
    assert_eq!(
        s2.len(),
        3,
        "persisted events must be replayed after a restart"
    );

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn unsent_events_are_replayed_at_least_once() {
    // Drain (ship) without an intervening compaction, then "restart": the
    // drained events are replayed — the documented at-least-once trade-off.
    let path = tmp_journal("atleastonce");
    {
        let mut s = Spool::durable_at(path.clone(), 100);
        s.push(dummy_event());
        s.push(dummy_event());
        s.drain(1); // shipped, but journal not yet compacted
    }
    let s2 = Spool::durable_at(path.clone(), 100);
    assert_eq!(
        s2.len(),
        2,
        "without compaction, shipped events replay (at-least-once)"
    );

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn compaction_reconciles_shipped_events() {
    let path = tmp_journal("compact");
    let mut s = Spool::durable_at(path.clone(), 100);
    s.push(dummy_event());
    s.push(dummy_event());
    s.push(dummy_event());
    s.drain(2); // ship two
    s.compact(); // reconcile the journal to the live set
    drop(s);

    let s2 = Spool::durable_at(path.clone(), 100);
    assert_eq!(
        s2.len(),
        1,
        "after compaction only the un-shipped event remains"
    );

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn durable_spool_enforces_cap_across_reload() {
    let path = tmp_journal("cap");
    {
        let mut s = Spool::durable_at(path.clone(), 2);
        for _ in 0..5 {
            s.push(dummy_event());
        }
        assert_eq!(s.len(), 2);
    }
    // Reload also enforces the cap on the replayed journal.
    let s2 = Spool::durable_at(path.clone(), 2);
    assert_eq!(s2.len(), 2, "cap is enforced when replaying a journal");

    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
