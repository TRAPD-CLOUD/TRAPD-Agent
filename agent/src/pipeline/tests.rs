use uuid::Uuid;

use super::RingBuffer;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, Severity, SystemSnapshotData,
};

fn dummy_event() -> AgentEvent {
    AgentEvent::new(
        Uuid::new_v4(),
        "test-host".to_string(),
        EventClass::System,
        EventAction::Snapshot,
        Severity::Info,
        EventData::SystemSnapshot(SystemSnapshotData {
            os:               "Linux".to_string(),
            kernel:           "6.0.0".to_string(),
            distro:           "Test".to_string(),
            cpu_count:        1,
            cpu_usage_pct:    0.0,
            memory_total_mb:  1024,
            memory_used_mb:   512,
            memory_free_mb:   512,
            uptime_secs:      100,
            load_avg:         [0.0, 0.0, 0.0],
        }),
    )
}

#[test]
fn test_ring_buffer_drops_oldest_when_full() {
    let mut buf = RingBuffer::with_max(3);
    buf.push(dummy_event()); // slot 1
    buf.push(dummy_event()); // slot 2
    buf.push(dummy_event()); // slot 3  — buffer now full
    buf.push(dummy_event()); // slot 4  — oldest (slot 1) must be dropped
    assert_eq!(buf.len(), 3, "buffer must not exceed max capacity");
}

#[test]
fn test_peek_batch_returns_correct_count_without_consuming() {
    let mut buf = RingBuffer::new();
    for _ in 0..5 {
        buf.push(dummy_event());
    }

    let batch = buf.peek_batch(3);
    assert_eq!(batch.len(), 3, "peek_batch must return exactly n events");
    assert_eq!(buf.len(), 5, "peek_batch must not consume events");
}

#[test]
fn test_peek_batch_capped_at_buffer_size() {
    let mut buf = RingBuffer::new();
    buf.push(dummy_event());
    buf.push(dummy_event());

    let batch = buf.peek_batch(100);
    assert_eq!(batch.len(), 2, "peek_batch must return at most buf.len() events");
    assert_eq!(buf.len(), 2);
}

#[test]
fn test_drain_removes_correct_number_of_items() {
    let mut buf = RingBuffer::new();
    for _ in 0..5 {
        buf.push(dummy_event());
    }

    buf.drain(3);
    assert_eq!(buf.len(), 2, "drain(3) on 5-item buffer must leave 2 items");
}

#[test]
fn test_drain_does_not_underflow() {
    let mut buf = RingBuffer::new();
    buf.push(dummy_event());
    buf.push(dummy_event());

    buf.drain(10); // more than available
    assert_eq!(buf.len(), 0, "drain beyond len must empty the buffer");
}
