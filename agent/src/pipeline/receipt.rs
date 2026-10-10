//! Durable handoff for sensors whose checkpoints otherwise outrun the journal.
use crate::schema::AgentEvent;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

fn waiters() -> &'static Mutex<HashMap<Uuid, oneshot::Sender<bool>>> {
    static WAITERS: OnceLock<Mutex<HashMap<Uuid, oneshot::Sender<bool>>>> = OnceLock::new();
    WAITERS.get_or_init(|| Mutex::new(HashMap::new()))
}

struct Registration(Uuid);
impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut waiters) = waiters().lock() {
            waiters.remove(&self.0);
        }
    }
}

pub(super) fn requested(id: Uuid) -> bool {
    waiters()
        .lock()
        .is_ok_and(|waiters| waiters.contains_key(&id))
}

pub(super) fn complete(id: Uuid, durable: bool) {
    if let Ok(mut waiters) = waiters().lock() {
        if let Some(sender) = waiters.remove(&id) {
            let _ = sender.send(durable);
        }
    }
}

/// Only online checkpointing sensors use this handoff. The bounded registration
/// is removed on success, failure, timeout or cancellation. Offline collection
/// keeps the existing NDJSON output semantics and uses ordinary channel sends.
pub async fn send_durable(tx: &mpsc::Sender<AgentEvent>, event: AgentEvent) -> anyhow::Result<()> {
    let (sender, receiver) = oneshot::channel();
    {
        let mut waiters = waiters()
            .lock()
            .map_err(|_| anyhow::anyhow!("durable handoff unavailable"))?;
        anyhow::ensure!(
            waiters.len() < super::CHANNEL_CAPACITY,
            "too many durable handoffs"
        );
        anyhow::ensure!(
            !waiters.contains_key(&event.event_id),
            "duplicate durable handoff"
        );
        waiters.insert(event.event_id, sender);
    }
    let _registration = Registration(event.event_id);
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        tx.send(event)
            .await
            .map_err(|_| anyhow::anyhow!("pipeline closed"))?;
        anyhow::ensure!(
            receiver.await.unwrap_or(false),
            "event was not durably journaled"
        );
        Ok(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("durable handoff timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::Spool;
    use crate::schema::{EventAction, EventClass, EventData, Severity};

    fn event() -> AgentEvent {
        AgentEvent::new(
            "test".into(),
            "host".into(),
            EventClass::Process,
            EventAction::Create,
            Severity::Info,
            EventData::ProcessExec(Box::default()),
        )
    }

    #[tokio::test]
    async fn checkpoint_handoff_waits_for_journal_sync() {
        let dir = std::env::temp_dir().join(format!("trapd-receipt-{}", uuid::Uuid::new_v4()));
        let path = dir.join("queue.journal");
        let mut spool = Spool::durable_at(path.clone(), 100);
        let (tx, mut rx) = mpsc::channel(1);
        let sender = tokio::spawn(async move { send_durable(&tx, event()).await });
        let event = rx.recv().await.unwrap();
        tokio::task::yield_now().await;
        assert!(
            !sender.is_finished(),
            "mpsc acceptance is not durable handoff"
        );
        let id = event.event_id;
        spool.push(event).unwrap();
        sender.await.unwrap().unwrap();
        assert_eq!(
            spool.fsyncs_total(),
            1,
            "receipt requires immediate sync, not 50 events"
        );
        drop(spool);
        let recovered = Spool::durable_at(path, 100);
        assert_eq!(recovered.peek_batch(1)[0].event.event_id, id);
        drop(recovered);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn memory_only_queue_cannot_advance_a_durable_checkpoint() {
        let mut spool = Spool::in_memory(100);
        let (tx, mut rx) = mpsc::channel(1);
        let sender = tokio::spawn(async move { send_durable(&tx, event()).await });
        spool.push(rx.recv().await.unwrap()).unwrap();
        assert!(sender.await.unwrap().is_err());
        assert_eq!(
            spool.len(),
            1,
            "collection may continue without a durable receipt"
        );
    }

    #[tokio::test]
    async fn repeated_checkpoint_attempts_do_not_evict_unrelated_telemetry() {
        let mut spool = Spool::in_memory(2);
        let unrelated = event();
        let unrelated_id = unrelated.event_id;
        spool.push(unrelated).unwrap();
        let pending = event();
        let (tx, mut rx) = mpsc::channel(1);
        let mut first_seq = None;
        for _ in 0..5 {
            let tx = tx.clone();
            let retry = pending.clone();
            let sender = tokio::spawn(async move { send_durable(&tx, retry).await });
            let seq = spool.push(rx.recv().await.unwrap()).unwrap();
            assert!(sender.await.unwrap().is_err());
            assert_eq!(seq, *first_seq.get_or_insert(seq));
            assert_eq!(spool.len(), 2);
            assert!(spool
                .peek_batch(2)
                .iter()
                .any(|e| e.event.event_id == unrelated_id));
        }
    }

    #[tokio::test]
    async fn retry_receipt_syncs_existing_record_without_appending_a_duplicate() {
        let dir = std::env::temp_dir().join(format!("trapd-receipt-retry-{}", Uuid::new_v4()));
        let path = dir.join("queue.journal");
        let mut spool = Spool::durable_at(path.clone(), 100);
        let pending = event();
        let id = pending.event_id;
        let first_seq = spool.push(pending.clone()).unwrap();
        assert_eq!(spool.fsyncs_total(), 0);
        let (tx, mut rx) = mpsc::channel(1);
        let sender = tokio::spawn(async move { send_durable(&tx, pending).await });
        let retry_seq = spool.push(rx.recv().await.unwrap()).unwrap();
        sender.await.unwrap().unwrap();
        assert_eq!(retry_seq, first_seq);
        assert_eq!(spool.len(), 1);
        assert_eq!(spool.fsyncs_total(), 1);
        drop(spool);
        let recovered = Spool::durable_at(path, 100);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered.peek_batch(1)[0].event.event_id, id);
        drop(recovered);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn cancelled_native_handoff_copies_keep_one_queue_entry() {
        let mut pending = event();
        pending.class = EventClass::Log;
        pending.action = EventAction::Log;
        pending.data = EventData::Log(Box::new(serde_json::from_value(serde_json::json!({
            "source":"windows", "source_type":"windows_eventlog", "source_path":"System",
            "parser":"windows_eventlog_xml", "message":"record", "category":"system", "fields":{}
        })).unwrap()));
        pending = pending.with_source("windows_eventlog:System");
        let mut spool = Spool::in_memory(2);
        let (tx, mut rx) = mpsc::channel(1);
        let retry = pending.clone();
        let sender = tokio::spawn(async move { send_durable(&tx, retry).await });
        let queued = rx.recv().await.unwrap();
        sender.abort();
        assert!(sender.await.unwrap_err().is_cancelled());
        assert!(!requested(pending.event_id));
        let first_seq = spool.push(queued).unwrap();
        // An already-enqueued copy can arrive after its receipt registration
        // was cancelled/completed. It still must not duplicate retained raw data.
        assert_eq!(spool.push(pending).unwrap(), first_seq);
        assert_eq!(spool.len(), 1);
    }

    #[tokio::test]
    async fn backend_ack_does_not_replace_a_local_checkpoint_receipt() {
        let pending = AgentEvent::new(
            "test".into(),
            "host".into(),
            EventClass::Registry,
            EventAction::Modify,
            Severity::Info,
            EventData::Registry(
                serde_json::from_value(serde_json::json!({
                    "key_path":"HKLM\\SOFTWARE\\Test", "value_name":"Value",
                    "category":"run_key", "new_value":"changed"
                }))
                .unwrap(),
            ),
        )
        .with_source("windows_registry_snapshot");
        let mut checkpoints = crate::detection::CheckpointTracker::default();
        let mut spool = Spool::in_memory(2);
        let unrelated_id = event().event_id;
        let mut unrelated = event();
        unrelated.event_id = unrelated_id;
        spool.push(unrelated).unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let mut previous_seq = None;
        for attempt in 0..3 {
            assert_eq!(checkpoints.is_retry(&pending), attempt != 0);
            let tx = tx.clone();
            let retry = pending.clone();
            let sender = tokio::spawn(async move { send_durable(&tx, retry).await });
            let seq = spool.push(rx.recv().await.unwrap()).unwrap();
            assert!(sender.await.unwrap().is_err());
            if attempt == 0 {
                assert_eq!(spool.ack(&[seq]), 1);
                assert_eq!(spool.len(), 1);
            } else {
                assert_eq!(spool.len(), 2);
                if attempt == 1 {
                    assert_ne!(Some(seq), previous_seq);
                } else {
                    assert_eq!(Some(seq), previous_seq);
                }
            }
            assert!(spool
                .peek_batch(2)
                .iter()
                .any(|entry| entry.event.event_id == unrelated_id));
            previous_seq = Some(seq);
        }
    }

    #[tokio::test]
    async fn cancelled_registry_handoff_copies_keep_one_queue_entry() {
        let pending = AgentEvent::new(
            "test".into(),
            "host".into(),
            EventClass::Registry,
            EventAction::Modify,
            Severity::Info,
            EventData::Registry(
                serde_json::from_value(serde_json::json!({
                    "key_path":"HKLM\\SOFTWARE\\Test", "value_name":"Value",
                    "category":"run_key", "new_value":"changed"
                }))
                .unwrap(),
            ),
        )
        .with_source("windows_registry_snapshot");
        let mut spool = Spool::in_memory(2);
        let (tx, mut rx) = mpsc::channel(1);
        let retry = pending.clone();
        let sender = tokio::spawn(async move { send_durable(&tx, retry).await });
        let queued = rx.recv().await.unwrap();
        sender.abort();
        assert!(sender.await.unwrap_err().is_cancelled());
        assert!(!requested(pending.event_id));
        let first_seq = spool.push(queued).unwrap();
        assert_eq!(spool.push(pending).unwrap(), first_seq);
        assert_eq!(spool.len(), 1);
    }

    #[tokio::test]
    async fn cancelling_a_handoff_removes_its_registration() {
        let (tx, mut rx) = mpsc::channel(1);
        let sender = tokio::spawn(async move { send_durable(&tx, event()).await });
        let event = rx.recv().await.unwrap();
        assert!(requested(event.event_id));
        sender.abort();
        assert!(sender.await.unwrap_err().is_cancelled());
        assert!(!requested(event.event_id));
    }

    #[tokio::test]
    async fn closed_pipeline_cannot_leave_a_pending_handoff() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let event = event();
        let id = event.event_id;
        assert!(send_durable(&tx, event).await.is_err());
        assert!(!requested(id));
    }
}
