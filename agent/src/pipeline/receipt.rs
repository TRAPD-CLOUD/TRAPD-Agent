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
