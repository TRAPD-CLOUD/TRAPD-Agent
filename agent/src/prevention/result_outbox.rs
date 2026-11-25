//! Durable outbox for the outcome of signed commands (audit SR-07).
//!
//! The intent of a command is written to disk before it runs and its first
//! result right after. A record leaves the outbox only once the backend
//! acknowledged it (see `result_reporter`). An intent that has no result when
//! the agent starts again belongs to a run that stopped between the action
//! and saving its result: it is reported as `interrupted_unknown`, never
//! retried, because whether the action took effect is unknown.
//!
//! The telemetry event of the same result is still sent; the outbox adds a
//! delivery the backend confirms after its own commit.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Notify;
use tracing::warn;
use uuid::Uuid;

/// Records kept at most. Intents without a result are never evicted.
const MAX_ENTRIES: usize = 512;
/// Upper bound of the outbox file read at start.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// Backend limits for one result.
pub(super) const MAX_REASON_CHARS: usize = 1024;
pub(super) const MAX_DETAILS_BYTES: usize = 16 * 1024;

const INTERRUPTED_REASON: &str =
    "the agent stopped after starting this command and before saving its result";
const NO_RESULT_REASON: &str = "the command finished without recording a result";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Succeeded,
    Failed,
    InterruptedUnknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub status: ResultStatus,
    pub reason: String,
    pub details: Option<Value>,
    pub reported_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub command_id: Uuid,
    /// Stable across retries so the backend can recognise a duplicate.
    pub event_id: Uuid,
    pub kind: String,
    pub started_at: DateTime<Utc>,
    pub outcome: Option<Outcome>,
}

pub struct ResultOutbox {
    path: PathBuf,
    entries: Mutex<Vec<Entry>>,
    ready: Notify,
}

impl ResultOutbox {
    /// Load the outbox and turn intents of the previous run into
    /// `interrupted_unknown`. A damaged file is moved aside so response
    /// commands keep working; its records are lost and the error is logged.
    pub fn load(path: &Path) -> Result<Self> {
        let mut entries = match crate::paths::bounded_regular_bytes(path, MAX_FILE_BYTES) {
            Ok(bytes) => match serde_json::from_slice::<Vec<Entry>>(&bytes) {
                Ok(entries) => entries,
                Err(error) => {
                    let aside = path.with_extension("json.damaged");
                    warn!(%error, aside = %aside.display(), "command result outbox is damaged; moving it aside");
                    std::fs::rename(path, &aside).context("move damaged command result outbox")?;
                    Vec::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).context("read command result outbox"),
        };
        let now = Utc::now();
        let mut changed = false;
        for entry in entries.iter_mut().filter(|e| e.outcome.is_none()) {
            entry.outcome = Some(Outcome {
                status: ResultStatus::InterruptedUnknown,
                reason: INTERRUPTED_REASON.into(),
                details: None,
                reported_at: now,
            });
            changed = true;
        }
        let outbox = Self {
            path: path.to_path_buf(),
            entries: Mutex::new(entries),
            ready: Notify::new(),
        };
        if changed {
            let entries = outbox.lock();
            outbox.persist(&entries)?;
        }
        Ok(outbox)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Entry>> {
        // The list stays consistent even if a holder panicked: every change is
        // a single push, field update or removal.
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn persist(&self, entries: &[Entry]) -> Result<()> {
        let bytes = serde_json::to_vec(entries)?;
        crate::paths::write_atomic(&self.path, &bytes, 0o600)
    }

    /// Record the intent durably. A command must not run when this fails.
    pub fn begin(&self, command_id: Uuid, kind: &str) -> Result<()> {
        let mut entries = self.lock();
        if entries.iter().any(|e| e.command_id == command_id) {
            return Ok(());
        }
        let mut next = entries.clone();
        if next.len() >= MAX_ENTRIES {
            // Evict the oldest finished record; its telemetry copy was sent.
            let Some(oldest) = next.iter().position(|e| e.outcome.is_some()) else {
                anyhow::bail!("command result outbox is full of unfinished commands");
            };
            next.remove(oldest);
            crate::telemetry::metrics::metrics().state_capacity_dropped(1);
        }
        next.push(Entry {
            command_id,
            event_id: Uuid::new_v4(),
            kind: kind.chars().take(64).collect(),
            started_at: Utc::now(),
            outcome: None,
        });
        self.persist(&next).context("persist command intent")?;
        *entries = next;
        Ok(())
    }

    /// Record the first result of a started command. Later calls are ignored.
    pub fn finish(&self, command_id: Uuid, success: bool, reason: &str, details: &Value) {
        self.set_outcome(
            command_id,
            if success {
                ResultStatus::Succeeded
            } else {
                ResultStatus::Failed
            },
            reason,
            details,
        );
    }

    /// Close a command that ended without any result.
    pub fn finish_without_result(&self, command_id: Uuid) {
        self.set_outcome(
            command_id,
            ResultStatus::InterruptedUnknown,
            NO_RESULT_REASON,
            &Value::Null,
        );
    }

    fn set_outcome(&self, command_id: Uuid, status: ResultStatus, reason: &str, details: &Value) {
        let mut entries = self.lock();
        let Some(entry) = entries
            .iter_mut()
            .find(|e| e.command_id == command_id && e.outcome.is_none())
        else {
            return;
        };
        entry.outcome = Some(Outcome {
            status,
            reason: reason.chars().take(MAX_REASON_CHARS).collect(),
            details: bounded_details(details),
            reported_at: Utc::now(),
        });
        // The result is kept in memory either way; a failed write only loses
        // it across a restart, where it then becomes interrupted_unknown.
        if let Err(error) = self.persist(&entries) {
            warn!(%error, %command_id, "could not persist command result");
        }
        drop(entries);
        self.ready.notify_one();
    }

    /// Finished records waiting for acknowledgement, oldest first.
    pub fn pending(&self) -> Vec<Entry> {
        self.lock()
            .iter()
            .filter(|e| e.outcome.is_some())
            .cloned()
            .collect()
    }

    /// Whether the command still has an open intent.
    pub fn is_open(&self, command_id: Uuid) -> bool {
        self.lock()
            .iter()
            .any(|e| e.command_id == command_id && e.outcome.is_none())
    }

    /// Drop a record the backend acknowledged or refused for good.
    pub fn remove(&self, command_id: Uuid) {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|e| e.command_id != command_id);
        if entries.len() != before {
            if let Err(error) = self.persist(&entries) {
                warn!(%error, %command_id, "could not persist acknowledged command result");
            }
        }
    }

    /// Resolves when a new result was recorded.
    pub async fn wait_ready(&self) {
        self.ready.notified().await;
    }
}

/// The backend accepts an object of at most 16 KiB. Anything else is reduced
/// to a marker instead of being refused as a whole.
fn bounded_details(details: &Value) -> Option<Value> {
    match details {
        Value::Null => None,
        Value::Object(_) => {
            let size = serde_json::to_vec(details)
                .map(|b| b.len())
                .unwrap_or(usize::MAX);
            if size <= MAX_DETAILS_BYTES {
                Some(details.clone())
            } else {
                Some(serde_json::json!({ "truncated": true, "original_bytes": size }))
            }
        }
        other => Some(serde_json::json!({ "value": other }))
            .filter(|v| serde_json::to_vec(v).is_ok_and(|b| b.len() <= MAX_DETAILS_BYTES)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path() -> PathBuf {
        let dir = std::env::temp_dir().join(Uuid::new_v4().to_string());
        std::fs::create_dir(&dir).unwrap();
        dir.join("command_results.json")
    }

    #[test]
    fn intent_without_result_becomes_interrupted_unknown_after_restart() {
        let path = temp_path();
        let id = Uuid::new_v4();
        let outbox = ResultOutbox::load(&path).unwrap();
        outbox.begin(id, "kill_pid").unwrap();
        assert!(
            outbox.pending().is_empty(),
            "an open intent is not reported"
        );
        let event_id = outbox.lock()[0].event_id;
        drop(outbox);

        let reloaded = ResultOutbox::load(&path).unwrap();
        let pending = reloaded.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].event_id, event_id, "event id is stable");
        let outcome = pending[0].outcome.as_ref().unwrap();
        assert_eq!(outcome.status, ResultStatus::InterruptedUnknown);
        // and stays so on disk
        let again = ResultOutbox::load(&path).unwrap();
        assert_eq!(again.pending(), pending);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn first_result_wins_and_survives_restart_until_removed() {
        let path = temp_path();
        let id = Uuid::new_v4();
        let outbox = ResultOutbox::load(&path).unwrap();
        outbox.begin(id, "isolate_network").unwrap();
        outbox.finish(id, true, "isolated", &serde_json::json!({"rules": 4}));
        outbox.finish(id, false, "later", &Value::Null);
        let pending = outbox.pending();
        assert_eq!(
            pending[0].outcome.as_ref().unwrap().status,
            ResultStatus::Succeeded
        );
        assert!(!outbox.is_open(id));

        let reloaded = ResultOutbox::load(&path).unwrap();
        assert_eq!(reloaded.pending(), pending);
        reloaded.remove(id);
        assert!(ResultOutbox::load(&path).unwrap().pending().is_empty());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn begin_fails_closed_when_the_intent_cannot_be_persisted() {
        // A directory where the file belongs: the write cannot succeed.
        let path = temp_path();
        let outbox = ResultOutbox::load(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(outbox.begin(Uuid::new_v4(), "kill_pid").is_err());
        assert!(outbox.lock().is_empty());
    }

    #[test]
    fn capacity_evicts_finished_records_but_never_open_intents() {
        let path = temp_path();
        let outbox = ResultOutbox::load(&path).unwrap();
        let first = Uuid::new_v4();
        outbox.begin(first, "kill_pid").unwrap();
        outbox.finish(first, true, "", &Value::Null);
        for _ in 1..MAX_ENTRIES {
            outbox.begin(Uuid::new_v4(), "kill_pid").unwrap();
        }
        outbox.begin(Uuid::new_v4(), "kill_pid").unwrap();
        assert!(outbox.lock().iter().all(|e| e.command_id != first));
        assert!(
            outbox.begin(Uuid::new_v4(), "kill_pid").is_err(),
            "only open intents left: refuse instead of losing one"
        );
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn damaged_file_is_moved_aside() {
        let path = temp_path();
        std::fs::write(&path, b"{not json").unwrap();
        let outbox = ResultOutbox::load(&path).unwrap();
        assert!(outbox.pending().is_empty());
        assert!(path.with_extension("json.damaged").exists());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn details_and_reason_respect_backend_limits() {
        let path = temp_path();
        let outbox = ResultOutbox::load(&path).unwrap();
        let id = Uuid::new_v4();
        outbox.begin(id, "quarantine_file").unwrap();
        let big = serde_json::json!({ "blob": "x".repeat(MAX_DETAILS_BYTES) });
        outbox.finish(id, false, &"r".repeat(5000), &big);
        let outcome = outbox.pending()[0].outcome.clone().unwrap();
        assert_eq!(outcome.reason.chars().count(), MAX_REASON_CHARS);
        assert_eq!(outcome.details.unwrap()["truncated"], true);
        assert_eq!(
            bounded_details(&serde_json::json!("s")).unwrap()["value"],
            "s"
        );
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
