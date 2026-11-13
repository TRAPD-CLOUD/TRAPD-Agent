//! Durable, bounded command execution and result outbox.
//!
//! Accepted/running entries become explicit interrupted failures on restart.
//! An uncertain side effect is never automatically repeated.
use super::commands::CommandEnvelope;
use anyhow::{ensure, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

const MAX_ENTRIES: usize = 2048;
const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const RESULT_RESERVE: u64 = 512 * 1024 + 8192;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommandResult {
    pub action: String,
    pub kind: String,
    pub success: bool,
    pub reason: Option<String>,
    pub details: serde_json::Value,
    pub reported_at: DateTime<Utc>,
}
impl CommandResult {
    pub fn failure(reason: impl Into<String>) -> Self {
        Self {
            action: "command_rejected".into(),
            kind: "command_rejected".into(),
            success: false,
            reason: Some(reason.into()),
            details: serde_json::Value::Null,
            reported_at: Utc::now(),
        }
    }
    fn interrupted() -> Self {
        Self::failure(
            "execution interrupted; outcome uncertain, inspect before issuing a new command",
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum State {
    Accepted,
    Running,
    Completed,
}
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    envelope: CommandEnvelope,
    state: State,
    result: Option<CommandResult>,
    reported: bool,
}

pub struct CommandJournal {
    directory: PathBuf,
    records: Mutex<BTreeMap<Uuid, Record>>,
    terminal_pending: Mutex<BTreeMap<Uuid, CommandResult>>,
}
impl CommandJournal {
    pub fn open(directory: &Path) -> Result<Self> {
        std::fs::create_dir_all(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut records = BTreeMap::new();
        let mut total_bytes = 0_u64;
        for entry in std::fs::read_dir(directory)? {
            let path = entry?.path();
            // Ignore atomic-write stages, never treat them as an accepted record.
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let meta = std::fs::symlink_metadata(&path)?;
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= MAX_RECORD_BYTES,
                "unsafe command journal record"
            );
            total_bytes = total_bytes.saturating_add(meta.len());
            ensure!(
                total_bytes <= MAX_TOTAL_BYTES,
                "command journal byte capacity exceeded"
            );
            let mut record: Record = serde_json::from_slice(&std::fs::read(&path)?)
                .context("corrupt command journal")?;
            ensure!(
                path.file_stem().and_then(|s| s.to_str())
                    == Some(record.envelope.command_id.to_string().as_str()),
                "journal identity mismatch"
            );
            ensure!(
                records.len() < MAX_ENTRIES,
                "command journal capacity exceeded"
            );
            ensure!(
                (record.state == State::Completed) == record.result.is_some(),
                "invalid journal terminal state"
            );
            ensure!(
                !record.reported || record.state == State::Completed,
                "invalid journal acknowledgement"
            );
            if record.state != State::Completed {
                record.state = State::Completed;
                record.result = Some(CommandResult::interrupted());
                record.reported = false;
                Self::save(directory, &record)?;
            }
            records.insert(record.envelope.command_id, record);
        }
        Ok(Self {
            directory: directory.into(),
            records: Mutex::new(records),
            terminal_pending: Mutex::new(BTreeMap::new()),
        })
    }
    fn save(directory: &Path, record: &Record) -> Result<()> {
        ensure!(directory.is_dir(), "command journal directory unavailable");
        let bytes = serde_json::to_vec(record)?;
        ensure!(
            bytes.len() as u64 <= MAX_RECORD_BYTES,
            "command journal record too large"
        );
        crate::paths::write_atomic(
            &directory.join(format!("{}.json", record.envelope.command_id)),
            &bytes,
            0o600,
        )
    }
    pub fn contains(&self, env: &CommandEnvelope) -> Result<bool> {
        let records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("command journal poisoned"))?;
        if let Some(record) = records.get(&env.command_id) {
            ensure!(
                serde_json::to_vec(&record.envelope)? == serde_json::to_vec(env)?,
                "command id reused with different envelope"
            );
            return Ok(true);
        }
        Ok(false)
    }
    pub fn accept(&self, env: &CommandEnvelope) -> Result<bool> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("command journal poisoned"))?;
        if let Some(record) = records.get(&env.command_id) {
            ensure!(
                serde_json::to_vec(&record.envelope)? == serde_json::to_vec(env)?,
                "command id reused with different envelope"
            );
            return Ok(false);
        }
        // Completed acknowledged records are retained through the signed window.
        let old: Vec<_> = records
            .iter()
            .filter(|(_, r)| r.reported && r.envelope.expires_at < Utc::now())
            .map(|(id, _)| *id)
            .collect();
        for id in old {
            std::fs::remove_file(self.directory.join(format!("{id}.json")))?;
            records.remove(&id);
        }
        ensure!(
            records.len() < MAX_ENTRIES,
            "command journal full; refusing new effects"
        );
        let record = Record {
            envelope: env.clone(),
            state: State::Accepted,
            result: None,
            reported: false,
        };
        Self::check_budget(&records, &record)?;
        Self::save(&self.directory, &record)?;
        records.insert(env.command_id, record);
        Ok(true)
    }
    pub fn start(&self, id: Uuid) -> Result<()> {
        self.update(id, |r| {
            ensure!(r.state == State::Accepted, "command already started");
            r.state = State::Running;
            Ok(())
        })
    }
    pub fn complete(&self, id: Uuid, mut result: CommandResult) -> Result<()> {
        if let Some(reason) = &mut result.reason {
            if reason.len() > 4096 {
                let mut end = 4096;
                while !reason.is_char_boundary(end) {
                    end -= 1;
                }
                reason.truncate(end);
            }
        }
        if serde_json::to_vec(&result)?.len() > 512 * 1024 {
            result.details = serde_json::json!({"truncated":true,"reason":"result details exceed receipt budget"});
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("command journal poisoned"))?;
        let mut record = records.get(&id).context("unrecorded command")?.clone();
        if record.state == State::Completed {
            return Ok(());
        }
        let mut pending = self
            .terminal_pending
            .lock()
            .map_err(|_| anyhow::anyhow!("command result retry state poisoned"))?;
        // Remember the first outcome even if the durable write fails. The
        // reporter retries this exact outcome, without executing the effect.
        let result = pending.entry(id).or_insert(result).clone();
        record.state = State::Completed;
        record.result = Some(result);
        record.reported = false;
        Self::check_budget(&records, &record)?;
        Self::save(&self.directory, &record)?;
        records.insert(id, record);
        pending.remove(&id);
        Ok(())
    }
    pub fn retry_terminalizations(&self) -> Result<()> {
        let pending = self
            .terminal_pending
            .lock()
            .map_err(|_| anyhow::anyhow!("command result retry state poisoned"))?
            .clone();
        for (id, result) in pending {
            let _ = self.complete(id, result);
        }
        Ok(())
    }

    pub fn mark_reported(&self, id: Uuid) -> Result<()> {
        self.update(id, |r| {
            ensure!(r.state == State::Completed, "command unfinished");
            r.reported = true;
            Ok(())
        })
    }
    fn update(&self, id: Uuid, change: impl FnOnce(&mut Record) -> Result<()>) -> Result<()> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("command journal poisoned"))?;
        let mut record = records.get(&id).context("unrecorded command")?.clone();
        change(&mut record)?;
        Self::check_budget(&records, &record)?;
        Self::save(&self.directory, &record)?;
        records.insert(id, record);
        Ok(())
    }
    fn reserved_bytes(record: &Record) -> Result<u64> {
        let bytes = serde_json::to_vec(record)?.len() as u64;
        if record.state == State::Completed {
            Ok(bytes)
        } else {
            ensure!(
                bytes.saturating_add(RESULT_RESERVE) <= MAX_RECORD_BYTES,
                "command too large to reserve its result"
            );
            Ok(bytes.saturating_add(RESULT_RESERVE))
        }
    }
    fn check_budget(records: &BTreeMap<Uuid, Record>, changed: &Record) -> Result<()> {
        let mut total = Self::reserved_bytes(changed)?;
        for (id, record) in records {
            if *id != changed.envelope.command_id {
                total = total.saturating_add(Self::reserved_bytes(record)?);
                ensure!(
                    total <= MAX_TOTAL_BYTES,
                    "command journal byte capacity exceeded"
                );
            }
        }
        ensure!(
            total <= MAX_TOTAL_BYTES,
            "command journal byte capacity exceeded"
        );
        Ok(())
    }
    pub fn pending_results(&self) -> Result<Vec<(Uuid, CommandResult)>> {
        self.retry_terminalizations()?;
        let records = self
            .records
            .lock()
            .map_err(|_| anyhow::anyhow!("command journal poisoned"))?;
        Ok(records
            .iter()
            .filter(|(_, r)| !r.reported)
            .filter_map(|(id, r)| r.result.clone().map(|result| (*id, result)))
            .collect())
    }
    pub fn finish_if_unreported(&self, id: Uuid) -> Result<()> {
        self.complete(
            id,
            CommandResult::failure("execution produced no durable result; outcome uncertain"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prevention::commands::CommandPayload;
    use chrono::{Duration, Utc};
    fn command() -> CommandEnvelope {
        CommandEnvelope {
            command_id: Uuid::new_v4(),
            nonce: Uuid::new_v4(),
            agent_id: "test".into(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            payload: CommandPayload::DeisolateNetwork,
        }
    }
    fn directory() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("trapd-journal-test-{}", Uuid::new_v4()))
    }
    #[test]
    fn accepted_commands_survive_restart_as_explicit_interrupted_results() {
        let dir = directory();
        let env = command();
        let journal = CommandJournal::open(&dir).unwrap();
        assert!(journal.accept(&env).unwrap());
        drop(journal);
        let journal = CommandJournal::open(&dir).unwrap();
        let pending = journal.pending_results().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(!pending[0].1.success);
        assert!(pending[0]
            .1
            .reason
            .as_deref()
            .unwrap()
            .contains("interrupted"));
        assert!(!journal.accept(&env).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn mismatched_reuse_and_unrecorded_results_are_rejected() {
        let dir = directory();
        let journal = CommandJournal::open(&dir).unwrap();
        let env = command();
        journal.accept(&env).unwrap();
        let mut altered = env.clone();
        altered.nonce = Uuid::new_v4();
        assert!(journal.accept(&altered).is_err());
        assert!(journal
            .complete(Uuid::new_v4(), CommandResult::interrupted())
            .is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn completion_is_durable_and_duplicate_delivery_never_reexecutes() {
        let dir = directory();
        let env = command();
        let journal = CommandJournal::open(&dir).unwrap();
        journal.accept(&env).unwrap();
        journal.start(env.command_id).unwrap();
        let result = CommandResult {
            action: "network_deisolated".into(),
            kind: "network_deisolate".into(),
            success: true,
            reason: Some("done".into()),
            details: serde_json::json!({}),
            reported_at: Utc::now(),
        };
        journal.complete(env.command_id, result).unwrap();
        journal
            .complete(env.command_id, CommandResult::interrupted())
            .unwrap();
        assert!(journal.pending_results().unwrap()[0].1.success);
        drop(journal);
        let journal = CommandJournal::open(&dir).unwrap();
        assert!(journal.pending_results().unwrap()[0].1.success);
        journal.mark_reported(env.command_id).unwrap();
        assert!(journal.pending_results().unwrap().is_empty());
        assert!(!journal.accept(&env).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn corrupt_or_unwritable_journal_fails_closed() {
        let dir = directory();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{}.json", Uuid::new_v4())), b"broken").unwrap();
        assert!(CommandJournal::open(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
        let dir = directory();
        let journal = CommandJournal::open(&dir).unwrap();
        std::fs::remove_dir(&dir).unwrap();
        std::fs::write(&dir, b"occupied").unwrap();
        assert!(journal.accept(&command()).is_err());
        std::fs::remove_file(dir).unwrap();
    }
    #[test]
    fn failed_completion_retries_first_outcome_without_restart() {
        let dir = directory();
        let journal = CommandJournal::open(&dir).unwrap();
        let env = command();
        journal.accept(&env).unwrap();
        journal.start(env.command_id).unwrap();
        let moved = dir.with_extension("hidden");
        std::fs::rename(&dir, &moved).unwrap();
        std::fs::write(&dir, b"blocked").unwrap();
        let mut outcome = CommandResult::interrupted();
        outcome.success = true;
        outcome.reason = Some("real outcome".into());
        assert!(journal.complete(env.command_id, outcome).is_err());
        assert!(journal.finish_if_unreported(env.command_id).is_err());
        std::fs::remove_file(&dir).unwrap();
        std::fs::rename(&moved, &dir).unwrap();
        let pending = journal.pending_results().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].1.success);
        assert_eq!(pending[0].1.reason.as_deref(), Some("real outcome"));
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn start_write_failure_can_finalize_after_storage_recovers() {
        let dir = directory();
        let journal = CommandJournal::open(&dir).unwrap();
        let env = command();
        journal.accept(&env).unwrap();
        let moved = dir.with_extension("hidden");
        std::fs::rename(&dir, &moved).unwrap();
        std::fs::write(&dir, b"blocked").unwrap();
        assert!(journal.start(env.command_id).is_err());
        assert!(journal
            .complete(env.command_id, CommandResult::failure("not executed"))
            .is_err());
        std::fs::remove_file(&dir).unwrap();
        std::fs::rename(&moved, &dir).unwrap();
        assert_eq!(
            journal.pending_results().unwrap()[0].1.reason.as_deref(),
            Some("not executed")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn acceptance_reserves_terminal_capacity_and_bounds_result_payload() {
        let dir = directory();
        let journal = CommandJournal::open(&dir).unwrap();
        let mut ids = Vec::new();
        for _ in 0..MAX_ENTRIES {
            let env = command();
            if journal.accept(&env).is_err() {
                break;
            }
            ids.push(env.command_id);
        }
        assert!(!ids.is_empty() && ids.len() < MAX_ENTRIES);
        for id in ids {
            let mut result = CommandResult::interrupted();
            result.details = serde_json::json!({"data":"x".repeat(600*1024)});
            journal.complete(id, result).unwrap();
        }
        assert!(journal
            .pending_results()
            .unwrap()
            .iter()
            .all(|(_, r)| serde_json::to_vec(r).unwrap().len() < 512 * 1024));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
