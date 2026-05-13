//! Prevention engine — wires policy, audit, network, quarantine and process
//! kill into one orchestrated runtime.
//!
//! Two input streams:
//!
//!   1. **Events**  — every `AgentEvent` flowing through the telemetry pipe
//!     is tee'd into this engine.  On `ExecEventData` we run `enforce_exec`
//!     to apply IoC rules in real time.
//!   2. **Commands** — verified `CommandEnvelope`s from the backend puller.
//!     Each is dispatched to the matching handler (kill / isolate / …).
//!
//! Errors are audited but never propagated; the prevention engine MUST keep
//! running even when individual actions fail (e.g. `nft` missing on the box).

use std::path::Path;
use std::sync::Arc;
use std::collections::HashSet;

use serde_json::json;
use tokio::sync::mpsc::Receiver;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::schema::{AgentEvent, EventData};

use super::audit::AuditEmitter;
use super::commands::{CommandEnvelope, CommandPayload};
use super::network::{self, Backend};
use super::policy::{IocRule, PolicyHandle, PolicyStore};
use super::process;
use super::quarantine;

#[derive(Clone)]
pub struct EngineConfig {
    pub net_backend: Backend,
    pub default_isolation_allowlist: Vec<std::net::IpAddr>,
}

pub struct Engine {
    policy: PolicyHandle,
    audit:  AuditEmitter,
    cfg:    EngineConfig,
    /// Set of currently-blocked IPs/CIDRs (string form for direct nft passthrough).
    blocked: Arc<tokio::sync::Mutex<HashSet<String>>>,
}

impl Engine {
    pub fn new(policy: PolicyHandle, audit: AuditEmitter, cfg: EngineConfig) -> Self {
        Self {
            policy,
            audit,
            cfg,
            blocked: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
        }
    }

    /// Spawn the event-enforcement loop.  Consumes the receiver.
    pub fn spawn_event_loop(&self, mut rx: Receiver<AgentEvent>) {
        let policy = self.policy.clone();
        let audit  = self.audit.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let EventData::ProcessExec(exec) = &event.data {
                    let _ = process::enforce_exec(exec, &policy, &audit);
                }
            }
        });
    }

    /// Spawn the command-dispatch loop.
    pub fn spawn_command_loop(self: Arc<Self>, mut rx: Receiver<CommandEnvelope>) {
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                let me = Arc::clone(&self);
                tokio::spawn(async move {
                    me.handle(cmd).await;
                });
            }
        });
    }

    async fn handle(&self, env: CommandEnvelope) {
        let cmd_id = env.command_id.to_string();
        match &env.payload {
            CommandPayload::KillPid { pid } => {
                self.cmd_kill_pid(*pid, &cmd_id);
            }
            CommandPayload::IsolateNetwork { allowlist_ips } => {
                self.cmd_isolate(allowlist_ips.clone(), &cmd_id);
            }
            CommandPayload::DeisolateNetwork => {
                self.cmd_deisolate(&cmd_id);
            }
            CommandPayload::QuarantineFile { path } => {
                self.cmd_quarantine(path, &cmd_id);
            }
            CommandPayload::RestoreFile { quarantine_id } => {
                self.cmd_restore(quarantine_id, &cmd_id);
            }
            CommandPayload::BlockIp { ip, ttl_secs } => {
                self.cmd_block_ip(ip, *ttl_secs, &cmd_id).await;
            }
            CommandPayload::UnblockIp { ip } => {
                self.cmd_unblock_ip(ip, &cmd_id).await;
            }
            CommandPayload::UpdatePolicy { rules } => {
                self.cmd_update_policy(rules.clone(), &cmd_id);
            }
        }
    }

    fn cmd_kill_pid(&self, pid: i32, cmd_id: &str) {
        let res = process::kill_pid(pid);
        let success = res.is_ok();
        let reason = match res {
            Ok(_)  => format!("SIGKILL delivered to pid {pid}"),
            Err(e) => format!("kill failed: {e:#}"),
        };
        self.audit.emit(
            crate::schema::EventAction::ProcessBlocked,
            if success { crate::schema::Severity::High } else { crate::schema::Severity::Medium },
            "process_block",
            pid.to_string(),
            success,
            reason,
            None,
            Some(cmd_id.into()),
            json!({ "pid": pid, "source": "command" }),
        );
    }

    fn cmd_isolate(&self, mut allow: Vec<std::net::IpAddr>, cmd_id: &str) {
        for ip in &self.cfg.default_isolation_allowlist {
            if !allow.contains(ip) {
                allow.push(*ip);
            }
        }
        let res = network::isolate(self.cfg.net_backend, &allow);
        let (success, reason) = match res {
            Ok(_)  => (true,  format!("host isolated; allowlist size = {}", allow.len())),
            Err(e) => (false, format!("isolate failed: {e:#}")),
        };
        self.audit.emit(
            crate::schema::EventAction::NetworkIsolated,
            crate::schema::Severity::Critical,
            "network_isolate",
            "host",
            success,
            reason,
            None,
            Some(cmd_id.into()),
            json!({ "allowlist": allow }),
        );
    }

    fn cmd_deisolate(&self, cmd_id: &str) {
        let res = network::deisolate(self.cfg.net_backend);
        let (success, reason) = match res {
            Ok(_)  => (true,  "host isolation lifted".to_string()),
            Err(e) => (false, format!("deisolate failed: {e:#}")),
        };
        self.audit.emit(
            crate::schema::EventAction::NetworkDeisolated,
            crate::schema::Severity::High,
            "network_deisolate",
            "host",
            success,
            reason,
            None,
            Some(cmd_id.into()),
            serde_json::Value::Null,
        );
    }

    fn cmd_quarantine(&self, path: &str, cmd_id: &str) {
        let res = quarantine::quarantine(Path::new(path));
        match res {
            Ok(record) => {
                self.audit.emit(
                    crate::schema::EventAction::FileQuarantined,
                    crate::schema::Severity::High,
                    "quarantine",
                    record.original_path.clone(),
                    true,
                    format!("file quarantined as {}", record.id),
                    None,
                    Some(cmd_id.into()),
                    serde_json::to_value(&record).unwrap_or(serde_json::Value::Null),
                );
            }
            Err(e) => {
                error!(path, error = %e, "quarantine failed");
                self.audit.emit(
                    crate::schema::EventAction::FileQuarantined,
                    crate::schema::Severity::Medium,
                    "quarantine",
                    path.to_string(),
                    false,
                    format!("quarantine failed: {e:#}"),
                    None,
                    Some(cmd_id.into()),
                    serde_json::Value::Null,
                );
            }
        }
    }

    fn cmd_restore(&self, qid: &str, cmd_id: &str) {
        let parsed = match Uuid::parse_str(qid) {
            Ok(u)  => u,
            Err(e) => {
                self.audit.emit(
                    crate::schema::EventAction::FileRestored,
                    crate::schema::Severity::Low,
                    "restore",
                    qid.to_string(),
                    false,
                    format!("invalid quarantine id: {e}"),
                    None,
                    Some(cmd_id.into()),
                    serde_json::Value::Null,
                );
                return;
            }
        };
        match quarantine::restore(&parsed) {
            Ok(record) => {
                self.audit.emit(
                    crate::schema::EventAction::FileRestored,
                    crate::schema::Severity::Info,
                    "restore",
                    record.original_path.clone(),
                    true,
                    "file restored from quarantine".into(),
                    None,
                    Some(cmd_id.into()),
                    serde_json::to_value(&record).unwrap_or(serde_json::Value::Null),
                );
            }
            Err(e) => {
                self.audit.emit(
                    crate::schema::EventAction::FileRestored,
                    crate::schema::Severity::Medium,
                    "restore",
                    qid.to_string(),
                    false,
                    format!("restore failed: {e:#}"),
                    None,
                    Some(cmd_id.into()),
                    serde_json::Value::Null,
                );
            }
        }
    }

    async fn cmd_block_ip(&self, ip: &str, ttl_secs: Option<u64>, cmd_id: &str) {
        let res = network::block_ip(self.cfg.net_backend, ip);
        let (success, reason) = match &res {
            Ok(handle) => (true,  format!("block rule installed ({handle})")),
            Err(e)     => (false, format!("block_ip failed: {e:#}")),
        };
        if success {
            self.blocked.lock().await.insert(ip.to_string());
        }
        self.audit.emit(
            crate::schema::EventAction::IpBlocked,
            crate::schema::Severity::High,
            "ip_block",
            ip.to_string(),
            success,
            reason,
            None,
            Some(cmd_id.into()),
            json!({ "ttl_secs": ttl_secs }),
        );

        if let (true, Some(ttl)) = (success, ttl_secs) {
            let backend = self.cfg.net_backend;
            let blocked = Arc::clone(&self.blocked);
            let ip_owned = ip.to_string();
            let audit    = self.audit.clone();
            let cmd_id   = cmd_id.to_string();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(ttl)).await;
                if let Err(e) = network::unblock_ip(backend, &ip_owned) {
                    warn!(ip = %ip_owned, error = %e, "TTL unblock failed");
                } else {
                    blocked.lock().await.remove(&ip_owned);
                    audit.emit(
                        crate::schema::EventAction::IpUnblocked,
                        crate::schema::Severity::Info,
                        "ip_unblock",
                        ip_owned.clone(),
                        true,
                        "TTL expired".into(),
                        None,
                        Some(cmd_id),
                        serde_json::Value::Null,
                    );
                }
            });
        }
    }

    async fn cmd_unblock_ip(&self, ip: &str, cmd_id: &str) {
        let res = network::unblock_ip(self.cfg.net_backend, ip);
        let (success, reason) = match res {
            Ok(_)  => (true,  format!("unblocked {ip}")),
            Err(e) => (false, format!("unblock failed: {e:#}")),
        };
        if success { self.blocked.lock().await.remove(ip); }
        self.audit.emit(
            crate::schema::EventAction::IpUnblocked,
            crate::schema::Severity::Info,
            "ip_unblock",
            ip.to_string(),
            success,
            reason,
            None,
            Some(cmd_id.into()),
            serde_json::Value::Null,
        );
    }

    fn cmd_update_policy(&self, rules: Vec<IocRule>, cmd_id: &str) {
        let count = rules.len();
        match PolicyStore::from_rules(rules) {
            Ok(store) => {
                self.policy.replace(store);
                info!(rules = count, "IoC policy reloaded from backend");
                self.audit.emit(
                    crate::schema::EventAction::PolicyUpdated,
                    crate::schema::Severity::Info,
                    "policy_update",
                    "<policy>",
                    true,
                    format!("{count} rule(s) loaded"),
                    None,
                    Some(cmd_id.into()),
                    json!({ "rule_count": count }),
                );
            }
            Err(e) => {
                self.audit.emit(
                    crate::schema::EventAction::PolicyUpdated,
                    crate::schema::Severity::Medium,
                    "policy_update",
                    "<policy>",
                    false,
                    format!("policy reload failed: {e:#}"),
                    None,
                    Some(cmd_id.into()),
                    serde_json::Value::Null,
                );
            }
        }
    }
}
