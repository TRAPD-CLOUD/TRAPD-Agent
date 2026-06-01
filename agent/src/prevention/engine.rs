//! Prevention engine — wires policy, audit, network, quarantine and process
//! kill into one orchestrated runtime.
//!
//! Two input streams:
//!
//!   1. **Events**  — every `AgentEvent` flowing through the telemetry pipe
//!      is tee'd into this engine.  On `ExecEventData` we run `enforce_exec`
//!      to apply IoC rules in real time.
//!   2. **Commands** — verified `CommandEnvelope`s from the backend puller.
//!      Each is dispatched to the matching handler (kill / isolate / …).
//!
//! Errors are audited but never propagated; the prevention engine MUST keep
//! running even when individual actions fail (e.g. `nft` missing on the box).

use std::path::Path;
use std::sync::{Arc, RwLock};
use std::collections::HashSet;

use base64::Engine as _;
use serde_json::json;
use tokio::sync::mpsc::Receiver;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::AgentConfig;
use crate::deception::{self, DeployRequest, HoneytokenStore};
use crate::schema::{AgentEvent, EventData, HoneytokenAccessData};

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

/// Escalating honeytoken-access response, parsed from `AgentConfig::honeytoken_response`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseLevel {
    /// Detection only is emitted upstream; the engine takes no further action.
    None,
    /// Default: a critical prevention alert, no process action.
    Alert,
    /// Alert + SIGKILL the accessing process.
    Kill,
    /// Alert + kill + full host network isolation.
    Isolate,
}

impl ResponseLevel {
    fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => ResponseLevel::None,
            "kill" => ResponseLevel::Kill,
            "isolate" | "isolate_network" | "jail" => ResponseLevel::Isolate,
            _ => ResponseLevel::Alert, // safe default for unknown values
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ResponseLevel::None => "none",
            ResponseLevel::Alert => "alert",
            ResponseLevel::Kill => "kill",
            ResponseLevel::Isolate => "isolate",
        }
    }
}

pub struct Engine {
    policy: PolicyHandle,
    audit:  AuditEmitter,
    cfg:    EngineConfig,
    /// Set of currently-blocked IPs/CIDRs (string form for direct nft passthrough).
    blocked: Arc<tokio::sync::Mutex<HashSet<String>>>,
    /// Register of honeytokens deployed on this host (deploy/revoke lifecycle).
    honeytokens: Arc<HoneytokenStore>,
    /// Live agent config — read for the policy-driven honeytoken response level.
    cfg_handle: Arc<RwLock<AgentConfig>>,
}

impl Engine {
    pub fn new(
        policy: PolicyHandle,
        audit: AuditEmitter,
        cfg: EngineConfig,
        honeytokens: Arc<HoneytokenStore>,
        cfg_handle: Arc<RwLock<AgentConfig>>,
    ) -> Self {
        Self {
            policy,
            audit,
            cfg,
            blocked: Arc::new(tokio::sync::Mutex::new(HashSet::new())),
            honeytokens,
            cfg_handle,
        }
    }

    /// Spawn the event-enforcement loop.  Consumes the receiver.
    ///
    /// Two enforcement paths ride this stream: IoC enforcement on `ProcessExec`,
    /// and the policy-driven auto-response on a `HoneytokenAccess` detection.
    pub fn spawn_event_loop(self: Arc<Self>, mut rx: Receiver<AgentEvent>) {
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                match &event.data {
                    EventData::ProcessExec(exec) => {
                        let _ = process::enforce_exec(exec, &self.policy, &self.audit);
                    }
                    EventData::HoneytokenAccess(data) => {
                        self.respond_honeytoken(data).await;
                    }
                    _ => {}
                }
            }
        });
    }

    /// Policy-driven response to a confirmed honeytoken access. Escalating:
    /// `none` < `alert` < `kill` < `isolate`. Every decision is audited so the
    /// backend sees exactly what was done (and gets the hit telemetry for the
    /// ML feedback loop).
    async fn respond_honeytoken(&self, data: &HoneytokenAccessData) {
        let level = self.honeytoken_response_level();
        let pid = data.accessor.pid;
        let target = format!("{} (pid {})", data.path, pid);

        // Above `alert`, terminate the accessing process. Best-effort: it may
        // already have exited.
        let mut actions: Vec<&str> = vec!["alert"];
        let mut killed = false;
        if matches!(level, ResponseLevel::Kill | ResponseLevel::Isolate) && pid > 0 {
            killed = process::kill_pid(pid).is_ok();
            actions.push(if killed { "kill" } else { "kill_failed" });
        }
        let mut isolated = false;
        if matches!(level, ResponseLevel::Isolate) {
            let mut allow = self.cfg.default_isolation_allowlist.clone();
            allow.sort();
            allow.dedup();
            isolated = network::isolate(self.cfg.net_backend, &allow).is_ok();
            actions.push(if isolated { "isolate" } else { "isolate_failed" });
        }

        let severity = match level {
            ResponseLevel::None => crate::schema::Severity::High,
            _ => crate::schema::Severity::Critical,
        };
        self.audit.emit(
            crate::schema::EventAction::HoneytokenAccess,
            severity,
            "honeytoken_response",
            target,
            true,
            format!(
                "honeytoken '{}' accessed by {} (pid {}) — response level '{}'",
                data.kind, data.accessor.comm, pid, level.as_str()
            ),
            None,
            None,
            json!({
                "token_id": data.token_id,
                "path": data.path,
                "kind": data.kind,
                "accessor_pid": pid,
                "accessor_comm": data.accessor.comm,
                "accessor_uid": data.accessor.uid,
                "open_flags": data.open_flags,
                "response_level": level.as_str(),
                "actions": actions,
                "killed": killed,
                "isolated": isolated,
            }),
        );
    }

    fn honeytoken_response_level(&self) -> ResponseLevel {
        let raw = self
            .cfg_handle
            .read()
            .map(|c| c.honeytoken_response.clone())
            .unwrap_or_else(|_| "alert".to_string());
        ResponseLevel::parse(&raw)
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
            CommandPayload::InstallPackage { name } => {
                self.cmd_package(super::software::Operation::Install(name), &cmd_id);
            }
            CommandPayload::RemovePackage { name } => {
                self.cmd_package(super::software::Operation::Remove(name), &cmd_id);
            }
            CommandPayload::UpgradePackage { name } => {
                let op = match name {
                    Some(n) => super::software::Operation::Upgrade(n),
                    None => super::software::Operation::UpgradeAll,
                };
                self.cmd_package(op, &cmd_id);
            }
            CommandPayload::DeployHoneytoken {
                path,
                content_b64,
                mode,
                mimic_neighbor,
                canary_marker,
                token_kind,
                breadcrumbs,
            } => {
                self.cmd_deploy_honeytoken(
                    path,
                    content_b64,
                    *mode,
                    *mimic_neighbor,
                    canary_marker.clone(),
                    token_kind.clone(),
                    breadcrumbs,
                    &cmd_id,
                );
            }
            CommandPayload::RevokeHoneytoken { path } => {
                self.cmd_revoke_honeytoken(path, &cmd_id);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn cmd_deploy_honeytoken(
        &self,
        path: &str,
        content_b64: &str,
        mode: u32,
        mimic_neighbor: bool,
        canary_marker: Option<String>,
        kind: Option<String>,
        breadcrumbs: &[super::commands::BreadcrumbSpec],
        cmd_id: &str,
    ) {
        let content = match base64::engine::general_purpose::STANDARD.decode(content_b64) {
            Ok(c) => c,
            Err(e) => {
                self.audit.emit(
                    crate::schema::EventAction::HoneytokenDeployed,
                    crate::schema::Severity::Medium,
                    "honeytoken_deploy",
                    path.to_string(),
                    false,
                    format!("bad base64 content: {e}"),
                    None,
                    Some(cmd_id.into()),
                    serde_json::Value::Null,
                );
                return;
            }
        };

        // Decode breadcrumbs; a single bad one is skipped (logged) rather than
        // failing the whole deployment.
        let breadcrumbs: Vec<deception::Breadcrumb> = breadcrumbs
            .iter()
            .filter_map(|b| {
                match base64::engine::general_purpose::STANDARD.decode(&b.content_b64) {
                    Ok(content) => Some(deception::Breadcrumb {
                        path: b.path.clone(),
                        content,
                        mode: b.mode,
                        append: b.append,
                    }),
                    Err(e) => {
                        tracing::warn!(path = %b.path, error = %e, "skipping breadcrumb with bad base64");
                        None
                    }
                }
            })
            .collect();

        let req = DeployRequest {
            path: path.to_string(),
            content,
            mode,
            mimic_neighbor,
            canary_marker,
            kind,
            command_id: Some(cmd_id.to_string()),
            breadcrumbs,
        };

        match deception::deploy(&self.honeytokens, req) {
            Ok(record) => {
                self.audit.emit(
                    crate::schema::EventAction::HoneytokenDeployed,
                    crate::schema::Severity::Info,
                    "honeytoken_deploy",
                    record.path.clone(),
                    true,
                    format!("honeytoken '{}' deployed", record.kind),
                    None,
                    Some(cmd_id.into()),
                    // Never echo the bait content — only safe metadata.
                    json!({
                        "id": record.id,
                        "kind": record.kind,
                        "mode": record.mode,
                        "size_bytes": record.size_bytes,
                        "sha256": record.sha256,
                        "mimic_neighbor": record.mimic_neighbor,
                        "neighbor_path": record.neighbor_path,
                        "has_canary": record.canary_marker.is_some(),
                        "breadcrumbs": record.breadcrumbs.len(),
                    }),
                );
            }
            Err(e) => {
                self.audit.emit(
                    crate::schema::EventAction::HoneytokenDeployed,
                    crate::schema::Severity::Medium,
                    "honeytoken_deploy",
                    path.to_string(),
                    false,
                    format!("honeytoken deploy failed: {e:#}"),
                    None,
                    Some(cmd_id.into()),
                    serde_json::Value::Null,
                );
            }
        }
    }

    fn cmd_revoke_honeytoken(&self, path: &str, cmd_id: &str) {
        match deception::revoke(&self.honeytokens, path) {
            Ok(record) => {
                self.audit.emit(
                    crate::schema::EventAction::HoneytokenRevoked,
                    crate::schema::Severity::Info,
                    "honeytoken_revoke",
                    record.path.clone(),
                    true,
                    format!("honeytoken '{}' revoked", record.kind),
                    None,
                    Some(cmd_id.into()),
                    json!({ "id": record.id, "kind": record.kind }),
                );
            }
            Err(e) => {
                self.audit.emit(
                    crate::schema::EventAction::HoneytokenRevoked,
                    crate::schema::Severity::Medium,
                    "honeytoken_revoke",
                    path.to_string(),
                    false,
                    format!("honeytoken revoke failed: {e:#}"),
                    None,
                    Some(cmd_id.into()),
                    serde_json::Value::Null,
                );
            }
        }
    }

    /// Run a software-management operation and audit the outcome.  Package work
    /// shells out to the package manager (via an argv, no shell).
    fn cmd_package(&self, op: super::software::Operation<'_>, cmd_id: &str) {
        use crate::schema::{EventAction, Severity};
        use super::software::Operation;

        let (action, kind, target): (EventAction, &str, String) = match &op {
            Operation::Install(p) => (EventAction::PackageInstalled, "package_install", p.to_string()),
            Operation::Remove(p)  => (EventAction::PackageRemoved,   "package_remove",  p.to_string()),
            Operation::Upgrade(p) => (EventAction::PackageUpgraded,  "package_upgrade", p.to_string()),
            Operation::UpgradeAll => (EventAction::PackageUpgraded,  "package_upgrade", "<all>".to_string()),
        };

        let result = super::software::execute(op);
        let severity = if result.success { Severity::Info } else { Severity::Medium };

        self.audit.emit(
            action,
            severity,
            kind,
            target,
            result.success,
            result.summary,
            None,
            Some(cmd_id.into()),
            json!({ "output": result.output }),
        );
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
                    "file restored from quarantine",
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
                        "TTL expired",
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
