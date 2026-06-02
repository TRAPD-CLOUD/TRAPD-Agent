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
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::json;
use tokio::sync::mpsc::Receiver;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::AgentConfig;
use crate::deception::{self, DeployRequest, HoneytokenStore};
use crate::forensics::{self, FlightRecorder};
use crate::schema::{
    AgentEvent, DetectionData, EventAction, EventData, HoneytokenAccessData,
    RansomwareIndicatorData, Severity,
};

use super::audit::AuditEmitter;
use super::commands::{CommandEnvelope, CommandPayload};
use super::network::{self, Backend};
use super::policy::{IocRule, PolicyHandle, PolicyStore};
use super::process;
use super::quarantine;
use super::response::{self, AutoAction, Targets};
use super::rtr as response_rtr;

/// Per-(rule, pid) cooldown so a looping attacker (or a chatty detector) cannot
/// trigger an auto-response storm of the same action.
const AUTO_RESPONSE_COOLDOWN: Duration = Duration::from_secs(30);

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
    /// Alert + **freeze** the accessing process (SIGSTOP) and snapshot it,
    /// leaving the decision (kill / thaw) to an operator — "freeze, snapshot,
    /// then decide" (issue #32, point 5). The process is suspended, not killed.
    Freeze,
    /// Alert + SIGKILL the accessing process.
    Kill,
    /// Alert + kill + full host network isolation.
    Isolate,
}

impl ResponseLevel {
    fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => ResponseLevel::None,
            // "jail" semantically means *freeze the process*, not network isolate.
            "freeze" | "jail" => ResponseLevel::Freeze,
            "kill" => ResponseLevel::Kill,
            "isolate" | "isolate_network" => ResponseLevel::Isolate,
            _ => ResponseLevel::Alert, // safe default for unknown values
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ResponseLevel::None => "none",
            ResponseLevel::Alert => "alert",
            ResponseLevel::Freeze => "freeze",
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
    /// Bounded flight recorder of recent telemetry, pulled into a honeytoken
    /// response as the accessor session's pre-history (issue #32, point 5).
    recorder: Arc<FlightRecorder>,
    /// Cooldown register for automated detection-response, keyed `rule_id:pid`.
    auto_cooldown: Arc<tokio::sync::Mutex<HashMap<String, Instant>>>,
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
            recorder: Arc::new(FlightRecorder::new(forensics::recorder::DEFAULT_CAPACITY)),
            auto_cooldown: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Spawn the event-enforcement loop.  Consumes the receiver.
    ///
    /// Two enforcement paths ride this stream: IoC enforcement on `ProcessExec`,
    /// and the policy-driven auto-response on a `HoneytokenAccess` detection.
    pub fn spawn_event_loop(self: Arc<Self>, mut rx: Receiver<AgentEvent>) {
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                // Flight recorder (issue #32, point 5): every event feeds the
                // bounded ring so a later honeytoken hit can ship the session's
                // pre-history. Cheap and lock-poison-tolerant.
                self.recorder.record(&event);
                match &event.data {
                    EventData::ProcessExec(exec) => {
                        let _ = process::enforce_exec(exec, &self.policy, &self.audit);
                    }
                    EventData::HoneytokenAccess(data) => {
                        self.respond_honeytoken(data).await;
                    }
                    // Policy-driven auto-response to the local detection stream
                    // (opt-in; off by default). Honeytoken hits are handled
                    // above by their own escalation, so they are not double-acted.
                    EventData::Detection(det) => {
                        self.auto_respond_detection(&event, det).await;
                    }
                    EventData::RansomwareIndicator(r) => {
                        self.auto_respond_ransomware(&event, r).await;
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

        let mut actions: Vec<&str> = vec!["alert"];
        let mut killed = false;
        let mut frozen = false;
        let mut isolated = false;
        let mut snapshot: Option<forensics::ProcessSnapshot> = None;

        // Freeze (SIGSTOP) + snapshot — suspend the intruder process without
        // killing it, capture its state while it cannot react, and leave the
        // kill/thaw decision to an operator (issue #32, point 5).
        if matches!(level, ResponseLevel::Freeze) && pid > 0 {
            frozen = process::freeze_pid(pid).is_ok();
            actions.push(if frozen { "freeze" } else { "freeze_failed" });
            // Snapshot regardless — a process that raced to exit is itself signal.
            snapshot = Some(forensics::capture_snapshot(pid, frozen));
        }

        // Above `alert` (kill/isolate), terminate the accessing process.
        if matches!(level, ResponseLevel::Kill | ResponseLevel::Isolate) && pid > 0 {
            killed = process::kill_pid(pid).is_ok();
            actions.push(if killed { "kill" } else { "kill_failed" });
        }
        if matches!(level, ResponseLevel::Isolate) {
            let mut allow = self.cfg.default_isolation_allowlist.clone();
            allow.sort();
            allow.dedup();
            isolated = network::isolate(self.cfg.net_backend, &allow).is_ok();
            actions.push(if isolated { "isolate" } else { "isolate_failed" });
        }

        // Flight recorder: pull the buffered pre-history of the accessor and its
        // ancestry, so the response ships the session's recent story.
        let mut pids: Vec<i32> = Vec::with_capacity(1 + data.accessor.ancestors.len());
        pids.push(pid);
        pids.extend(data.accessor.ancestors.iter().map(|a| a.pid));
        let history = self.recorder.history_for(&pids, 64);

        // Session correlation: echo the detection-time context, filling the
        // remote source IP from buffered logons when it was not already known.
        let session = self.correlate_session(data);

        // Deception escalation (config-gated): emit the agent's signal for the
        // backend to deploy more bait / redirect into a honeypot / tarpit.
        let escalate = self.deception_escalation_enabled();
        if escalate {
            self.emit_deception_escalation(data, session.as_ref(), &target);
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
                "frozen": frozen,
                "isolated": isolated,
                "snapshot": snapshot,
                "session": session,
                "flight_recorder": history,
                "escalation_triggered": escalate,
            }),
        );
    }

    /// Auto-respond to a generic local detection (config-gated, off by default).
    async fn auto_respond_detection(&self, event: &AgentEvent, det: &DetectionData) {
        let targets = response::targets_from_detection(&det.subject, &det.evidence);
        self.auto_respond(event, &det.rule_id, &det.category, det.confidence, &det.subject, targets)
            .await;
    }

    /// Auto-respond to a ransomware indicator. Its payload carries the writer
    /// pid and the file under encryption directly, so kill + quarantine act
    /// precisely on the source.
    async fn auto_respond_ransomware(&self, event: &AgentEvent, r: &RansomwareIndicatorData) {
        let targets = Targets {
            pid: r.pid.filter(|p| *p > 1),
            file_path: r.path.clone(),
        };
        let subject = r
            .path
            .clone()
            .or_else(|| r.comm.clone())
            .unwrap_or_else(|| "ransomware".to_string());
        self.auto_respond(
            event,
            &format!("ransomware.{}", r.indicator_type),
            "ransomware",
            90,
            &subject,
            targets,
        )
        .await;
    }

    /// Shared auto-response core: snapshot policy, decide (pure), de-dupe via a
    /// per-(rule,pid) cooldown, then execute and audit. The decision logic lives
    /// in [`super::response`] so the "should we kill this?" call is unit-tested.
    async fn auto_respond(
        &self,
        event: &AgentEvent,
        rule_id: &str,
        category: &str,
        confidence: u8,
        subject: &str,
        targets: Targets,
    ) {
        let (enabled, action, min_sev, min_conf, allow) = match self.cfg_handle.read() {
            Ok(c) => (
                c.auto_response_enabled,
                AutoAction::parse(&c.auto_response_action),
                response::parse_severity(&c.auto_response_min_severity),
                c.auto_response_min_confidence,
                c.auto_response_allowlist.clone(),
            ),
            Err(_) => return,
        };

        let decision = response::decide(
            enabled, action, min_sev, min_conf, &allow,
            event.severity, rule_id, category, confidence, &targets,
        );
        if matches!(decision.action, AutoAction::None) {
            return;
        }

        // Cooldown so a repeating detection cannot storm the same action.
        let key = format!("{rule_id}:{}", targets.pid.unwrap_or(0));
        {
            let mut cd = self.auto_cooldown.lock().await;
            let now = Instant::now();
            if let Some(prev) = cd.get(&key) {
                if now.duration_since(*prev) < AUTO_RESPONSE_COOLDOWN {
                    return;
                }
            }
            cd.insert(key, now);
            cd.retain(|_, t| now.duration_since(*t) < AUTO_RESPONSE_COOLDOWN);
        }

        self.execute_auto(rule_id, category, subject, &targets, &decision);
    }

    /// Execute a decided auto-response: kill / quarantine / isolate. Never the
    /// agent itself or pid ≤ 1. Best-effort — failures are audited, never fatal.
    fn execute_auto(
        &self,
        rule_id: &str,
        category: &str,
        subject: &str,
        targets: &Targets,
        decision: &response::Decision,
    ) {
        let own_pid = std::process::id() as i32;
        let mut actions: Vec<&str> = Vec::new();
        let mut killed = false;
        let mut quarantined = false;
        let mut isolated = false;

        let wants_kill = matches!(
            decision.action,
            AutoAction::Kill | AutoAction::Quarantine | AutoAction::Isolate
        );
        if wants_kill {
            if let Some(pid) = targets.pid {
                if pid > 1 && pid != own_pid {
                    killed = process::kill_pid(pid).is_ok();
                    actions.push(if killed { "kill" } else { "kill_failed" });
                } else {
                    actions.push("kill_skipped_self");
                }
            }
        }

        if matches!(decision.action, AutoAction::Quarantine) {
            if let Some(path) = &targets.file_path {
                quarantined = quarantine::quarantine(Path::new(path)).is_ok();
                actions.push(if quarantined { "quarantine" } else { "quarantine_failed" });
            }
        }

        if matches!(decision.action, AutoAction::Isolate) {
            let mut allow = self.cfg.default_isolation_allowlist.clone();
            allow.sort();
            allow.dedup();
            isolated = network::isolate(self.cfg.net_backend, &allow).is_ok();
            actions.push(if isolated { "isolate" } else { "isolate_failed" });
        }

        if actions.is_empty() {
            actions.push("alert");
        }

        let event_action = match decision.action {
            AutoAction::Isolate => EventAction::NetworkIsolated,
            AutoAction::Quarantine => EventAction::FileQuarantined,
            AutoAction::Kill => EventAction::ProcessBlocked,
            _ => EventAction::Detected,
        };
        let success =
            killed || quarantined || isolated || matches!(decision.action, AutoAction::Alert);

        self.audit.emit(
            event_action,
            Severity::Critical,
            "auto_response",
            subject.to_string(),
            success,
            format!(
                "auto-response '{}' to detection '{}' ({})",
                decision.action.as_str(),
                rule_id,
                decision.reason
            ),
            Some(rule_id.to_string()),
            None,
            json!({
                "rule_id": rule_id,
                "category": category,
                "action": decision.action.as_str(),
                "reason": decision.reason,
                "target_pid": targets.pid,
                "target_path": targets.file_path,
                "actions": actions,
                "killed": killed,
                "quarantined": quarantined,
                "isolated": isolated,
            }),
        );

        info!(
            rule_id,
            action = decision.action.as_str(),
            target_pid = ?targets.pid,
            "auto-response executed"
        );
    }

    /// Echo the detection-time session, correlating the remote source IP from
    /// the flight recorder's buffered logons when it is not already populated.
    fn correlate_session(&self, data: &HoneytokenAccessData) -> Option<crate::schema::SessionContext> {
        let mut s = data.session.clone()?;
        if s.remote_addr.is_none() {
            if let Some((addr, port)) = self.recorder.correlate_remote(s.login_user.as_deref()) {
                s.remote_addr = Some(addr);
                s.remote_port = port;
            }
        }
        Some(s)
    }

    /// Emit the deception-escalation signal: a prevention event carrying the
    /// attacker context so the backend can deploy more bait, redirect the
    /// session into a real honeypot, or tarpit it. The agent never mints bait or
    /// reroutes traffic itself (that is backend/infra work) — it raises the
    /// trigger with full context (issue #32, point 5).
    fn emit_deception_escalation(
        &self,
        data: &HoneytokenAccessData,
        session: Option<&crate::schema::SessionContext>,
        target: &str,
    ) {
        self.audit.emit(
            crate::schema::EventAction::DeceptionEscalation,
            crate::schema::Severity::Critical,
            "deception_escalation",
            target.to_string(),
            true,
            format!(
                "deception escalation triggered by honeytoken '{}' hit (pid {})",
                data.kind, data.accessor.pid
            ),
            None,
            None,
            json!({
                "token_id": data.token_id,
                "path": data.path,
                "kind": data.kind,
                "accessor": data.accessor,
                "session": session,
                "recommended": ["deploy_additional_bait", "redirect_honeypot", "tarpit"],
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

    fn deception_escalation_enabled(&self) -> bool {
        self.cfg_handle
            .read()
            .map(|c| c.honeytoken_deception_escalation)
            .unwrap_or(false)
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
                out_of_band,
                token_kind,
                breadcrumbs,
            } => {
                self.cmd_deploy_honeytoken(
                    path,
                    content_b64,
                    *mode,
                    *mimic_neighbor,
                    canary_marker.clone(),
                    out_of_band.clone(),
                    token_kind.clone(),
                    breadcrumbs,
                    &cmd_id,
                );
            }
            CommandPayload::RevokeHoneytoken { path } => {
                self.cmd_revoke_honeytoken(path, &cmd_id);
            }
            CommandPayload::FreezePid { pid } => {
                self.cmd_freeze_pid(*pid, &cmd_id);
            }
            CommandPayload::ThawPid { pid } => {
                self.cmd_thaw_pid(*pid, &cmd_id);
            }
            CommandPayload::RunScript { interpreter, script_b64, timeout_secs } => {
                self.cmd_run_script(interpreter.as_deref(), script_b64, *timeout_secs, &cmd_id)
                    .await;
            }
            CommandPayload::CollectFile { path, max_bytes } => {
                self.cmd_collect_file(path, *max_bytes, &cmd_id);
            }
            CommandPayload::ListDirectory { path } => {
                self.cmd_list_directory(path, &cmd_id);
            }
            CommandPayload::CollectProcessMemory { pid, max_bytes } => {
                self.cmd_collect_process_memory(*pid, *max_bytes, &cmd_id);
            }
        }
    }

    // ── RTR (Real-Time Response) ─────────────────────────────────────────────

    /// Read `(rtr_enabled, rtr_max_artifact_bytes)` from the live config.
    fn rtr_settings(&self) -> (bool, u64) {
        self.cfg_handle
            .read()
            .map(|c| (c.rtr_enabled, c.rtr_max_artifact_bytes))
            .unwrap_or((false, 0))
    }

    /// Audit an RTR command that was refused because RTR is disabled.
    fn rtr_refuse(&self, kind: &str, target: impl Into<String>, cmd_id: &str) {
        self.audit.emit(
            EventAction::CommandRejected,
            Severity::Medium,
            kind,
            target,
            false,
            "RTR is disabled (set rtr_enabled=true to allow)",
            None,
            Some(cmd_id.into()),
            serde_json::Value::Null,
        );
    }

    /// Execute a signed remediation script with a timeout, returning capped
    /// stdout/stderr in the audited result.
    async fn cmd_run_script(
        &self,
        interpreter: Option<&str>,
        script_b64: &str,
        timeout_secs: Option<u64>,
        cmd_id: &str,
    ) {
        let (enabled, max_bytes) = self.rtr_settings();
        if !enabled {
            return self.rtr_refuse("rtr_run_script", "script", cmd_id);
        }
        let script = match base64::engine::general_purpose::STANDARD.decode(script_b64) {
            Ok(b) => match String::from_utf8(b) {
                Ok(s) => s,
                Err(_) => return self.rtr_refuse("rtr_run_script", "script", cmd_id),
            },
            Err(_) => return self.rtr_refuse("rtr_run_script", "script", cmd_id),
        };

        let (prog, flag) = response_rtr::shell_invocation(interpreter);
        let timeout = Duration::from_secs(timeout_secs.unwrap_or(30).clamp(1, 300));

        let run = tokio::process::Command::new(&prog)
            .arg(flag)
            .arg(&script)
            .stdin(std::process::Stdio::null())
            .output();

        let (success, code, stdout, stderr, note) =
            match tokio::time::timeout(timeout, run).await {
                Ok(Ok(out)) => (
                    out.status.success(),
                    out.status.code(),
                    out.stdout,
                    out.stderr,
                    String::new(),
                ),
                Ok(Err(e)) => (false, None, Vec::new(), Vec::new(), format!("spawn failed: {e}")),
                Err(_) => (false, None, Vec::new(), Vec::new(), "timed out".to_string()),
            };

        let max = max_bytes as usize;
        let out_art = response_rtr::cap_and_encode(&stdout, max);
        let err_art = response_rtr::cap_and_encode(&stderr, max.saturating_sub(out_art.b64.len()).max(1));

        self.audit.emit(
            EventAction::CommandAccepted,
            if success { Severity::Info } else { Severity::Medium },
            "rtr_run_script",
            prog.clone(),
            success,
            format!(
                "ran script via {prog} (exit {}{})",
                code.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
                if note.is_empty() { String::new() } else { format!(", {note}") }
            ),
            None,
            Some(cmd_id.into()),
            json!({
                "interpreter": prog,
                "exit_code": code,
                "note": note,
                "stdout_b64": out_art.b64,
                "stdout_len": out_art.total_len,
                "stdout_truncated": out_art.truncated,
                "stderr_b64": err_art.b64,
                "stderr_len": err_art.total_len,
                "stderr_truncated": err_art.truncated,
            }),
        );
    }

    /// Read a file and return its capped contents as a base64 artifact.
    fn cmd_collect_file(&self, path: &str, max_bytes: Option<u64>, cmd_id: &str) {
        let (enabled, default_max) = self.rtr_settings();
        if !enabled {
            return self.rtr_refuse("rtr_collect_file", path.to_string(), cmd_id);
        }
        let cap = max_bytes.unwrap_or(default_max).min(default_max) as usize;
        match std::fs::read(path) {
            Ok(bytes) => {
                let art = response_rtr::cap_and_encode(&bytes, cap);
                self.audit.emit(
                    EventAction::CommandAccepted,
                    Severity::Info,
                    "rtr_collect_file",
                    path.to_string(),
                    true,
                    format!("collected {} of {} bytes from {path}", art.returned_len, art.total_len),
                    None,
                    Some(cmd_id.into()),
                    json!({
                        "path": path,
                        "content_b64": art.b64,
                        "total_len": art.total_len,
                        "truncated": art.truncated,
                    }),
                );
            }
            Err(e) => self.audit.emit(
                EventAction::CommandRejected,
                Severity::Medium,
                "rtr_collect_file",
                path.to_string(),
                false,
                format!("collect_file failed: {e}"),
                None,
                Some(cmd_id.into()),
                serde_json::Value::Null,
            ),
        }
    }

    /// List a directory (names, types, sizes) for triage.
    fn cmd_list_directory(&self, path: &str, cmd_id: &str) {
        let (enabled, _) = self.rtr_settings();
        if !enabled {
            return self.rtr_refuse("rtr_list_directory", path.to_string(), cmd_id);
        }
        match std::fs::read_dir(path) {
            Ok(rd) => {
                let entries: Vec<serde_json::Value> = rd
                    .flatten()
                    .take(4096)
                    .map(|e| {
                        let md = e.metadata().ok();
                        json!({
                            "name": e.file_name().to_string_lossy(),
                            "dir": md.as_ref().map(|m| m.is_dir()).unwrap_or(false),
                            "size": md.as_ref().map(|m| m.len()).unwrap_or(0),
                        })
                    })
                    .collect();
                self.audit.emit(
                    EventAction::CommandAccepted,
                    Severity::Info,
                    "rtr_list_directory",
                    path.to_string(),
                    true,
                    format!("listed {} entries in {path}", entries.len()),
                    None,
                    Some(cmd_id.into()),
                    json!({ "path": path, "entries": entries }),
                );
            }
            Err(e) => self.audit.emit(
                EventAction::CommandRejected,
                Severity::Medium,
                "rtr_list_directory",
                path.to_string(),
                false,
                format!("list_directory failed: {e}"),
                None,
                Some(cmd_id.into()),
                serde_json::Value::Null,
            ),
        }
    }

    /// Dump a process's readable memory (anonymous-executable regions first) as
    /// a capped base64 artifact. Requires CAP_SYS_PTRACE / root to read
    /// `/proc/<pid>/mem`; partial reads are returned best-effort.
    fn cmd_collect_process_memory(&self, pid: i32, max_bytes: Option<u64>, cmd_id: &str) {
        use std::io::{Read, Seek, SeekFrom};

        let (enabled, default_max) = self.rtr_settings();
        if !enabled {
            return self.rtr_refuse("rtr_collect_memory", format!("pid {pid}"), cmd_id);
        }
        let cap = max_bytes.unwrap_or(default_max).min(default_max);

        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default();
        let regions = response_rtr::dumpable_regions(&maps, cap);

        let mut buf = Vec::new();
        let mut mem = std::fs::File::open(format!("/proc/{pid}/mem"));
        if let Ok(f) = mem.as_mut() {
            for (start, end) in &regions {
                if f.seek(SeekFrom::Start(*start)).is_err() {
                    continue;
                }
                let mut chunk = vec![0u8; (end - start) as usize];
                // Reads can short-read or fail per region (guard pages, races);
                // keep whatever we got and move on.
                if let Ok(n) = f.read(&mut chunk) {
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
        }

        let art = response_rtr::cap_and_encode(&buf, cap as usize);
        let success = !buf.is_empty();
        self.audit.emit(
            if success { EventAction::CommandAccepted } else { EventAction::CommandRejected },
            if success { Severity::Info } else { Severity::Medium },
            "rtr_collect_memory",
            format!("pid {pid}"),
            success,
            format!(
                "dumped {} bytes from {} region(s) of pid {pid}{}",
                art.returned_len,
                regions.len(),
                if mem.is_err() { " (/proc/<pid>/mem unreadable — need CAP_SYS_PTRACE)" } else { "" }
            ),
            None,
            Some(cmd_id.into()),
            json!({
                "pid": pid,
                "regions": regions.len(),
                "memory_b64": art.b64,
                "total_len": art.total_len,
                "truncated": art.truncated,
            }),
        );
    }

    /// Freeze a process (SIGSTOP) on operator command and audit a forensic
    /// snapshot of it while it is suspended (issue #32, point 5).
    fn cmd_freeze_pid(&self, pid: i32, cmd_id: &str) {
        use crate::schema::{EventAction, Severity};
        let frozen = process::freeze_pid(pid).is_ok();
        let snapshot = forensics::capture_snapshot(pid, frozen);
        self.audit.emit(
            EventAction::ProcessFrozen,
            if frozen { Severity::High } else { Severity::Medium },
            "process_freeze",
            pid.to_string(),
            frozen,
            if frozen {
                format!("pid {pid} frozen (SIGSTOP) for forensic capture")
            } else {
                format!("freeze of pid {pid} failed (process may have exited)")
            },
            None,
            Some(cmd_id.into()),
            json!({ "pid": pid, "frozen": frozen, "snapshot": snapshot }),
        );
    }

    /// Resume a previously-frozen process (SIGCONT) on operator command.
    fn cmd_thaw_pid(&self, pid: i32, cmd_id: &str) {
        use crate::schema::{EventAction, Severity};
        let thawed = process::thaw_pid(pid).is_ok();
        self.audit.emit(
            EventAction::ProcessThawed,
            if thawed { Severity::Info } else { Severity::Medium },
            "process_thaw",
            pid.to_string(),
            thawed,
            if thawed {
                format!("pid {pid} resumed (SIGCONT)")
            } else {
                format!("thaw of pid {pid} failed (process may have exited)")
            },
            None,
            Some(cmd_id.into()),
            json!({ "pid": pid, "thawed": thawed }),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn cmd_deploy_honeytoken(
        &self,
        path: &str,
        content_b64: &str,
        mode: u32,
        mimic_neighbor: bool,
        canary_marker: Option<String>,
        out_of_band: Option<Box<super::commands::OutOfBandSpec>>,
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

        // Map the wire-level out-of-band spec into the deception model. The
        // descriptor is validated inside `deploy`, so a malformed one fails the
        // placement cleanly rather than planting an uncorrelatable canary.
        let out_of_band = out_of_band.map(|o| {
            let o = *o;
            deception::OutOfBandCanary {
                channel: o.channel,
                tracking_id: o.tracking_id,
                markers: o.markers,
            }
        });

        let req = DeployRequest {
            path: path.to_string(),
            content,
            mode,
            mimic_neighbor,
            canary_marker,
            out_of_band,
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
                    // Never echo the bait content — only safe metadata. The
                    // `out_of_band` block is the agent's registration of a
                    // second-channel canary (issue #32, point 2): it binds this
                    // token to its host (the event carries agent_id/hostname) and
                    // to the channel/tracking_id/markers the backend needs to
                    // correlate an inbound foreign signal. Markers are the *fake*
                    // attacker-facing identifiers (key id, tracking domain), never
                    // the bait content, so they are safe to publish.
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
                        "out_of_band": record.out_of_band.as_ref().map(|o| json!({
                            "channel": o.channel,
                            "tracking_id": o.tracking_id,
                            "markers": o.markers,
                        })),
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
                    // Echo the out-of-band tracking id on revoke so the backend can
                    // retire the canary's correlation entry (issue #32, point 2).
                    json!({
                        "id": record.id,
                        "kind": record.kind,
                        "out_of_band": record.out_of_band.as_ref().map(|o| json!({
                            "channel": o.channel,
                            "tracking_id": o.tracking_id,
                        })),
                    }),
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

#[cfg(test)]
mod tests {
    use super::ResponseLevel;

    #[test]
    fn response_level_parses_escalation_ladder() {
        assert_eq!(ResponseLevel::parse("none"), ResponseLevel::None);
        assert_eq!(ResponseLevel::parse("alert"), ResponseLevel::Alert);
        assert_eq!(ResponseLevel::parse("kill"), ResponseLevel::Kill);
        assert_eq!(ResponseLevel::parse("isolate"), ResponseLevel::Isolate);
        assert_eq!(ResponseLevel::parse("isolate_network"), ResponseLevel::Isolate);
        // Unknown values fail safe to the non-destructive default.
        assert_eq!(ResponseLevel::parse("wat"), ResponseLevel::Alert);
        // Case/whitespace insensitive.
        assert_eq!(ResponseLevel::parse("  KILL "), ResponseLevel::Kill);
    }

    #[test]
    fn freeze_and_jail_both_mean_freeze_not_isolate() {
        // "jail" is the process-freeze response (SIGSTOP), NOT network isolation.
        assert_eq!(ResponseLevel::parse("freeze"), ResponseLevel::Freeze);
        assert_eq!(ResponseLevel::parse("jail"), ResponseLevel::Freeze);
        assert_eq!(ResponseLevel::Freeze.as_str(), "freeze");
    }
}
