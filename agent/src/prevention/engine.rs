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

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::json;
use tokio::sync::mpsc::Receiver;
use tokio::sync::Notify;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::AgentConfig;
use crate::deception::{self, DeployRequest, HoneytokenStore};
use crate::forensics::{self, FlightRecorder};
use crate::schema::{
    AgentEvent, DetectionData, DnsResolutionData, EventAction, EventData, HoneytokenAccessData,
    NetworkConnectionData, RansomwareIndicatorData, Severity,
};

use super::audit::AuditEmitter;
use super::commands::{CommandEnvelope, CommandPayload};
use super::isolation_state;
use super::lsm_loader::LsmHandle;
use super::network::{self, Backend};
use super::policy::{IocRule, Match, PolicyHandle, PolicyStore, RuleAction};
use super::process;
use super::quarantine;
use super::response::{self, AutoAction, Targets};
use super::rtr as response_rtr;

/// Per-(rule, pid) cooldown so a looping attacker (or a chatty detector) cannot
/// trigger an auto-response storm of the same action.
const AUTO_RESPONSE_COOLDOWN: Duration = Duration::from_secs(30);

/// Whether `pid` is a legitimate target for a PID-directed action.
///
/// A signed PID-targeted command (`kill` / `freeze` / `thaw` / `collect-memory`)
/// must name one real, individual process. It must never be a `kill(2)` broadcast
/// selector — `pid == -1` signals *every* process the caller may signal, `pid == 0`
/// the *whole process group* — and never init (`pid == 1`) or the agent's own PID
/// (which would let a command take the self-defense agent down via its own channel).
///
/// This is the single guard shared by both the auto-response path
/// ([`Engine::execute_auto`]) and the command handlers, so a target rejected by one
/// is rejected by the other (issue #59).
fn is_valid_target_pid(pid: i32, own_pid: i32) -> bool {
    // PID 4 is the Windows `System` process, the analogue of init.
    let first_valid = if cfg!(windows) { 4 } else { 1 };
    pid > first_valid && pid != own_pid
}

#[derive(Clone)]
pub struct EngineConfig {
    pub net_backend: Backend,
    pub management_host: Option<String>,
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
    /// The response actually taken for one access. A verified sweeper
    /// (backup/AV/indexer) is never frozen, killed or isolated automatically:
    /// a scheduled run gets no response at all, an interactive one an alert at
    /// most. An operator decides on anything more disruptive.
    fn for_access(self, data: &HoneytokenAccessData) -> Option<Self> {
        if crate::detection::honeytoken_policy::assess(data, Severity::Critical).mode
            == crate::schema::DetectionMode::Signal
        {
            return None;
        }
        if data.allowlisted_accessor && self != ResponseLevel::None {
            return Some(ResponseLevel::Alert);
        }
        Some(self)
    }

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
    audit: AuditEmitter,
    cfg: EngineConfig,
    /// Set of currently-blocked IPs/CIDRs (string form for direct nft passthrough).
    blocked: Arc<tokio::sync::Mutex<HashSet<String>>>,
    /// Register of honeytokens deployed on this host (deploy/revoke lifecycle).
    honeytokens: Arc<HoneytokenStore>,
    /// Live agent config — read for the policy-driven honeytoken response level.
    cfg_handle: Arc<RwLock<AgentConfig>>,
    /// Bounded flight recorder of recent telemetry, pulled into a honeytoken
    /// response as the accessor session's pre-history (issue #32, point 5).
    recorder: Arc<FlightRecorder>,
    /// Cooldown register for automated responses, keyed by rule and process generation.
    auto_cooldown: Arc<tokio::sync::Mutex<HashMap<String, Instant>>>,
    /// Shared kick to the eBPF reconciler + health checker, pulsed right after a
    /// honeytoken deploy/revoke so arming and the on-disk verification run
    /// immediately instead of waiting for the next periodic tick. `None` in tests
    /// or when eBPF detection is unavailable.
    reconcile_signal: Option<Arc<Notify>>,
    /// Owns the attached kernel program for the full prevention runtime.
    kernel_blocker: LsmHandle,
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
            reconcile_signal: None,
            kernel_blocker: LsmHandle::disabled(),
        }
    }

    /// Attach the shared reconcile/health kick. Pulsed after every honeytoken
    /// deploy/revoke so the eBPF reconciler arms/disarms and the health checker
    /// re-verifies the affected token within ms.
    pub fn with_reconcile_signal(mut self, signal: Arc<Notify>) -> Self {
        self.reconcile_signal = Some(signal);
        self
    }

    /// Pulse the reconcile/health kick, if wired. `notify_waiters` wakes *both*
    /// consumers (the eBPF reconciler and the health checker) that are currently
    /// parked; a consumer mid-pass simply catches the change on its next periodic
    /// tick, so no wakeup is ever required for correctness.
    fn kick_reconcile(&self) {
        if let Some(sig) = &self.reconcile_signal {
            sig.notify_waiters();
        }
    }

    fn prevention_enabled(&self) -> bool {
        self.cfg_handle
            .read()
            .map(|c| c.prevention_enabled)
            .unwrap_or(false)
    }

    /// Resolve the backend and read signed-config allowances at the action
    /// boundary so DNS rotation and config changes apply without restart.
    async fn isolation_allowlist(
        &self,
        additional: &[std::net::IpAddr],
    ) -> anyhow::Result<Vec<std::net::IpAddr>> {
        let mut allow = match &self.cfg.management_host {
            Some(host) => super::runtime::resolve_management_ips(host).await?,
            None => Vec::new(),
        };
        // Query native DNS before taking the signed-config lock. Reject an
        // unsafe hostname isolation before any command/automatic path mutates
        // firewall state; cached backend IPs alone cannot preserve recovery.
        let dns = match &self.cfg.management_host {
            Some(host) => {
                super::runtime::management_dns_servers(host, self.cfg.net_backend).await?
            }
            None => None,
        };
        let cfg = self
            .cfg_handle
            .read()
            .map_err(|_| anyhow::anyhow!("isolation config lock poisoned"))?;
        anyhow::ensure!(
            cfg.prevention_enabled,
            "prevention was disabled before isolation"
        );
        let mut explicit: Vec<std::net::IpAddr> = cfg
            .isolation_allowlist_ips
            .iter()
            .filter_map(|ip| ip.parse().ok())
            .collect();
        explicit.extend_from_slice(additional);
        if let (Some(host), Some(dns)) = (&self.cfg.management_host, dns) {
            super::firewall::require_management_dns(host, &dns, &explicit)?;
        }
        allow.extend(explicit);
        allow.sort();
        allow.dedup();
        Ok(allow)
    }

    async fn sync_kernel_prevention(&self) {
        let enabled = self.prevention_enabled();
        self.kernel_blocker.set_enabled(enabled).await;
        if enabled {
            // Configuration can change while the program is being loaded.
            if self.prevention_enabled() {
                self.kernel_blocker.sync(&self.policy).await;
            } else {
                self.kernel_blocker.set_enabled(false).await;
            }
        }
    }

    /// Recover persistent Windows deadlines before consuming new responses.
    #[cfg(windows)]
    pub async fn start_firewall_expiry(self: Arc<Self>) {
        if !matches!(self.cfg.net_backend, Backend::WindowsFirewall) {
            return;
        }
        // Reconcile before starting command/event consumers, then retry even
        // when prevention has been disabled since installing rules.
        self.reconcile_firewall_expiry().await;
        tokio::spawn(async move {
            let period = Duration::from_secs(5);
            let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                self.reconcile_firewall_expiry().await;
            }
        });
    }

    #[cfg(windows)]
    async fn reconcile_firewall_expiry(&self) {
        let mut blocked = self.blocked.lock().await;
        let expired = match tokio::task::spawn_blocking(super::winfirewall::expire_due_blocks).await
        {
            Ok(Ok(expired)) => expired,
            Ok(Err(error)) => {
                warn!(%error, "firewall TTL reconciliation failed; will retry");
                return;
            }
            Err(error) => {
                warn!(%error, "firewall TTL reconciliation task failed; will retry");
                return;
            }
        };
        for expiry in expired {
            blocked.retain(|key| {
                network::canonical_windows_target(key).ok().as_deref()
                    != Some(expiry.target.as_str())
            });
            self.audit.emit(
                EventAction::IpUnblocked,
                Severity::Info,
                "ip_unblock",
                expiry.target,
                true,
                "TTL expired",
                None,
                Some(expiry.command_id),
                serde_json::Value::Null,
            );
        }
    }

    /// Spawn the event-enforcement loop. Consumes the receiver.
    pub fn spawn_event_loop(self: Arc<Self>, mut rx: Receiver<AgentEvent>) {
        tokio::spawn(async move {
            let mut config_tick = tokio::time::interval(Duration::from_millis(100));
            let mut last_enabled = None;
            loop {
                let event = tokio::select! {
                    _ = config_tick.tick() => {
                        let enabled = self.prevention_enabled();
                        if last_enabled != Some(enabled) {
                            self.sync_kernel_prevention().await;
                            last_enabled = Some(enabled);
                        }
                        continue;
                    }
                    event = rx.recv() => match event {
                        Some(event) => event,
                        None => break,
                    },
                };
                // Flight recorder (issue #32, point 5): every event feeds the
                // bounded ring so a later honeytoken hit can ship the session's
                // pre-history. Cheap and lock-poison-tolerant.
                self.recorder.record(&event);
                if crate::detection::is_historical_windows_record(&event) {
                    continue;
                }
                if !self.prevention_enabled() {
                    self.kernel_blocker.set_enabled(false).await;
                    continue;
                }
                match &event.data {
                    EventData::ProcessExec(exec) => {
                        let _ = process::enforce_exec(exec, &self.policy, &self.audit);
                    }
                    // Windows has no exec-time kernel event; the process sensor
                    // (ETW, or the poller) reports creation. The Linux poller
                    // also emits `ProcessCreate`, but there eBPF already
                    // enforces `ProcessExec`, so only Windows acts on it.
                    #[cfg(windows)]
                    EventData::ProcessCreate(create) => {
                        let exec = process::exec_from_create(create);
                        let _ = process::enforce_exec(&exec, &self.policy, &self.audit);
                    }
                    // Inline IoC enforcement on the network plane (Phase 0): a
                    // backend-pushed Ip/Cidr/Port/Domain rule now actively drops
                    // the destination and kills the connecting process, not just
                    // alerts. Closes the "detect-but-don't-prevent" gap for C2.
                    EventData::NetworkConnection(net) => {
                        self.enforce_network(net).await;
                    }
                    EventData::DnsResolution(dns) => {
                        self.enforce_dns_resolution(dns).await;
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
        if !self.prevention_enabled() {
            return;
        }
        let Some(level) = self.honeytoken_response_level().for_access(data) else {
            return;
        };
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
            frozen = process::freeze_observed(pid, data.accessor.process_start_time).is_ok();
            actions.push(if frozen { "freeze" } else { "freeze_failed" });
            // Snapshot regardless — a process that raced to exit is itself signal.
            snapshot = Some(forensics::capture_snapshot(pid, frozen));
        }

        // Above `alert` (kill/isolate), terminate the accessing process.
        if matches!(level, ResponseLevel::Kill | ResponseLevel::Isolate) && pid > 0 {
            killed = process::kill_observed(pid, data.accessor.process_start_time).is_ok();
            actions.push(if killed { "kill" } else { "kill_failed" });
        }
        if matches!(level, ResponseLevel::Isolate) {
            isolated = self
                .isolation_allowlist(&[])
                .await
                .and_then(|allow| self.apply_isolation(Vec::new(), allow).map(|_| ()))
                .is_ok();
            actions.push(if isolated {
                "isolate"
            } else {
                "isolate_failed"
            });
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
                data.kind,
                data.accessor.comm,
                pid,
                level.as_str()
            ),
            None,
            None,
            json!({
                "token_id": data.token_id,
                "path": data.path,
                "kind": data.kind,
                "accessor_pid": pid,
                "process_start_time": data.accessor.process_start_time,
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
        if crate::detection::is_historical_windows_record(event) {
            return;
        }
        // Signals are context, and shadow findings are observations only.
        // Neither may cause a response even with permissive signed thresholds.
        if matches!(
            det.mode,
            Some(crate::schema::DetectionMode::Signal | crate::schema::DetectionMode::Shadow)
        ) {
            return;
        }
        let targets = response::targets_for_rule(&det.rule_id, &det.subject, &det.evidence);
        self.auto_respond(
            event,
            &det.rule_id,
            &det.category,
            det.confidence,
            &det.subject,
            targets,
        )
        .await;
    }

    /// Auto-respond to a ransomware indicator. Its payload carries the writer
    /// pid and the file under encryption directly, so kill + quarantine act
    /// precisely on the source.
    async fn auto_respond_ransomware(&self, event: &AgentEvent, r: &RansomwareIndicatorData) {
        let targets = Targets {
            pid: r
                .pid
                .filter(|p| is_valid_target_pid(*p, std::process::id() as i32)),
            process_start_time: r.process_start_time,
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
        if !self.prevention_enabled() {
            return;
        }
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
            enabled,
            action,
            min_sev,
            min_conf,
            &allow,
            event.severity,
            rule_id,
            category,
            confidence,
            &targets,
        );
        if matches!(decision.action, AutoAction::None) {
            return;
        }

        // Cooldown so a repeating detection cannot storm the same action.
        let key = format!(
            "{rule_id}:{}:{:?}",
            targets.pid.unwrap_or(0),
            targets.process_start_time
        );
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

        self.execute_auto(rule_id, category, subject, &targets, &decision)
            .await;
    }

    /// Execute a decided auto-response: kill / quarantine / isolate. Never the
    /// agent itself or pid ≤ 1. Best-effort — failures are audited, never fatal.
    async fn execute_auto(
        &self,
        rule_id: &str,
        category: &str,
        subject: &str,
        targets: &Targets,
        decision: &response::Decision,
    ) {
        if !self.prevention_enabled() {
            return;
        }
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
                let own_pid = std::process::id() as i32;
                if is_valid_target_pid(pid, own_pid) {
                    killed = process::kill_observed(pid, targets.process_start_time).is_ok();
                    actions.push(if killed { "kill" } else { "kill_failed" });
                } else {
                    actions.push("kill_skipped_self");
                }
            }
        }

        if matches!(decision.action, AutoAction::Quarantine) {
            if let Some(path) = &targets.file_path {
                quarantined = response::validated_quarantine_path(path)
                    .is_some_and(|path| quarantine::quarantine(Path::new(&path)).is_ok());
                actions.push(if quarantined {
                    "quarantine"
                } else {
                    "quarantine_failed"
                });
            }
        }

        if matches!(decision.action, AutoAction::Isolate) {
            isolated = self
                .isolation_allowlist(&[])
                .await
                .and_then(|allow| self.apply_isolation(Vec::new(), allow).map(|_| ()))
                .is_ok();
            actions.push(if isolated {
                "isolate"
            } else {
                "isolate_failed"
            });
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
                "process_start_time": targets.process_start_time,
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

    /// Inline IoC enforcement on an observed network flow. A backend-pushed
    /// `Ip`/`Cidr`/`Port` rule with action `Block` installs a firewall drop for
    /// the destination and (best-effort) SIGKILLs the connecting process;
    /// `Alert` audits only. The network analogue of [`process::enforce_exec`].
    async fn enforce_network(&self, data: &NetworkConnectionData) {
        if !self.prevention_enabled() {
            return;
        }
        // Only act on flow *start* records, never the synthetic close event.
        if data.state.eq_ignore_ascii_case("closed") {
            return;
        }
        let addr = match data.dst_addr.parse::<std::net::IpAddr>() {
            Ok(a) => a,
            Err(_) => return,
        };
        let m = match self.policy.read().match_network(addr, data.dst_port) {
            Some(m) => m,
            None => return,
        };
        self.enforce_net_match(
            addr,
            data.dst_port,
            data.pid,
            data.process_start_time,
            m,
            "flow",
            None,
        )
        .await;
    }

    /// Inline IoC enforcement on a resolved DNS answer. A backend-pushed
    /// `Domain` block rule drops every resolved A/AAAA address so the
    /// follow-up connection cannot complete, even though the resolution itself
    /// carries no originating PID.
    async fn enforce_dns_resolution(&self, data: &DnsResolutionData) {
        if !self.prevention_enabled() {
            return;
        }
        let m = match self.policy.read().match_domain(&data.qname) {
            Some(m) => m,
            None => return,
        };
        for ip in &data.resolved_ips {
            if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                self.enforce_net_match(addr, 0, None, None, m.clone(), "dns", Some(&data.qname))
                    .await;
            }
        }
    }

    /// Shared network-enforcement core: install a deduplicated firewall drop for
    /// `addr` on `Block`, optionally SIGKILL the connecting `pid`, and audit the
    /// outcome. Best-effort — a missing firewall backend or a vanished process
    /// is recorded, never fatal.
    #[allow(clippy::too_many_arguments)]
    async fn enforce_net_match(
        &self,
        addr: std::net::IpAddr,
        port: u16,
        pid: Option<i32>,
        process_start_time: Option<u64>,
        m: Match,
        source: &str,
        qname: Option<&str>,
    ) {
        if !self.prevention_enabled() {
            return;
        }
        let block = matches!(m.action, RuleAction::Block);

        // Deduplicate firewall installs per destination so a chatty flow does
        // not spam `nft`/`iptables` with identical drop rules.
        let mut blocked_now = false;
        if block {
            let key = addr.to_string();
            let mut set = self.blocked.lock().await;
            if set.contains(&key) {
                blocked_now = true;
            } else {
                match network::block_ip(self.cfg.net_backend, &key) {
                    Ok(handle) => {
                        info!(%addr, rule = %m.rule_id, %handle, "network IoC blocked");
                        set.insert(key);
                        blocked_now = true;
                    }
                    Err(e) => warn!(%addr, rule = %m.rule_id, error = %e, "network block failed"),
                }
            }
        }

        // Terminate the connecting process (Block only, valid single target).
        let mut killed = false;
        if block {
            if let Some(pid) = pid {
                let own_pid = std::process::id() as i32;
                if is_valid_target_pid(pid, own_pid) {
                    killed = process::kill_observed(pid, process_start_time).is_ok();
                }
            }
        }

        let (event_action, kind, severity) = if block {
            (EventAction::IpBlocked, "network_block", Severity::High)
        } else {
            (EventAction::Detected, "network_alert", Severity::Medium)
        };
        // On Block the action succeeds if either the drop installed or the
        // process was killed; an Alert always "succeeds" (it only records).
        let success = if block { blocked_now || killed } else { true };

        self.audit.emit(
            event_action,
            severity,
            kind,
            addr.to_string(),
            success,
            format!(
                "network IoC {} on {addr} ({}) — {}",
                if block { "block" } else { "alert" },
                m.rule_id,
                m.reason
            ),
            Some(m.rule_id.clone()),
            None,
            json!({
                "addr": addr.to_string(),
                "port": port,
                "source": source,
                "qname": qname,
                "rule_id": m.rule_id,
                "action": if block { "block" } else { "alert" },
                "blocked": blocked_now,
                "killed": killed,
                "target_pid": pid,
                "process_start_time": process_start_time,
            }),
        );
    }

    /// Echo the detection-time session, correlating the remote source IP from
    /// the flight recorder's buffered logons when it is not already populated.
    fn correlate_session(
        &self,
        data: &HoneytokenAccessData,
    ) -> Option<crate::schema::SessionContext> {
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
        if !self.prevention_enabled() {
            self.kernel_blocker.set_enabled(false).await;
            self.audit.emit(
                EventAction::CommandRejected,
                Severity::Medium,
                "command_rejected",
                "<command>",
                false,
                "prevention is disabled by agent configuration",
                None,
                Some(cmd_id),
                serde_json::Value::Null,
            );
            return;
        }
        match &env.payload {
            CommandPayload::KillPid {
                pid,
                process_generation,
            } => {
                self.cmd_kill_pid(*pid, process_generation.map(|g| g.0), &cmd_id);
            }
            CommandPayload::IsolateNetwork { allowlist_ips } => {
                self.cmd_isolate(allowlist_ips.clone(), &cmd_id).await;
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
                self.cmd_update_policy(rules.clone(), &cmd_id).await;
            }
            CommandPayload::InstallPackage { name } => {
                self.cmd_package(super::software::Operation::Install(name), &cmd_id)
                    .await;
            }
            CommandPayload::RemovePackage { name } => {
                self.cmd_package(super::software::Operation::Remove(name), &cmd_id)
                    .await;
            }
            CommandPayload::UpgradePackage { name } => {
                let op = match name {
                    Some(n) => super::software::Operation::Upgrade(n),
                    None => super::software::Operation::UpgradeAll,
                };
                self.cmd_package(op, &cmd_id).await;
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
            CommandPayload::FreezePid {
                pid,
                process_generation,
            } => {
                self.cmd_freeze_pid(*pid, process_generation.map(|g| g.0), &cmd_id);
            }
            CommandPayload::ThawPid {
                pid,
                process_generation,
            } => {
                self.cmd_thaw_pid(*pid, process_generation.map(|g| g.0), &cmd_id);
            }
            CommandPayload::RunScript {
                interpreter,
                script_b64,
                timeout_secs,
            } => {
                self.cmd_run_script(interpreter.as_deref(), script_b64, *timeout_secs, &cmd_id)
                    .await;
            }
            CommandPayload::CollectFile { path, max_bytes } => {
                self.cmd_collect_file(path, *max_bytes, &cmd_id);
            }
            CommandPayload::ListDirectory { path } => {
                self.cmd_list_directory(path, &cmd_id);
            }
            CommandPayload::CollectProcessMemory {
                pid,
                max_bytes,
                process_start_time,
            } => {
                self.cmd_collect_process_memory(*pid, *max_bytes, *process_start_time, &cmd_id);
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

        let prog = response_rtr::interpreter(interpreter);
        let script_args = response_rtr::script_args(&prog, &script);
        let timeout = Duration::from_secs(timeout_secs.unwrap_or(30).clamp(1, 300));

        let max = max_bytes as usize;
        let run = response_rtr::run_script_bounded(&prog, &script_args, timeout, max).await;
        let (success, code, note) = (run.success, run.code, run.note);
        let out_art = response_rtr::encode_prefix(&run.stdout, run.stdout_total);
        let err_cap = max.saturating_sub(out_art.b64.len()).max(1);
        let err_art = response_rtr::encode_prefix(
            &run.stderr[..run.stderr.len().min(err_cap)],
            run.stderr_total,
        );

        self.audit.emit(
            EventAction::CommandAccepted,
            if success {
                Severity::Info
            } else {
                Severity::Medium
            },
            "rtr_run_script",
            prog.clone(),
            success,
            format!(
                "ran script via {prog} (exit {}{})",
                code.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
                if note.is_empty() {
                    String::new()
                } else {
                    format!(", {note}")
                }
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
        match response_rtr::collect_file(path, cap) {
            Ok(art) => {
                self.audit.emit(
                    EventAction::CommandAccepted,
                    Severity::Info,
                    "rtr_collect_file",
                    path.to_string(),
                    true,
                    format!(
                        "collected {} of {} bytes from {path}",
                        art.returned_len, art.total_len
                    ),
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

    /// Gate a PID-directed command on a sane target. Returns `true` if `pid`
    /// names a single real process that may be acted on; otherwise emits a
    /// `CommandRejected` audit event and returns `false` so the caller bails
    /// out **before** any signal is sent. Rejects broadcast selectors
    /// (`pid <= 0`), init (`pid == 1`) and the agent's own PID (issue #59).
    fn accept_target_pid(
        &self,
        pid: i32,
        process_start_time: Option<u64>,
        kind: &str,
        cmd_id: &str,
    ) -> bool {
        let own_pid = std::process::id() as i32;
        if is_valid_target_pid(pid, own_pid) {
            return true;
        }
        self.audit.emit(
            EventAction::CommandRejected,
            Severity::Medium,
            kind,
            pid.to_string(),
            false,
            format!(
                "refusing PID-targeted command: pid {pid} is not a valid single \
                 target (must be > 1 and not the agent's own pid {own_pid})"
            ),
            None,
            Some(cmd_id.into()),
            json!({ "pid": pid, "process_start_time": process_start_time, "rejected": "invalid_target_pid" }),
        );
        false
    }

    fn process_action_succeeded(
        &self,
        result: anyhow::Result<()>,
        pid: i32,
        process_start_time: Option<u64>,
        kind: &str,
        cmd_id: &str,
    ) -> bool {
        match result {
            Ok(()) => true,
            Err(error) => {
                self.audit.emit(
                    EventAction::CommandRejected, Severity::Medium, kind,
                    pid.to_string(), false, format!("process action refused or failed: {error}"),
                    None, Some(cmd_id.into()),
                    json!({ "pid": pid, "process_start_time": process_start_time, "source": "command" }),
                );
                false
            }
        }
    }

    /// Read up to `cap` bytes of `pid`'s memory, anonymous-executable regions
    /// first. Returns the bytes, the number of regions read and a note for the
    /// audit trail when the process memory could not be opened.
    #[cfg(not(windows))]
    fn read_process_memory(
        pid: i32,
        cap: u64,
        expected_start: Option<u64>,
    ) -> anyhow::Result<(Vec<u8>, usize, &'static str)> {
        use std::io::{Read, Seek, SeekFrom};

        let verify_generation = || -> anyhow::Result<()> {
            if let Some(expected) = expected_start {
                anyhow::ensure!(
                    expected > 0,
                    "unknown observed identity for pid {pid}; refusing"
                );
                anyhow::ensure!(
                    crate::telemetry::identity::process_start_time(pid) == Some(expected),
                    "pid {pid} belongs to a different or unknown process; refusing"
                );
            }
            Ok(())
        };
        verify_generation()?;

        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default();
        let regions = response_rtr::dumpable_regions(&maps, cap);

        let mut buf = Vec::new();
        let mut mem = std::fs::File::open(format!("/proc/{pid}/mem"));
        // Check again after opening: subsequent reads use the retained memory
        // fd, which cannot switch to a recycled PID's address space.
        verify_generation()?;
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
        let note = if mem.is_err() {
            " (/proc/<pid>/mem unreadable — need CAP_SYS_PTRACE)"
        } else {
            ""
        };
        Ok((buf, regions.len(), note))
    }

    #[cfg(windows)]
    fn read_process_memory(
        pid: i32,
        cap: u64,
        expected_start: Option<u64>,
    ) -> anyhow::Result<(Vec<u8>, usize, &'static str)> {
        let dump = super::winproc::dump_memory(pid, cap, expected_start)?;
        Ok((dump.bytes, dump.regions, ""))
    }

    /// Dump a process's readable memory (anonymous-executable regions first) as
    /// a capped base64 artifact. Requires CAP_SYS_PTRACE / root to read
    /// `/proc/<pid>/mem`; partial reads are returned best-effort.
    fn cmd_collect_process_memory(
        &self,
        pid: i32,
        max_bytes: Option<u64>,
        process_start_time: Option<u64>,
        cmd_id: &str,
    ) {
        let refuse = |reason: String| {
            self.audit.emit(
                EventAction::CommandRejected,
                Severity::Medium,
                "rtr_collect_memory",
                format!("pid {pid}"),
                false,
                reason,
                None,
                Some(cmd_id.into()),
                json!({ "pid": pid, "process_start_time": process_start_time }),
            );
        };
        if !is_valid_target_pid(pid, std::process::id() as i32) {
            refuse(format!(
                "refusing PID-targeted command: invalid target pid {pid}"
            ));
            return;
        }

        let (enabled, default_max) = self.rtr_settings();
        if !enabled {
            return refuse("RTR is disabled (set rtr_enabled=true to allow)".into());
        }
        let cap = max_bytes.unwrap_or(default_max).min(default_max);

        let (buf, region_count, unreadable_note) =
            match Self::read_process_memory(pid, cap, process_start_time) {
                Ok(dump) => dump,
                Err(e) => {
                    return refuse(format!("process memory collection refused or failed: {e}"))
                }
            };
        if buf.is_empty() {
            return refuse(format!(
                "no readable memory returned for pid {pid}{unreadable_note}"
            ));
        }

        let art = response_rtr::cap_and_encode(&buf, cap as usize);
        self.audit.emit(
            EventAction::CommandAccepted,
            Severity::Info,
            "rtr_collect_memory",
            format!("pid {pid}"),
            true,
            format!(
                "dumped {} bytes from {} region(s) of pid {pid}{}",
                art.returned_len, region_count, unreadable_note
            ),
            None,
            Some(cmd_id.into()),
            json!({
                "pid": pid,
                "process_start_time": process_start_time,
                "regions": region_count,
                "memory_b64": art.b64,
                "total_len": art.total_len,
                "truncated": art.truncated,
            }),
        );
    }

    /// Freeze a process (SIGSTOP) on operator command and audit a forensic
    /// snapshot of it while it is suspended (issue #32, point 5).
    fn cmd_freeze_pid(&self, pid: i32, process_start_time: Option<u64>, cmd_id: &str) {
        use crate::schema::{EventAction, Severity};
        if !self.accept_target_pid(pid, process_start_time, "process_freeze", cmd_id) {
            return;
        }
        if !self.process_action_succeeded(
            process::freeze_pid(pid, process_start_time),
            pid,
            process_start_time,
            "process_freeze",
            cmd_id,
        ) {
            return;
        }
        let snapshot = forensics::capture_snapshot(pid, true);
        self.audit.emit(
            EventAction::ProcessFrozen,
            Severity::High,
            "process_freeze",
            pid.to_string(),
            true,
            format!("pid {pid} frozen (SIGSTOP) for forensic capture"),
            None,
            Some(cmd_id.into()),
            json!({ "pid": pid, "process_start_time": process_start_time, "frozen": true, "snapshot": snapshot }),
        );
    }

    /// Resume a previously-frozen process (SIGCONT) on operator command.
    fn cmd_thaw_pid(&self, pid: i32, process_start_time: Option<u64>, cmd_id: &str) {
        use crate::schema::{EventAction, Severity};
        if !self.accept_target_pid(pid, process_start_time, "process_thaw", cmd_id) {
            return;
        }
        if !self.process_action_succeeded(
            process::thaw_pid(pid, process_start_time),
            pid,
            process_start_time,
            "process_thaw",
            cmd_id,
        ) {
            return;
        }
        self.audit.emit(
            EventAction::ProcessThawed,
            Severity::Info,
            "process_thaw",
            pid.to_string(),
            true,
            format!("pid {pid} resumed (SIGCONT)"),
            None,
            Some(cmd_id.into()),
            json!({ "pid": pid, "process_start_time": process_start_time, "thawed": true }),
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
                // Arm the new token in the eBPF maps + verify it on disk now,
                // rather than waiting for the next periodic reconcile tick.
                self.kick_reconcile();
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
        let outcome = deception::revoke(&self.honeytokens, path);
        // Disarm in the kernel maps immediately on a successful revoke.
        if outcome.is_ok() {
            self.kick_reconcile();
        }
        match outcome {
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
    /// starts the package manager with an argv (no shell) and a deadline.
    async fn cmd_package(&self, op: super::software::Operation<'_>, cmd_id: &str) {
        use super::software::Operation;
        use crate::schema::{EventAction, Severity};

        let (action, kind, target): (EventAction, &str, String) = match &op {
            Operation::Install(p) => (
                EventAction::PackageInstalled,
                "package_install",
                p.to_string(),
            ),
            Operation::Remove(p) => (EventAction::PackageRemoved, "package_remove", p.to_string()),
            Operation::Upgrade(p) => (
                EventAction::PackageUpgraded,
                "package_upgrade",
                p.to_string(),
            ),
            Operation::UpgradeAll => (
                EventAction::PackageUpgraded,
                "package_upgrade",
                "<all>".to_string(),
            ),
        };

        let result = super::software::execute(op).await;
        let severity = if result.success {
            Severity::Info
        } else {
            Severity::Medium
        };

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

    fn cmd_kill_pid(&self, pid: i32, process_start_time: Option<u64>, cmd_id: &str) {
        if !self.accept_target_pid(pid, process_start_time, "process_block", cmd_id) {
            return;
        }
        if !self.process_action_succeeded(
            process::kill_pid(pid, process_start_time),
            pid,
            process_start_time,
            "process_block",
            cmd_id,
        ) {
            return;
        }
        self.audit.emit(
            crate::schema::EventAction::ProcessBlocked,
            crate::schema::Severity::High,
            "process_block",
            pid.to_string(),
            true,
            format!("SIGKILL delivered to pid {pid}"),
            None,
            Some(cmd_id.into()),
            json!({ "pid": pid, "process_start_time": process_start_time, "source": "command" }),
        );
    }

    async fn cmd_isolate(&self, mut allow: Vec<std::net::IpAddr>, cmd_id: &str) {
        let requested = allow.clone();
        let res = self.isolation_allowlist(&allow).await.and_then(|current| {
            allow = current;
            self.apply_isolation(requested, allow.clone())
        });
        let (success, reason) = match res {
            Ok(persisted) => (
                true,
                format!(
                    "host isolated; allowlist size = {}{}",
                    allow.len(),
                    if persisted {
                        ""
                    } else {
                        "; WARNING: isolation will not survive a reboot"
                    }
                ),
            ),
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

    /// The only way host isolation is applied, so it is always recorded.
    fn apply_isolation(
        &self,
        requested: Vec<std::net::IpAddr>,
        resolved: Vec<std::net::IpAddr>,
    ) -> anyhow::Result<bool> {
        let backend = self.cfg.net_backend;
        isolation_state::isolate(
            &isolation_state::path(),
            &isolation_state::IsolationState {
                requested,
                resolved,
            },
            || network::holds_isolation(backend),
            |ips| network::isolate(backend, ips),
            || network::deisolate(backend),
        )
    }

    /// Re-apply recorded isolation after a restart. Linux rules do not survive a
    /// reboot; Windows firewall rules do, so there is nothing to do there.
    #[cfg(not(windows))]
    pub async fn restore_isolation(&self) {
        let path = isolation_state::path();
        let recorded = match isolation_state::load(&path) {
            Ok(Some(recorded)) => recorded,
            Ok(None) => return,
            Err(error) => {
                self.audit_isolation_restore(
                    false,
                    format!("isolation state unreadable: {error:#}"),
                );
                return;
            }
        };
        // The last known list first: containment must not wait for DNS.
        const ATTEMPTS: u32 = 6;
        let mut failure = None;
        for attempt in 1..=ATTEMPTS {
            let backend = self.cfg.net_backend;
            let applied = network::ensure_chains(backend)
                .and_then(|()| network::isolate(backend, &recorded.resolved));
            match applied {
                Ok(()) => {
                    failure = None;
                    break;
                }
                Err(error) => failure = Some(format!("{error:#}")),
            }
            if attempt < ATTEMPTS {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        }
        if let Some(error) = failure {
            self.audit_isolation_restore(false, format!("isolation not restored: {error}"));
            return;
        }
        if let Ok(current) = self.isolation_allowlist(&recorded.requested).await {
            if current != recorded.resolved {
                if let Err(error) = self.apply_isolation(recorded.requested.clone(), current) {
                    warn!(error = %format!("{error:#}"), "could not refresh the isolation allowlist");
                }
            }
        }
        self.audit_isolation_restore(true, "host isolation restored after restart".into());
    }

    #[cfg(not(windows))]
    fn audit_isolation_restore(&self, success: bool, reason: String) {
        self.audit.emit(
            crate::schema::EventAction::NetworkIsolated,
            crate::schema::Severity::Critical,
            "network_isolate",
            "host",
            success,
            reason,
            None,
            None,
            serde_json::Value::Null,
        );
    }

    fn cmd_deisolate(&self, cmd_id: &str) {
        let backend = self.cfg.net_backend;
        let res =
            isolation_state::release(&isolation_state::path(), || network::deisolate(backend));
        let (success, reason) = match res {
            Ok(_) => (true, "host isolation lifted".to_string()),
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
            Ok(u) => u,
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
        let mut blocked = self.blocked.lock().await;
        let res = network::block_ip_with_ttl(self.cfg.net_backend, ip, ttl_secs, cmd_id);
        let (success, reason) = match &res {
            Ok(handle) => (true, format!("block rule installed ({handle})")),
            Err(e) => (false, format!("block_ip failed: {e:#}")),
        };
        if success {
            blocked.insert(ip.to_string());
        }
        drop(blocked);
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

        // Windows expiry is driven by persistent rule metadata, including
        // replacement commands, rather than a stale per-command sleep.
        #[cfg(windows)]
        if matches!(self.cfg.net_backend, Backend::WindowsFirewall) {
            return;
        }

        if let (true, Some(ttl)) = (success, ttl_secs) {
            let backend = self.cfg.net_backend;
            let blocked = Arc::clone(&self.blocked);
            let ip_owned = ip.to_string();
            let audit = self.audit.clone();
            let cmd_id = cmd_id.to_string();
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
        let mut blocked = self.blocked.lock().await;
        let res = network::unblock_ip(self.cfg.net_backend, ip);
        let (success, reason) = match res {
            Ok(_) => (true, format!("unblocked {ip}")),
            Err(e) => (false, format!("unblock failed: {e:#}")),
        };
        if success {
            blocked.remove(ip);
            #[cfg(windows)]
            if let Ok(target) = network::canonical_windows_target(ip) {
                blocked.retain(|key| {
                    network::canonical_windows_target(key).ok().as_deref() != Some(target.as_str())
                });
            }
        }
        drop(blocked);
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

    async fn cmd_update_policy(&self, rules: Vec<IocRule>, cmd_id: &str) {
        let count = rules.len();
        match PolicyStore::from_rules(rules) {
            Ok(store) => {
                self.policy.replace(store);
                self.sync_kernel_prevention().await;
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
mod tests;
