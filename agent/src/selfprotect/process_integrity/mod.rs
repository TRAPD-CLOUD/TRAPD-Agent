//! Process integrity self-checks (phase 09, layer L3).
//!
//! A periodic task asks "has someone tampered with *this* process?":
//!
//! | Finding (`rule_id`)             | Windows                                           | Linux                                                |
//! |---------------------------------|---------------------------------------------------|------------------------------------------------------|
//! | `selfprotect.code_patched`      | `.text` of ntdll/kernelbase/own image, `EtwEventWrite`/`NtTraceEvent` prologues | (covered by `module_injected` anon-exec) |
//! | `selfprotect.module_injected`   | loaded module outside the allowlist               | anon/rwx/deleted/untrusted exec mappings, `LD_PRELOAD`, `/etc/ld.so.preload` |
//! | `selfprotect.remote_thread`     | thread start address in no known module           | -                                                    |
//! | `selfprotect.debugger_attached` | debug port / debug object                         | `TracerPid` of the agent or its children             |
//! | `selfprotect.handle_access`     | foreign process holds a dangerous handle to us    | -                                                    |
//!
//! Design rules:
//! * Findings are deduplicated by a stable key and repeated at most every
//!   [`REREPORT`], so a persistent hook does not flood the pipeline.
//! * Each check has its own switch (`TRAPD_SELFPROTECT_*`, read from the
//!   environment / `agent.env`), and operator allowlists silence known tools.
//! * CPU is bounded: a 30 s jittered tick, work done on the blocking pool,
//!   page digests instead of copies of code, handle snapshot only every 60 s.
//!   The duration of each pass is logged at debug level.
//! * Detection, not prevention: nothing here stops the agent or blocks a
//!   process, so a false positive costs a finding, never telemetry.

// Linux builds the portable Windows-only helpers (pe, handles, policy) so they
// are unit-tested there; they are only *used* on Windows.
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc::Sender;
use tracing::{debug, warn};

use crate::collectors::Collector;
use crate::schema::{AgentEvent, DetectionData, EventAction, EventClass, EventData, Severity};

pub mod handles;
pub mod pe;
pub mod policy;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
mod windows;

/// Tick of the self-check; the handle watch runs every `WATCH_EVERY` ticks.
const TICK: Duration = Duration::from_secs(30);
const WATCH_EVERY: u64 = 2;
/// First pass shortly after start so a pre-existing implant is seen early,
/// but after start-up work has loaded its modules.
const FIRST_DELAY: Duration = Duration::from_secs(20);
/// A still-present finding is reported again after this long.
const REREPORT: Duration = Duration::from_secs(6 * 3600);
const MAX_TRACKED: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    CodePatched,
    ModuleInjected,
    RemoteThread,
    DebuggerAttached,
    HandleAccess,
}

impl Kind {
    pub fn rule_id(self) -> &'static str {
        match self {
            Kind::CodePatched => "selfprotect.code_patched",
            Kind::ModuleInjected => "selfprotect.module_injected",
            Kind::RemoteThread => "selfprotect.remote_thread",
            Kind::DebuggerAttached => "selfprotect.debugger_attached",
            Kind::HandleAccess => "selfprotect.handle_access",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Kind::CodePatched => "Code of the TRAPD agent process was modified",
            Kind::ModuleInjected => "Unexpected module loaded into the TRAPD agent",
            Kind::RemoteThread => "Thread started outside any module in the TRAPD agent",
            Kind::DebuggerAttached => "Debugger attached to the TRAPD agent",
            Kind::HandleAccess => "Process holds a dangerous handle to the TRAPD agent",
        }
    }

    fn technique(self) -> &'static str {
        match self {
            Kind::CodePatched => "T1562.001",
            Kind::ModuleInjected | Kind::RemoteThread => "T1055",
            Kind::DebuggerAttached | Kind::HandleAccess => "T1562.001",
        }
    }

    fn confidence(self) -> u8 {
        match self {
            Kind::CodePatched | Kind::DebuggerAttached => 85,
            Kind::ModuleInjected => 70,
            Kind::RemoteThread => 65,
            Kind::HandleAccess => 40,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub kind: Kind,
    pub severity: Severity,
    /// What the finding is about (module path, pid, function).
    pub subject: String,
    pub detail: String,
    pub evidence: Value,
    /// Stable identity for deduplication.
    pub dedup_key: String,
}

impl Finding {
    pub fn into_detection(self) -> DetectionData {
        DetectionData {
            // The sensor policy caps this at the catalogued maximum.
            base_severity: Some(self.severity),
            rule_id: self.kind.rule_id().into(),
            title: self.kind.title().into(),
            category: "defense_evasion".into(),
            mitre_tactic: Some("TA0005 Defense Evasion".into()),
            mitre_technique: Some(self.kind.technique().into()),
            confidence: self.kind.confidence(),
            subject: self.subject,
            detail: self.detail,
            evidence: self.evidence,
            dedup_key: Some(self.dedup_key),
            ..Default::default()
        }
    }
}

/// Suppresses repeats of the same finding.
#[derive(Default)]
pub struct Deduper {
    seen: HashMap<String, Instant>,
}

impl Deduper {
    /// `true` when `key` is new or was last reported more than [`REREPORT`] ago.
    pub fn fresh(&mut self, key: &str, now: Instant) -> bool {
        if self.seen.len() >= MAX_TRACKED {
            // Bounded: drop everything older than the re-report window, and if
            // that frees nothing (a flood of distinct keys) start over.
            self.seen.retain(|_, t| now.duration_since(*t) < REREPORT);
            if self.seen.len() >= MAX_TRACKED {
                self.seen.clear();
            }
        }
        match self.seen.get(key) {
            Some(t) if now.duration_since(*t) < REREPORT => false,
            _ => {
                self.seen.insert(key.to_string(), now);
                true
            }
        }
    }
}

/// Per-check switches and allowlists. Everything defaults to on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub enabled: bool,
    pub code: bool,
    pub modules: bool,
    pub threads: bool,
    pub debugger: bool,
    pub handles: bool,
    /// Extra module path prefixes (lower case) that are not injection.
    pub module_allow: Vec<String>,
    /// Extra opener image names / full paths (lower case) for the handle watch.
    pub handle_allow: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            code: true,
            modules: true,
            threads: true,
            debugger: true,
            handles: true,
            module_allow: Vec::new(),
            handle_allow: Vec::new(),
        }
    }
}

/// `on`/`1`/`true`/`yes` and `off`/`0`/`false`/`no`; anything else keeps `default`.
pub fn parse_switch(value: Option<&str>, default: bool) -> bool {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "on" | "true" | "yes") => true,
        Some("0" | "off" | "false" | "no") => false,
        _ => default,
    }
}

fn parse_list(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or("")
        .split(';')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

impl Config {
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let sw = |name: &str| parse_switch(get(name).as_deref(), true);
        Self {
            enabled: sw("TRAPD_SELFPROTECT_PROCESS_INTEGRITY"),
            code: sw("TRAPD_SELFPROTECT_CHECK_CODE"),
            modules: sw("TRAPD_SELFPROTECT_CHECK_MODULES"),
            threads: sw("TRAPD_SELFPROTECT_CHECK_THREADS"),
            debugger: sw("TRAPD_SELFPROTECT_CHECK_DEBUGGER"),
            handles: sw("TRAPD_SELFPROTECT_CHECK_HANDLES"),
            module_allow: parse_list(get("TRAPD_SELFPROTECT_MODULE_ALLOW").as_deref()),
            handle_allow: parse_list(get("TRAPD_SELFPROTECT_HANDLE_ALLOW").as_deref()),
        }
    }

    pub fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }
}

/// Next sleep: `TICK` +/- 20 %, so the checks do not align with an attacker's
/// own schedule and several agents do not wake together.
pub fn jittered(base: Duration, random: u32) -> Duration {
    let span = base.as_millis() as u64 * 2 / 5; // 40 % window
    let offset = span * u64::from(random) / u64::from(u32::MAX);
    base - Duration::from_millis(span / 2) + Duration::from_millis(offset)
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    let _ = getrandom::fill(&mut b);
    u32::from_le_bytes(b)
}

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "windows")]
use windows as platform;

pub struct ProcessIntegrityMonitor {
    cfg: Config,
}

impl ProcessIntegrityMonitor {
    pub fn new() -> Self {
        Self {
            cfg: Config::from_env(),
        }
    }
}

#[async_trait]
impl Collector for ProcessIntegrityMonitor {
    fn name(&self) -> &'static str {
        "ProcessIntegrityMonitor"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        if !self.cfg.enabled {
            tracing::info!("process integrity self-checks disabled by configuration");
            return Ok(());
        }
        let mut deduper = Deduper::default();
        let cfg = self.cfg.clone();
        let mut checker = Some(platform::Checker::new(&cfg));
        let mut wait = jittered(FIRST_DELAY, random_u32());
        let mut tick = 0u64;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = tx.closed() => return Ok(()),
            }
            wait = jittered(TICK, random_u32());
            let watch = tick.is_multiple_of(WATCH_EVERY);
            tick += 1;
            let mut c = checker
                .take()
                .unwrap_or_else(|| platform::Checker::new(&cfg));
            let started = Instant::now();
            let joined = tokio::task::spawn_blocking(move || {
                let mut found = c.self_check();
                if watch {
                    found.extend(c.watch());
                }
                (c, found)
            })
            .await;
            let found = match joined {
                Ok((c, found)) => {
                    checker = Some(c);
                    found
                }
                Err(e) => {
                    // A panic loses the cached baselines; start fresh next tick.
                    warn!(error = %e, "process integrity pass failed");
                    continue;
                }
            };
            debug!(
                elapsed_ms = started.elapsed().as_millis() as u64,
                findings = found.len(),
                "process integrity pass"
            );
            let now = Instant::now();
            for f in found {
                if !deduper.fresh(&f.dedup_key, now) {
                    continue;
                }
                warn!(rule = f.kind.rule_id(), subject = %f.subject, "process integrity finding");
                let severity = f.severity;
                let ev = AgentEvent::new(
                    agent_id.clone(),
                    hostname.clone(),
                    EventClass::Detection,
                    EventAction::Detected,
                    severity,
                    EventData::Detection(Box::new(f.into_detection())),
                );
                if tx.send(ev).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_reports_once_then_again_after_the_window() {
        let mut d = Deduper::default();
        let t0 = Instant::now();
        assert!(d.fresh("a", t0));
        assert!(!d.fresh("a", t0 + Duration::from_secs(60)));
        assert!(d.fresh("b", t0));
        assert!(d.fresh("a", t0 + REREPORT + Duration::from_secs(1)));
    }

    #[test]
    fn dedup_is_bounded() {
        let mut d = Deduper::default();
        let t0 = Instant::now();
        for i in 0..(MAX_TRACKED * 2) {
            d.fresh(&format!("k{i}"), t0);
        }
        assert!(d.seen.len() <= MAX_TRACKED);
    }

    #[test]
    fn switches_parse_and_default_on() {
        assert!(parse_switch(None, true));
        assert!(!parse_switch(Some("off"), true));
        assert!(!parse_switch(Some(" 0 "), true));
        assert!(parse_switch(Some("YES"), false));
        assert!(parse_switch(Some("garbage"), true), "unknown keeps default");
        assert!(!parse_switch(Some("garbage"), false));
    }

    #[test]
    fn config_reads_switches_and_lowercases_allowlists() {
        let env: HashMap<&str, &str> = [
            ("TRAPD_SELFPROTECT_CHECK_THREADS", "off"),
            ("TRAPD_SELFPROTECT_MODULE_ALLOW", r"C:\Vendor\Av\; D:\X "),
            ("TRAPD_SELFPROTECT_HANDLE_ALLOW", "Backup.EXE;;"),
        ]
        .into();
        let c = Config::from_lookup(|k| env.get(k).map(|v| v.to_string()));
        assert!(c.enabled && c.code && c.modules && c.debugger && c.handles);
        assert!(!c.threads);
        assert_eq!(c.module_allow, [r"c:\vendor\av\", r"d:\x"]);
        assert_eq!(c.handle_allow, ["backup.exe"]);
        assert_eq!(
            Config::from_lookup(|_| None),
            Config::default(),
            "no configuration: everything on"
        );
    }

    #[test]
    fn jitter_stays_within_twenty_percent() {
        let lo = jittered(TICK, 0);
        let hi = jittered(TICK, u32::MAX);
        assert_eq!(lo, Duration::from_secs(24));
        assert_eq!(hi, Duration::from_secs(36));
        let mid = jittered(TICK, u32::MAX / 2);
        assert!(mid > lo && mid < hi);
    }

    #[test]
    fn findings_become_catalogued_detections() {
        let f = Finding {
            kind: Kind::CodePatched,
            severity: Severity::High,
            subject: "ntdll.dll!EtwEventWrite".into(),
            detail: "d".into(),
            evidence: serde_json::json!({"offset": 1}),
            dedup_key: "k".into(),
        };
        let d = f.into_detection();
        assert_eq!(d.rule_id, "selfprotect.code_patched");
        assert_eq!(d.dedup_key.as_deref(), Some("k"));
        assert_eq!(d.base_severity, Some(Severity::High));
        assert_eq!(d.mitre_technique.as_deref(), Some("T1562.001"));
        for k in [
            Kind::CodePatched,
            Kind::ModuleInjected,
            Kind::RemoteThread,
            Kind::DebuggerAttached,
            Kind::HandleAccess,
        ] {
            assert!(k.rule_id().starts_with("selfprotect."));
        }
    }
}
