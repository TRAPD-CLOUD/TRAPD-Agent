//! Rootkit and host-tampering detection.
//!
//! Every detector here works by **cross-view comparison**: the same fact is read
//! through two or more independent interfaces, and a disagreement between them
//! is the signal. A rootkit hides by lying to one interface; it has to lie
//! consistently to *all* of them to stay invisible, which is much harder.
//!
//! | Detector | Views compared |
//! |---|---|
//! | [`hidden_process`] | `/proc` listing vs. direct `/proc/<pid>` access vs. signal liveness vs. eBPF-observed PIDs |
//! | [`hidden_socket`] | `/proc/net/*` vs. `sock_diag` netlink vs. eBPF-observed binds |
//! | [`modules`] | `/proc/modules` vs. `/sys/module` vs. eBPF module loads vs. the on-disk module tree |
//! | [`binaries`] | on-disk digest vs. the package manager's recorded digest |
//!
//! This is deliberately *not* a signature scanner. The one place a name list is
//! used ([`modules::KNOWN_ROOTKIT_MODULES`]) is an escalation hint on top of a
//! finding that already stands on its own.
//!
//! ## False positives are the design constraint
//!
//! A cross-view detector that cries wolf is worse than none, because the whole
//! value is that a hit is worth waking someone for. Three mechanisms keep that
//! true:
//!
//! * **Benign-explanation filters.** Each detector knows the legitimate reasons
//!   its views can disagree — threads are absent from the `/proc` listing,
//!   built-in modules are absent from `/proc/modules` — and excludes them
//!   before reporting rather than by scoring them down afterwards.
//! * **Corroboration.** [`Corroborator`] holds a finding back until the same
//!   disagreement is observed in consecutive sweeps, so the constant churn of
//!   processes and sockets cannot produce a hit on its own.
//! * **Bulk collapse.** A change that touches many objects at once is a package
//!   upgrade, not a rootkit; those are reported once, quietly, instead of as a
//!   storm of critical findings.

pub mod binaries;
pub mod hidden_process;
pub mod hidden_socket;
pub mod kernel_view;
pub mod modules;

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use serde_json::Value;

use crate::schema::{AgentEvent, DetectionData, EventAction, EventClass, EventData, Severity};

/// Detection category shared by every finding this subsystem raises.
pub const CATEGORY: &str = "rootkit";

/// Whether a finding has to survive a second look before it is believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// A standing disagreement between views, e.g. a process that is alive but
    /// unlisted. Held back until it is observed in consecutive sweeps, because
    /// a single sighting is more likely to be a race than a rootkit.
    Corroborate,
    /// A transition observed by comparing two sweeps, e.g. a module that was
    /// loaded and now is not, or a binary whose digest changed. It exists in
    /// exactly one sweep by construction, so waiting for a second sighting
    /// would discard it — and there is no race to filter out, because the
    /// evidence is the difference between two completed reads.
    Immediate,
}

/// One cross-view disagreement, before it is turned into a detection event.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub confirmation: Confirmation,
    pub severity: Severity,
    pub confidence: u8,
    pub mitre_tactic: &'static str,
    pub mitre_technique: &'static str,
    /// What the finding is about: `pid:1234`, `module:diamorphine`, a path, …
    pub subject: String,
    pub detail: String,
    pub evidence: Value,
}

impl Finding {
    /// Identity used to recognise the *same* disagreement across sweeps.
    pub fn key(&self) -> String {
        format!("{}|{}", self.rule_id, self.subject)
    }

    pub fn into_event(self, agent_id: &str, hostname: &str) -> AgentEvent {
        AgentEvent::new(
            agent_id.to_string(),
            hostname.to_string(),
            EventClass::Detection,
            EventAction::Detected,
            self.severity,
            EventData::Detection(DetectionData {
                rule_id: self.rule_id.to_string(),
                title: self.title.to_string(),
                category: CATEGORY.to_string(),
                mitre_tactic: Some(self.mitre_tactic.to_string()),
                mitre_technique: Some(self.mitre_technique.to_string()),
                confidence: self.confidence,
                subject: self.subject,
                detail: self.detail,
                evidence: self.evidence,
            }),
        )
        .with_source("rootkit")
    }
}

/// Holds a finding back until it has been observed in enough consecutive
/// sweeps, and then reports it exactly once.
///
/// Processes and sockets appear and disappear between any two reads, so a
/// single-sweep disagreement is far more likely to be a race than a rootkit.
/// Requiring the same disagreement to survive a second independent look costs
/// one sweep interval of latency and removes that entire class of false
/// positive. A finding that stops being observed is forgotten, so the same
/// object alerting again later is reported again.
#[derive(Debug)]
pub struct Corroborator {
    required: u32,
    streaks: HashMap<String, u32>,
    reported: HashSet<String>,
}

impl Corroborator {
    pub fn new(required: u32) -> Self {
        Self {
            required: required.max(1),
            streaks: HashMap::new(),
            reported: HashSet::new(),
        }
    }

    /// Feed one sweep's findings; returns those that should be reported now.
    ///
    /// [`Confirmation::Immediate`] findings pass straight through.
    /// [`Confirmation::Corroborate`] findings are returned once their streak
    /// reaches the threshold, and not again while they persist.
    pub fn observe(&mut self, findings: Vec<Finding>) -> Vec<Finding> {
        let present: HashSet<String> = findings
            .iter()
            .filter(|f| f.confirmation == Confirmation::Corroborate)
            .map(Finding::key)
            .collect();
        self.streaks.retain(|key, _| present.contains(key));
        self.reported.retain(|key| present.contains(key));

        let mut out = Vec::new();
        for finding in findings {
            if finding.confirmation == Confirmation::Immediate {
                out.push(finding);
                continue;
            }
            let key = finding.key();
            let streak = self.streaks.entry(key.clone()).or_insert(0);
            *streak += 1;
            if *streak >= self.required && self.reported.insert(key) {
                out.push(finding);
            }
        }
        out
    }
}

/// Runtime knobs, read from the environment.
///
/// These are environment variables rather than [`crate::config::AgentConfig`]
/// fields on purpose: the config envelope is signed over its canonical byte
/// sequence, so adding a field changes the bytes the backend must produce and
/// would make every agent reject config from a backend that has not been
/// updated in lockstep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootkitConfig {
    pub enabled: bool,
    /// Interval between cross-view sweeps of processes, sockets and modules.
    pub interval: Duration,
    /// Interval between binary-integrity sweeps, which are much heavier.
    pub integrity_interval: Duration,
    /// Highest PID probed when searching for processes hidden from `/proc`.
    pub pid_scan_max: i32,
    /// Consecutive sweeps a disagreement must survive before it is reported.
    pub corroboration: u32,
}

impl Default for RootkitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(300),
            integrity_interval: Duration::from_secs(3600),
            pid_scan_max: 65_536,
            corroboration: 2,
        }
    }
}

impl RootkitConfig {
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            enabled: !env_disabled("TRAPD_ROOTKIT"),
            interval: env_secs("TRAPD_ROOTKIT_INTERVAL_SECS", defaults.interval, 60),
            integrity_interval: env_secs(
                "TRAPD_ROOTKIT_INTEGRITY_INTERVAL_SECS",
                defaults.integrity_interval,
                300,
            ),
            pid_scan_max: std::env::var("TRAPD_ROOTKIT_PID_SCAN_MAX")
                .ok()
                .and_then(|v| v.trim().parse::<i32>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(defaults.pid_scan_max),
            corroboration: std::env::var("TRAPD_ROOTKIT_CORROBORATION")
                .ok()
                .and_then(|v| v.trim().parse::<u32>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(defaults.corroboration),
        }
    }
}

/// One-shot cross-view sweep rendered for `trapd-agent diagnostics rootkit`.
///
/// Reports the **views themselves**, not only the findings. A detector built on
/// comparing interfaces is worthless if one of the interfaces silently returns
/// nothing — an empty netlink dump because the kernel lacks `sock_diag`, or an
/// empty kernel view because the eBPF programs never loaded — and that failure
/// looks exactly like a clean host from the findings alone. Printing the counts
/// makes the difference visible.
///
/// Read-only: it does not move the baselines a running agent compares against,
/// and findings are shown without corroboration, so a transient race can
/// legitimately appear here and not in the event stream.
pub fn diagnostics() -> String {
    use std::fmt::Write as _;

    let cfg = RootkitConfig::from_env();
    let view = kernel_view::kernel_view();
    let mut out = String::new();

    let _ = writeln!(out, "TRAPD rootkit cross-view sweep\n");
    let _ = writeln!(out, "configuration");
    let _ = writeln!(out, "  enabled                 {}", cfg.enabled);
    let _ = writeln!(out, "  sweep interval          {}s", cfg.interval.as_secs());
    let _ = writeln!(
        out,
        "  integrity interval      {}s",
        cfg.integrity_interval.as_secs()
    );
    let _ = writeln!(out, "  pid scan ceiling        {}", cfg.pid_scan_max);
    let _ = writeln!(out, "  corroborating sweeps    {}\n", cfg.corroboration);

    let sightings = view.processes();
    let comparable = kernel_view::in_initial_pid_namespace();
    let process_views = hidden_process::gather(&cfg, &sightings);
    let hidden = hidden_process::analyze(&process_views, &hidden_process::HostProbe);
    let _ = writeln!(out, "processes");
    let _ = writeln!(
        out,
        "  /proc listing           {}",
        process_views.listed.len()
    );
    let _ = writeln!(
        out,
        "  alive but unlisted      {}",
        process_views.alive.len()
    );
    let _ = writeln!(
        out,
        "  reachable but unlisted  {}",
        process_views.direct.len()
    );
    let _ = writeln!(
        out,
        "  eBPF sightings          {}{}",
        process_views.kernel.len(),
        if comparable {
            ""
        } else {
            " (not comparable: agent is not in the initial PID namespace)"
        }
    );
    let _ = writeln!(out, "  concealed               {}\n", hidden.len());

    let socket_views = hidden_socket::gather(&view.binds());
    let socket_findings = hidden_socket::analyze(&socket_views);
    let _ = writeln!(out, "sockets");
    let _ = writeln!(
        out,
        "  /proc/net               {}",
        socket_views.procfs.len()
    );
    let _ = writeln!(
        out,
        "  sock_diag netlink       {}{}",
        socket_views.netlink.len(),
        if socket_views.netlink.is_empty() {
            " (no netlink answer — the cross-view check cannot run)"
        } else {
            ""
        }
    );
    let _ = writeln!(
        out,
        "  eBPF binds (live pid)   {}",
        socket_views.kernel_binds.len()
    );
    let _ = writeln!(out, "  concealed               {}\n", socket_findings.len());

    let mut history = modules::ModuleHistory::default();
    let (module_views, tree) = modules::gather(&view.modules());
    let module_findings = modules::analyze(&module_views, &mut history);
    let _ = writeln!(out, "kernel modules");
    let _ = writeln!(
        out,
        "  /proc/modules           {}",
        module_views.proc_modules.len()
    );
    let _ = writeln!(
        out,
        "  /sys/module (loadable)  {}",
        module_views.sysfs_loadable.len()
    );
    let _ = writeln!(
        out,
        "  eBPF load sightings     {}",
        module_views.kernel_loaded.len()
    );
    let _ = writeln!(
        out,
        "  module tree files       {}{}",
        tree.len(),
        if module_views.on_disk_readable {
            ""
        } else {
            " (unreadable — provenance check skipped)"
        }
    );
    let _ = writeln!(out, "  findings                {}\n", module_findings.len());

    let (binary_findings, summary) = binaries::observe(crate::paths::state_dir(), false);
    let _ = writeln!(out, "system binaries");
    let _ = writeln!(out, "  watched                 {}", summary.watched);
    let _ = writeln!(
        out,
        "  package database        {}",
        if summary.package_db_available {
            "available (tampering provable)"
        } else {
            "absent (change detectable, tampering not provable)"
        }
    );
    let _ = writeln!(
        out,
        "  digest baseline         {}",
        if summary.baseline_existed {
            "established"
        } else {
            "not yet recorded"
        }
    );
    let _ = writeln!(out, "  findings                {}\n", binary_findings.len());

    let all: Vec<Finding> = hidden_process::findings(&hidden)
        .into_iter()
        .chain(socket_findings)
        .chain(module_findings)
        .chain(binary_findings)
        .collect();

    if all.is_empty() {
        let _ = writeln!(out, "no findings (uncorroborated single sweep)");
        return out;
    }

    let _ = writeln!(out, "findings ({}, uncorroborated single sweep)", all.len());
    for finding in &all {
        let _ = writeln!(
            out,
            "  [{:?}/{:>3}] {} {}\n            {}",
            finding.severity, finding.confidence, finding.rule_id, finding.subject, finding.detail
        );
    }
    out
}

/// Ask the kernel's task table whether a PID exists, without touching procfs.
///
/// `EPERM` also means "it exists" — the caller simply may not signal it. This
/// is the liveness view that survives a rootkit hiding a `/proc` entry.
pub fn task_exists(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 performs the permission and existence checks only; it is
    // never delivered, so it cannot affect the target process.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn env_disabled(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            )
        })
        .unwrap_or(false)
}

fn env_secs(key: &str, fallback: Duration, floor: u64) -> Duration {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|secs| Duration::from_secs(secs.max(floor)))
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule_id: &'static str, subject: &str) -> Finding {
        Finding {
            rule_id,
            title: "t",
            confirmation: Confirmation::Corroborate,
            severity: Severity::High,
            confidence: 80,
            mitre_tactic: "TA0005 Defense Evasion",
            mitre_technique: "T1014",
            subject: subject.to_string(),
            detail: "d".into(),
            evidence: serde_json::json!({}),
        }
    }

    #[test]
    fn a_single_sighting_is_not_reported() {
        let mut c = Corroborator::new(2);
        assert!(c
            .observe(vec![finding("rootkit.hidden_process", "pid:7")])
            .is_empty());
    }

    #[test]
    fn a_repeated_sighting_is_reported_once() {
        let mut c = Corroborator::new(2);
        c.observe(vec![finding("rootkit.hidden_process", "pid:7")]);
        let out = c.observe(vec![finding("rootkit.hidden_process", "pid:7")]);
        assert_eq!(out.len(), 1);
        assert!(
            c.observe(vec![finding("rootkit.hidden_process", "pid:7")])
                .is_empty(),
            "a still-present finding must not re-alert every sweep"
        );
    }

    #[test]
    fn a_transient_disagreement_never_accumulates() {
        // The race case: the same PID flickers in and out across sweeps. Each
        // gap resets the streak, so it never reaches the threshold.
        let mut c = Corroborator::new(2);
        for _ in 0..5 {
            assert!(c
                .observe(vec![finding("rootkit.hidden_process", "pid:7")])
                .is_empty());
            assert!(c.observe(Vec::new()).is_empty());
        }
    }

    #[test]
    fn a_finding_that_clears_and_returns_alerts_again() {
        let mut c = Corroborator::new(1);
        assert_eq!(
            c.observe(vec![finding("rootkit.hidden_process", "pid:7")])
                .len(),
            1
        );
        c.observe(Vec::new());
        assert_eq!(
            c.observe(vec![finding("rootkit.hidden_process", "pid:7")])
                .len(),
            1
        );
    }

    #[test]
    fn findings_are_tracked_per_rule_and_subject() {
        let mut c = Corroborator::new(1);
        let out = c.observe(vec![
            finding("rootkit.hidden_process", "pid:7"),
            finding("rootkit.hidden_process", "pid:8"),
            finding("rootkit.hidden_socket", "pid:7"),
        ]);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn a_transition_finding_is_reported_on_its_only_sighting() {
        // A module unload or a changed digest exists in exactly one sweep;
        // corroboration would discard it entirely.
        let mut c = Corroborator::new(2);
        let mut f = finding("rootkit.module_unloaded", "module:dummy");
        f.confirmation = Confirmation::Immediate;
        assert_eq!(c.observe(vec![f]).len(), 1);
    }

    #[test]
    fn transition_findings_do_not_disturb_a_running_streak() {
        let mut c = Corroborator::new(2);
        let state = finding("rootkit.hidden_process", "pid:7");
        let mut transition = finding("rootkit.module_unloaded", "module:dummy");
        transition.confirmation = Confirmation::Immediate;

        assert_eq!(c.observe(vec![state.clone(), transition]).len(), 1);
        let out = c.observe(vec![state]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, "rootkit.hidden_process");
    }

    #[test]
    fn intervals_are_floored_so_a_sweep_cannot_be_made_continuous() {
        std::env::set_var("TRAPD_ROOTKIT_INTERVAL_SECS", "1");
        assert_eq!(RootkitConfig::from_env().interval, Duration::from_secs(60));
        std::env::remove_var("TRAPD_ROOTKIT_INTERVAL_SECS");
    }
}
