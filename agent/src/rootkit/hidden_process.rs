//! Processes that exist but do not appear where they should.
//!
//! Three independent answers to "which processes are running?" are collected
//! and compared:
//!
//! 1. **The `/proc` listing** — what `ps` and every other tool sees. A rootkit
//!    that hooks `getdents` on `/proc` removes entries here.
//! 2. **Direct `/proc/<pid>` access** — reading a specific entry never goes
//!    through the directory listing, so a process hidden only from `readdir`
//!    is still reachable by name.
//! 3. **Signal liveness** — `kill(pid, 0)` asks the kernel's task table
//!    directly and does not involve procfs at all, so it still answers for a
//!    process whose `/proc` entry has been removed entirely.
//!
//! A fourth view, the eBPF-observed PIDs in [`super::kernel_view`], cannot
//! prove concealment on its own (a process it saw has usually just exited) but
//! raises confidence when it corroborates one of the checks above.
//!
//! ## Why the obvious version of this check is wrong
//!
//! "In `/proc/<pid>` but not in the `/proc` listing" describes every thread on
//! the system: only thread-group leaders get a directory entry, while every
//! individual thread remains directly reachable at `/proc/<tid>`. A detector
//! that skips the `Tgid` check reports hundreds of hidden processes on an idle
//! host. That check, and re-reading the listing to absorb processes that start
//! mid-sweep, are what make the signal usable.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use super::kernel_view::ProcessSighting;
use super::{Confirmation, Finding, RootkitConfig};
use crate::schema::Severity;

/// The independent answers, reduced to PID sets.
#[derive(Debug, Default, Clone)]
pub struct ProcessViews {
    /// PIDs present in the `/proc` directory listing.
    pub listed: BTreeSet<i32>,
    /// Unlisted PIDs that the kernel confirms are alive via `kill(pid, 0)`.
    pub alive: BTreeSet<i32>,
    /// Of [`Self::alive`], those whose `/proc/<pid>` entry can still be read.
    pub direct: BTreeSet<i32>,
    /// PIDs the eBPF collectors observed recently, with the command name the
    /// kernel reported. Empty when the views are not comparable.
    pub kernel: BTreeMap<i32, String>,
}

/// How a process is concealed, which decides how damning the finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Concealment {
    /// Reachable at `/proc/<pid>`, missing from the `/proc` listing — the
    /// signature of a hooked directory read.
    AbsentFromListing,
    /// Alive per the kernel's task table, with no `/proc` entry at all.
    AbsentFromProcfs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenProcess {
    pub pid: i32,
    pub concealment: Concealment,
    pub kernel_observed: bool,
    pub comm: Option<String>,
}

/// The `/proc` reads the analysis needs, behind a trait so the decision logic
/// can be tested without a host that actually has a rootkit on it.
pub trait ProcProbe {
    /// Thread-group id from `/proc/<pid>/status`; `None` when unreadable.
    fn tgid(&self, pid: i32) -> Option<i32>;
    fn comm(&self, pid: i32) -> Option<String>;
}

/// Compare the views and return the processes that only one of them can see.
pub fn analyze<P: ProcProbe>(views: &ProcessViews, probe: &P) -> Vec<HiddenProcess> {
    let mut out = Vec::new();

    for &pid in &views.direct {
        if views.listed.contains(&pid) {
            continue;
        }
        // A thread is reachable at /proc/<tid> and legitimately absent from the
        // listing. Only its thread-group leader is ever listed.
        match probe.tgid(pid) {
            Some(tgid) if tgid != pid => continue,
            // Unreadable status: the entry vanished between the two reads.
            None => continue,
            Some(_) => {}
        }
        out.push(HiddenProcess {
            pid,
            concealment: Concealment::AbsentFromListing,
            kernel_observed: views.kernel.contains_key(&pid),
            comm: probe.comm(pid).or_else(|| views.kernel.get(&pid).cloned()),
        });
    }

    for &pid in &views.alive {
        if views.listed.contains(&pid) || views.direct.contains(&pid) {
            continue;
        }
        // With no /proc entry the eBPF sighting is the only place a name for
        // this process can come from, which is exactly when it matters most.
        out.push(HiddenProcess {
            pid,
            concealment: Concealment::AbsentFromProcfs,
            kernel_observed: views.kernel.contains_key(&pid),
            comm: views.kernel.get(&pid).cloned(),
        });
    }

    out.sort_by_key(|h| h.pid);
    out
}

/// Turn concealed processes into findings.
pub fn findings(hidden: &[HiddenProcess]) -> Vec<Finding> {
    hidden.iter().map(finding_for).collect()
}

fn finding_for(hidden: &HiddenProcess) -> Finding {
    let (rule_id, title, detail, base_confidence) = match hidden.concealment {
        Concealment::AbsentFromListing => (
            "rootkit.process_hidden_from_listing",
            "Process reachable in /proc but missing from the /proc listing",
            format!(
                "PID {} can be read at /proc/{} and is not a thread of another process, \
                 but does not appear in the /proc directory listing. Directory reads on \
                 /proc are being filtered, which is how a rootkit hides a process from ps.",
                hidden.pid, hidden.pid
            ),
            80,
        ),
        Concealment::AbsentFromProcfs => (
            "rootkit.process_hidden_from_procfs",
            "Process alive in the kernel task table with no /proc entry",
            format!(
                "The kernel accepts signals for PID {}, so the task exists, yet it has no \
                 /proc entry at all. procfs is not reporting a running process.",
                hidden.pid
            ),
            85,
        ),
    };

    let confidence = if hidden.kernel_observed {
        (base_confidence + 10).min(99)
    } else {
        base_confidence
    };

    Finding {
        rule_id,
        title,
        confirmation: Confirmation::Corroborate,
        severity: Severity::Critical,
        confidence,
        mitre_tactic: "TA0005 Defense Evasion",
        mitre_technique: "T1014",
        subject: format!("pid:{}", hidden.pid),
        detail,
        evidence: json!({
            "pid": hidden.pid,
            "comm": hidden.comm,
            "concealment": match hidden.concealment {
                Concealment::AbsentFromListing => "absent_from_listing",
                Concealment::AbsentFromProcfs => "absent_from_procfs",
            },
            "views": {
                "proc_listing": false,
                "proc_direct": hidden.concealment == Concealment::AbsentFromListing,
                "signal_liveness": true,
                "ebpf": hidden.kernel_observed,
            },
        }),
    }
}

// ── Host collection ─────────────────────────────────────────────────────────

/// Read the three views from this host.
///
/// The `/proc` listing is read **twice**, before and after probing, and the
/// union is used. A process that starts mid-sweep is otherwise absent from the
/// listing taken before it existed while being fully alive during the probe —
/// indistinguishable from a hidden process, and common enough on a busy host to
/// swamp the signal.
pub fn gather(cfg: &RootkitConfig, kernel: &[(i32, ProcessSighting)]) -> ProcessViews {
    let listed_before = list_proc();
    let kernel_pids: BTreeMap<i32, String> = if super::kernel_view::in_initial_pid_namespace() {
        kernel
            .iter()
            .map(|(pid, sighting)| (*pid, sighting.comm.clone()))
            .collect()
    } else {
        BTreeMap::new()
    };

    let mut alive = BTreeSet::new();
    let mut direct = BTreeSet::new();

    let candidates = (1..=cfg.pid_scan_max).chain(kernel_pids.keys().copied());
    let mut probed = BTreeSet::new();
    for pid in candidates {
        if pid <= 0 || listed_before.contains(&pid) || !probed.insert(pid) {
            continue;
        }
        if !super::task_exists(pid) {
            continue;
        }
        alive.insert(pid);
        if std::path::Path::new(&format!("/proc/{pid}/stat")).exists() {
            direct.insert(pid);
        }
    }

    let mut listed = listed_before;
    listed.extend(list_proc());

    ProcessViews {
        listed,
        alive,
        direct,
        kernel: kernel_pids,
    }
}

fn list_proc() -> BTreeSet<i32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return BTreeSet::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<i32>().ok())
        .collect()
}

/// Reads the real `/proc`.
pub struct HostProbe;

impl ProcProbe for HostProbe {
    fn tgid(&self, pid: i32) -> Option<i32> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        status
            .lines()
            .find_map(|l| l.strip_prefix("Tgid:"))
            .and_then(|v| v.trim().parse().ok())
    }

    fn comm(&self, pid: i32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakeProbe {
        tgids: HashMap<i32, i32>,
        comms: HashMap<i32, String>,
    }

    impl ProcProbe for FakeProbe {
        fn tgid(&self, pid: i32) -> Option<i32> {
            self.tgids.get(&pid).copied()
        }
        fn comm(&self, pid: i32) -> Option<String> {
            self.comms.get(&pid).cloned()
        }
    }

    fn views(listed: &[i32], alive: &[i32], direct: &[i32], kernel: &[i32]) -> ProcessViews {
        ProcessViews {
            listed: listed.iter().copied().collect(),
            alive: alive.iter().copied().collect(),
            direct: direct.iter().copied().collect(),
            kernel: kernel
                .iter()
                .map(|pid| (*pid, format!("observed-{pid}")))
                .collect(),
        }
    }

    #[test]
    fn a_process_missing_only_from_the_listing_is_hidden() {
        let mut probe = FakeProbe::default();
        probe.tgids.insert(4242, 4242);
        probe.comms.insert(4242, "sshd".into());

        let found = analyze(&views(&[1, 2], &[4242], &[4242], &[]), &probe);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].pid, 4242);
        assert_eq!(found[0].concealment, Concealment::AbsentFromListing);
        assert_eq!(found[0].comm.as_deref(), Some("sshd"));
    }

    #[test]
    fn threads_are_not_hidden_processes() {
        // The single most important exclusion: every non-leader thread is
        // reachable at /proc/<tid> and absent from the listing by design.
        let mut probe = FakeProbe::default();
        probe.tgids.insert(4243, 4242);

        assert!(analyze(&views(&[4242], &[4243], &[4243], &[]), &probe).is_empty());
    }

    #[test]
    fn a_process_with_no_proc_entry_at_all_is_hidden() {
        let found = analyze(&views(&[1], &[9001], &[], &[]), &FakeProbe::default());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].concealment, Concealment::AbsentFromProcfs);
    }

    #[test]
    fn a_process_with_no_proc_entry_is_still_named_from_the_kernel_view() {
        // /proc cannot name it, so the eBPF sighting is the only source left.
        let found = analyze(&views(&[1], &[9001], &[], &[9001]), &FakeProbe::default());
        assert_eq!(found[0].comm.as_deref(), Some("observed-9001"));
    }

    #[test]
    fn a_pid_that_reappears_in_the_listing_is_not_reported() {
        // The mid-sweep start case, absorbed by unioning both listings.
        let mut probe = FakeProbe::default();
        probe.tgids.insert(500, 500);
        assert!(analyze(&views(&[500], &[500], &[500], &[]), &probe).is_empty());
    }

    #[test]
    fn a_vanished_pid_is_not_reported_as_hidden() {
        // Exited between the liveness probe and the status read: tgid unreadable.
        assert!(analyze(&views(&[1], &[777], &[777], &[]), &FakeProbe::default()).is_empty());
    }

    #[test]
    fn ebpf_corroboration_raises_confidence_but_is_not_required() {
        let mut probe = FakeProbe::default();
        probe.tgids.insert(10, 10);
        probe.tgids.insert(11, 11);

        let plain = findings(&analyze(&views(&[], &[10], &[10], &[]), &probe));
        let corroborated = findings(&analyze(&views(&[], &[11], &[11], &[11]), &probe));

        assert_eq!(plain.len(), 1);
        assert_eq!(corroborated.len(), 1);
        assert!(corroborated[0].confidence > plain[0].confidence);
    }

    #[test]
    fn findings_are_critical_and_mapped_to_the_rootkit_technique() {
        let found = analyze(&views(&[], &[9001], &[], &[]), &FakeProbe::default());
        let f = &findings(&found)[0];
        assert!(matches!(f.severity, Severity::Critical));
        assert_eq!(f.mitre_technique, "T1014");
        assert_eq!(f.subject, "pid:9001");
    }

    #[test]
    fn a_quiet_host_produces_nothing() {
        let mut probe = FakeProbe::default();
        probe.tgids.insert(1, 1);
        assert!(analyze(&views(&[1, 2, 3], &[], &[], &[]), &probe).is_empty());
    }
}
