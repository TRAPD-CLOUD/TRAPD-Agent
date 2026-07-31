use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::{info, warn};
use walkdir::WalkDir;

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, DetectionData, EventAction, EventClass, EventData, MemoryAnomalyData,
    ProcessCreateData, ProcessTerminateData, Severity,
};
use crate::telemetry::limits::{truncate_str, MAX_CMDLINE_BYTES};
use crate::telemetry::metrics::{metrics, CollectorMode};
use crate::telemetry::{Enrichment, EnrichmentError};

/// What the collector remembers about a process between polls.
///
/// The start time is carried alongside the name because a PID on its own cannot
/// answer "is this still the same process?" — see [`diff_processes`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct KnownProcess {
    name: String,
    start_time: Option<u64>,
}

/// What changed between two polls.
#[derive(Debug, Default, PartialEq, Eq)]
struct ProcessDiff {
    /// PIDs newly observed, including PIDs that were recycled onto a new
    /// process since the previous poll.
    created: Vec<i32>,
    /// `(pid, name)` of processes that are gone, including the previous
    /// occupant of a recycled PID.
    terminated: Vec<(i32, String)>,
}

pub struct ProcessCollector {
    initialized: bool,
    known: HashMap<i32, KnownProcess>,
    uid_to_user: HashMap<u32, String>,
    /// Baseline of every SUID binary present on the host at agent start.  An
    /// exec of a SUID binary *not* in this set is suspicious (MITRE T1548.001).
    suid_baseline: HashSet<PathBuf>,
}

impl ProcessCollector {
    pub fn new() -> Self {
        let suid_baseline = scan_suid_baseline();
        info!(
            "ProcessCollector: SUID baseline ready — {} binaries",
            suid_baseline.len()
        );
        Self {
            initialized: false,
            known: HashMap::new(),
            uid_to_user: load_passwd().unwrap_or_default(),
            suid_baseline,
        }
    }
}

/// Compare two polls and report what was created and what ended.
///
/// A poll interval is long enough for a PID to be freed and handed to a new
/// process, and the kernel recycles PIDs aggressively on a busy host. Comparing
/// PID sets alone would then see the PID in *both* polls and emit neither a
/// terminate for the process that ended nor a create for the one that started —
/// two events lost with nothing to indicate anything was missed. That silent
/// hole is exactly what the start-time comparison closes: a PID present in both
/// polls with a *different* start time is reported as a termination followed by
/// a creation.
///
/// Reuse must be *proven*, not assumed: when either start time is unknown the
/// PID is treated as the same process, because inventing a spurious
/// terminate/create pair on every unreadable `/proc` entry would be its own
/// kind of false telemetry.
fn diff_processes(
    known: &HashMap<i32, KnownProcess>,
    current: &HashMap<i32, ProcessCreateData>,
) -> ProcessDiff {
    let mut diff = ProcessDiff::default();

    for (pid, info) in current {
        match known.get(pid) {
            None => diff.created.push(*pid),
            Some(prev) => {
                let before = crate::telemetry::ProcessKey::new(*pid, prev.start_time);
                let now = crate::telemetry::ProcessKey::new(*pid, info.process_start_time);
                if before.provably_different_from(&now) {
                    // The PID was recycled: report both halves.
                    diff.terminated.push((*pid, prev.name.clone()));
                    diff.created.push(*pid);
                }
            }
        }
    }

    for (pid, prev) in known {
        if !current.contains_key(pid) {
            diff.terminated.push((*pid, prev.name.clone()));
        }
    }

    // Deterministic order keeps the emitted event stream reproducible, which
    // matters for both tests and for reading a live event log.
    diff.created.sort_unstable();
    diff.terminated.sort_unstable();
    diff
}

/// `PF_KTHREAD` — the kernel's own flag marking a task as a kernel thread.
///
/// Using the flag rather than heuristics like "ppid == 2" is what makes this
/// reliable: a userspace process can be reparented, but only the kernel sets
/// this bit.
const PF_KTHREAD: u32 = 0x0020_0000;

/// Whether this task is a kernel thread, and therefore legitimately has no
/// executable image and no command line.
fn is_kernel_thread(stat: &procfs::process::Stat) -> bool {
    stat.flags & PF_KTHREAD != 0
}

/// True if `path` currently has its SUID bit set.  `stat()`s the binary.
fn is_suid_path(path: &Path) -> bool {
    fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o4000 != 0)
        .unwrap_or(false)
}

/// One-time scan of all SUID binaries on the host — the userspace equivalent of
/// `find / -xdev -perm -4000 -type f`.  Stays on the root filesystem (so the
/// `/proc`, `/sys` and `/dev` pseudo-mounts are skipped) and never follows
/// symlinks.  Errors on individual entries are ignored — a best-effort baseline.
fn scan_suid_baseline() -> HashSet<PathBuf> {
    let mut set = HashSet::new();
    for entry in WalkDir::new("/")
        .same_file_system(true)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if meta.permissions().mode() & 0o4000 != 0 {
                set.insert(entry.path().to_path_buf());
            }
        }
    }
    set
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn load_passwd() -> Result<HashMap<u32, String>> {
    let content = fs::read_to_string("/etc/passwd")?;
    let mut map = HashMap::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(7, ':').collect();
        if parts.len() >= 4 {
            if let Ok(uid) = parts[2].parse::<u32>() {
                map.insert(uid, parts[0].to_string());
            }
        }
    }
    Ok(map)
}

/// Parse /proc/{pid}/maps and return (region, perms) pairs for rwx anonymous mappings.
fn check_rwx_maps(pid: i32) -> Vec<(String, String)> {
    let content = match fs::read_to_string(format!("/proc/{pid}/maps")) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut results = Vec::new();
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let region = match fields.next() {
            Some(r) => r,
            None => continue,
        };
        let perms = match fields.next() {
            Some(p) => p,
            None => continue,
        };
        let _offset = fields.next();
        let _dev = fields.next();
        let inode_str = match fields.next() {
            Some(i) => i,
            None => continue,
        };
        let pathname = fields.next();

        let inode: u64 = inode_str.parse().unwrap_or(1);
        let is_rwx = perms.contains('r') && perms.contains('w') && perms.contains('x');
        let is_anon = inode == 0 && pathname.is_none();

        if is_rwx && is_anon {
            results.push((region.to_string(), perms.to_string()));
        }
    }
    results
}

fn collect_processes(uid_map: &HashMap<u32, String>) -> HashMap<i32, ProcessCreateData> {
    let mut out = HashMap::new();

    let all = match procfs::process::all_processes() {
        Ok(iter) => iter,
        Err(e) => {
            warn!("Failed to list processes: {e}");
            return out;
        }
    };

    for proc_result in all {
        let proc = match proc_result {
            Ok(p) => p,
            Err(_) => continue,
        };

        let stat = match proc.stat() {
            Ok(s) => s,
            Err(_) => continue,
        };

        let status = match proc.status() {
            Ok(s) => s,
            Err(_) => continue,
        };

        // A process can exit between the directory scan and these reads, so
        // each field is recorded as resolved-or-explained rather than being
        // flattened to an empty string that reads like "no command line".
        //
        // Kernel threads are the exception: they have no executable image and
        // no argv *by construction*, so reporting a failure for each would
        // brand a few hundred perfectly normal tasks as enrichment failures on
        // every poll and pin agent health at "degraded" forever.
        let kthread = is_kernel_thread(&stat);
        let mut notes = Enrichment::new();

        let exe = match proc.exe() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(_) => {
                if !kthread {
                    notes.fail("exe", EnrichmentError::ProcessExited);
                }
                String::new()
            }
        };

        let cmdline = match proc.cmdline() {
            Ok(args) => {
                let (value, truncation) = truncate_str(&args.join(" "), MAX_CMDLINE_BYTES);
                notes.truncated("cmdline", truncation);
                value
            }
            Err(_) => {
                if !kthread {
                    notes.fail("cmdline", EnrichmentError::ProcessExited);
                }
                String::new()
            }
        };

        let uid = status.ruid;
        let username = uid_map.get(&uid).cloned().unwrap_or_default();
        let exe_sha256 = super::exehash::hash_executable(&exe);

        let data = ProcessCreateData {
            pid: stat.pid,
            ppid: stat.ppid,
            name: stat.comm.clone(),
            exe,
            cmdline,
            uid,
            username,
            exe_sha256,
            // `stat.starttime` is field 22 straight from the kernel — the same
            // value that makes this process distinguishable from a later one
            // reusing its PID.
            process_start_time: Some(stat.starttime),
            enrichment: notes.finish(if kthread { 0 } else { 2 }),
        };
        out.insert(stat.pid, data);
    }
    out
}

#[async_trait]
impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "ProcessCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let mut ticker = interval(Duration::from_secs(3));
        metrics().add_collector_mode(CollectorMode::ProcPolling);

        loop {
            ticker.tick().await;

            let current = collect_processes(&self.uid_to_user);

            if !self.initialized {
                self.known = snapshot_known(&current);
                self.initialized = true;
                continue;
            }

            let diff = diff_processes(&self.known, &current);

            // New processes
            for pid in diff.created {
                if let Some(info) = current.get(&pid) {
                    let event = AgentEvent::new(
                        agent_id.clone(),
                        hostname.clone(),
                        EventClass::Process,
                        EventAction::Create,
                        Severity::Info,
                        EventData::ProcessCreate(info.clone()),
                    );
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }

                    // Check for rwx anonymous memory mappings (fileless shellcode indicator).
                    for (region, perms) in check_rwx_maps(pid) {
                        let anomaly = AgentEvent::new(
                            agent_id.clone(),
                            hostname.clone(),
                            EventClass::Memory,
                            EventAction::MemoryAnomaly,
                            Severity::High,
                            EventData::MemoryAnomaly(MemoryAnomalyData { pid, region, perms }),
                        );
                        if tx.send(anomaly).await.is_err() {
                            return Ok(());
                        }
                    }

                    // ── SUID-binary tracking (MITRE T1548.001) ──────────────
                    // Flag execution of a SUID binary that was not present in
                    // the startup baseline (e.g. a freshly-planted setuid root
                    // backdoor used for privilege escalation).
                    if !info.exe.is_empty() {
                        let exe_path = PathBuf::from(&info.exe);
                        if is_suid_path(&exe_path) && !self.suid_baseline.contains(&exe_path) {
                            let det = AgentEvent::new(
                                agent_id.clone(),
                                hostname.clone(),
                                EventClass::Detection,
                                EventAction::Detected,
                                Severity::High,
                                EventData::Detection(DetectionData {
                                    rule_id: "privesc.untracked_suid_exec".into(),
                                    title: "Execution of a SUID binary not in the startup baseline".into(),
                                    category: "privilege_escalation".into(),
                                    mitre_tactic: Some("TA0004 Privilege Escalation".into()),
                                    mitre_technique: Some("T1548.001".into()),
                                    confidence: 75,
                                    subject: info.exe.clone(),
                                    detail: format!(
                                        "Process {} (pid {}) executed SUID binary {} which is not in the baseline",
                                        info.name, info.pid, info.exe,
                                    ),
                                    evidence: serde_json::json!({
                                        "exe": info.exe,
                                        "pid": info.pid,
                                        "uid": info.uid,
                                        "comm": info.name,
                                    }),
                                }),
                            );
                            if tx.send(det).await.is_err() {
                                return Ok(());
                            }
                        }
                    }
                }
            }

            // Terminated processes
            for (pid, name) in diff.terminated {
                let event = AgentEvent::new(
                    agent_id.clone(),
                    hostname.clone(),
                    EventClass::Process,
                    EventAction::Terminate,
                    Severity::Info,
                    EventData::ProcessTerminate(ProcessTerminateData { pid, name }),
                );
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }

            self.known = snapshot_known(&current);
        }
    }
}

/// Reduce a poll to the state needed to diff against the next one.
fn snapshot_known(current: &HashMap<i32, ProcessCreateData>) -> HashMap<i32, KnownProcess> {
    current
        .iter()
        .map(|(pid, info)| {
            (
                *pid,
                KnownProcess {
                    name: info.name.clone(),
                    start_time: info.process_start_time,
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(pid: i32, name: &str, start_time: Option<u64>) -> (i32, KnownProcess) {
        (
            pid,
            KnownProcess {
                name: name.to_string(),
                start_time,
            },
        )
    }

    fn seen(pid: i32, name: &str, start_time: Option<u64>) -> (i32, ProcessCreateData) {
        (
            pid,
            ProcessCreateData {
                pid,
                name: name.to_string(),
                process_start_time: start_time,
                ..Default::default()
            },
        )
    }

    #[test]
    fn an_unchanged_process_produces_no_events() {
        let before = HashMap::from([known(100, "bash", Some(5))]);
        let after = HashMap::from([seen(100, "bash", Some(5))]);
        assert_eq!(diff_processes(&before, &after), ProcessDiff::default());
    }

    #[test]
    fn a_new_pid_is_a_creation() {
        let before = HashMap::new();
        let after = HashMap::from([seen(100, "bash", Some(5))]);
        let diff = diff_processes(&before, &after);
        assert_eq!(diff.created, vec![100]);
        assert!(diff.terminated.is_empty());
    }

    #[test]
    fn a_vanished_pid_is_a_termination() {
        let before = HashMap::from([known(100, "bash", Some(5))]);
        let after = HashMap::new();
        let diff = diff_processes(&before, &after);
        assert!(diff.created.is_empty());
        assert_eq!(diff.terminated, vec![(100, "bash".to_string())]);
    }

    #[test]
    fn a_recycled_pid_yields_both_a_termination_and_a_creation() {
        // The bug this exists to prevent: comparing PID sets alone sees 100 in
        // both polls and emits nothing, losing two events with no trace.
        let before = HashMap::from([known(100, "bash", Some(5))]);
        let after = HashMap::from([seen(100, "nc", Some(9_999))]);

        let diff = diff_processes(&before, &after);
        assert_eq!(
            diff.created,
            vec![100],
            "the process that took over the PID must be reported"
        );
        assert_eq!(
            diff.terminated,
            vec![(100, "bash".to_string())],
            "and so must the one that gave it up, under its own name"
        );
    }

    #[test]
    fn an_unknown_start_time_does_not_invent_a_reuse() {
        // Guessing here would emit a spurious terminate/create pair on every
        // poll for any process whose /proc entry could not be read.
        for (before_st, after_st) in [(None, Some(5)), (Some(5), None), (None, None)] {
            let before = HashMap::from([known(100, "bash", before_st)]);
            let after = HashMap::from([seen(100, "bash", after_st)]);
            assert_eq!(
                diff_processes(&before, &after),
                ProcessDiff::default(),
                "unproven reuse ({before_st:?} -> {after_st:?}) must produce no events"
            );
        }
    }

    #[test]
    fn a_renamed_process_keeping_its_start_time_is_not_a_reuse() {
        // A process can rename itself via prctl; that is not a new process.
        let before = HashMap::from([known(100, "bash", Some(5))]);
        let after = HashMap::from([seen(100, "definitely-not-bash", Some(5))]);
        assert_eq!(diff_processes(&before, &after), ProcessDiff::default());
    }

    #[test]
    fn a_termination_reports_the_previous_occupants_name() {
        // Reporting the *new* occupant's name for the terminated process would
        // attribute the exit to the wrong binary.
        let before = HashMap::from([known(100, "sshd", Some(1))]);
        let after = HashMap::from([seen(100, "cryptominer", Some(2))]);
        let diff = diff_processes(&before, &after);
        assert_eq!(diff.terminated, vec![(100, "sshd".to_string())]);
    }

    #[test]
    fn multiple_changes_are_all_reported_in_a_stable_order() {
        let before = HashMap::from([
            known(1, "init", Some(1)),
            known(2, "gone", Some(2)),
            known(3, "recycled", Some(3)),
        ]);
        let after = HashMap::from([
            seen(1, "init", Some(1)),   // unchanged
            seen(3, "newthing", Some(30)), // recycled
            seen(4, "fresh", Some(40)), // new
        ]);

        let diff = diff_processes(&before, &after);
        assert_eq!(diff.created, vec![3, 4]);
        assert_eq!(
            diff.terminated,
            vec![(2, "gone".to_string()), (3, "recycled".to_string())]
        );
    }

    #[test]
    fn snapshot_carries_the_start_time_forward() {
        // If the snapshot dropped the start time, reuse detection would work
        // once and then silently stop.
        let current = HashMap::from([seen(7, "bash", Some(42))]);
        let snap = snapshot_known(&current);
        assert_eq!(snap[&7].start_time, Some(42));
        assert_eq!(snap[&7].name, "bash");
    }

    #[test]
    fn an_empty_poll_terminates_everything_known() {
        let before = HashMap::from([known(1, "a", Some(1)), known(2, "b", Some(2))]);
        let diff = diff_processes(&before, &HashMap::new());
        assert_eq!(diff.terminated.len(), 2);
        assert!(diff.created.is_empty());
    }
}
