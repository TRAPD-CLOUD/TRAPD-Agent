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

pub struct ProcessCollector {
    initialized:   bool,
    known_pids:    HashSet<i32>,
    known_names:   HashMap<i32, String>,
    uid_to_user:   HashMap<u32, String>,
    /// Baseline of every SUID binary present on the host at agent start.  An
    /// exec of a SUID binary *not* in this set is suspicious (MITRE T1548.001).
    suid_baseline: HashSet<PathBuf>,
}

impl ProcessCollector {
    pub fn new() -> Self {
        let suid_baseline = scan_suid_baseline();
        info!("ProcessCollector: SUID baseline ready — {} binaries", suid_baseline.len());
        Self {
            initialized:   false,
            known_pids:    HashSet::new(),
            known_names:   HashMap::new(),
            uid_to_user:   load_passwd().unwrap_or_default(),
            suid_baseline,
        }
    }
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
        let region     = match fields.next() { Some(r) => r, None => continue };
        let perms      = match fields.next() { Some(p) => p, None => continue };
        let _offset    = fields.next();
        let _dev       = fields.next();
        let inode_str  = match fields.next() { Some(i) => i, None => continue };
        let pathname   = fields.next();

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

        let exe = proc
            .exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        let cmdline = proc
            .cmdline()
            .map(|args| args.join(" "))
            .unwrap_or_default();

        let uid = status.ruid;
        let username = uid_map.get(&uid).cloned().unwrap_or_default();

        let data = ProcessCreateData {
            pid:     stat.pid,
            ppid:    stat.ppid,
            name:    stat.comm.clone(),
            exe,
            cmdline,
            uid,
            username,
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
        tx:       Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let mut ticker = interval(Duration::from_secs(3));

        loop {
            ticker.tick().await;

            let current = collect_processes(&self.uid_to_user);

            if !self.initialized {
                for (pid, info) in &current {
                    self.known_pids.insert(*pid);
                    self.known_names.insert(*pid, info.name.clone());
                }
                self.initialized = true;
                continue;
            }

            let current_pids: HashSet<i32> = current.keys().copied().collect();

            // New processes
            for pid in current_pids.difference(&self.known_pids).copied().collect::<Vec<_>>() {
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
                    self.known_names.insert(pid, info.name.clone());

                    // Check for rwx anonymous memory mappings (fileless shellcode indicator).
                    for (region, perms) in check_rwx_maps(pid) {
                        let anomaly = AgentEvent::new(
                            agent_id.clone(),
                            hostname.clone(),
                            EventClass::Memory,
                            EventAction::MemoryAnomaly,
                            Severity::High,
                            EventData::MemoryAnomaly(MemoryAnomalyData {
                                pid,
                                region,
                                perms,
                            }),
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
            for pid in self.known_pids.difference(&current_pids).copied().collect::<Vec<_>>() {
                let name = self.known_names.remove(&pid).unwrap_or_default();
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

            self.known_pids = current_pids;
        }
    }
}
