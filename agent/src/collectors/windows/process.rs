//! Windows process telemetry: poll-based create/terminate events via `sysinfo`.
//!
//! The Windows counterpart of the Linux polling [`ProcessCollector`]
//! (`collectors/linux/process.rs`): every few seconds the process table is
//! diffed against the previous snapshot; new PIDs become
//! `EventClass::Process` / `EventAction::Create` events and vanished PIDs
//! become `Terminate` events — the exact same OS-neutral schema the Linux
//! agent emits, so the shared detection engine (Sigma rules, IOC hash/path
//! matching, behavioural analytics) inspects Windows processes unchanged.
//!
//! The executable image is SHA256-hashed at collection time (size-capped,
//! cached per path+mtime) to anchor IOC and reputation matching. Polling can
//! miss processes shorter than one interval — the same known trade-off as the
//! Linux fallback path without eBPF; an ETW-based collector can replace this
//! later without touching the schema.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Result;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sysinfo::{Pid, ProcessRefreshKind, System, UpdateKind};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::info;

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, ProcessCreateData, ProcessTerminateData,
    Severity,
};
use crate::telemetry::limits::{truncate_str, MAX_CMDLINE_BYTES};
use crate::telemetry::{Enrichment, EnrichmentError};

/// Poll cadence — matches the Linux polling collector.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Images larger than this are not hashed (hashing a multi-GB installer on
/// every spawn would stall the collector); the event simply omits the digest.
const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;

/// Upper bound on the exe-hash cache before it is reset (paths churn slowly,
/// so this is rarely hit; the bound only guards against pathological hosts).
const MAX_HASH_CACHE: usize = 4096;

fn refresh_kind() -> ProcessRefreshKind {
    // sysinfo's default refresh omits command lines and account identities.
    // Fetch them explicitly so detection receives the same process context
    // as the Linux collector; immutable fields only need loading once.
    ProcessRefreshKind::new()
        .with_cmd(UpdateKind::OnlyIfNotSet)
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_user(UpdateKind::OnlyIfNotSet)
}

pub struct ProcessCollector {
    sys: System,
    initialized: bool,
    /// pid → name of every process seen in the previous poll.
    known: HashMap<i32, (String, Option<u64>)>,
    /// exe path → (len, mtime, sha256) so an unchanged image is hashed once.
    hash_cache: HashMap<PathBuf, (u64, Option<SystemTime>, String)>,
}

impl ProcessCollector {
    pub fn new() -> Self {
        Self {
            sys: System::new(),
            initialized: false,
            known: HashMap::new(),
            hash_cache: HashMap::new(),
        }
    }

    /// SHA256 of the executable image, size-capped and cached per path+mtime.
    fn exe_sha256(&mut self, path: &Path) -> Option<String> {
        if path.as_os_str().is_empty() {
            return None;
        }
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() || meta.len() > MAX_HASH_BYTES {
            return None;
        }
        let key = (meta.len(), meta.modified().ok());
        if let Some((len, mtime, hash)) = self.hash_cache.get(path) {
            if (*len, *mtime) == key {
                return Some(hash.clone());
            }
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .ok()?
            .take(MAX_HASH_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > MAX_HASH_BYTES {
            return None;
        }
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if self.hash_cache.len() >= MAX_HASH_CACHE {
            self.hash_cache.clear();
        }
        self.hash_cache
            .insert(path.to_path_buf(), (key.0, key.1, digest.clone()));
        Some(digest)
    }

    fn username_of(&self, pid: Pid) -> String {
        crate::telemetry::identity::windows_process_account(pid.as_u32() as i32)
            .unwrap_or_else(|| "unknown".into())
    }
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "WindowsProcessCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let mut ticker = interval(POLL_INTERVAL);
        info!("WindowsProcessCollector: polling process table every 3s");
        crate::telemetry::metrics::metrics()
            .set_collector_mode(crate::telemetry::metrics::CollectorMode::WindowsPolling);

        loop {
            ticker.tick().await;
            self.sys.refresh_processes_specifics(refresh_kind());

            let current: HashMap<i32, (String, Option<u64>)> = self
                .sys
                .processes()
                .iter()
                .map(|(pid, p)| {
                    let pid = pid.as_u32() as i32;
                    (
                        pid,
                        (
                            p.name().to_string(),
                            crate::telemetry::identity::process_start_time(pid),
                        ),
                    )
                })
                .collect();

            // Maintain cross-view state even while ETW owns process emissions.
            if crate::telemetry::coverage::snapshot().etw_process_active() {
                self.known = current;
                self.initialized = true;
                continue;
            }
            crate::telemetry::coverage::update(|c| c.process_sensor = Some("polling".into()));
            crate::telemetry::metrics::metrics()
                .set_collector_mode(crate::telemetry::metrics::CollectorMode::WindowsPolling);
            // First pass: absorb the already-running baseline without events.
            if !self.initialized {
                self.known = current;
                self.initialized = true;
                continue;
            }

            // A recycled PID terminates its previous occupant before creating
            // the replacement. Missing start times do not prove a reuse.
            for (pid, (name, before)) in &self.known {
                let gone = match current.get(pid) {
                    None => true,
                    Some((_, after)) => matches!((before, after), (Some(a), Some(b)) if a != b),
                };
                if gone {
                    let event = AgentEvent::new(
                        agent_id.clone(),
                        hostname.clone(),
                        EventClass::Process,
                        EventAction::Terminate,
                        Severity::Info,
                        EventData::ProcessTerminate(ProcessTerminateData {
                            pid: *pid,
                            name: name.clone(),
                        }),
                    );
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
            }

            // New processes, including a proven replacement in an existing PID.
            let created: Vec<i32> = current
                .keys()
                .filter(|pid| match self.known.get(pid) {
                    None => true,
                    Some((_, before)) => {
                        matches!((before, current[*pid].1), (Some(a), Some(b)) if *a != b)
                    }
                })
                .copied()
                .collect();
            for pid in created {
                let spid = Pid::from_u32(pid as u32);
                let Some(proc_) = self.sys.process(spid) else {
                    continue; // already gone again
                };
                let exe: PathBuf = proc_.exe().map(Path::to_path_buf).unwrap_or_default();
                let ppid = proc_.parent().map(|p| p.as_u32() as i32).unwrap_or(0);
                let name = proc_.name().to_string();
                let start_time = current[&pid].1;

                // Cap the command line and mark it when it does not fit, so a
                // consumer can tell a complete command line from a prefix —
                // the same contract the Linux collectors follow.
                let mut notes = Enrichment::new();
                let (cmdline, truncation) = truncate_str(&proc_.cmd().join(" "), MAX_CMDLINE_BYTES);
                notes.truncated("cmdline", truncation);

                // Everything above borrows `self.sys` through `proc_`; the two
                // calls below need `&mut self`, so the borrow has to end first.
                let username = self.username_of(spid);
                let exe_sha256 = self.exe_sha256(&exe);
                // sysinfo does not expose the native error for these missing
                // fields. Record unresolved data without inventing a cause
                // such as permission_denied or treating it as complete.
                if exe.as_os_str().is_empty() {
                    notes.fail("exe", EnrichmentError::IoError);
                }
                if cmdline.is_empty() {
                    notes.fail("cmdline", EnrichmentError::IoError);
                }
                if username == "unknown" {
                    notes.fail("username", EnrichmentError::IoError);
                }
                if start_time.is_none() {
                    notes.fail("process_start_time", EnrichmentError::IoError);
                }

                let data = ProcessCreateData {
                    pid,
                    ppid,
                    name,
                    exe: exe.to_string_lossy().into_owned(),
                    cmdline,
                    // Windows has no numeric uid; identity is carried by
                    // `username` (account name), uid stays 0.
                    uid: 0,
                    username,
                    exe_sha256,
                    // Native GetProcessTimes creation FILETIME (100ns ticks
                    // since 1601). Its precision distinguishes PID reuse even
                    // within one second; unresolved identity remains unknown.
                    process_start_time: start_time,
                    enrichment: notes.finish(0),
                };
                crate::deception::activity::record_exec(&data.username, &data.exe);
                let event = AgentEvent::new(
                    agent_id.clone(),
                    hostname.clone(),
                    EventClass::Process,
                    EventAction::Create,
                    Severity::Info,
                    EventData::ProcessCreate(data),
                );
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }

            self.known = current;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_process_refresh_collects_detection_context() {
        let mut system = System::new();
        system.refresh_processes_specifics(refresh_kind());
        let process = system
            .process(Pid::from_u32(std::process::id()))
            .expect("current Windows process must be visible");
        assert!(!process.cmd().is_empty(), "command line must be requested");
        assert!(process.exe().is_some(), "executable must be requested");
        assert!(process.user_id().is_some(), "account must be requested");
    }
}
