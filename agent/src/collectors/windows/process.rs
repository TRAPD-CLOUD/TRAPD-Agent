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
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::Result;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sysinfo::{Pid, System, Users};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::info;

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, ProcessCreateData, ProcessTerminateData,
    Severity,
};

/// Poll cadence — matches the Linux polling collector.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Images larger than this are not hashed (hashing a multi-GB installer on
/// every spawn would stall the collector); the event simply omits the digest.
const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;

/// Upper bound on the exe-hash cache before it is reset (paths churn slowly,
/// so this is rarely hit; the bound only guards against pathological hosts).
const MAX_HASH_CACHE: usize = 4096;

pub struct ProcessCollector {
    sys: System,
    users: Users,
    initialized: bool,
    /// pid → name of every process seen in the previous poll.
    known: HashMap<i32, String>,
    /// exe path → (len, mtime, sha256) so an unchanged image is hashed once.
    hash_cache: HashMap<PathBuf, (u64, Option<SystemTime>, String)>,
}

impl ProcessCollector {
    pub fn new() -> Self {
        Self {
            sys: System::new(),
            users: Users::new_with_refreshed_list(),
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
        let bytes = std::fs::read(path).ok()?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if self.hash_cache.len() >= MAX_HASH_CACHE {
            self.hash_cache.clear();
        }
        self.hash_cache
            .insert(path.to_path_buf(), (key.0, key.1, digest.clone()));
        Some(digest)
    }

    fn username_of(&self, pid: Pid) -> String {
        self.sys
            .process(pid)
            .and_then(|p| p.user_id())
            .and_then(|uid| self.users.get_user_by_id(uid))
            .map(|u| u.name().to_string())
            .unwrap_or_else(|| "unknown".to_string())
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

        loop {
            ticker.tick().await;
            self.sys.refresh_processes();

            let current: HashMap<i32, String> = self
                .sys
                .processes()
                .iter()
                .map(|(pid, p)| (pid.as_u32() as i32, p.name().to_string()))
                .collect();

            // First pass: absorb the already-running baseline without events.
            if !self.initialized {
                self.known = current;
                self.initialized = true;
                continue;
            }

            // New processes.
            let created: Vec<i32> = current
                .keys()
                .filter(|pid| !self.known.contains_key(pid))
                .copied()
                .collect();
            for pid in created {
                let spid = Pid::from_u32(pid as u32);
                let Some(proc_) = self.sys.process(spid) else {
                    continue; // already gone again
                };
                let exe: PathBuf = proc_.exe().map(Path::to_path_buf).unwrap_or_default();
                let cmdline = proc_.cmd().join(" ");
                let ppid = proc_.parent().map(|p| p.as_u32() as i32).unwrap_or(0);
                let username = self.username_of(spid);
                let name = proc_.name().to_string();
                let exe_sha256 = self.exe_sha256(&exe);

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
                };
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

            // Vanished processes.
            let terminated: Vec<(i32, String)> = self
                .known
                .iter()
                .filter(|(pid, _)| !current.contains_key(pid))
                .map(|(pid, name)| (*pid, name.clone()))
                .collect();
            for (pid, name) in terminated {
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

            self.known = current;
        }
    }
}
