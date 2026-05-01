use std::collections::{HashMap, HashSet};
use std::fs;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::warn;

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, ProcessCreateData, ProcessTerminateData,
    Severity,
};

pub struct ProcessCollector {
    initialized:  bool,
    known_pids:   HashSet<i32>,
    known_names:  HashMap<i32, String>,
    uid_to_user:  HashMap<u32, String>,
}

impl ProcessCollector {
    pub fn new() -> Self {
        Self {
            initialized:  false,
            known_pids:   HashSet::new(),
            known_names:  HashMap::new(),
            uid_to_user:  load_passwd().unwrap_or_default(),
        }
    }
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
