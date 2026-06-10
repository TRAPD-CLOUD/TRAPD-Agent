//! Process lifecycle telemetry — the Windows counterpart of the polling half
//! of `collectors::linux::process`.
//!
//! Diffs the process table on an interval and emits `process/create` /
//! `process/terminate` events with the same [`ProcessCreateData`] /
//! [`ProcessTerminateData`] payloads the Linux agent produces. Windows has no
//! numeric uid; the schema's `uid` field is reported as `0` and `username`
//! carries the account name resolved from the process SID.

use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use sysinfo::{ProcessRefreshKind, RefreshKind, System, Users};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, ProcessCreateData, ProcessTerminateData,
    Severity,
};

const POLL_INTERVAL: Duration = Duration::from_secs(15);

pub struct ProcessCollector {
    initialized: bool,
    /// pid → name of every process seen on the previous pass.
    known: HashMap<i32, String>,
    sys: System,
    users: Users,
}

impl ProcessCollector {
    pub fn new() -> Self {
        Self {
            initialized: false,
            known: HashMap::new(),
            sys: System::new_with_specifics(
                RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
            ),
            users: Users::new_with_refreshed_list(),
        }
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
        "ProcessCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let mut ticker = interval(POLL_INTERVAL);

        loop {
            ticker.tick().await;
            self.sys.refresh_processes();

            let mut current: HashMap<i32, String> = HashMap::with_capacity(self.known.len());

            for (pid, proc_) in self.sys.processes() {
                let pid = pid.as_u32() as i32;
                let name = proc_.name().to_string();
                current.insert(pid, name.clone());

                // First pass only establishes the baseline — a freshly started
                // agent must not report every pre-existing process as new.
                if !self.initialized || self.known.contains_key(&pid) {
                    continue;
                }

                let username = proc_
                    .user_id()
                    .and_then(|uid| self.users.get_user_by_id(uid))
                    .map(|u| u.name().to_string())
                    .unwrap_or_default();

                let data = ProcessCreateData {
                    pid,
                    ppid: proc_.parent().map(|p| p.as_u32() as i32).unwrap_or(0),
                    name,
                    exe: proc_
                        .exe()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    cmdline: proc_.cmd().join(" "),
                    uid: 0,
                    username,
                    exe_sha256: None,
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

            if self.initialized {
                for (pid, name) in &self.known {
                    if current.contains_key(pid) {
                        continue;
                    }
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

            self.known = current;
            self.initialized = true;
        }
    }
}
