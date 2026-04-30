use std::collections::{HashMap, HashSet};
use std::fs;

use anyhow::Result;
use async_trait::async_trait;
use procfs::net::TcpState;
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::warn;
use uuid::Uuid;

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, NetworkConnectionData, Severity,
};

pub struct NetworkCollector {
    known_tcp: HashSet<String>,
    known_udp: HashSet<String>,
}

impl NetworkCollector {
    pub fn new() -> Self {
        Self {
            known_tcp: HashSet::new(),
            known_udp: HashSet::new(),
        }
    }
}

impl Default for NetworkCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn build_inode_pid_map() -> HashMap<u64, i32> {
    let mut map = HashMap::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: i32 = match name_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let fd_path = format!("/proc/{pid}/fd");
        let fd_dir = match fs::read_dir(&fd_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd_entry in fd_dir.flatten() {
            let link = match fs::read_link(fd_entry.path()) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let link_str = link.to_string_lossy();

            if let Some(inode_str) = link_str
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
            {
                if let Ok(inode) = inode_str.parse::<u64>() {
                    map.insert(inode, pid);
                }
            }
        }
    }
    map
}

fn resolve_pid_name(inode: u64, inode_map: &HashMap<u64, i32>) -> (Option<i32>, Option<String>) {
    let pid = match inode_map.get(&inode) {
        Some(&p) => p,
        None => return (None, None),
    };

    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .ok();

    (Some(pid), comm)
}

#[async_trait]
impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "NetworkCollector"
    }

    async fn run(
        &mut self,
        tx:       Sender<AgentEvent>,
        agent_id: Uuid,
        hostname: String,
    ) -> Result<()> {
        let mut ticker = interval(Duration::from_secs(5));

        loop {
            ticker.tick().await;

            let inode_map = tokio::task::spawn_blocking(build_inode_pid_map)
                .await
                .unwrap_or_default();

            // ── TCP (established only) ──────────────────────────────────────
            let mut tcp_entries = Vec::new();
            match procfs::net::tcp() {
                Ok(v) => tcp_entries.extend(v),
                Err(e) => warn!("Failed to read /proc/net/tcp: {e}"),
            }
            match procfs::net::tcp6() {
                Ok(v) => tcp_entries.extend(v),
                Err(e) => warn!("Failed to read /proc/net/tcp6: {e}"),
            }

            let mut new_tcp: HashSet<String> = HashSet::new();

            for entry in &tcp_entries {
                if entry.state != TcpState::Established {
                    continue;
                }

                let src_addr = entry.local_address.ip().to_string();
                let src_port = entry.local_address.port();
                let dst_addr = entry.remote_address.ip().to_string();
                let dst_port = entry.remote_address.port();
                let key = format!("{src_addr}:{src_port}-{dst_addr}:{dst_port}-tcp");
                new_tcp.insert(key.clone());

                if self.known_tcp.contains(&key) {
                    continue;
                }

                let (pid, process) = resolve_pid_name(entry.inode, &inode_map);
                let event = AgentEvent::new(
                    agent_id,
                    hostname.clone(),
                    EventClass::Network,
                    EventAction::Connection,
                    Severity::Info,
                    EventData::NetworkConnection(NetworkConnectionData {
                        protocol: "tcp".to_string(),
                        src_addr,
                        src_port,
                        dst_addr,
                        dst_port,
                        state: "established".to_string(),
                        pid,
                        process,
                    }),
                );
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }
            self.known_tcp = new_tcp;

            // ── UDP (all sockets) ────────────────────────────────────────────
            let mut udp_entries = Vec::new();
            match procfs::net::udp() {
                Ok(v) => udp_entries.extend(v),
                Err(e) => warn!("Failed to read /proc/net/udp: {e}"),
            }
            match procfs::net::udp6() {
                Ok(v) => udp_entries.extend(v),
                Err(e) => warn!("Failed to read /proc/net/udp6: {e}"),
            }

            let mut new_udp: HashSet<String> = HashSet::new();

            for entry in &udp_entries {
                let src_addr = entry.local_address.ip().to_string();
                let src_port = entry.local_address.port();
                let dst_addr = entry.remote_address.ip().to_string();
                let dst_port = entry.remote_address.port();
                let key = format!("{src_addr}:{src_port}-{dst_addr}:{dst_port}-udp");
                new_udp.insert(key.clone());

                if self.known_udp.contains(&key) {
                    continue;
                }

                let (pid, process) = resolve_pid_name(entry.inode, &inode_map);
                let event = AgentEvent::new(
                    agent_id,
                    hostname.clone(),
                    EventClass::Network,
                    EventAction::Connection,
                    Severity::Info,
                    EventData::NetworkConnection(NetworkConnectionData {
                        protocol: "udp".to_string(),
                        src_addr,
                        src_port,
                        dst_addr,
                        dst_port,
                        state: "open".to_string(),
                        pid,
                        process,
                    }),
                );
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }
            self.known_udp = new_udp;
        }
    }
}
