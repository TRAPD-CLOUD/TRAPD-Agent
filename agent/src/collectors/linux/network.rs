use std::collections::HashMap;
use std::fs;
use std::time::Instant;

use anyhow::Result;
use async_trait::async_trait;
use procfs::net::TcpState;
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::warn;

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, NetworkConnectionData, Severity,
};

pub struct NetworkCollector {
    /// Connection key → flow facts (incl. first-observed time). Doubles as the
    /// "known" set: a key leaving this map between polls is a closed flow.
    known_tcp: HashMap<String, FlowInfo>,
    known_udp: HashMap<String, FlowInfo>,
}

impl NetworkCollector {
    pub fn new() -> Self {
        Self {
            known_tcp: HashMap::new(),
            known_udp: HashMap::new(),
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

/// The per-flow facts needed to emit both the start and the close record. Stored
/// alongside the first-observed timestamp so the close record can carry the
/// flow's lifetime — the duration dimension of "netflow depth".
#[derive(Clone)]
struct FlowInfo {
    first_seen: Instant,
    protocol:   String,
    src_addr:   String,
    src_port:   u16,
    dst_addr:   String,
    dst_port:   u16,
    pid:        Option<i32>,
    process:    Option<String>,
    /// Cumulative byte/packet/rtt counters from the most recent INET_DIAG poll
    /// (joined by socket inode at observation time; empty for UDP).
    stats:      super::inet_diag::FlowStats,
}

impl FlowInfo {
    fn connection_event(&self, state: &str, duration_ms: Option<u64>) -> NetworkConnectionData {
        NetworkConnectionData {
            protocol: self.protocol.clone(),
            src_addr: self.src_addr.clone(),
            src_port: self.src_port,
            dst_addr: self.dst_addr.clone(),
            dst_port: self.dst_port,
            state: state.to_string(),
            pid: self.pid,
            process: self.process.clone(),
            duration_ms,
            bytes_sent: self.stats.bytes_sent,
            bytes_recv: self.stats.bytes_recv,
            packets_sent: self.stats.packets_sent,
            packets_recv: self.stats.packets_recv,
            rtt_us: self.stats.rtt_us,
        }
    }
}

#[async_trait]
impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "NetworkCollector"
    }

    async fn run(
        &mut self,
        tx:       Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let mut ticker = interval(Duration::from_secs(5));
        // Self-exclusion: never report the agent's own sockets (e.g. its uplink
        // to the backend) as host network activity.
        let agent_pid = std::process::id() as i32;

        loop {
            ticker.tick().await;

            let inode_map = tokio::task::spawn_blocking(build_inode_pid_map)
                .await
                .unwrap_or_default();

            // Per-socket byte/packet/rtt counters (best-effort; empty without
            // privilege). Keyed by socket inode, joined onto TCP flows below.
            let diag = tokio::task::spawn_blocking(super::inet_diag::query_tcp)
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

            let mut new_tcp: HashMap<String, FlowInfo> = HashMap::new();
            for entry in &tcp_entries {
                if entry.state != TcpState::Established {
                    continue;
                }
                let (pid, process) = resolve_pid_name(entry.inode, &inode_map);
                if pid == Some(agent_pid) {
                    continue; // self-exclusion
                }
                let flow = FlowInfo {
                    first_seen: Instant::now(),
                    protocol: "tcp".to_string(),
                    src_addr: entry.local_address.ip().to_string(),
                    src_port: entry.local_address.port(),
                    dst_addr: entry.remote_address.ip().to_string(),
                    dst_port: entry.remote_address.port(),
                    pid,
                    process,
                    stats: diag.get(&entry.inode).copied().unwrap_or_default(),
                };
                let key = flow_key(&flow);
                new_tcp.insert(key, flow);
            }
            if reconcile(&mut self.known_tcp, new_tcp, "established", &tx, &agent_id, &hostname)
                .await
                .is_err()
            {
                return Ok(());
            }

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

            let mut new_udp: HashMap<String, FlowInfo> = HashMap::new();
            for entry in &udp_entries {
                let (pid, process) = resolve_pid_name(entry.inode, &inode_map);
                if pid == Some(agent_pid) {
                    continue; // self-exclusion
                }
                let flow = FlowInfo {
                    first_seen: Instant::now(),
                    protocol: "udp".to_string(),
                    src_addr: entry.local_address.ip().to_string(),
                    src_port: entry.local_address.port(),
                    dst_addr: entry.remote_address.ip().to_string(),
                    dst_port: entry.remote_address.port(),
                    pid,
                    process,
                    stats: super::inet_diag::FlowStats::default(),
                };
                let key = flow_key(&flow);
                new_udp.insert(key, flow);
            }
            if reconcile(&mut self.known_udp, new_udp, "open", &tx, &agent_id, &hostname)
                .await
                .is_err()
            {
                return Ok(());
            }
        }
    }
}

/// Stable key for a flow (proto + 4-tuple). Built from the parsed fields, so it
/// is unambiguous for IPv6 (which would break a naive colon-split of a string).
fn flow_key(f: &FlowInfo) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        f.protocol, f.src_addr, f.src_port, f.dst_addr, f.dst_port
    )
}

/// Diff the previous flow set against the freshly-observed one:
///   * a flow present only in `next` is **new** → emit a start record;
///   * a flow present only in `prev` has **closed** → emit a close record with
///     its measured lifetime;
///   * a flow in both carries its original `first_seen` forward.
///
/// Returns `Err(())` only when the event channel is closed (agent shutting down).
async fn reconcile(
    prev: &mut HashMap<String, FlowInfo>,
    mut next: HashMap<String, FlowInfo>,
    open_state: &str,
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
) -> Result<(), ()> {
    // New flows + carry-forward of first_seen for surviving flows.
    for (key, flow) in next.iter_mut() {
        match prev.remove(key) {
            Some(existing) => {
                // Surviving flow — preserve its original first-seen timestamp.
                flow.first_seen = existing.first_seen;
            }
            None => {
                // Newly observed flow — emit the start record.
                let data = flow.connection_event(open_state, None);
                if emit(tx, agent_id, hostname, data).await.is_err() {
                    return Err(());
                }
            }
        }
    }

    // Whatever remains in `prev` was not seen this poll → the flow closed.
    for (_key, flow) in prev.drain() {
        let duration_ms = flow.first_seen.elapsed().as_millis() as u64;
        let data = flow.connection_event("closed", Some(duration_ms));
        if emit(tx, agent_id, hostname, data).await.is_err() {
            return Err(());
        }
    }

    *prev = next;
    Ok(())
}

async fn emit(
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    data: NetworkConnectionData,
) -> Result<(), ()> {
    let event = AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Network,
        EventAction::Connection,
        Severity::Info,
        EventData::NetworkConnection(data),
    );
    tx.send(event).await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(dst: &str, port: u16, first_seen: Instant) -> FlowInfo {
        FlowInfo {
            first_seen,
            protocol: "tcp".into(),
            src_addr: "10.0.0.2".into(),
            src_port: 5000,
            dst_addr: dst.into(),
            dst_port: port,
            pid: Some(42),
            process: Some("curl".into()),
            stats: super::super::inet_diag::FlowStats::default(),
        }
    }

    fn conn(ev: &AgentEvent) -> &NetworkConnectionData {
        match &ev.data {
            EventData::NetworkConnection(c) => c,
            _ => panic!("expected NetworkConnection"),
        }
    }

    #[tokio::test]
    async fn emits_start_for_new_flow_and_carries_first_seen() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let mut prev: HashMap<String, FlowInfo> = HashMap::new();

        let f = flow("1.1.1.1", 443, Instant::now());
        let mut next = HashMap::new();
        next.insert(flow_key(&f), f);

        reconcile(&mut prev, next, "established", &tx, "a", "h").await.unwrap();

        let ev = rx.try_recv().expect("a start event");
        let c = conn(&ev);
        assert_eq!(c.state, "established");
        assert!(c.duration_ms.is_none());
        assert_eq!(prev.len(), 1, "flow is now tracked");
    }

    #[tokio::test]
    async fn emits_close_with_duration_for_vanished_flow() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);

        // A flow first seen ~50ms ago, now gone.
        let started = Instant::now() - std::time::Duration::from_millis(50);
        let f = flow("2.2.2.2", 80, started);
        let mut prev = HashMap::new();
        prev.insert(flow_key(&f), f);

        reconcile(&mut prev, HashMap::new(), "established", &tx, "a", "h").await.unwrap();

        let ev = rx.try_recv().expect("a close event");
        let c = conn(&ev);
        assert_eq!(c.state, "closed");
        assert!(c.duration_ms.unwrap() >= 50, "duration measured from first-seen");
        assert!(prev.is_empty(), "closed flow dropped from tracking");
    }

    #[test]
    fn flow_key_is_ipv6_safe() {
        let a = flow("fe80::1", 443, Instant::now());
        let b = flow("fe80::2", 443, Instant::now());
        assert_ne!(flow_key(&a), flow_key(&b));
        // Same 4-tuple ⇒ same key (stable across polls).
        assert_eq!(flow_key(&a), flow_key(&flow("fe80::1", 443, Instant::now())));
    }
}
