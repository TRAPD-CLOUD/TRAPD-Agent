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

fn build_inode_pid_map() -> HashMap<u64, (i32, u64)> {
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

        let Some(start) = crate::telemetry::identity::process_start_time(pid) else {
            continue;
        };
        let mut inodes = Vec::new();
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
                    inodes.push(inode);
                }
            }
        }
        // Do not assign a reused PID's sockets to the older generation.
        if crate::telemetry::identity::process_start_time(pid) == Some(start) {
            for inode in inodes {
                map.insert(inode, (pid, start));
            }
        }
    }
    map
}

fn resolve_pid_name(
    inode: u64,
    inode_map: &HashMap<u64, (i32, u64)>,
) -> (Option<i32>, Option<u64>, Option<String>) {
    let (pid, start) = match inode_map.get(&inode) {
        Some(&(pid, start)) => (pid, start),
        None => return (None, None, None),
    };
    if crate::telemetry::identity::process_start_time(pid) != Some(start) {
        return (None, None, None);
    }

    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .ok();

    (Some(pid), Some(start), comm)
}

/// The per-flow facts needed to emit both the start and the close record. Stored
/// alongside the first-observed timestamp so the close record can carry the
/// flow's lifetime — the duration dimension of "netflow depth".
#[derive(Clone)]
struct FlowInfo {
    inode: u64,
    first_seen: Instant,
    protocol: String,
    src_addr: String,
    src_port: u16,
    dst_addr: String,
    dst_port: u16,
    pid: Option<i32>,
    process_start_time: Option<u64>,
    process: Option<String>,
    /// Historical conflict guard; never enriches current observations.
    owner: (Option<i32>, Option<u64>),
    /// Cumulative byte/packet/rtt counters from the most recent INET_DIAG poll
    /// (joined by socket inode at observation time; empty for UDP).
    stats: super::inet_diag::FlowStats,
}

impl FlowInfo {
    fn owner(&self) -> (Option<i32>, Option<u64>) {
        let pid = self.owner.0.or(self.pid.filter(|pid| *pid > 0));
        (
            pid,
            self.owner
                .1
                .or(self.process_start_time.filter(|start| *start > 0)),
        )
    }

    fn conflicts_with(&self, observed: &Self) -> bool {
        let (pid, start) = self.owner();
        let next_pid = observed.pid.filter(|pid| *pid > 0);
        pid.zip(next_pid).is_some_and(|(old, new)| old != new)
            || (pid.is_some()
                && pid == next_pid
                && start
                    .zip(observed.process_start_time.filter(|start| *start > 0))
                    .is_some_and(|(old, new)| old != new))
    }

    fn connection_event(&self, state: &str, duration_ms: Option<u64>) -> NetworkConnectionData {
        // A close record may retain the last observed owner. Live observations
        // remain unknown when attribution is missing; history cannot authorize.
        let (pid, process_start_time) = if state == "closed" {
            self.owner()
        } else {
            (self.pid, self.process_start_time)
        };
        NetworkConnectionData {
            protocol: self.protocol.clone(),
            src_addr: self.src_addr.clone(),
            src_port: self.src_port,
            dst_addr: self.dst_addr.clone(),
            dst_port: self.dst_port,
            state: state.to_string(),
            pid,
            process_start_time,
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
        tx: Sender<AgentEvent>,
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
                let (pid, process_start_time, process) = resolve_pid_name(entry.inode, &inode_map);
                if pid == Some(agent_pid) {
                    continue; // self-exclusion
                }
                let flow = FlowInfo {
                    inode: entry.inode,
                    first_seen: Instant::now(),
                    protocol: "tcp".to_string(),
                    src_addr: entry.local_address.ip().to_string(),
                    src_port: entry.local_address.port(),
                    dst_addr: entry.remote_address.ip().to_string(),
                    dst_port: entry.remote_address.port(),
                    pid,
                    process_start_time,
                    process,
                    owner: (None, None),
                    stats: diag.get(&entry.inode).copied().unwrap_or_default(),
                };
                let key = flow_key(&flow);
                new_tcp.insert(key, flow);
            }
            if reconcile(
                &mut self.known_tcp,
                new_tcp,
                "established",
                &tx,
                &agent_id,
                &hostname,
            )
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
                let (pid, process_start_time, process) = resolve_pid_name(entry.inode, &inode_map);
                if pid == Some(agent_pid) {
                    continue; // self-exclusion
                }
                let flow = FlowInfo {
                    inode: entry.inode,
                    first_seen: Instant::now(),
                    protocol: "udp".to_string(),
                    src_addr: entry.local_address.ip().to_string(),
                    src_port: entry.local_address.port(),
                    dst_addr: entry.remote_address.ip().to_string(),
                    dst_port: entry.remote_address.port(),
                    pid,
                    process_start_time,
                    process,
                    owner: (None, None),
                    stats: super::inet_diag::FlowStats::default(),
                };
                let key = flow_key(&flow);
                new_udp.insert(key, flow);
            }
            if reconcile(
                &mut self.known_udp,
                new_udp,
                "open",
                &tx,
                &agent_id,
                &hostname,
            )
            .await
            .is_err()
            {
                return Ok(());
            }
        }
    }
}

/// Stable socket key (protocol, 4-tuple and inode). Built from parsed fields, so it
/// is unambiguous for IPv6 (which would break a naive colon-split of a string).
fn flow_key(f: &FlowInfo) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        f.protocol, f.src_addr, f.src_port, f.dst_addr, f.dst_port, f.inode
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
        // Inode zero provides no socket identity. Preserve separate records
        // rather than guessing continuity from an ambiguous endpoint tuple.
        let compatible =
            flow.inode != 0 && prev.get(key).is_some_and(|old| !old.conflicts_with(flow));
        match compatible.then(|| prev.remove(key)).flatten() {
            Some(existing) => {
                // Surviving flow — preserve its original first-seen timestamp.
                flow.first_seen = existing.first_seen;
                let owner = existing.owner();
                flow.owner = (
                    flow.pid.filter(|pid| *pid > 0).or(owner.0),
                    flow.process_start_time
                        .filter(|start| *start > 0)
                        .or(owner.1),
                );
                flow.stats.bytes_sent = flow.stats.bytes_sent.or(existing.stats.bytes_sent);
                flow.stats.bytes_recv = flow.stats.bytes_recv.or(existing.stats.bytes_recv);
                flow.stats.packets_sent = flow.stats.packets_sent.or(existing.stats.packets_sent);
                flow.stats.packets_recv = flow.stats.packets_recv.or(existing.stats.packets_recv);
                flow.stats.rtt_us = flow.stats.rtt_us.or(existing.stats.rtt_us);
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

    #[test]
    fn flow_start_and_close_keep_the_observed_process_generation() {
        let observed = flow("203.0.113.7", 443, Instant::now());
        assert_eq!(
            observed
                .connection_event("established", None)
                .process_start_time,
            Some(100)
        );
        assert_eq!(
            observed
                .connection_event("closed", Some(20))
                .process_start_time,
            Some(100)
        );
    }

    fn flow(dst: &str, port: u16, first_seen: Instant) -> FlowInfo {
        FlowInfo {
            inode: 1000,
            first_seen,
            protocol: "tcp".into(),
            src_addr: "10.0.0.2".into(),
            src_port: 5000,
            dst_addr: dst.into(),
            dst_port: port,
            pid: Some(42),
            process_start_time: Some(100),
            process: Some("curl".into()),
            owner: (None, None),
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
    async fn attribution_gaps_keep_one_flow_lifetime_and_counters_without_authorizing_unknown() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let started = Instant::now() - std::time::Duration::from_millis(50);
        let mut original = flow("203.0.113.7", 443, started);
        original.pid = None;
        original.process_start_time = None;
        original.process = None;
        original.stats.bytes_sent = Some(100);
        let mut prev = HashMap::from([(flow_key(&original), original)]);
        let mut attributed = flow("203.0.113.7", 443, Instant::now());
        attributed.stats.bytes_sent = Some(200);
        reconcile(
            &mut prev,
            HashMap::from([(flow_key(&attributed), attributed)]),
            "established",
            &tx,
            "a",
            "h",
        )
        .await
        .unwrap();
        assert!(
            rx.try_recv().is_err(),
            "enrichment is not a second connection"
        );
        let mut unknown = flow("203.0.113.7", 443, Instant::now());
        unknown.pid = None;
        unknown.process_start_time = None;
        unknown.process = None;
        reconcile(
            &mut prev,
            HashMap::from([(flow_key(&unknown), unknown)]),
            "established",
            &tx,
            "a",
            "h",
        )
        .await
        .unwrap();
        assert!(rx.try_recv().is_err());
        let tracked = prev.values().next().unwrap();
        assert_eq!(tracked.first_seen, started);
        assert_eq!(tracked.stats.bytes_sent, Some(200));
        assert_eq!(tracked.connection_event("established", None).pid, None);
        assert_eq!(
            tracked
                .connection_event("established", None)
                .process_start_time,
            None
        );
        reconcile(&mut prev, HashMap::new(), "established", &tx, "a", "h")
            .await
            .unwrap();
        let closed = rx.try_recv().unwrap();
        assert_eq!(conn(&closed).state, "closed");
        assert!(conn(&closed).duration_ms.unwrap() >= 50);
        assert_eq!(conn(&closed).bytes_sent, Some(200));
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn attribution_gap_does_not_hide_a_changed_known_generation_or_pid() {
        for changed_pid in [false, true] {
            let (tx, mut rx) = tokio::sync::mpsc::channel(16);
            let original = flow("203.0.113.7", 443, Instant::now());
            let mut prev = HashMap::from([(flow_key(&original), original)]);
            let mut unknown = flow("203.0.113.7", 443, Instant::now());
            unknown.pid = None;
            unknown.process_start_time = None;
            reconcile(
                &mut prev,
                HashMap::from([(flow_key(&unknown), unknown)]),
                "established",
                &tx,
                "a",
                "h",
            )
            .await
            .unwrap();
            assert!(rx.try_recv().is_err());
            let mut changed = flow("203.0.113.7", 443, Instant::now());
            if changed_pid {
                changed.pid = Some(43);
                changed.process_start_time = None;
            } else {
                changed.process_start_time = Some(200);
            }
            reconcile(
                &mut prev,
                HashMap::from([(flow_key(&changed), changed)]),
                "established",
                &tx,
                "a",
                "h",
            )
            .await
            .unwrap();
            let events = [rx.try_recv().unwrap(), rx.try_recv().unwrap()];
            assert!(events.iter().any(|event| conn(event).state == "closed"));
            assert!(events
                .iter()
                .any(|event| conn(event).state == "established"));
            assert!(rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn separate_socket_inodes_do_not_merge_shared_udp_tuples_or_owners() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let mut first = flow("0.0.0.0", 0, Instant::now());
        first.protocol = "udp".into();
        first.pid = None;
        first.process_start_time = None;
        let mut second = first.clone();
        second.inode += 1;
        let mut prev = HashMap::from([
            (flow_key(&first), first.clone()),
            (flow_key(&second), second.clone()),
        ]);
        assert_eq!(prev.len(), 2);
        first.pid = Some(42);
        first.process_start_time = Some(100);
        second.pid = Some(43);
        second.process_start_time = Some(200);
        reconcile(
            &mut prev,
            HashMap::from([(flow_key(&first), first), (flow_key(&second), second)]),
            "open",
            &tx,
            "a",
            "h",
        )
        .await
        .unwrap();
        assert!(rx.try_recv().is_err());
        assert_eq!(prev.len(), 2);
        assert!(prev.values().any(|flow| flow.pid == Some(42)));
        assert!(prev.values().any(|flow| flow.pid == Some(43)));
    }

    #[tokio::test]
    async fn emits_start_for_new_flow_and_carries_first_seen() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let mut prev: HashMap<String, FlowInfo> = HashMap::new();

        let f = flow("1.1.1.1", 443, Instant::now());
        let mut next = HashMap::new();
        next.insert(flow_key(&f), f);

        reconcile(&mut prev, next, "established", &tx, "a", "h")
            .await
            .unwrap();

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

        reconcile(&mut prev, HashMap::new(), "established", &tx, "a", "h")
            .await
            .unwrap();

        let ev = rx.try_recv().expect("a close event");
        let c = conn(&ev);
        assert_eq!(c.state, "closed");
        assert!(
            c.duration_ms.unwrap() >= 50,
            "duration measured from first-seen"
        );
        assert!(prev.is_empty(), "closed flow dropped from tracking");
    }

    #[test]
    fn flow_key_is_ipv6_safe() {
        let a = flow("fe80::1", 443, Instant::now());
        let b = flow("fe80::2", 443, Instant::now());
        assert_ne!(flow_key(&a), flow_key(&b));
        // Same 4-tuple ⇒ same key (stable across polls).
        assert_eq!(
            flow_key(&a),
            flow_key(&flow("fe80::1", 443, Instant::now()))
        );
    }
}
