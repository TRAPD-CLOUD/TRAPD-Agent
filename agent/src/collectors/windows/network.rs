//! TCP IPv4/IPv6 flow telemetry through the IP Helper owner-PID tables.
//! Polling observes established connections and their closure, matching the
//! Linux polling fallback. It cannot see flows shorter than the poll interval.
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use anyhow::{bail, Result};
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, NetworkConnectionData, Severity,
};

fn table(family: u32) -> Result<Vec<u32>> {
    let mut bytes = 0;
    // SAFETY: the first call only queries the required size.
    let status = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut bytes,
            0,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if status != 0 && status != 122 {
        bail!("TCP table sizing failed: {status}");
    }
    for _ in 0..3 {
        if !(4..=16 * 1024 * 1024).contains(&bytes) {
            bail!("invalid TCP table size: {bytes}");
        }
        let mut data = vec![0u32; (bytes as usize).div_ceil(4)];
        // SAFETY: aligned buffer provides at least `bytes` writable bytes.
        let status = unsafe {
            GetExtendedTcpTable(
                data.as_mut_ptr().cast(),
                &mut bytes,
                0,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if status == 0 {
            data.truncate((bytes as usize).div_ceil(4));
            return Ok(data);
        }
        if status != 122 {
            bail!("TCP table read failed: {status}");
        }
    }
    bail!("TCP table changed repeatedly during read")
}

pub fn snapshot() -> Result<Vec<NetworkConnectionData>> {
    let mut system = sysinfo::System::new();
    system.refresh_processes();
    let starts: HashMap<i32, u64> = system
        .processes()
        .keys()
        .filter_map(|pid| {
            let pid = pid.as_u32() as i32;
            crate::telemetry::identity::process_start_time(pid).map(|start| (pid, start))
        })
        .collect();
    let mut out = Vec::new();
    for (family, row_size) in [
        (AF_INET as u32, std::mem::size_of::<MIB_TCPROW_OWNER_PID>()),
        (
            AF_INET6 as u32,
            std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>(),
        ),
    ] {
        let data = table(family)?;
        let count = data[0] as usize;
        if count > (data.len() * 4 - 4) / row_size {
            bail!("invalid TCP table row count");
        }
        for index in 0..count {
            // SAFETY: count and row size were checked against the buffer. Copy
            // each C row out rather than borrowing a flexible array member.
            let row = unsafe { data.as_ptr().cast::<u8>().add(4 + index * row_size) };
            let (state, pid, src_addr, src_port, dst_addr, dst_port) = if family == AF_INET as u32 {
                let row = unsafe { std::ptr::read_unaligned(row.cast::<MIB_TCPROW_OWNER_PID>()) };
                (
                    row.dwState,
                    row.dwOwningPid,
                    Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()).to_string(),
                    u16::from_be(row.dwLocalPort as u16),
                    Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()).to_string(),
                    u16::from_be(row.dwRemotePort as u16),
                )
            } else {
                let row = unsafe { std::ptr::read_unaligned(row.cast::<MIB_TCP6ROW_OWNER_PID>()) };
                (
                    row.dwState,
                    row.dwOwningPid,
                    Ipv6Addr::from(row.ucLocalAddr).to_string(),
                    u16::from_be(row.dwLocalPort as u16),
                    Ipv6Addr::from(row.ucRemoteAddr).to_string(),
                    u16::from_be(row.dwRemotePort as u16),
                )
            };
            if state != 2 && state != 5 {
                continue;
            }
            out.push(NetworkConnectionData {
                protocol: if family == AF_INET as u32 {
                    "tcp"
                } else {
                    "tcp6"
                }
                .into(),
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                state: if state == 2 { "listen" } else { "established" }.into(),
                pid: i32::try_from(pid).ok(),
                process_start_time: i32::try_from(pid).ok().and_then(|pid| {
                    starts.get(&pid).copied().filter(|start| {
                        crate::telemetry::identity::process_start_time(pid) == Some(*start)
                    })
                }),
                process: None,
                duration_ms: None,
                bytes_sent: None,
                bytes_recv: None,
                packets_sent: None,
                packets_recv: None,
                rtt_us: None,
            });
        }
    }
    Ok(out)
}

pub struct NetworkCollector;

struct TrackedFlow {
    row: NetworkConnectionData,
    since: Instant,
    /// Conflict history only; never replaces the current row's attribution.
    owner: (Option<i32>, Option<u64>),
}

fn observed_owner(row: &NetworkConnectionData) -> (Option<i32>, Option<u64>) {
    let pid = row.pid.filter(|pid| *pid > 0);
    (
        pid,
        pid.and(row.process_start_time.filter(|start| *start > 0)),
    )
}

fn owner_conflicts(owner: (Option<i32>, Option<u64>), row: &NetworkConnectionData) -> bool {
    let next = observed_owner(row);
    owner.0.zip(next.0).is_some_and(|(old, new)| old != new)
        || (owner.0.is_some()
            && owner.0 == next.0
            && owner.1.zip(next.1).is_some_and(|(old, new)| old != new))
}

fn tuple_key(row: &NetworkConnectionData) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        row.protocol, row.src_addr, row.src_port, row.dst_addr, row.dst_port
    )
}

fn flow_key(row: &NetworkConnectionData) -> String {
    format!(
        "{}|{:?}|{:?}",
        tuple_key(row),
        row.pid,
        row.process_start_time
    )
}

struct TupleGroup {
    count: usize,
    first_key: String,
    fully_attributed: bool,
}

fn tuple_groups(flows: &HashMap<String, TrackedFlow>) -> HashMap<String, TupleGroup> {
    let mut groups = HashMap::new();
    for (key, flow) in flows {
        let owner = observed_owner(&flow.row);
        let full = owner.0.is_some() && owner.1.is_some();
        let group = groups
            .entry(tuple_key(&flow.row))
            .or_insert_with(|| TupleGroup {
                count: 0,
                first_key: key.clone(),
                fully_attributed: true,
            });
        group.count += 1;
        group.fully_attributed &= full;
    }
    groups
}

/// Linear reconciliation. Unknown attribution may retain socket lifetime only
/// in unambiguous 1:1 tuple groups; known owners cannot cross a generation gap.
fn reconcile(
    known: &mut HashMap<String, TrackedFlow>,
    rows: Vec<NetworkConnectionData>,
    etw_active: bool,
) -> Vec<NetworkConnectionData> {
    let mut current: HashMap<_, _> = rows
        .into_iter()
        .map(|row| {
            (
                flow_key(&row),
                TrackedFlow {
                    owner: observed_owner(&row),
                    row,
                    since: Instant::now(),
                },
            )
        })
        .collect();
    let previous_groups = tuple_groups(known);
    let current_groups = tuple_groups(&current);
    let mut events = Vec::new();
    for (key, flow) in &mut current {
        let tuple = tuple_key(&flow.row);
        let group = &current_groups[&tuple];
        let candidate = previous_groups.get(&tuple).and_then(|previous| {
            if previous.count == 1 && group.count == 1 {
                Some(previous.first_key.as_str())
            } else if previous.fully_attributed && group.fully_attributed {
                // Every candidate has a complete owner: the exact identity key
                // picks one without guessing among partially attributed rows.
                Some(key.as_str())
            } else {
                None
            }
        });
        let previous = candidate
            .filter(|key| {
                known
                    .get(*key)
                    .is_some_and(|old| !owner_conflicts(old.owner, &flow.row))
            })
            .and_then(|key| known.remove(key));
        if let Some(previous) = previous {
            flow.since = previous.since;
            flow.owner = (
                flow.owner.0.or(previous.owner.0),
                flow.owner.1.or(previous.owner.1),
            );
            flow.row.bytes_sent = flow.row.bytes_sent.or(previous.row.bytes_sent);
            flow.row.bytes_recv = flow.row.bytes_recv.or(previous.row.bytes_recv);
            flow.row.packets_sent = flow.row.packets_sent.or(previous.row.packets_sent);
            flow.row.packets_recv = flow.row.packets_recv.or(previous.row.packets_recv);
            flow.row.rtt_us = flow.row.rtt_us.or(previous.row.rtt_us);
        } else if !etw_active {
            events.push(flow.row.clone());
        }
    }
    if !etw_active {
        for (_, mut flow) in known.drain() {
            flow.row.state = "closed".into();
            flow.row.duration_ms = Some(flow.since.elapsed().as_millis() as u64);
            // Close records describe historical flow facts; enforcement skips
            // closed events. Current unknown rows remain unknown above.
            flow.row.pid = flow.owner.0;
            flow.row.process_start_time = flow.owner.1;
            events.push(flow.row);
        }
    }
    *known = current;
    events
}

#[async_trait]
impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "WindowsNetworkCollector"
    }
    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let mut known = HashMap::new();
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3));
        loop {
            ticker.tick().await;
            let etw_active = crate::telemetry::coverage::snapshot().etw_network_active();
            let rows = match tokio::task::spawn_blocking(snapshot).await? {
                Ok(rows) => rows,
                Err(e) => {
                    tracing::warn!(error = %e, "Windows TCP snapshot failed");
                    continue;
                }
            };
            // ETW owns emission while active; still update polling history so
            // a later ETW outage does not re-announce an existing connection.
            let rows = rows
                .into_iter()
                .filter(|row| row.state == "established")
                .collect();
            for row in reconcile(&mut known, rows, etw_active) {
                let event = AgentEvent::new(
                    agent_id.clone(),
                    hostname.clone(),
                    EventClass::Network,
                    EventAction::Connection,
                    Severity::Info,
                    EventData::NetworkConnection(row),
                );
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(pid: Option<i32>, start: Option<u64>) -> NetworkConnectionData {
        serde_json::from_value(serde_json::json!({
            "protocol": "tcp6", "src_addr": "2001:db8::1", "src_port": 5000,
            "dst_addr": "2001:db8::2", "dst_port": 443, "state": "established",
            "pid": pid, "process_start_time": start,
        }))
        .unwrap()
    }

    #[test]
    fn flow_fifo_attribution_gaps_keep_lifetime_counters_and_unknown_current_rows() {
        let mut known = HashMap::new();
        let mut initial = flow(None, None);
        initial.bytes_sent = Some(100);
        let events = reconcile(&mut known, vec![initial], false);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].pid, None);
        let since = Instant::now() - std::time::Duration::from_millis(50);
        known.values_mut().next().unwrap().since = since;
        let mut attributed = flow(Some(42), Some(100));
        attributed.bytes_sent = Some(200);
        assert!(reconcile(&mut known, vec![attributed], false).is_empty());
        assert!(reconcile(&mut known, vec![flow(None, None)], false).is_empty());
        let tracked = known.values().next().unwrap();
        assert_eq!(tracked.since, since);
        assert_eq!(tracked.row.pid, None);
        assert_eq!(tracked.row.process_start_time, None);
        assert_eq!(tracked.row.bytes_sent, Some(200));
        assert!(reconcile(&mut known, vec![flow(Some(42), Some(100))], false).is_empty());
        let events = reconcile(&mut known, Vec::new(), false);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].state, "closed");
        assert!(events[0].duration_ms.unwrap() >= 50);
        assert_eq!(events[0].bytes_sent, Some(200));
    }

    #[test]
    fn flow_fifo_history_detects_generation_and_pid_changes_across_unknown_polls() {
        for changed in [flow(Some(42), Some(200)), flow(Some(43), None)] {
            let mut known = HashMap::new();
            assert_eq!(
                reconcile(&mut known, vec![flow(Some(42), Some(100))], false).len(),
                1
            );
            assert!(reconcile(&mut known, vec![flow(Some(42), None)], false).is_empty());
            assert!(reconcile(&mut known, vec![flow(None, None)], false).is_empty());
            let events = reconcile(&mut known, vec![changed], false);
            assert_eq!(events.len(), 2);
            let old = events.iter().find(|event| event.state == "closed").unwrap();
            assert_eq!((old.pid, old.process_start_time), (Some(42), Some(100)));
            assert!(events.iter().any(|event| event.state == "established"));
        }
    }

    #[test]
    fn flow_fifo_never_guesses_ambiguous_owners_and_preserves_known_exact_matches() {
        let mut known = HashMap::new();
        let owners = vec![flow(Some(42), Some(100)), flow(Some(43), Some(200))];
        assert_eq!(reconcile(&mut known, owners.clone(), false).len(), 2);
        assert!(reconcile(&mut known, owners.clone(), false).is_empty());
        let events = reconcile(&mut known, vec![flow(None, None)], false);
        assert_eq!(events.len(), 3);
        assert_eq!(known.len(), 1);
        assert_eq!(known.values().next().unwrap().owner, (None, None));
        assert_eq!(reconcile(&mut known, owners, false).len(), 3);
        assert_eq!(known.len(), 2);
        // ETW owns emission, but the fallback still carries existing lifetimes.
        assert!(reconcile(&mut known, vec![flow(Some(42), Some(100))], true).is_empty());
        assert!(reconcile(&mut known, vec![flow(None, None)], false).is_empty());
    }

    #[test]
    fn native_tcp_snapshot_binds_socket_owner_to_observed_generation() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let pid = std::process::id() as i32;
        let expected = crate::telemetry::identity::process_start_time(pid).unwrap();
        let rows = snapshot().unwrap();
        let row = rows
            .iter()
            .find(|row| row.pid == Some(pid) && row.src_port == port)
            .expect("own TCP listener is visible in the native owner-PID table");
        assert_eq!(row.process_start_time, Some(expected));
    }
}
