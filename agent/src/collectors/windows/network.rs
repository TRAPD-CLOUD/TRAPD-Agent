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
        let mut known: HashMap<String, (NetworkConnectionData, Instant)> = HashMap::new();
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
            let mut current = HashMap::new();
            for row in rows.into_iter().filter(|r| r.state == "established") {
                let key = format!(
                    "{}:{}:{}:{}:{}:{:?}",
                    row.protocol, row.src_addr, row.src_port, row.dst_addr, row.dst_port, row.pid
                );
                let since = known
                    .get(&key)
                    .map(|(_, since)| *since)
                    .unwrap_or_else(Instant::now);
                if !etw_active && !known.contains_key(&key) {
                    let event = AgentEvent::new(
                        agent_id.clone(),
                        hostname.clone(),
                        EventClass::Network,
                        EventAction::Connection,
                        Severity::Info,
                        EventData::NetworkConnection(row.clone()),
                    );
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
                current.insert(key, (row, since));
            }
            if etw_active {
                // ETW owns emission (start and close). Keep the snapshot fresh
                // so a later ETW outage does not re-announce live connections.
                known = current;
                continue;
            }
            for (key, (mut row, since)) in known {
                if current.contains_key(&key) {
                    continue;
                }
                row.state = "closed".into();
                row.duration_ms = Some(since.elapsed().as_millis() as u64);
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
            known = current;
        }
    }
}
