//! Network reconnaissance & lateral-movement heuristics.
//!
//! Pure, time-injected trackers (like [`super::beaconing`]) so they are
//! deterministic, unit-testable and reusable by the future Windows agent.
//!
//! Three behaviours are tracked, each keyed and windowed independently:
//!
//!   * **Port scan** — one host contacted on many *distinct ports* within a
//!     short window (horizontal knowledge-gathering of a single target).
//!   * **Address sweep / lateral movement** — many *distinct internal hosts*
//!     contacted on the same admin/service port (SSH, SMB, RDP, WinRM) within a
//!     window (an attacker spreading across the network).
//!   * **Cloud metadata (IMDS) access** — any connection to `169.254.169.254`,
//!     the AWS/GCP/Azure instance-metadata endpoint commonly abused to steal
//!     cloud credentials.
//!
//! Each behaviour fires once per key per window, then resets, to avoid storms.

use std::collections::HashMap;

/// Distinct ports on one host within the window to call a port scan.
const PORT_SCAN_THRESHOLD: usize = 15;
/// Distinct hosts on one admin port within the window to call a sweep.
const SWEEP_THRESHOLD: usize = 10;
/// Sliding window length (seconds) for both detectors.
const WINDOW_SECS: f64 = 60.0;

/// Admin / remote-service ports whose fan-out across hosts signals lateral
/// movement.  Port → human label.
const ADMIN_PORTS: &[(u16, &str)] = &[
    (22, "SSH"),
    (23, "Telnet"),
    (135, "MSRPC"),
    (139, "NetBIOS"),
    (445, "SMB"),
    (1433, "MSSQL"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (5985, "WinRM-HTTP"),
    (5986, "WinRM-HTTPS"),
    (6379, "Redis"),
];

/// The cloud instance-metadata service address (all major providers).
pub const IMDS_ADDR: &str = "169.254.169.254";

/// What [`NetScanTracker::observe`] decided about one connection.
#[derive(Debug, Clone, PartialEq)]
pub enum NetVerdict {
    PortScan { target: String, ports: usize },
    LateralMovement { port: u16, service: String, hosts: usize },
    ImdsAccess,
}

#[derive(Default)]
struct Window<K: std::hash::Hash + Eq> {
    /// observed item -> last-seen time, for windowing
    seen: HashMap<K, f64>,
    alerted_at: Option<f64>,
}

impl<K: std::hash::Hash + Eq + Clone> Window<K> {
    fn prune(&mut self, now: f64) {
        self.seen.retain(|_, &mut t| now - t <= WINDOW_SECS);
        if let Some(a) = self.alerted_at {
            if now - a > WINDOW_SECS {
                self.alerted_at = None;
            }
        }
    }
    fn insert(&mut self, k: K, now: f64) -> usize {
        self.seen.insert(k, now);
        self.seen.len()
    }
    fn ready_to_alert(&self) -> bool {
        self.alerted_at.is_none()
    }
    fn mark_alerted(&mut self, now: f64) {
        self.alerted_at = Some(now);
    }
}

/// Tracks per-target port fan-out and per-port host fan-out.
#[derive(Default)]
pub struct NetScanTracker {
    /// dst_addr -> set of dst_ports seen
    by_target: HashMap<String, Window<u16>>,
    /// admin dst_port -> set of dst_addrs seen
    by_port: HashMap<u16, Window<String>>,
}

impl NetScanTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one outbound connection.  Returns any verdicts it triggers
    /// (usually zero; occasionally one; IMDS + scan could both fire).
    pub fn observe(&mut self, dst_addr: &str, dst_port: u16, now: f64) -> Vec<NetVerdict> {
        let mut out = Vec::new();

        // ── Cloud metadata access (fires every time; it is always notable) ──
        if dst_addr == IMDS_ADDR {
            out.push(NetVerdict::ImdsAccess);
        }

        // ── Port scan: many distinct ports on one target ──
        let tw = self.by_target.entry(dst_addr.to_string()).or_default();
        tw.prune(now);
        let distinct_ports = tw.insert(dst_port, now);
        if distinct_ports >= PORT_SCAN_THRESHOLD && tw.ready_to_alert() {
            tw.mark_alerted(now);
            out.push(NetVerdict::PortScan {
                target: dst_addr.to_string(),
                ports: distinct_ports,
            });
        }

        // ── Lateral movement: one admin port fanned across many hosts ──
        if let Some((_, service)) = ADMIN_PORTS.iter().find(|(p, _)| *p == dst_port) {
            // Only internal/private destinations count as lateral movement.
            if is_private_ipv4(dst_addr) {
                let pw = self.by_port.entry(dst_port).or_default();
                pw.prune(now);
                let distinct_hosts = pw.insert(dst_addr.to_string(), now);
                if distinct_hosts >= SWEEP_THRESHOLD && pw.ready_to_alert() {
                    pw.mark_alerted(now);
                    out.push(NetVerdict::LateralMovement {
                        port: dst_port,
                        service: (*service).to_string(),
                        hosts: distinct_hosts,
                    });
                }
            }
        }

        out
    }

    /// Distinct items currently retained (diagnostics).
    #[allow(dead_code)]
    pub fn tracked_targets(&self) -> usize {
        self.by_target.len()
    }
}

/// RFC1918 / CGNAT private IPv4 ranges (lateral movement is an *internal*
/// behaviour; scanning the public internet on :22 is not "lateral").
fn is_private_ipv4(addr: &str) -> bool {
    let octets: Vec<u8> = addr.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 {
        // IPv6 unique-local fc00::/7
        let lower = addr.to_ascii_lowercase();
        return lower.starts_with("fc") || lower.starts_with("fd");
    }
    match (octets[0], octets[1]) {
        (10, _) => true,
        (172, b) if (16..=31).contains(&b) => true,
        (192, 168) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_port_scan() {
        let mut t = NetScanTracker::new();
        let mut hit = None;
        for port in 1..=20u16 {
            for v in t.observe("198.51.100.5", port, 1.0) {
                if let NetVerdict::PortScan { ports, .. } = v {
                    hit = Some(ports);
                }
            }
        }
        assert!(hit.is_some(), "should detect a horizontal port scan");
    }

    #[test]
    fn detects_lateral_movement_on_ssh() {
        let mut t = NetScanTracker::new();
        let mut hit = false;
        // 12 distinct internal hosts on :22 within the window.
        for h in 1..=12u8 {
            for v in t.observe(&format!("10.0.0.{h}"), 22, 5.0) {
                if let NetVerdict::LateralMovement { service, .. } = v {
                    assert_eq!(service, "SSH");
                    hit = true;
                }
            }
        }
        assert!(hit, "should detect SSH sweep across internal hosts");
    }

    #[test]
    fn public_ssh_is_not_lateral() {
        let mut t = NetScanTracker::new();
        let mut hit = false;
        for h in 1..=20u8 {
            // public addresses — not internal, so not lateral movement
            for v in t.observe(&format!("93.184.216.{h}"), 22, 5.0) {
                if matches!(v, NetVerdict::LateralMovement { .. }) {
                    hit = true;
                }
            }
        }
        assert!(!hit, "public SSH fan-out must not be flagged as lateral movement");
    }

    #[test]
    fn detects_imds_access() {
        let mut t = NetScanTracker::new();
        let v = t.observe(IMDS_ADDR, 80, 1.0);
        assert!(v.contains(&NetVerdict::ImdsAccess));
    }

    #[test]
    fn benign_traffic_is_quiet() {
        let mut t = NetScanTracker::new();
        assert!(t.observe("93.184.216.34", 443, 1.0).is_empty());
        assert!(t.observe("10.0.0.5", 443, 1.0).is_empty()); // 443 is not an admin port
    }

    #[test]
    fn private_range_classification() {
        assert!(is_private_ipv4("10.1.2.3"));
        assert!(is_private_ipv4("172.16.0.1"));
        assert!(is_private_ipv4("172.31.255.255"));
        assert!(!is_private_ipv4("172.32.0.1"));
        assert!(is_private_ipv4("192.168.1.1"));
        assert!(!is_private_ipv4("8.8.8.8"));
    }
}
