//! Sockets the kernel knows about but the host's own tools do not show.
//!
//! `/proc/net/tcp` and friends are formatted text files; `sock_diag` netlink is
//! a binary protocol into the same socket tables. They are read by completely
//! different code paths, so a rootkit that filters the text a `netstat` reads
//! usually leaves the netlink answer (what modern `ss` uses) intact, and vice
//! versa. Where the two disagree, something is filtering one of them.
//!
//! The eBPF bind sightings add a third view from below both: a port the kernel
//! was asked to bind, whose binding process is still alive, that neither
//! userspace view accounts for.
//!
//! ## Directionality
//!
//! Only "visible over netlink, absent from procfs" is reported. The opposite
//! direction is a normal race — a netlink dump is a point-in-time snapshot and
//! a socket can close during it — and is not evidence of concealment, so
//! treating it as such would trade a real signal for noise.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde_json::json;

use super::{Confirmation, Finding};
use crate::collectors::linux::inet_diag::{self, DiagSocket, TCP_ESTABLISHED, TCP_LISTEN};
use crate::schema::Severity;

/// One socket, in a form both views can be reduced to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SocketKey {
    pub protocol: &'static str,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
}

impl SocketKey {
    fn describe(&self) -> String {
        format!(
            "{}/{}:{} -> {}:{}",
            self.protocol, self.local_addr, self.local_port, self.remote_addr, self.remote_port
        )
    }
}

/// A bind the eBPF tracer saw, whose process is still running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelBind {
    pub port: u16,
    pub pid: i32,
    pub comm: String,
}

#[derive(Debug, Default, Clone)]
pub struct SocketViews {
    /// Sockets parsed out of `/proc/net/{tcp,tcp6,udp,udp6}`.
    pub procfs: BTreeSet<SocketKey>,
    /// Sockets returned by a `sock_diag` netlink dump.
    pub netlink: BTreeSet<SocketKey>,
    /// Every local port either userspace view accounts for.
    pub visible_ports: BTreeSet<u16>,
    /// Binds observed below both views, filtered to live processes.
    pub kernel_binds: Vec<KernelBind>,
}

pub fn analyze(views: &SocketViews) -> Vec<Finding> {
    let mut out = Vec::new();

    for key in views.netlink.difference(&views.procfs) {
        out.push(Finding {
            rule_id: "rootkit.socket_hidden_from_procfs",
            title: "Socket visible over netlink but absent from /proc/net",
            confirmation: Confirmation::Corroborate,
            severity: Severity::Critical,
            confidence: 85,
            mitre_tactic: "TA0005 Defense Evasion",
            mitre_technique: "T1014",
            subject: key.describe(),
            detail: format!(
                "The kernel reports {} over sock_diag netlink, but it does not appear in \
                 /proc/net/{}. The text interface that netstat and every /proc-based tool \
                 read is being filtered while the netlink view still shows the socket.",
                key.describe(),
                key.protocol
            ),
            evidence: json!({
                "protocol": key.protocol,
                "local_addr": key.local_addr,
                "local_port": key.local_port,
                "remote_addr": key.remote_addr,
                "remote_port": key.remote_port,
                "views": { "netlink": true, "procfs": false },
            }),
        });
    }

    for bind in &views.kernel_binds {
        if views.visible_ports.contains(&bind.port) {
            continue;
        }
        out.push(Finding {
            rule_id: "rootkit.listener_hidden_from_host_views",
            title: "Bound port missing from both /proc/net and netlink",
            confirmation: Confirmation::Corroborate,
            severity: Severity::High,
            confidence: 70,
            mitre_tactic: "TA0005 Defense Evasion",
            mitre_technique: "T1014",
            subject: format!("port:{}", bind.port),
            detail: format!(
                "Process {} (pid {}) bound port {} and is still running, but neither \
                 /proc/net nor sock_diag netlink reports a socket on that port.",
                bind.comm, bind.pid, bind.port
            ),
            evidence: json!({
                "port": bind.port,
                "pid": bind.pid,
                "comm": bind.comm,
                "views": { "ebpf_bind": true, "procfs": false, "netlink": false },
            }),
        });
    }

    out
}

// ── Host collection ─────────────────────────────────────────────────────────

/// IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) are how a dual-stack socket
/// shows up in the v6 tables. Both views must render them the same way or every
/// dual-stack socket looks like a mismatch.
fn canonical_ip(addr: IpAddr) -> String {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
        IpAddr::V4(v4) => v4.to_string(),
    }
}

/// TCP sockets in transient states (`TIME_WAIT`, `SYN_RECV`, …) churn far too
/// fast for a cross-view comparison to say anything; only a listening or
/// established socket is stable enough for a disagreement to mean something.
fn tcp_state_is_stable(state: u8) -> bool {
    state == TCP_ESTABLISHED || state == TCP_LISTEN
}

fn key_from_diag(sock: &DiagSocket) -> SocketKey {
    SocketKey {
        protocol: sock.protocol,
        local_addr: canonical_ip(sock.local_addr),
        local_port: sock.local_port,
        remote_addr: canonical_ip(sock.remote_addr),
        remote_port: sock.remote_port,
    }
}

pub fn gather(kernel_binds: &[(u16, super::kernel_view::BindSighting)]) -> SocketViews {
    let mut procfs = BTreeSet::new();
    let mut visible_ports = BTreeSet::new();

    let mut tcp = Vec::new();
    if let Ok(v) = procfs::net::tcp() {
        tcp.extend(v);
    }
    if let Ok(v) = procfs::net::tcp6() {
        tcp.extend(v);
    }
    for entry in &tcp {
        visible_ports.insert(entry.local_address.port());
        let stable = matches!(
            entry.state,
            procfs::net::TcpState::Established | procfs::net::TcpState::Listen
        );
        if !stable {
            continue;
        }
        procfs.insert(SocketKey {
            protocol: "tcp",
            local_addr: canonical_ip(entry.local_address.ip()),
            local_port: entry.local_address.port(),
            remote_addr: canonical_ip(entry.remote_address.ip()),
            remote_port: entry.remote_address.port(),
        });
    }

    let mut udp = Vec::new();
    if let Ok(v) = procfs::net::udp() {
        udp.extend(v);
    }
    if let Ok(v) = procfs::net::udp6() {
        udp.extend(v);
    }
    for entry in &udp {
        visible_ports.insert(entry.local_address.port());
        procfs.insert(SocketKey {
            protocol: "udp",
            local_addr: canonical_ip(entry.local_address.ip()),
            local_port: entry.local_address.port(),
            remote_addr: canonical_ip(entry.remote_address.ip()),
            remote_port: entry.remote_address.port(),
        });
    }

    let mut netlink = BTreeSet::new();
    for sock in inet_diag::query_sockets() {
        visible_ports.insert(sock.local_port);
        if sock.protocol == "tcp" && !tcp_state_is_stable(sock.state) {
            continue;
        }
        netlink.insert(key_from_diag(&sock));
    }

    // A bind whose process has exited took its socket with it; reporting the
    // port as hidden would just be reporting that the listener stopped.
    let kernel_binds = kernel_binds
        .iter()
        .filter(|(_, sighting)| super::task_exists(sighting.pid))
        .map(|(port, sighting)| KernelBind {
            port: *port,
            pid: sighting.pid,
            comm: sighting.comm.clone(),
        })
        .collect();

    SocketViews {
        procfs,
        netlink,
        visible_ports,
        kernel_binds,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn key(protocol: &'static str, local_port: u16) -> SocketKey {
        SocketKey {
            protocol,
            local_addr: "0.0.0.0".into(),
            local_port,
            remote_addr: "0.0.0.0".into(),
            remote_port: 0,
        }
    }

    #[test]
    fn a_socket_only_netlink_can_see_is_reported() {
        let views = SocketViews {
            netlink: [key("tcp", 31337)].into_iter().collect(),
            procfs: BTreeSet::new(),
            visible_ports: [31337].into_iter().collect(),
            kernel_binds: Vec::new(),
        };
        let found = analyze(&views);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "rootkit.socket_hidden_from_procfs");
    }

    #[test]
    fn agreeing_views_produce_nothing() {
        let views = SocketViews {
            netlink: [key("tcp", 22)].into_iter().collect(),
            procfs: [key("tcp", 22)].into_iter().collect(),
            visible_ports: [22].into_iter().collect(),
            kernel_binds: Vec::new(),
        };
        assert!(analyze(&views).is_empty());
    }

    #[test]
    fn a_socket_only_procfs_can_see_is_not_reported() {
        // The netlink dump racing a closing socket is not concealment.
        let views = SocketViews {
            netlink: BTreeSet::new(),
            procfs: [key("tcp", 22)].into_iter().collect(),
            visible_ports: [22].into_iter().collect(),
            kernel_binds: Vec::new(),
        };
        assert!(analyze(&views).is_empty());
    }

    #[test]
    fn a_bound_port_no_view_accounts_for_is_reported() {
        let views = SocketViews {
            kernel_binds: vec![KernelBind {
                port: 4444,
                pid: 1234,
                comm: "nc".into(),
            }],
            ..Default::default()
        };
        let found = analyze(&views);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "rootkit.listener_hidden_from_host_views");
        assert_eq!(found[0].subject, "port:4444");
    }

    #[test]
    fn a_bound_port_either_view_accounts_for_is_not_reported() {
        let views = SocketViews {
            visible_ports: [4444].into_iter().collect(),
            kernel_binds: vec![KernelBind {
                port: 4444,
                pid: 1234,
                comm: "nc".into(),
            }],
            ..Default::default()
        };
        assert!(analyze(&views).is_empty());
    }

    #[test]
    fn dual_stack_addresses_render_identically_in_both_views() {
        assert_eq!(
            canonical_ip(IpAddr::V6("::ffff:10.0.0.1".parse::<Ipv6Addr>().unwrap())),
            canonical_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            "a dual-stack socket must not look like a cross-view mismatch"
        );
    }

    #[test]
    fn only_stable_tcp_states_are_compared() {
        assert!(tcp_state_is_stable(TCP_LISTEN));
        assert!(tcp_state_is_stable(TCP_ESTABLISHED));
        assert!(
            !tcp_state_is_stable(6),
            "TIME_WAIT churns too fast to compare"
        );
    }
}
