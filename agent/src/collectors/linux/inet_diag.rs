//! Per-connection byte/packet counters via `INET_DIAG` (`sock_diag` netlink).
//!
//! `/proc/net/tcp` exposes only the current send/recv *queue* depth, not the
//! cumulative byte/packet totals a Falcon-class netflow record needs. Those live
//! in the kernel's per-socket `tcp_info`, reachable from userspace via the
//! `NETLINK_SOCK_DIAG` family — no eBPF required. This module issues an
//! `INET_DIAG_REQ_V2` dump for TCP (IPv4 + IPv6) and returns a
//! `socket-inode → `[`FlowStats`] map the [`super::network`] collector joins
//! onto its flow records.
//!
//! ## ABI safety
//!
//! `tcp_info` only ever *grows* (fields are appended across kernel versions), so
//! the byte/packet fields sit at stable offsets. The risk is an *older* kernel
//! returning a shorter struct — handled by [`parse_tcp_info`], which reads a
//! field only when the returned attribute actually covers its offset. That
//! offset-parsing is pure and unit-tested; the netlink socket I/O around it is
//! best-effort and degrades to an empty map (e.g. when blocked by sandboxing or
//! lacking privilege).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;

use tracing::debug;

// ── Netlink / sock_diag constants (not all are in the libc crate) ─────────────
const NETLINK_SOCK_DIAG: libc::c_int = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
/// `idiag_ext` bit requesting `INET_DIAG_INFO` (= attr 2 → bit `1 << (2-1)`).
const INET_DIAG_INFO_REQ: u8 = 1 << 1;
/// rtattr type for the `tcp_info` blob.
const INET_DIAG_INFO: u16 = 2;
/// All TCP states (`idiag_states` is a bitmask over TCP states).
const TCP_STATES_ALL: u32 = 0xffff_ffff;

/// `inet_diag_msg` field offsets (the message body before the rtattrs).
const IDIAG_MSG_LEN: usize = 72; // NLMSG_ALIGN(sizeof(struct inet_diag_msg))
const IDIAG_FAMILY_OFF: usize = 0;
const IDIAG_STATE_OFF: usize = 1;
// `struct inet_diag_sockid id` starts at offset 4.
const IDIAG_SPORT_OFF: usize = 4;
const IDIAG_DPORT_OFF: usize = 6;
const IDIAG_SRC_OFF: usize = 8;
const IDIAG_DST_OFF: usize = 24;
const IDIAG_INODE_OFF: usize = 68;

/// `TCP_ESTABLISHED`, the only "connected" state worth cross-checking.
pub const TCP_ESTABLISHED: u8 = 1;
/// `TCP_LISTEN`.
pub const TCP_LISTEN: u8 = 10;

// ── tcp_info field offsets (bytes from the start of the struct) ───────────────
// Stable since the fields were introduced (only ever appended).
const TCPI_RTT_OFF: usize = 68; //   __u32 tcpi_rtt
const TCPI_BYTES_ACKED_OFF: usize = 120; // __u64 tcpi_bytes_acked
const TCPI_BYTES_RECEIVED_OFF: usize = 128; // __u64 tcpi_bytes_received
const TCPI_SEGS_OUT_OFF: usize = 136; // __u32 tcpi_segs_out
const TCPI_SEGS_IN_OFF: usize = 140; // __u32 tcpi_segs_in

/// Cumulative counters for one connection, extracted from `tcp_info`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowStats {
    pub bytes_sent: Option<u64>,
    pub bytes_recv: Option<u64>,
    pub packets_sent: Option<u64>,
    pub packets_recv: Option<u64>,
    pub rtt_us: Option<u32>,
}

impl FlowStats {
    fn is_empty(&self) -> bool {
        self.bytes_sent.is_none()
            && self.bytes_recv.is_none()
            && self.packets_sent.is_none()
            && self.packets_recv.is_none()
            && self.rtt_us.is_none()
    }
}

/// Query `tcp_info` for every TCP socket (IPv4 + IPv6); returns inode → stats.
/// Best-effort: any error degrades to an empty map.
pub fn query_tcp() -> HashMap<u64, FlowStats> {
    let mut map = HashMap::new();
    for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
        match query_family(family) {
            Ok(part) => map.extend(part),
            Err(e) => debug!("inet_diag: query for family {family} failed: {e}"),
        }
    }
    map
}

fn query_family(family: u8) -> std::io::Result<HashMap<u64, FlowStats>> {
    let mut out = HashMap::new();
    dump(family, IPPROTO_TCP, |body| {
        if let Some((inode, stats)) = parse_inet_diag_msg(body) {
            if !stats.is_empty() {
                out.insert(inode, stats);
            }
        }
    })?;
    Ok(out)
}

/// Run one `SOCK_DIAG_BY_FAMILY` dump, handing each returned `inet_diag_msg`
/// body to `on_msg`. Shared by the flow-stats join and the socket cross-view.
fn dump<F: FnMut(&[u8])>(family: u8, protocol: u8, mut on_msg: F) -> std::io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_SOCK_DIAG) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let guard = FdGuard(fd);

    let req = build_request(family, protocol);
    let sent = unsafe { libc::send(guard.0, req.as_ptr() as *const libc::c_void, req.len(), 0) };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = unsafe { libc::recv(guard.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            break;
        }
        match parse_dump(&buf[..n as usize], &mut on_msg) {
            ParseOutcome::Done => break,
            ParseOutcome::More => continue,
            ParseOutcome::Error => break,
        }
    }
    Ok(())
}

/// One socket as the kernel reports it over netlink.
///
/// This is the second, independent answer to "which sockets exist" that
/// [`crate::rootkit::hidden_socket`] compares against `/proc/net/*`: it is a
/// binary netlink protocol rather than a formatted text file, so hiding a
/// socket from it takes a different hook than hiding it from procfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagSocket {
    pub protocol: &'static str,
    pub state: u8,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub inode: u64,
}

/// Dump every TCP and UDP socket (IPv4 + IPv6) via `sock_diag`.
/// Best-effort: an unavailable netlink family degrades to fewer entries.
pub fn query_sockets() -> Vec<DiagSocket> {
    let mut out = Vec::new();
    for (protocol, name) in [(IPPROTO_TCP, "tcp"), (IPPROTO_UDP, "udp")] {
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            if let Err(e) = dump(family, protocol, |body| {
                if let Some(sock) = parse_socket(body, name) {
                    out.push(sock);
                }
            }) {
                debug!("inet_diag: socket dump for {name}/{family} failed: {e}");
            }
        }
    }
    out
}

/// Build a `SOCK_DIAG_BY_FAMILY` / `INET_DIAG_REQ_V2` dump request.
fn build_request(family: u8, protocol: u8) -> Vec<u8> {
    // nlmsghdr(16) + inet_diag_req_v2(56)
    let total = 16 + 56;
    let mut m = vec![0u8; total];
    // nlmsghdr
    m[0..4].copy_from_slice(&(total as u32).to_ne_bytes());
    m[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    m[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    m[8..12].copy_from_slice(&1u32.to_ne_bytes()); // seq
    m[12..16].copy_from_slice(&0u32.to_ne_bytes()); // pid
                                                    // inet_diag_req_v2 (starts at 16)
    m[16] = family; // sdiag_family
    m[17] = protocol; // sdiag_protocol
    m[18] = INET_DIAG_INFO_REQ; // idiag_ext
    m[19] = 0; // pad
    m[20..24].copy_from_slice(&TCP_STATES_ALL.to_ne_bytes()); // idiag_states
                                                              // id (sockid, 48 bytes) left zeroed → dump all
    m
}

enum ParseOutcome {
    Done,
    More,
    Error,
}

/// Walk the netlink messages in `data`, handing each `inet_diag_msg` body to
/// `on_msg`.
fn parse_dump<F: FnMut(&[u8])>(data: &[u8], on_msg: &mut F) -> ParseOutcome {
    let mut off = 0usize;
    while off + 16 <= data.len() {
        let len =
            u32::from_ne_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as usize;
        let mtype = u16::from_ne_bytes([data[off + 4], data[off + 5]]);
        if len < 16 || off + len > data.len() {
            break;
        }
        match mtype {
            NLMSG_DONE => return ParseOutcome::Done,
            NLMSG_ERROR => return ParseOutcome::Error,
            SOCK_DIAG_BY_FAMILY => on_msg(&data[off + 16..off + len]),
            _ => {}
        }
        // Messages are NLMSG_ALIGN(4)-padded.
        off += align4(len);
    }
    ParseOutcome::More
}

/// Parse one `inet_diag_msg` body: inode + the `tcp_info` rtattr stats.
fn parse_inet_diag_msg(body: &[u8]) -> Option<(u64, FlowStats)> {
    if body.len() < IDIAG_MSG_LEN {
        return None;
    }
    let inode = u32::from_ne_bytes([
        body[IDIAG_INODE_OFF],
        body[IDIAG_INODE_OFF + 1],
        body[IDIAG_INODE_OFF + 2],
        body[IDIAG_INODE_OFF + 3],
    ]) as u64;

    let mut stats = FlowStats::default();
    // rtattrs follow the fixed message body.
    let mut p = IDIAG_MSG_LEN;
    while p + 4 <= body.len() {
        let rta_len = u16::from_ne_bytes([body[p], body[p + 1]]) as usize;
        let rta_type = u16::from_ne_bytes([body[p + 2], body[p + 3]]);
        if rta_len < 4 || p + rta_len > body.len() {
            break;
        }
        let payload = &body[p + 4..p + rta_len];
        if rta_type == INET_DIAG_INFO {
            stats = parse_tcp_info(payload);
        }
        p += align4(rta_len);
    }
    Some((inode, stats))
}

/// Parse one `inet_diag_msg` body into a socket identity.
///
/// Ports and addresses are network byte order regardless of host endianness,
/// which is why they are read big-endian while the surrounding netlink headers
/// are read natively.
fn parse_socket(body: &[u8], protocol: &'static str) -> Option<DiagSocket> {
    if body.len() < IDIAG_MSG_LEN {
        return None;
    }
    let family = body[IDIAG_FAMILY_OFF];
    let local_addr = read_addr(body, IDIAG_SRC_OFF, family)?;
    let remote_addr = read_addr(body, IDIAG_DST_OFF, family)?;
    Some(DiagSocket {
        protocol,
        state: body[IDIAG_STATE_OFF],
        local_addr,
        local_port: u16::from_be_bytes([body[IDIAG_SPORT_OFF], body[IDIAG_SPORT_OFF + 1]]),
        remote_addr,
        remote_port: u16::from_be_bytes([body[IDIAG_DPORT_OFF], body[IDIAG_DPORT_OFF + 1]]),
        inode: u32::from_ne_bytes([
            body[IDIAG_INODE_OFF],
            body[IDIAG_INODE_OFF + 1],
            body[IDIAG_INODE_OFF + 2],
            body[IDIAG_INODE_OFF + 3],
        ]) as u64,
    })
}

fn read_addr(body: &[u8], off: usize, family: u8) -> Option<IpAddr> {
    if family == libc::AF_INET as u8 {
        let b = body.get(off..off + 4)?;
        Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
    } else {
        let b = body.get(off..off + 16)?;
        let mut octets = [0u8; 16];
        octets.copy_from_slice(b);
        Some(IpAddr::V6(Ipv6Addr::from(octets)))
    }
}

/// Extract the byte/packet/rtt counters from a `tcp_info` blob, reading each
/// field only when the returned blob is long enough to contain it (older
/// kernels return a shorter struct). Pure + unit-tested.
pub fn parse_tcp_info(info: &[u8]) -> FlowStats {
    let read_u32 = |off: usize| -> Option<u32> {
        info.get(off..off + 4)
            .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
    };
    let read_u64 = |off: usize| -> Option<u64> {
        info.get(off..off + 8)
            .map(|b| u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    };
    FlowStats {
        bytes_sent: read_u64(TCPI_BYTES_ACKED_OFF),
        bytes_recv: read_u64(TCPI_BYTES_RECEIVED_OFF),
        packets_sent: read_u32(TCPI_SEGS_OUT_OFF).map(u64::from),
        packets_recv: read_u32(TCPI_SEGS_IN_OFF).map(u64::from),
        rtt_us: read_u32(TCPI_RTT_OFF),
    }
}

#[inline]
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Closes the netlink fd on drop.
struct FdGuard(RawFd);
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_tcp_info() {
        // A modern-length tcp_info: 232 bytes, with known counter values.
        let mut info = vec![0u8; 232];
        info[TCPI_RTT_OFF..TCPI_RTT_OFF + 4].copy_from_slice(&12_345u32.to_ne_bytes());
        info[TCPI_BYTES_ACKED_OFF..TCPI_BYTES_ACKED_OFF + 8]
            .copy_from_slice(&1_000_000u64.to_ne_bytes());
        info[TCPI_BYTES_RECEIVED_OFF..TCPI_BYTES_RECEIVED_OFF + 8]
            .copy_from_slice(&2_000_000u64.to_ne_bytes());
        info[TCPI_SEGS_OUT_OFF..TCPI_SEGS_OUT_OFF + 4].copy_from_slice(&500u32.to_ne_bytes());
        info[TCPI_SEGS_IN_OFF..TCPI_SEGS_IN_OFF + 4].copy_from_slice(&750u32.to_ne_bytes());

        let s = parse_tcp_info(&info);
        assert_eq!(s.bytes_sent, Some(1_000_000));
        assert_eq!(s.bytes_recv, Some(2_000_000));
        assert_eq!(s.packets_sent, Some(500));
        assert_eq!(s.packets_recv, Some(750));
        assert_eq!(s.rtt_us, Some(12_345));
    }

    #[test]
    fn short_tcp_info_degrades_gracefully() {
        // An old/truncated tcp_info (only up to rtt) → byte/segs fields None,
        // rtt still recovered. Must never panic / over-read.
        let mut info = vec![0u8; TCPI_RTT_OFF + 4];
        info[TCPI_RTT_OFF..TCPI_RTT_OFF + 4].copy_from_slice(&999u32.to_ne_bytes());
        let s = parse_tcp_info(&info);
        assert_eq!(s.rtt_us, Some(999));
        assert!(s.bytes_sent.is_none());
        assert!(s.packets_sent.is_none());
        assert!(!s.is_empty());
    }

    #[test]
    fn empty_tcp_info_is_all_none() {
        assert!(parse_tcp_info(&[]).is_empty());
    }

    #[test]
    fn parses_inet_diag_msg_with_info_attr() {
        // Build a minimal inet_diag_msg body: 72-byte header (inode at 68) plus
        // one INET_DIAG_INFO rtattr carrying a tcp_info.
        let mut info = vec![0u8; 232];
        info[TCPI_BYTES_ACKED_OFF..TCPI_BYTES_ACKED_OFF + 8].copy_from_slice(&42u64.to_ne_bytes());

        let mut body = vec![0u8; IDIAG_MSG_LEN];
        body[IDIAG_INODE_OFF..IDIAG_INODE_OFF + 4].copy_from_slice(&123_456u32.to_ne_bytes());
        // rtattr header: len, type
        let rta_len = (4 + info.len()) as u16;
        body.extend_from_slice(&rta_len.to_ne_bytes());
        body.extend_from_slice(&INET_DIAG_INFO.to_ne_bytes());
        body.extend_from_slice(&info);

        let (inode, stats) = parse_inet_diag_msg(&body).unwrap();
        assert_eq!(inode, 123_456);
        assert_eq!(stats.bytes_sent, Some(42));
    }

    #[test]
    fn parses_a_socket_identity_from_an_inet_diag_msg() {
        let mut body = vec![0u8; IDIAG_MSG_LEN];
        body[IDIAG_FAMILY_OFF] = libc::AF_INET as u8;
        body[IDIAG_STATE_OFF] = TCP_LISTEN;
        body[IDIAG_SPORT_OFF..IDIAG_SPORT_OFF + 2].copy_from_slice(&22u16.to_be_bytes());
        body[IDIAG_DPORT_OFF..IDIAG_DPORT_OFF + 2].copy_from_slice(&0u16.to_be_bytes());
        body[IDIAG_SRC_OFF..IDIAG_SRC_OFF + 4].copy_from_slice(&[10, 0, 0, 5]);
        body[IDIAG_INODE_OFF..IDIAG_INODE_OFF + 4].copy_from_slice(&4242u32.to_ne_bytes());

        let s = parse_socket(&body, "tcp").unwrap();
        assert_eq!(s.local_port, 22, "ports are network byte order");
        assert_eq!(s.local_addr.to_string(), "10.0.0.5");
        assert_eq!(s.state, TCP_LISTEN);
        assert_eq!(s.inode, 4242);
    }

    #[test]
    fn parses_an_ipv6_socket_identity() {
        let mut body = vec![0u8; IDIAG_MSG_LEN];
        body[IDIAG_FAMILY_OFF] = libc::AF_INET6 as u8;
        body[IDIAG_SRC_OFF..IDIAG_SRC_OFF + 16].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        body[IDIAG_SPORT_OFF..IDIAG_SPORT_OFF + 2].copy_from_slice(&443u16.to_be_bytes());

        let s = parse_socket(&body, "tcp").unwrap();
        assert_eq!(s.local_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(s.local_port, 443);
    }

    #[test]
    fn a_truncated_socket_message_is_rejected_not_guessed() {
        assert!(parse_socket(&[0u8; 8], "tcp").is_none());
    }

    #[test]
    fn align4_rounds_up() {
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
    }
}
