//! Passive packet capture for DNS responses and TLS handshakes (userspace, no
//! eBPF).
//!
//! Falcon-class network telemetry needs two things the query-only eBPF DNS probe
//! and the `/proc/net` flow poller cannot provide:
//!
//!   * **DNS responses** — the *resolved* A/AAAA set, so a later outbound
//!     connection can be correlated back to the domain that produced its IP.
//!   * **TLS SNI + JA3** — the requested server name and the client fingerprint,
//!     the pivot for C2-over-TLS detection and malware-family attribution.
//!
//! Both are recovered by passively sniffing with an `AF_PACKET`/`SOCK_DGRAM`
//! socket (L3 frames, link-layer stripped by the kernel) and parsing the packets
//! in pure, unit-tested functions. The socket is best-effort: without
//! `CAP_NET_RAW` it fails to open and the collector exits cleanly, exactly like
//! the eBPF collectors — every other collector keeps running.
//!
//! Scope is deliberately narrow (UDP/53 responses and the TLS ClientHello in the
//! first TCP segment) so the parse path stays bounded and the capture volume
//! low; deep TCP reassembly / JA3S (server-side) are out of scope here.

use std::net::IpAddr;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::Sender;
use tracing::info;

use crate::collectors::Collector;
use crate::schema::{
    AgentEvent, DnsResolutionData, EventAction, EventClass, EventData, Severity, TlsHandshakeData,
};

// ── IP protocol constants ─────────────────────────────────────────────────────
const IPPROTO_UDP: u8 = 17;
const IPPROTO_TCP: u8 = 6;

// ── Collector ─────────────────────────────────────────────────────────────────

pub struct PacketCaptureCollector;

impl PacketCaptureCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PacketCaptureCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for PacketCaptureCollector {
    fn name(&self) -> &'static str {
        "PacketCaptureCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let sock = open_packet_socket()
            .context("AF_PACKET socket (needs CAP_NET_RAW) — passive DNS/TLS capture disabled")?;
        let async_fd = AsyncFd::new(sock).context("AsyncFd for packet socket")?;
        info!("Passive DNS/TLS capture attached (AF_PACKET)");

        let mut buf = [0u8; 65_536];
        loop {
            let mut guard = async_fd.readable().await?;
            // Drain everything currently queued before re-arming readiness.
            loop {
                let fd = guard.get_inner().0;
                let n =
                    unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
                if n <= 0 {
                    // EWOULDBLOCK (queue drained) or a transient error: re-arm.
                    guard.clear_ready();
                    break;
                }
                let frame = &buf[..n as usize];
                for ev in parse_frame(frame) {
                    let event = match ev {
                        CaptureEvent::Dns(d) => AgentEvent::new(
                            agent_id.clone(),
                            hostname.clone(),
                            EventClass::Network,
                            EventAction::DnsResponse,
                            Severity::Info,
                            EventData::DnsResolution(d),
                        ),
                        CaptureEvent::Tls(t) => AgentEvent::new(
                            agent_id.clone(),
                            hostname.clone(),
                            EventClass::Network,
                            EventAction::TlsHandshake,
                            Severity::Info,
                            EventData::TlsHandshake(t),
                        ),
                    };
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Owns the raw fd and closes it on drop. The frame protocol is delivered out of
/// band via `sockaddr_ll`, but for `SOCK_DGRAM` the payload starts at L3 and we
/// dispatch on the IP version nibble, so we do not need `recvfrom` here.
struct PacketSocket(libc::c_int);

impl std::os::unix::io::AsRawFd for PacketSocket {
    fn as_raw_fd(&self) -> libc::c_int {
        self.0
    }
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// Open a non-blocking `AF_PACKET`/`SOCK_DGRAM` socket capturing all protocols.
fn open_packet_socket() -> Result<PacketSocket> {
    // htons(ETH_P_ALL)
    let proto = (libc::ETH_P_ALL as u16).to_be() as libc::c_int;
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK,
            proto,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(PacketSocket(fd))
}

// ── Parsed-event enum ─────────────────────────────────────────────────────────

#[derive(Debug)]
enum CaptureEvent {
    Dns(DnsResolutionData),
    Tls(TlsHandshakeData),
}

/// Parse one captured L3 frame (IP packet) into zero or more capture events.
fn parse_frame(frame: &[u8]) -> Vec<CaptureEvent> {
    let mut out = Vec::new();
    let Some(l3) = parse_l3(frame) else {
        return out;
    };
    match l3.proto {
        IPPROTO_UDP => {
            if let Some((sport, dport, payload)) = parse_udp(l3.payload) {
                // DNS responses originate from port 53. Only parse responses
                // (QR bit set) so we emit the resolved set, not the query.
                if sport == 53 {
                    if let Some(d) = parse_dns_response(payload, l3.dst, l3.src, dport) {
                        out.push(CaptureEvent::Dns(d));
                    }
                }
            }
        }
        IPPROTO_TCP => {
            if let Some((_sport, dport, payload)) = parse_tcp(l3.payload) {
                if let Some(t) = parse_tls(payload, l3.src, l3.dst, dport) {
                    out.push(CaptureEvent::Tls(t));
                }
            }
        }
        _ => {}
    }
    out
}

// ── L3 (IPv4 / IPv6) ──────────────────────────────────────────────────────────

struct L3<'a> {
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    payload: &'a [u8],
}

fn parse_l3(data: &[u8]) -> Option<L3<'_>> {
    let version = data.first()? >> 4;
    match version {
        4 => parse_ipv4(data),
        6 => parse_ipv6(data),
        _ => None,
    }
}

fn parse_ipv4(data: &[u8]) -> Option<L3<'_>> {
    if data.len() < 20 {
        return None;
    }
    let ihl = (data[0] & 0x0f) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    let proto = data[9];
    let src = IpAddr::from([data[12], data[13], data[14], data[15]]);
    let dst = IpAddr::from([data[16], data[17], data[18], data[19]]);
    Some(L3 {
        proto,
        src,
        dst,
        payload: &data[ihl..],
    })
}

fn parse_ipv6(data: &[u8]) -> Option<L3<'_>> {
    if data.len() < 40 {
        return None;
    }
    // No extension-header chasing: only accept a UDP/TCP next-header directly.
    let next = data[6];
    if next != IPPROTO_UDP && next != IPPROTO_TCP {
        return None;
    }
    let mut s = [0u8; 16];
    let mut d = [0u8; 16];
    s.copy_from_slice(&data[8..24]);
    d.copy_from_slice(&data[24..40]);
    Some(L3 {
        proto: next,
        src: IpAddr::from(s),
        dst: IpAddr::from(d),
        payload: &data[40..],
    })
}

fn parse_udp(data: &[u8]) -> Option<(u16, u16, &[u8])> {
    if data.len() < 8 {
        return None;
    }
    let sport = u16::from_be_bytes([data[0], data[1]]);
    let dport = u16::from_be_bytes([data[2], data[3]]);
    Some((sport, dport, &data[8..]))
}

fn parse_tcp(data: &[u8]) -> Option<(u16, u16, &[u8])> {
    if data.len() < 20 {
        return None;
    }
    let sport = u16::from_be_bytes([data[0], data[1]]);
    let dport = u16::from_be_bytes([data[2], data[3]]);
    let data_off = (data[12] >> 4) as usize * 4;
    if data_off < 20 || data.len() < data_off {
        return None;
    }
    Some((sport, dport, &data[data_off..]))
}

// ── DNS ─────────────────────────────────────────────────────────────────────

fn qtype_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        _ => "OTHER",
    }
}

fn rcode_name(flags: u16) -> &'static str {
    match flags & 0x000f {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

/// Parse a DNS *response* message into a [`DnsResolutionData`]. Returns `None`
/// for malformed packets or non-responses (QR bit clear).
fn parse_dns_response(
    msg: &[u8],
    client_addr: IpAddr,
    server_addr: IpAddr,
    _client_port: u16,
) -> Option<DnsResolutionData> {
    if msg.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    // QR bit (response) must be set.
    if flags & 0x8000 == 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);
    if qdcount == 0 {
        return None;
    }

    let mut pos = 12;
    // Question: name + qtype(2) + qclass(2). We keep the first question.
    let (qname, after) = read_name(msg, pos)?;
    pos = after;
    if pos + 4 > msg.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
    pos += 4;

    let mut resolved_ips = Vec::new();
    let mut cnames = Vec::new();

    for _ in 0..ancount {
        // Answer: name, type(2), class(2), ttl(4), rdlength(2), rdata.
        let (_aname, after) = read_name(msg, pos)?;
        pos = after;
        if pos + 10 > msg.len() {
            break;
        }
        let atype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            break;
        }
        let rdata = &msg[pos..pos + rdlen];
        match atype {
            1 if rdlen == 4 => {
                resolved_ips
                    .push(IpAddr::from([rdata[0], rdata[1], rdata[2], rdata[3]]).to_string());
            }
            28 if rdlen == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(rdata);
                resolved_ips.push(IpAddr::from(a).to_string());
            }
            5 => {
                if let Some((cname, _)) = read_name(msg, pos) {
                    cnames.push(cname);
                }
            }
            _ => {}
        }
        pos += rdlen;
    }

    Some(DnsResolutionData {
        qname,
        qtype: qtype_name(qtype).to_string(),
        resolved_ips,
        cnames,
        server_addr: server_addr.to_string(),
        client_addr: client_addr.to_string(),
        transaction_id: id,
        rcode: rcode_name(flags).to_string(),
    })
}

/// Read a (possibly compressed) DNS name starting at `start`. Returns the name
/// and the offset *after the name in the record stream* (i.e. past the first
/// pointer, per RFC 1035). Bounded against pointer loops.
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut after = start;
    let mut hops = 0;

    loop {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            if !jumped {
                after = pos;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer (two bytes).
            let b2 = *msg.get(pos + 1)? as usize;
            let ptr = ((len & 0x3f) << 8) | b2;
            if !jumped {
                after = pos + 2;
            }
            jumped = true;
            hops += 1;
            if hops > 64 || ptr >= msg.len() {
                return None;
            }
            pos = ptr;
            continue;
        }
        // Plain label.
        let s = pos + 1;
        let e = s + len;
        let label = msg.get(s..e)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos = e;
        if !jumped {
            after = pos;
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Some((name, after))
}

// ── TLS ClientHello + JA3 ─────────────────────────────────────────────────────

struct ClientHello {
    legacy_version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    groups: Vec<u16>,
    point_formats: Vec<u8>,
    supported_versions: Vec<u16>,
    sni: Option<String>,
    alpn: Vec<String>,
}

/// GREASE values (RFC 8701) are excluded from JA3 — pattern `0x?A?A`.
fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a
}

fn tls_version_name(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "unknown",
    }
}

/// Parse a TLS record carrying a ClientHello (first TCP segment) into a
/// [`TlsHandshakeData`] with SNI + JA3. Returns `None` if it isn't a ClientHello.
fn parse_tls(payload: &[u8], src: IpAddr, dst: IpAddr, dport: u16) -> Option<TlsHandshakeData> {
    let ch = parse_client_hello(payload)?;

    // Prefer the highest non-GREASE supported_versions entry, else the legacy
    // version, for the human-readable label.
    let version_for_label = ch
        .supported_versions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(ch.legacy_version);

    let ja3 = ja3_string(&ch);
    let ja3_hash = md5_hex(ja3.as_bytes());

    Some(TlsHandshakeData {
        src_addr: src.to_string(),
        dst_addr: dst.to_string(),
        dst_port: dport,
        sni: ch.sni,
        tls_version: tls_version_name(version_for_label).to_string(),
        ja3,
        ja3_hash,
        alpn: ch.alpn,
    })
}

/// JA3 = `SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats`, each
/// list dash-joined, GREASE filtered. Version uses the legacy ClientHello field.
fn ja3_string(ch: &ClientHello) -> String {
    let join_u16 = |v: &[u16]| -> String {
        v.iter()
            .filter(|x| !is_grease(**x))
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    let ciphers = join_u16(&ch.ciphers);
    let exts = join_u16(&ch.extensions);
    let groups = join_u16(&ch.groups);
    let formats = ch
        .point_formats
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join("-");
    format!(
        "{},{},{},{},{}",
        ch.legacy_version, ciphers, exts, groups, formats
    )
}

fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Parse the ClientHello out of one or more TLS records in `payload`.
fn parse_client_hello(payload: &[u8]) -> Option<ClientHello> {
    // TLS record header: type(1)=22 handshake, version(2), length(2).
    if payload.len() < 5 || payload[0] != 22 {
        return None;
    }
    let rec_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let body = payload.get(5..5 + rec_len.min(payload.len().saturating_sub(5)))?;

    // Handshake header: type(1)=1 ClientHello, length(3).
    if body.len() < 4 || body[0] != 1 {
        return None;
    }
    let mut p = 4usize;

    // client_version(2)
    let legacy_version = be16(body, p)?;
    p += 2;
    // random(32)
    p += 32;
    // session_id
    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;
    // cipher_suites
    let cs_len = be16(body, p)? as usize;
    p += 2;
    let cs = body.get(p..p + cs_len)?;
    let ciphers: Vec<u16> = cs
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect();
    p += cs_len;
    // compression_methods
    let cm_len = *body.get(p)? as usize;
    p += 1 + cm_len;

    let mut ch = ClientHello {
        legacy_version,
        ciphers,
        extensions: Vec::new(),
        groups: Vec::new(),
        point_formats: Vec::new(),
        supported_versions: Vec::new(),
        sni: None,
        alpn: Vec::new(),
    };

    // extensions (optional)
    if p + 2 <= body.len() {
        let ext_total = be16(body, p)? as usize;
        p += 2;
        let ext_end = (p + ext_total).min(body.len());
        while p + 4 <= ext_end {
            let etype = be16(body, p)?;
            let elen = be16(body, p + 2)? as usize;
            p += 4;
            let edata = body.get(p..(p + elen).min(body.len()))?;
            ch.extensions.push(etype);
            parse_extension(&mut ch, etype, edata);
            p += elen;
        }
    }

    Some(ch)
}

fn parse_extension(ch: &mut ClientHello, etype: u16, edata: &[u8]) {
    match etype {
        // server_name
        0 => {
            // list_len(2), then entries: type(1), name_len(2), name.
            if edata.len() >= 5 && edata[2] == 0 {
                let nlen = u16::from_be_bytes([edata[3], edata[4]]) as usize;
                if edata.len() >= 5 + nlen {
                    ch.sni = Some(String::from_utf8_lossy(&edata[5..5 + nlen]).into_owned());
                }
            }
        }
        // supported_groups (elliptic curves)
        10 => {
            if edata.len() >= 2 {
                let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
                for c in edata.get(2..2 + list_len).unwrap_or(&[]).as_chunks::<2>().0 {
                    ch.groups.push(u16::from_be_bytes(*c));
                }
            }
        }
        // ec_point_formats
        11 => {
            if let Some(&len) = edata.first() {
                for &b in edata.get(1..1 + len as usize).unwrap_or(&[]) {
                    ch.point_formats.push(b);
                }
            }
        }
        // ALPN
        16 => {
            // list_len(2), then entries: proto_len(1), proto.
            let mut i = 2;
            while i < edata.len() {
                let l = edata[i] as usize;
                i += 1;
                if let Some(p) = edata.get(i..i + l) {
                    ch.alpn.push(String::from_utf8_lossy(p).into_owned());
                }
                i += l;
            }
        }
        // supported_versions
        43 => {
            if let Some(&len) = edata.first() {
                for c in edata
                    .get(1..1 + len as usize)
                    .unwrap_or(&[])
                    .as_chunks::<2>()
                    .0
                {
                    ch.supported_versions.push(u16::from_be_bytes(*c));
                }
            }
        }
        _ => {}
    }
}

fn be16(data: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*data.get(off)?, *data.get(off + 1)?]))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── DNS ──────────────────────────────────────────────────────────────────

    /// Build a DNS response for `example.com` → 93.184.216.34, with a CNAME.
    fn sample_dns_response() -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        m.extend_from_slice(&0x8180u16.to_be_bytes()); // flags: QR+RD+RA, NOERROR
        m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        m.extend_from_slice(&2u16.to_be_bytes()); // ancount
        m.extend_from_slice(&0u16.to_be_bytes()); // nscount
        m.extend_from_slice(&0u16.to_be_bytes()); // arcount
                                                  // Question: example.com A IN
        m.push(7);
        m.extend_from_slice(b"example");
        m.push(3);
        m.extend_from_slice(b"com");
        m.push(0);
        m.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        m.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
                                                  // Answer 1: CNAME (name = pointer to offset 12)
        m.extend_from_slice(&0xC00Cu16.to_be_bytes());
        m.extend_from_slice(&5u16.to_be_bytes()); // type CNAME
        m.extend_from_slice(&1u16.to_be_bytes()); // class
        m.extend_from_slice(&300u32.to_be_bytes()); // ttl
        let cname_start = m.len();
        m.extend_from_slice(&0u16.to_be_bytes()); // rdlength placeholder
        let rd = {
            let mut r = Vec::new();
            r.push(3);
            r.extend_from_slice(b"abc");
            r.push(3);
            r.extend_from_slice(b"net");
            r.push(0);
            r
        };
        let rdlen = rd.len() as u16;
        m[cname_start..cname_start + 2].copy_from_slice(&rdlen.to_be_bytes());
        m.extend_from_slice(&rd);
        // Answer 2: A 93.184.216.34
        m.extend_from_slice(&0xC00Cu16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes()); // type A
        m.extend_from_slice(&1u16.to_be_bytes()); // class
        m.extend_from_slice(&300u32.to_be_bytes()); // ttl
        m.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        m.extend_from_slice(&[93, 184, 216, 34]);
        m
    }

    #[test]
    fn parses_dns_response_with_cname_and_a() {
        let msg = sample_dns_response();
        let d = parse_dns_response(
            &msg,
            "10.0.0.5".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            54321,
        )
        .unwrap();
        assert_eq!(d.qname, "example.com");
        assert_eq!(d.qtype, "A");
        assert_eq!(d.rcode, "NOERROR");
        assert_eq!(d.transaction_id, 0x1234);
        assert!(d.resolved_ips.contains(&"93.184.216.34".to_string()));
        assert!(d.cnames.contains(&"abc.net".to_string()));
        assert_eq!(d.server_addr, "1.1.1.1");
        assert_eq!(d.client_addr, "10.0.0.5");
    }

    #[test]
    fn ignores_dns_query_qr_clear() {
        let mut msg = sample_dns_response();
        msg[2] = 0x01; // clear QR bit (flags high byte → 0x01)
        assert!(parse_dns_response(
            &msg,
            "10.0.0.5".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            1
        )
        .is_none());
    }

    #[test]
    fn read_name_rejects_pointer_loop() {
        // A name that is a pointer to itself → must not hang.
        let msg = [0xC0u8, 0x00];
        assert!(read_name(&msg, 0).is_none());
    }

    // ── L3 / L4 ────────────────────────────────────────────────────────────────

    #[test]
    fn parses_ipv4_udp() {
        let mut pkt = vec![
            0x45,
            0x00,
            0x00,
            0x00, // ver/ihl, tos, total len
            0x00,
            0x00,
            0x00,
            0x00, // id, frag
            0x40,
            IPPROTO_UDP,
            0x00,
            0x00, // ttl, proto, checksum
            10,
            0,
            0,
            1, // src
            8,
            8,
            8,
            8, // dst
        ];
        // UDP header: sport 53, dport 1000, len, csum
        pkt.extend_from_slice(&53u16.to_be_bytes());
        pkt.extend_from_slice(&1000u16.to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        let l3 = parse_l3(&pkt).unwrap();
        assert_eq!(l3.proto, IPPROTO_UDP);
        assert_eq!(l3.src.to_string(), "10.0.0.1");
        let (sport, dport, _) = parse_udp(l3.payload).unwrap();
        assert_eq!((sport, dport), (53, 1000));
    }

    // ── TLS / JA3 ────────────────────────────────────────────────────────────

    /// Minimal ClientHello: TLS1.2 legacy, one cipher 0x1301, SNI=example.com,
    /// one GREASE cipher that must be filtered from JA3.
    fn sample_client_hello() -> Vec<u8> {
        let mut hs = Vec::new();
        hs.push(1); // ClientHello
        let len_pos = hs.len();
        hs.extend_from_slice(&[0, 0, 0]); // handshake length placeholder
        hs.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy version TLS1.2
        hs.extend_from_slice(&[0u8; 32]); // random
        hs.push(0); // session id len
                    // cipher suites: GREASE 0x0a0a + 0x1301
        hs.extend_from_slice(&4u16.to_be_bytes());
        hs.extend_from_slice(&0x0a0au16.to_be_bytes());
        hs.extend_from_slice(&0x1301u16.to_be_bytes());
        hs.push(1); // compression methods len
        hs.push(0); // null compression
                    // extensions
        let mut exts = Vec::new();
        // SNI ext (0)
        let mut sni = Vec::new();
        let host = b"example.com";
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes()); // server_name_list len
        sni.push(0); // type host_name
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        exts.extend_from_slice(&0u16.to_be_bytes());
        exts.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni);
        // supported_groups ext (10): one group 0x001d
        let mut grp = Vec::new();
        grp.extend_from_slice(&2u16.to_be_bytes());
        grp.extend_from_slice(&0x001du16.to_be_bytes());
        exts.extend_from_slice(&10u16.to_be_bytes());
        exts.extend_from_slice(&(grp.len() as u16).to_be_bytes());
        exts.extend_from_slice(&grp);
        // ec_point_formats ext (11): one format 0
        exts.extend_from_slice(&11u16.to_be_bytes());
        exts.extend_from_slice(&2u16.to_be_bytes());
        exts.push(1);
        exts.push(0);

        hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        hs.extend_from_slice(&exts);

        // fix handshake length
        let hs_len = (hs.len() - 4) as u32;
        hs[len_pos..len_pos + 3].copy_from_slice(&hs_len.to_be_bytes()[1..4]);

        // wrap in a TLS record
        let mut rec = Vec::new();
        rec.push(22); // handshake
        rec.extend_from_slice(&0x0301u16.to_be_bytes()); // record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn parses_client_hello_sni_and_ja3() {
        let rec = sample_client_hello();
        let t = parse_tls(
            &rec,
            "10.0.0.5".parse().unwrap(),
            "1.2.3.4".parse().unwrap(),
            443,
        )
        .unwrap();
        assert_eq!(t.sni.as_deref(), Some("example.com"));
        assert_eq!(t.tls_version, "TLS 1.2");
        // JA3 string: version=771, ciphers=4865 (GREASE 0x0a0a filtered),
        // exts=0-10-11, groups=29, formats=0
        assert_eq!(t.ja3, "771,4865,0-10-11,29,0");
        // 32-hex md5
        assert_eq!(t.ja3_hash.len(), 32);
        assert!(t.ja3_hash.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x1301));
        assert!(!is_grease(0x0000));
    }

    #[test]
    fn non_tls_payload_is_none() {
        assert!(parse_client_hello(b"GET / HTTP/1.1\r\n").is_none());
        assert!(parse_client_hello(&[22, 3, 1, 0, 2, 99, 0]).is_none()); // handshake type 99
    }

    #[test]
    fn frame_dispatch_emits_dns() {
        // Build an IPv4/UDP frame carrying the sample DNS response from port 53.
        let dns = sample_dns_response();
        let mut pkt = vec![
            0x45,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0x40,
            IPPROTO_UDP,
            0,
            0,
            1,
            1,
            1,
            1,
            10,
            0,
            0,
            5,
        ];
        pkt.extend_from_slice(&53u16.to_be_bytes());
        pkt.extend_from_slice(&33333u16.to_be_bytes());
        pkt.extend_from_slice(&((dns.len() + 8) as u16).to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&dns);
        let events = parse_frame(&pkt);
        assert_eq!(events.len(), 1);
        match &events[0] {
            CaptureEvent::Dns(d) => assert_eq!(d.qname, "example.com"),
            _ => panic!("expected DNS event"),
        }
    }
}
