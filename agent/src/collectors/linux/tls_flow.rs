//! Bounded TLS handshake tracking for the passive packet capture: multi-segment
//! reassembly of the first ClientHello / ServerHello of a flow, plus JA3S.
//!
//! The capture socket delivers individual IP packets. A modern ClientHello
//! (post-quantum key shares, many extensions) regularly spans several TCP
//! segments, and the ServerHello travels in the *reverse* direction. This module
//! keeps a small per-flow state machine so one `tls_handshake` event can carry
//! the client fingerprint (JA3 + SNI) and the server fingerprint (JA3S):
//!
//! 1. A segment starting with a TLS handshake record whose handshake type is
//!    ClientHello creates a flow keyed by the client-oriented 4-tuple.
//! 2. Further client segments are placed by TCP sequence offset (first bytes
//!    win, so an on-path injector cannot rewrite bytes already accepted) until
//!    the first handshake message is complete.
//! 3. The finished ClientHello becomes a pending [`TlsHandshakeData`]; the flow
//!    then waits for the ServerHello in the reverse direction, reassembled the
//!    same way, and attaches `ja3s`.
//! 4. The event is released when the ServerHello arrives, the flow is closed
//!    (FIN/RST) or its TTL expires. A client event is never lost merely because
//!    the server side was not seen.
//!
//! Resource bounds (every limit is a constant below): per-direction buffer
//! [`MAX_STREAM_BYTES`], at most [`MAX_PENDING_SEGMENTS`] out-of-order segments
//! per direction, at most [`MAX_FLOWS`] concurrent flows (worst case about
//! 16 MiB), absolute flow lifetime [`FLOW_TTL`]. Only the first handshake
//! message of each direction is ever buffered; once it is complete (or the
//! stream proves not to be TLS) the buffers are freed.
//!
//! Loss accounting uses the existing [`DropReason`] vocabulary, and only for
//! resource-driven shedding (never for merely malformed traffic, so a hostile
//! peer cannot inflate the counters by sending garbage):
//!   * handshake larger than the buffer cap  -> `EventTooLarge`
//!   * flow table full, new flow refused     -> `RateLimitApplied`
//!   * ClientHello incomplete at TTL expiry  -> `EnrichmentTimeout`
//!
//! Known limit: a HelloRetryRequest (TLS 1.3) is recognised and yields no JA3S
//! (it is not the server's final hello); the client event is still emitted.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::packet_capture::{client_hello_event, is_grease};
use crate::schema::TlsHandshakeData;
use crate::telemetry::{metrics::metrics, DropReason};

/// Per-direction reassembly buffer (contiguous bytes plus out-of-order bytes).
pub(super) const MAX_STREAM_BYTES: usize = 16 * 1024;
/// Out-of-order segments held per direction while waiting for a gap to fill.
pub(super) const MAX_PENDING_SEGMENTS: usize = 8;
/// Concurrent tracked flows. 512 x 2 directions x 16 KiB = 16 MiB worst case.
pub(super) const MAX_FLOWS: usize = 512;
/// Absolute lifetime of a flow from its first ClientHello segment.
pub(super) const FLOW_TTL: Duration = Duration::from_secs(10);
/// Maximum plaintext TLS record body (RFC 8446 section 5.1).
const MAX_RECORD_BODY: usize = 16 * 1024;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

/// `ServerHello.random` value that marks a HelloRetryRequest (RFC 8446 4.1.3).
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// The TCP fields the tracker needs from one captured segment.
#[derive(Debug, Clone, Copy)]
pub(super) struct TcpSegment<'a> {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

// ── JA3S ──────────────────────────────────────────────────────────────────────

/// The fields of a ServerHello that JA3S needs.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ServerHello {
    pub version: u16,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub hello_retry: bool,
}

impl ServerHello {
    /// JA3S string: `SSLVersion,Cipher,Extensions` (decimal, extensions in wire
    /// order, dash-joined). The version is the legacy `server_version` field, as
    /// in the Salesforce JA3S reference, so TLS 1.3 shows as 771. GREASE
    /// extension types (RFC 8701) are excluded like in JA3; the single cipher is
    /// kept verbatim.
    pub(super) fn ja3s_string(&self) -> String {
        let exts = self
            .extensions
            .iter()
            .filter(|e| !is_grease(**e))
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");
        format!("{},{},{}", self.version, self.cipher, exts)
    }
}

/// Parse a complete ServerHello handshake message (starting at the handshake
/// header). Returns `None` for anything malformed; never panics.
pub(super) fn parse_server_hello(msg: &[u8]) -> Option<ServerHello> {
    if msg.len() < 4 || msg[0] != HS_SERVER_HELLO {
        return None;
    }
    let declared = u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize;
    let body = msg.get(4..4usize.checked_add(declared)?)?;
    let version = u16::from_be_bytes([*body.first()?, *body.get(1)?]);
    let random = body.get(2..34)?;
    let hello_retry = random == HELLO_RETRY_RANDOM;
    let mut p = 34usize;
    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;
    let cipher = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]);
    p += 2;
    let _compression = *body.get(p)?;
    p += 1;
    let mut extensions = Vec::new();
    if p < body.len() {
        let total = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
        p += 2;
        let end = p.checked_add(total)?;
        if end != body.len() {
            return None;
        }
        while p < end {
            let etype = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]);
            let elen = u16::from_be_bytes([*body.get(p + 2)?, *body.get(p + 3)?]) as usize;
            p += 4;
            if p.checked_add(elen)? > end {
                return None;
            }
            extensions.push(etype);
            p += elen;
        }
    }
    Some(ServerHello {
        version,
        cipher,
        extensions,
        hello_retry,
    })
}

// ── Record layer / handshake extraction ───────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum Extract {
    /// More bytes are needed.
    Need,
    /// The first handshake message, complete (header included).
    Msg(Vec<u8>),
    /// Not a TLS handshake stream of the expected shape.
    Invalid,
    /// The handshake message cannot fit the reassembly cap.
    TooLarge,
}

/// Concatenate handshake-record payloads from the start of `buf` and return the
/// first handshake message once complete. `expect` is the handshake type the
/// stream must begin with.
fn extract_handshake(buf: &[u8], expect: u8) -> Extract {
    let mut pos = 0usize;
    let mut hs: Vec<u8> = Vec::new();
    loop {
        let Some(hdr) = buf.get(pos..pos + 5) else {
            return Extract::Need;
        };
        if hdr[0] != 22 || hdr[1] != 3 {
            return Extract::Invalid;
        }
        let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        if rec_len == 0 || rec_len > MAX_RECORD_BODY {
            return Extract::Invalid;
        }
        pos += 5;
        let avail = buf.len().saturating_sub(pos).min(rec_len);
        hs.extend_from_slice(&buf[pos..pos + avail]);
        if hs.first().is_some_and(|t| *t != expect) {
            return Extract::Invalid;
        }
        if hs.len() >= 4 {
            let msg_len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
            // The whole message plus at least its first record header must fit.
            if msg_len + 4 + 5 > MAX_STREAM_BYTES {
                return Extract::TooLarge;
            }
            if hs.len() >= msg_len + 4 {
                hs.truncate(msg_len + 4);
                return Extract::Msg(hs);
            }
        }
        if avail < rec_len {
            return Extract::Need;
        }
        pos += rec_len;
    }
}

// ── Bounded one-direction reassembly ──────────────────────────────────────────

/// Reassembles one direction of a TCP stream from its first sequence number.
/// First-write-wins: bytes already accepted are never overwritten.
struct Stream {
    base: u32,
    data: Vec<u8>,
    pending: BTreeMap<usize, Vec<u8>>,
    pending_bytes: usize,
}

impl Stream {
    fn new(base: u32) -> Self {
        Self {
            base,
            data: Vec::new(),
            pending: BTreeMap::new(),
            pending_bytes: 0,
        }
    }

    /// Insert a segment. Returns true if the contiguous prefix grew.
    fn insert(&mut self, seq: u32, payload: &[u8]) -> bool {
        let diff = seq.wrapping_sub(self.base);
        if diff >= 0x8000_0000 {
            return false; // before the stream start (old retransmission)
        }
        let off = diff as usize;
        if off >= MAX_STREAM_BYTES || payload.is_empty() {
            return false; // outside the window: ignore, never abort the flow
        }
        let payload = &payload[..payload.len().min(MAX_STREAM_BYTES - off)];
        if off <= self.data.len() {
            let skip = self.data.len() - off;
            if skip >= payload.len() {
                return false; // pure duplicate
            }
            self.data.extend_from_slice(&payload[skip..]);
            self.drain_pending();
            true
        } else {
            if self.pending.len() >= MAX_PENDING_SEGMENTS
                || self.pending.contains_key(&off)
                || self.pending_bytes + payload.len() > MAX_STREAM_BYTES
            {
                return false;
            }
            self.pending_bytes += payload.len();
            self.pending.insert(off, payload.to_vec());
            false
        }
    }

    fn drain_pending(&mut self) {
        while let Some((&off, _)) = self.pending.first_key_value() {
            if off > self.data.len() {
                break;
            }
            let seg = self.pending.remove(&off).unwrap_or_default();
            self.pending_bytes = self.pending_bytes.saturating_sub(seg.len());
            let skip = self.data.len() - off;
            if skip < seg.len() {
                self.data.extend_from_slice(&seg[skip..]);
            }
        }
    }
}

// ── Flow table ────────────────────────────────────────────────────────────────

/// Client-oriented 4-tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    client: (IpAddr, u16),
    server: (IpAddr, u16),
}

struct Flow {
    created: Instant,
    client: Stream,
    /// Set once the ClientHello is complete; waiting for the ServerHello.
    hello: Option<TlsHandshakeData>,
    server: Option<Stream>,
}

/// Does `payload` begin a TLS handshake record carrying a ClientHello /
/// ServerHello? Cheap pre-filter so unrelated TCP traffic costs nothing.
fn starts_with_hello(payload: &[u8], hs_type: u8) -> bool {
    payload.len() >= 6 && payload[0] == 22 && payload[1] == 3 && payload[5] == hs_type
}

#[derive(Default)]
pub(super) struct TlsTracker {
    flows: HashMap<FlowKey, Flow>,
    /// Resource-driven losses, mirrored into the global drop metrics.
    pub dropped: BTreeMap<DropReason, u64>,
}

impl TlsTracker {
    pub(super) fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(super) fn flow_count(&self) -> usize {
        self.flows.len()
    }

    fn note_drop(&mut self, reason: DropReason) {
        *self.dropped.entry(reason).or_insert(0) += 1;
        metrics().event_dropped(reason);
    }

    /// Feed one TCP segment (`src` -> `dst`). Returns events that became ready.
    pub(super) fn on_tcp(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        seg: &TcpSegment<'_>,
        now: Instant,
    ) -> Vec<TlsHandshakeData> {
        let mut out = Vec::new();
        let fwd = FlowKey {
            client: (src, seg.sport),
            server: (dst, seg.dport),
        };
        let rev = FlowKey {
            client: (dst, seg.dport),
            server: (src, seg.sport),
        };

        if self.flows.contains_key(&fwd) {
            self.client_segment(fwd, seg);
        } else if self.flows.contains_key(&rev) {
            self.server_segment(rev, seg, &mut out);
        } else if starts_with_hello(seg.payload, HS_CLIENT_HELLO) {
            if self.flows.len() >= MAX_FLOWS {
                out.extend(self.sweep(now));
            }
            if self.flows.len() >= MAX_FLOWS {
                // Refuse the new flow instead of evicting live ones, so a flood
                // of fake ClientHellos cannot flush genuine in-flight handshakes.
                self.note_drop(DropReason::RateLimitApplied);
                return out;
            }
            self.flows.insert(
                fwd,
                Flow {
                    created: now,
                    client: Stream::new(seg.seq),
                    hello: None,
                    server: None,
                },
            );
            self.client_segment(fwd, seg);
        } else {
            return out;
        }

        if seg.flags & (TCP_FIN | TCP_RST) != 0 {
            let key = if self.flows.contains_key(&fwd) {
                fwd
            } else {
                rev
            };
            if let Some(flow) = self.flows.remove(&key) {
                out.extend(flow.hello);
            }
        }
        out
    }

    fn client_segment(&mut self, key: FlowKey, seg: &TcpSegment<'_>) {
        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };
        if flow.hello.is_some() || !flow.client.insert(seg.seq, seg.payload) {
            return; // hello already complete, or nothing new
        }
        match extract_handshake(&flow.client.data, HS_CLIENT_HELLO) {
            Extract::Need => {}
            Extract::Msg(msg) => {
                match client_hello_event(&msg, key.client.0, key.server.0, key.server.1) {
                    Some(ev) => {
                        flow.hello = Some(ev);
                        flow.client = Stream::new(0); // free the buffer
                    }
                    None => {
                        self.flows.remove(&key);
                    }
                }
            }
            Extract::Invalid => {
                self.flows.remove(&key);
            }
            Extract::TooLarge => {
                self.flows.remove(&key);
                self.note_drop(DropReason::EventTooLarge);
            }
        }
    }

    fn server_segment(
        &mut self,
        key: FlowKey,
        seg: &TcpSegment<'_>,
        out: &mut Vec<TlsHandshakeData>,
    ) {
        let Some(flow) = self.flows.get_mut(&key) else {
            return;
        };
        if flow.hello.is_none() {
            return; // the server cannot answer an incomplete ClientHello
        }
        if flow.server.is_none() {
            if !starts_with_hello(seg.payload, HS_SERVER_HELLO) {
                return; // cannot anchor the stream on this segment
            }
            flow.server = Some(Stream::new(seg.seq));
        }
        let Some(stream) = flow.server.as_mut() else {
            return;
        };
        if !stream.insert(seg.seq, seg.payload) {
            return;
        }
        let finished = match extract_handshake(&stream.data, HS_SERVER_HELLO) {
            Extract::Need => return,
            Extract::Msg(msg) => parse_server_hello(&msg),
            Extract::Invalid => None,
            Extract::TooLarge => {
                self.note_drop(DropReason::EventTooLarge);
                None
            }
        };
        let Some(mut flow) = self.flows.remove(&key) else {
            return;
        };
        if let (Some(ev), Some(sh)) = (flow.hello.as_mut(), finished) {
            if !sh.hello_retry {
                let s = sh.ja3s_string();
                ev.ja3s = Some(md5_hex(s.as_bytes()));
                ev.ja3s_string = Some(s);
            }
        }
        out.extend(flow.hello);
    }

    /// Expire flows older than [`FLOW_TTL`]. Complete ClientHellos are released
    /// without JA3S; incomplete ones are counted as lost.
    pub(super) fn sweep(&mut self, now: Instant) -> Vec<TlsHandshakeData> {
        let expired: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, f)| now.saturating_duration_since(f.created) >= FLOW_TTL)
            .map(|(k, _)| *k)
            .collect();
        let mut out = Vec::new();
        for key in expired {
            if let Some(flow) = self.flows.remove(&key) {
                match flow.hello {
                    Some(ev) => out.push(ev),
                    None => self.note_drop(DropReason::EnrichmentTimeout),
                }
            }
        }
        out
    }
}

fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    hex::encode(Md5::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = "10.0.0.5";
    const SERVER: &str = "93.184.216.34";
    const CPORT: u16 = 50000;
    const SPORT: u16 = 443;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ── byte builders (RFC 8446 section 4.1.2 / RFC 5246 section 7.4.1) ──

    fn ext(t: u16, data: &[u8]) -> Vec<u8> {
        let mut v = t.to_be_bytes().to_vec();
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    fn handshake(ty: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![ty];
        v.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        v.extend_from_slice(body);
        v
    }

    /// Client hello handshake message; `pad` adds a padding extension (type 21)
    /// so tests can force multi-segment hellos.
    fn client_hello_msg(sni: &str, pad: usize) -> Vec<u8> {
        let mut b = vec![3, 3];
        b.extend_from_slice(&[7u8; 32]);
        b.push(0);
        b.extend_from_slice(&[0, 4, 0x0a, 0x0a, 0x13, 0x01]); // GREASE + TLS_AES_128_GCM
        b.extend_from_slice(&[1, 0]);
        let mut name = vec![0];
        name.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        name.extend_from_slice(sni.as_bytes());
        let mut list = (name.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&name);
        let mut exts = ext(0, &list);
        exts.extend_from_slice(&ext(10, &[0, 2, 0, 29]));
        exts.extend_from_slice(&ext(11, &[1, 0]));
        exts.extend_from_slice(&ext(21, &vec![0u8; pad]));
        b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        b.extend_from_slice(&exts);
        handshake(1, &b)
    }

    fn server_hello_msg(cipher: u16, exts: &[Vec<u8>], random: [u8; 32]) -> Vec<u8> {
        let mut b = vec![3, 3];
        b.extend_from_slice(&random);
        b.push(0);
        b.extend_from_slice(&cipher.to_be_bytes());
        b.push(0);
        let all: Vec<u8> = exts.concat();
        b.extend_from_slice(&(all.len() as u16).to_be_bytes());
        b.extend_from_slice(&all);
        handshake(2, &b)
    }

    /// Wrap a handshake message into records of at most `chunk` bytes each.
    fn records(msg: &[u8], chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for part in msg.chunks(chunk) {
            out.extend_from_slice(&[22, 3, 3]);
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// Known-answer capture: TLS 1.2 ServerHello for ECDHE-RSA-AES128-GCM
    /// (0xc02f) with renegotiation_info, ec_point_formats, session_ticket and
    /// ALPN("h2"). Built byte by byte from RFC 5246.
    #[rustfmt::skip]
    fn kat_server_hello_record() -> Vec<u8> {
        let mut r = vec![
            0x16, 0x03, 0x03, 0x00, 0x46,       // record: handshake, TLS1.2, len 70
            0x02, 0x00, 0x00, 0x42,             // ServerHello, length 66
            0x03, 0x03,                         // server_version TLS 1.2
        ];
        r.extend(0u8..32);                      // random
        r.extend_from_slice(&[
            0x00,                               // session_id length 0
            0xc0, 0x2f,                         // cipher TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0x00,                               // compression null
            0x00, 0x1a,                         // extensions length 26
            0xff, 0x01, 0x00, 0x01, 0x00,       // renegotiation_info (65281)
            0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, // ec_point_formats (11)
            0x00, 0x23, 0x00, 0x00,             // session_ticket (35)
            0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32, // ALPN h2 (16)
        ]);
        r
    }

    // Expected values computed independently of this crate's code:
    //   python3 -c 'import hashlib; print(hashlib.md5(b"771,49199,65281-11-35-16").hexdigest())'
    const KAT_JA3S_STRING: &str = "771,49199,65281-11-35-16";
    const KAT_JA3S_MD5: &str = "8d2a028aa94425f76ced7826b1f39039";
    //   md5("771,4865,43-51")
    const TLS13_JA3S_MD5: &str = "f4febc55ea12b31ae17cfb7e614afda8";

    #[test]
    fn known_answer_tls12_server_hello() {
        let rec = kat_server_hello_record();
        let Extract::Msg(msg) = extract_handshake(&rec, HS_SERVER_HELLO) else {
            panic!("record must yield a complete ServerHello");
        };
        let sh = parse_server_hello(&msg).unwrap();
        assert_eq!(sh.version, 0x0303);
        assert_eq!(sh.cipher, 0xc02f);
        assert_eq!(sh.extensions, vec![0xff01, 0x000b, 0x0023, 0x0010]);
        assert!(!sh.hello_retry);
        assert_eq!(sh.ja3s_string(), KAT_JA3S_STRING);
        assert_eq!(md5_hex(sh.ja3s_string().as_bytes()), KAT_JA3S_MD5);
    }

    #[test]
    fn known_answer_tls13_server_hello() {
        let mut key_share = vec![0x00, 0x1d, 0x00, 0x20];
        key_share.extend_from_slice(&[9u8; 32]);
        let msg = server_hello_msg(0x1301, &[ext(43, &[3, 4]), ext(51, &key_share)], [1u8; 32]);
        let sh = parse_server_hello(&msg).unwrap();
        // TLS 1.3 keeps legacy_version 0x0303 = 771 on the wire.
        assert_eq!(sh.ja3s_string(), "771,4865,43-51");
        assert_eq!(md5_hex(sh.ja3s_string().as_bytes()), TLS13_JA3S_MD5);
    }

    #[test]
    fn ja3s_excludes_grease_extensions_and_handles_no_extensions() {
        let sh = ServerHello {
            version: 771,
            cipher: 4865,
            extensions: vec![0x0a0a, 43, 0xfafa, 51],
            hello_retry: false,
        };
        assert_eq!(sh.ja3s_string(), "771,4865,43-51");
        let sh = ServerHello {
            extensions: vec![],
            ..sh
        };
        assert_eq!(sh.ja3s_string(), "771,4865,");
    }

    // ── hostile input: parsers ──

    #[test]
    fn server_hello_truncation_never_panics_or_succeeds() {
        let rec = kat_server_hello_record();
        let msg = &rec[5..];
        assert!(parse_server_hello(msg).is_some());
        for n in 0..msg.len() {
            assert!(parse_server_hello(&msg[..n]).is_none(), "prefix {n}");
        }
    }

    #[test]
    fn server_hello_wrong_lengths_are_rejected() {
        let good = kat_server_hello_record()[5..].to_vec();
        // handshake length larger than the bytes present
        let mut m = good.clone();
        m[3] = m[3].wrapping_add(1);
        assert!(parse_server_hello(&m).is_none());
        // extensions length larger than remaining body
        let mut m = good.clone();
        m[4 + 2 + 32 + 1 + 2 + 1 + 1] = 0xff;
        assert!(parse_server_hello(&m).is_none());
        // single extension claiming more data than present
        let mut m = good.clone();
        m[4 + 2 + 32 + 1 + 2 + 1 + 2 + 3] = 0xff;
        assert!(parse_server_hello(&m).is_none());
        // session id length pointing past the end
        let mut m = good.clone();
        m[4 + 2 + 32] = 0xff;
        assert!(parse_server_hello(&m).is_none());
        // wrong handshake type
        let mut m = good;
        m[0] = 1;
        assert!(parse_server_hello(&m).is_none());
    }

    #[test]
    fn hello_retry_request_is_flagged() {
        let msg = server_hello_msg(0x1301, &[ext(43, &[3, 4])], HELLO_RETRY_RANDOM);
        assert!(parse_server_hello(&msg).unwrap().hello_retry);
    }

    #[test]
    fn extract_handshake_edge_cases() {
        let msg = client_hello_msg("a.example", 0);
        let rec = records(&msg, 4096);
        assert_eq!(extract_handshake(&rec, 1), Extract::Msg(msg.clone()));
        // handshake split over many tiny records still reassembles
        assert_eq!(
            extract_handshake(&records(&msg, 7), 1),
            Extract::Msg(msg.clone())
        );
        // every strict prefix needs more data (or is rejected), never a message
        for n in 0..rec.len() {
            assert!(
                !matches!(extract_handshake(&rec[..n], 1), Extract::Msg(_)),
                "prefix {n}"
            );
        }
        // wrong handshake type for the direction
        assert_eq!(extract_handshake(&rec, 2), Extract::Invalid);
        // not a handshake record / wrong major version
        assert_eq!(
            extract_handshake(&[23, 3, 3, 0, 5, 1, 0, 0, 1, 0], 1),
            Extract::Invalid
        );
        assert_eq!(
            extract_handshake(&[22, 9, 9, 0, 5, 1, 0, 0, 1, 0], 1),
            Extract::Invalid
        );
        // zero-length and oversized record lengths
        assert_eq!(extract_handshake(&[22, 3, 3, 0, 0], 1), Extract::Invalid);
        assert_eq!(
            extract_handshake(&[22, 3, 3, 0xff, 0xff, 1], 1),
            Extract::Invalid
        );
        // huge 24-bit handshake length: rejected without buffering
        assert_eq!(
            extract_handshake(&[22, 3, 3, 0, 4, 1, 0xff, 0xff, 0xff], 1),
            Extract::TooLarge
        );
    }

    // ── hostile input: reassembly buffer ──

    #[test]
    fn stream_out_of_order_duplicate_and_overlap() {
        let mut s = Stream::new(1000);
        assert!(!s.insert(1005, b"56789")); // gap: held
        assert!(!s.insert(1005, b"XXXXX")); // duplicate pending offset: first wins
        assert!(s.insert(1000, b"01234"));
        assert_eq!(s.data, b"0123456789");
        assert!(!s.insert(1000, b"01234")); // exact duplicate
        assert!(!s.insert(990, b"old")); // before the stream start
        assert!(s.insert(1008, b"89ab")); // overlapping retransmit extends
        assert_eq!(s.data, b"0123456789ab");
        assert!(!s.insert(1002, b"ZZ")); // overwrite attempt ignored
        assert_eq!(s.data, b"0123456789ab");
    }

    #[test]
    fn stream_handles_sequence_wraparound() {
        let mut s = Stream::new(u32::MAX - 2);
        assert!(s.insert(u32::MAX - 2, b"abc"));
        assert!(s.insert(0, b"def")); // seq wrapped
        assert_eq!(s.data, b"abcdef");
    }

    #[test]
    fn stream_buffer_cap_is_enforced() {
        let mut s = Stream::new(0);
        assert!(s.insert(0, &vec![1u8; MAX_STREAM_BYTES + 5000]));
        assert_eq!(s.data.len(), MAX_STREAM_BYTES);
        assert!(!s.insert(MAX_STREAM_BYTES as u32, b"x")); // beyond the window
        assert!(!s.insert(u32::MAX / 2, b"x")); // far away
                                                // out-of-order bytes count against the same cap
        let mut s = Stream::new(0);
        for i in 0..20u32 {
            s.insert(100 + i * 10, &[0u8; 5]);
        }
        assert!(s.pending.len() <= MAX_PENDING_SEGMENTS);
        let mut s = Stream::new(0);
        assert!(!s.insert(10, &vec![0u8; MAX_STREAM_BYTES - 10]));
        assert!(!s.insert(5, &[0u8; 6000])); // would exceed the pending byte cap
        assert!(s.pending_bytes <= MAX_STREAM_BYTES);
    }

    // ── tracker end to end ──

    struct Wire {
        t: TlsTracker,
        now: Instant,
        cseq: u32,
        sseq: u32,
    }

    impl Wire {
        fn new() -> Self {
            Self {
                t: TlsTracker::new(),
                now: Instant::now(),
                cseq: 5000,
                sseq: 90000,
            }
        }
        fn client(&mut self, seq: u32, payload: &[u8], flags: u8) -> Vec<TlsHandshakeData> {
            let seg = TcpSegment {
                sport: CPORT,
                dport: SPORT,
                seq,
                flags,
                payload,
            };
            self.t.on_tcp(ip(CLIENT), ip(SERVER), &seg, self.now)
        }
        fn server(&mut self, seq: u32, payload: &[u8], flags: u8) -> Vec<TlsHandshakeData> {
            let seg = TcpSegment {
                sport: SPORT,
                dport: CPORT,
                seq,
                flags,
                payload,
            };
            self.t.on_tcp(ip(SERVER), ip(CLIENT), &seg, self.now)
        }
    }

    #[test]
    fn multi_segment_client_and_server_yield_one_event_with_ja3_and_ja3s() {
        let mut w = Wire::new();
        let ch = records(&client_hello_msg("multi.example", 3000), 16000);
        let (a, rest) = ch.split_at(1000);
        let (b, c) = rest.split_at(1500);
        let base = w.cseq;
        // The head segment anchors the flow; the rest arrives out of order,
        // with duplicates and a retransmission.
        assert!(w.client(base, a, 0).is_empty());
        assert!(w.client(base + 2500, c, 0).is_empty()); // gap: held
        assert!(w.client(base, a, 0).is_empty());
        assert!(w.client(base + 1000, b, 0).is_empty()); // fills the gap: complete
        assert_eq!(w.t.flow_count(), 1);

        let sh = kat_server_hello_record();
        let (s1, s2) = sh.split_at(30);
        let sbase = w.sseq;
        assert!(w.server(sbase, s1, 0).is_empty());
        assert!(w.server(sbase, s1, 0).is_empty());
        let out = w.server(sbase + 30, s2, 0);
        assert_eq!(out.len(), 1);
        let ev = &out[0];
        assert_eq!(ev.sni.as_deref(), Some("multi.example"));
        assert_eq!(ev.dst_addr, SERVER);
        assert_eq!(ev.src_addr, CLIENT);
        assert_eq!(ev.dst_port, SPORT);
        assert_eq!(ev.ja3, "771,4865,0-10-11-21,29,0");
        assert_eq!(ev.ja3s.as_deref(), Some(KAT_JA3S_MD5));
        assert_eq!(ev.ja3s_string.as_deref(), Some(KAT_JA3S_STRING));
        assert_eq!(w.t.flow_count(), 0);
        assert!(w.t.dropped.is_empty());
    }

    #[test]
    fn single_segment_hello_without_server_is_released_after_ttl() {
        let mut w = Wire::new();
        let ch = records(&client_hello_msg("quiet.example", 0), 16000);
        assert!(w.client(w.cseq, &ch, 0).is_empty());
        assert!(w
            .t
            .sweep(w.now + FLOW_TTL - Duration::from_millis(1))
            .is_empty());
        let out = w.t.sweep(w.now + FLOW_TTL);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].sni.as_deref(), Some("quiet.example"));
        assert!(out[0].ja3s.is_none() && out[0].ja3s_string.is_none());
        assert_eq!(w.t.flow_count(), 0);
        assert!(w.t.dropped.is_empty()); // a missing server reply is not a loss
    }

    #[test]
    fn incomplete_client_hello_expires_and_is_counted() {
        let mut w = Wire::new();
        let ch = records(&client_hello_msg("cut.example", 2000), 16000);
        assert!(w.client(w.cseq, &ch[..500], 0).is_empty());
        assert!(w.t.sweep(w.now + FLOW_TTL).is_empty());
        assert_eq!(w.t.dropped.get(&DropReason::EnrichmentTimeout), Some(&1));
        assert_eq!(w.t.flow_count(), 0);
    }

    #[test]
    fn server_bytes_before_complete_client_hello_are_ignored() {
        let mut w = Wire::new();
        let ch = records(&client_hello_msg("early.example", 2000), 16000);
        w.client(w.cseq, &ch[..500], 0);
        assert!(w.server(w.sseq, &kat_server_hello_record(), 0).is_empty());
        let out = w.client(w.cseq + 500, &ch[500..], 0);
        assert!(out.is_empty());
        let out = w.server(w.sseq, &kat_server_hello_record(), 0);
        assert_eq!(out[0].ja3s.as_deref(), Some(KAT_JA3S_MD5));
    }

    #[test]
    fn rst_releases_pending_event_without_ja3s() {
        let mut w = Wire::new();
        let ch = records(&client_hello_msg("rst.example", 0), 16000);
        w.client(w.cseq, &ch, 0);
        let out = w.server(w.sseq, &[], TCP_RST);
        assert_eq!(out.len(), 1);
        assert!(out[0].ja3s.is_none());
        assert_eq!(w.t.flow_count(), 0);
    }

    #[test]
    fn hello_retry_request_yields_no_ja3s() {
        let mut w = Wire::new();
        let ch = records(&client_hello_msg("hrr.example", 0), 16000);
        w.client(w.cseq, &ch, 0);
        let hrr = records(
            &server_hello_msg(0x1301, &[ext(43, &[3, 4])], HELLO_RETRY_RANDOM),
            16000,
        );
        let out = w.server(w.sseq, &hrr, 0);
        assert_eq!(out.len(), 1);
        assert!(out[0].ja3s.is_none());
    }

    #[test]
    fn huge_declared_client_hello_is_shed_and_counted() {
        let mut w = Wire::new();
        let mut bad = vec![22, 3, 1, 0x00, 0x10, 1, 0xff, 0xff, 0xff];
        bad.extend_from_slice(&[0u8; 12]);
        assert!(w.client(w.cseq, &bad, 0).is_empty());
        assert_eq!(w.t.flow_count(), 0);
        assert_eq!(w.t.dropped.get(&DropReason::EventTooLarge), Some(&1));
    }

    #[test]
    fn malformed_and_non_tls_traffic_creates_no_state_and_no_drops() {
        let mut w = Wire::new();
        assert!(w.client(w.cseq, b"GET / HTTP/1.1\r\n\r\n", 0).is_empty());
        assert!(w.client(w.cseq, &[22, 3, 1], 0).is_empty());
        assert!(w
            .client(w.cseq, &[23, 3, 3, 0, 10, 1, 1, 1, 1, 1], 0)
            .is_empty());
        assert_eq!(w.t.flow_count(), 0);
        // wrong lengths inside a started hello: flow removed, nothing counted
        let mut bad = vec![22, 3, 1, 0, 6, 1, 0, 0, 2, 0, 0];
        assert!(w.client(w.cseq, &bad, 0).is_empty());
        assert_eq!(w.t.flow_count(), 0);
        bad[5] = 1;
        assert!(w.t.dropped.is_empty());
    }

    #[test]
    fn flow_table_is_capped_and_refuses_new_flows_when_full() {
        let mut t = TlsTracker::new();
        let now = Instant::now();
        let ch = records(&client_hello_msg("flood.example", 2000), 16000);
        let first = &ch[..300]; // never completes
        for i in 0..(MAX_FLOWS + 10) {
            let seg = TcpSegment {
                sport: 1024 + i as u16,
                dport: 443,
                seq: 1,
                flags: 0,
                payload: first,
            };
            t.on_tcp(ip(CLIENT), ip(SERVER), &seg, now);
        }
        assert_eq!(t.flow_count(), MAX_FLOWS);
        assert_eq!(t.dropped.get(&DropReason::RateLimitApplied), Some(&10));
        // after the TTL the table frees up and accepts new flows again
        let later = now + FLOW_TTL;
        let seg = TcpSegment {
            sport: 60000,
            dport: 443,
            seq: 1,
            flags: 0,
            payload: first,
        };
        t.on_tcp(ip(CLIENT), ip(SERVER), &seg, later);
        assert_eq!(t.flow_count(), 1);
        assert_eq!(
            t.dropped.get(&DropReason::EnrichmentTimeout),
            Some(&(MAX_FLOWS as u64))
        );
    }

    #[test]
    fn random_garbage_never_panics_and_stays_bounded() {
        let mut t = TlsTracker::new();
        let now = Instant::now();
        let mut x: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let len = (next() % 80) as usize;
            let mut p: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if len >= 6 && next() % 2 == 0 {
                p[0] = 22;
                p[1] = 3;
                p[5] = if next() % 2 == 0 { 1 } else { 2 };
            }
            let a = (next() % 8) as u16;
            let seg = TcpSegment {
                sport: 1000 + a,
                dport: 443,
                seq: next() as u32,
                flags: (next() % 8) as u8,
                payload: &p,
            };
            t.on_tcp(ip(CLIENT), ip(SERVER), &seg, now);
            let rseg = TcpSegment {
                sport: 443,
                dport: 1000 + a,
                seq: next() as u32,
                flags: 0,
                payload: &p,
            };
            t.on_tcp(ip(SERVER), ip(CLIENT), &rseg, now);
            assert!(t.flow_count() <= MAX_FLOWS);
        }
    }
}
