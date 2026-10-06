//! Real-time ETW sensor: process, image-load, network and DNS events.
//!
//! The polling [`super::process`] / [`super::network`] collectors miss
//! anything shorter than their interval and never see DNS. This collector runs
//! a real-time ETW session (`TRAPD-Agent`), enables the Kernel-Process,
//! Kernel-Network and DNS-Client providers (GUIDs and keywords in
//! [`crate::collectors::etw_map`]) and turns each decoded record into the same
//! OS-neutral schema events the rest of the agent consumes.
//!
//! Decoding is split so it can be tested off-Windows: the unsafe TDH plumbing
//! here produces an [`EtwRecord`] (provider, id, named property values); the
//! pure mapping in `etw_map` turns that into events. A process start is
//! enriched (command line, account, image hash) from `sysinfo` while the
//! process is still alive — the start event itself is emitted even when it has
//! already exited, which is exactly the case polling loses.
//!
//! Robustness: lost buffers/events and a stopped session are surfaced through
//! [`crate::telemetry::coverage`], and a session left over from a previous run
//! (crash, forced kill) is stopped before a new one starts.
//!
//! No kernel driver is installed; everything here is user-mode ETW. This does
//! not see, and must not be reported as seeing, LSASS handle access or a
//! privileged attacker who stops the session itself (that stop *is* detected).

use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sysinfo::{Pid, ProcessRefreshKind, System, UpdateKind, Users};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};
use windows_sys::core::{GUID, PWSTR};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS, MAX_PATH};
use windows_sys::Win32::System::Diagnostics::Etw::*;

use crate::collectors::etw_map::{self, DeviceMap, EtwRecord, EtwValue, ProcessEnrichment};
use crate::collectors::Collector;
use crate::schema::{AgentEvent, EventAction, EventClass, EventData, Severity};
use crate::telemetry::coverage;

const SESSION_NAME: &str = "TRAPD-Agent";
/// Cap on a single property's decoded size (defensive).
const MAX_PROP_BYTES: usize = 64 * 1024;
const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HASH_CACHE: usize = 4096;

/// Shared sink the C callback writes decoded records into, drained by the async
/// side. A plain channel keeps the `unsafe extern "system"` callback tiny.
struct Sink {
    tx: std::sync::Mutex<mpsc::Sender<EtwRecord>>,
}

/// Passed to the callback through `EVENT_TRACE_LOGFILEW.Context`.
static SINK: std::sync::OnceLock<Arc<Sink>> = std::sync::OnceLock::new();

fn utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub struct EtwCollector;

#[async_trait]
impl Collector for EtwCollector {
    fn name(&self) -> &'static str {
        "WindowsEtwCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let (rec_tx, rec_rx) = mpsc::channel::<EtwRecord>();
        let sink = Arc::new(Sink {
            tx: std::sync::Mutex::new(rec_tx),
        });
        if SINK.set(sink).is_err() {
            return Err(anyhow!("ETW sensor already running"));
        }

        // The blocking ProcessTrace loop owns a dedicated OS thread.
        let session = Session::start().context("start ETW session")?;
        let trace_thread = std::thread::Builder::new()
            .name("trapd-etw".into())
            .spawn(move || session.process())
            .context("spawn ETW process thread")?;

        coverage::update(|c| {
            c.process_sensor = Some("etw".into());
            c.etw_session = Some(true);
        });
        info!("WindowsEtwCollector: real-time ETW session started");
        crate::telemetry::metrics::metrics()
            .set_collector_mode(crate::telemetry::metrics::CollectorMode::WindowsPolling);

        let mut state = DecodeState::new();
        // Drain decoded records on a blocking-friendly cadence. `recv_timeout`
        // lets us notice the trace thread dying even in a quiet period.
        loop {
            match rec_rx.recv_timeout(std::time::Duration::from_secs(2)) {
                Ok(rec) => {
                    for event in state.map(&rec, &agent_id, &hostname) {
                        if tx.send(event).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if trace_thread.is_finished() {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        // The session stopped: either we are shutting down, or something (a
        // tampering actor stopping the logger, a provider reset) killed it.
        coverage::update(|c| c.etw_session = Some(false));
        warn!("WindowsEtwCollector: ETW session ended");
        let det = crate::schema::DetectionData {
            rule_id: "selfprotect.etw_session_stopped".into(),
            title: "TRAPD ETW telemetry session stopped".into(),
            category: "defense_evasion".into(),
            mitre_tactic: Some("TA0005 Defense Evasion".into()),
            mitre_technique: Some("T1562.006".into()),
            confidence: 80,
            subject: SESSION_NAME.into(),
            detail: "The real-time ETW session ended; process/network/DNS visibility is degraded until it restarts".into(),
            evidence: serde_json::json!({ "session": SESSION_NAME }),
            ..Default::default()
        };
        let _ = tx
            .send(AgentEvent::new(
                agent_id.clone(),
                hostname.clone(),
                EventClass::Detection,
                EventAction::Detected,
                Severity::High,
                EventData::Detection(Box::new(det)),
            ))
            .await;
        Err(anyhow!("ETW session ended"))
    }
}

/// Owns the controller + consumer handles and the enabled providers.
struct Session {
    control: CONTROLTRACE_HANDLE,
    trace: PROCESSTRACE_HANDLE,
}

// The handles are process-wide kernel objects; the struct is only moved to the
// trace thread, never shared.
unsafe impl Send for Session {}

impl Session {
    fn start() -> Result<Self> {
        unsafe {
            // Stop a leftover session of the same name first.
            let _ = stop_named(SESSION_NAME);

            let name = utf16(SESSION_NAME);
            // EVENT_TRACE_PROPERTIES is followed in memory by the logger name.
            let buf_len = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name.len() * 2;
            let mut buf = vec![0u8; buf_len];
            let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
            (*props).Wnode.BufferSize = buf_len as u32;
            (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props).Wnode.ClientContext = 1; // QPC timestamps
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            (*props).BufferSize = 64; // KB
            (*props).MinimumBuffers = 8;
            (*props).MaximumBuffers = 64;
            (*props).FlushTimer = 1;

            let mut control = CONTROLTRACE_HANDLE { Value: 0 };
            let rc = StartTraceW(&mut control, name.as_ptr(), props);
            if rc == ERROR_ALREADY_EXISTS {
                return Err(anyhow!(
                    "an ETW session named {SESSION_NAME} already exists"
                ));
            }
            if rc != ERROR_SUCCESS {
                return Err(anyhow!("StartTraceW failed: {rc}"));
            }

            for (guid, any_keyword) in [
                (etw_map::KERNEL_PROCESS, etw_map::KERNEL_PROCESS_KEYWORDS),
                (etw_map::KERNEL_NETWORK, etw_map::KERNEL_NETWORK_KEYWORDS),
                (etw_map::DNS_CLIENT, 0u64),
            ] {
                let g = guid_from_u128(guid);
                let rc = EnableTraceEx2(
                    control,
                    &g,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    TRACE_LEVEL_INFORMATION as u8,
                    any_keyword,
                    0,
                    0,
                    std::ptr::null(),
                );
                if rc != ERROR_SUCCESS {
                    warn!(provider = %format!("{guid:032x}"), rc, "EnableTraceEx2 failed");
                }
            }

            // Open the real-time consumer.
            let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            logfile.LoggerName = name.as_ptr() as PWSTR;
            logfile.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.Anonymous2.EventRecordCallback = Some(event_callback);
            let trace = OpenTraceW(&mut logfile);
            if trace.Value == u64::MAX {
                let _ = stop_named(SESSION_NAME);
                return Err(anyhow!(
                    "OpenTraceW failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self { control, trace })
        }
    }

    /// Blocks until the session stops (ProcessTrace returns).
    fn process(self) {
        unsafe {
            let handles = [self.trace];
            let _ = ProcessTrace(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null());
            CloseTrace(self.trace);
            let _ = stop_control(self.control);
        }
    }
}

unsafe fn stop_control(control: CONTROLTRACE_HANDLE) -> u32 {
    let mut buf =
        vec![0u8; std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 2 * (MAX_PATH as usize)];
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    (*props).Wnode.BufferSize = buf.len() as u32;
    ControlTraceW(control, std::ptr::null(), props, EVENT_TRACE_CONTROL_STOP)
}

unsafe fn stop_named(name: &str) -> u32 {
    let wname = utf16(name);
    let mut buf = vec![0u8; std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + wname.len() * 2];
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    (*props).Wnode.BufferSize = buf.len() as u32;
    (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    ControlTraceW(
        CONTROLTRACE_HANDLE { Value: 0 },
        wname.as_ptr(),
        props,
        EVENT_TRACE_CONTROL_STOP,
    )
}

fn guid_from_u128(v: u128) -> GUID {
    GUID::from_u128(v)
}

/// ETW record callback — kept minimal: decode to [`EtwRecord`], push to the
/// channel. Runs on the ProcessTrace thread.
unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
    let Some(sink) = SINK.get() else { return };
    if record.is_null() {
        return;
    }
    if let Some(decoded) = decode_record(&*record) {
        if let Ok(tx) = sink.tx.lock() {
            let _ = tx.send(decoded);
        }
    }
}

/// Decode an EVENT_RECORD into provider/id/properties using TDH.
unsafe fn decode_record(record: &EVENT_RECORD) -> Option<EtwRecord> {
    let header = &record.EventHeader;
    let provider = guid_to_u128(&header.ProviderId);
    // Only the providers we map; skip the TDH cost for anything else.
    if provider != etw_map::KERNEL_PROCESS
        && provider != etw_map::KERNEL_NETWORK
        && provider != etw_map::DNS_CLIENT
    {
        return None;
    }
    let id = header.EventDescriptor.Id;

    // Fetch the schema (TRACE_EVENT_INFO) to learn the property names/types.
    let mut size = 0u32;
    TdhGetEventInformation(record, 0, std::ptr::null(), std::ptr::null_mut(), &mut size);
    if size == 0 {
        return None;
    }
    let mut info_buf = vec![0u8; size as usize];
    let info = info_buf.as_mut_ptr() as *mut TRACE_EVENT_INFO;
    if TdhGetEventInformation(record, 0, std::ptr::null(), info, &mut size) != ERROR_SUCCESS {
        return None;
    }
    let count = (*info).TopLevelPropertyCount as usize;
    let props_base =
        std::ptr::addr_of!((*info).EventPropertyInfoArray) as *const EVENT_PROPERTY_INFO;
    let mut props = HashMap::new();
    for i in 0..count {
        let pi = &*props_base.add(i);
        // Structs and arrays are not needed by our mappings; skip them.
        if pi.Flags & PropertyStruct != 0 {
            continue;
        }
        let name_ptr = (info as *const u8).add(pi.NameOffset as usize) as *const u16;
        let name = wide_at(name_ptr);
        if name.is_empty() {
            continue;
        }
        let in_type = pi.Anonymous1.nonStructType.InType;
        if let Some(value) = read_property(record, &name, in_type) {
            props.insert(name, value);
        }
    }
    Some(EtwRecord {
        provider,
        id,
        header_pid: header.ProcessId,
        timestamp: header.TimeStamp,
        props,
    })
}

/// Read one named property via TDH (it does the per-event offset arithmetic).
unsafe fn read_property(record: &EVENT_RECORD, name: &str, in_type: u16) -> Option<EtwValue> {
    let wname = utf16(name);
    let descriptor = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: wname.as_ptr() as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut size = 0u32;
    if TdhGetPropertySize(record, 0, std::ptr::null(), 1, &descriptor, &mut size) != ERROR_SUCCESS {
        return None;
    }
    if size == 0 || size as usize > MAX_PROP_BYTES {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    if TdhGetProperty(
        record,
        0,
        std::ptr::null(),
        1,
        &descriptor,
        size,
        buf.as_mut_ptr(),
    ) != ERROR_SUCCESS
    {
        return None;
    }
    Some(interpret(in_type, buf))
}

fn interpret(in_type: u16, raw: Vec<u8>) -> EtwValue {
    let as_int = |raw: &[u8]| -> u64 {
        let mut b = [0u8; 8];
        let n = raw.len().min(8);
        b[..n].copy_from_slice(&raw[..n]);
        u64::from_le_bytes(b)
    };
    match in_type as i32 {
        TDH_INTYPE_UNICODESTRING => {
            // A step loop rather than `chunks_exact(2)`: avoids the 1.99
            // `clippy::chunks_exact_to_as_chunks` lint without the unstable
            // `as_chunks`, and stops at the first NUL.
            let mut u16s = Vec::with_capacity(raw.len() / 2);
            let mut i = 0;
            while i + 1 < raw.len() {
                let c = u16::from_le_bytes([raw[i], raw[i + 1]]);
                if c == 0 {
                    break;
                }
                u16s.push(c);
                i += 2;
            }
            EtwValue::Str(String::from_utf16_lossy(&u16s))
        }
        TDH_INTYPE_ANSISTRING => {
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            EtwValue::Str(String::from_utf8_lossy(&raw[..end]).into_owned())
        }
        TDH_INTYPE_INT8 | TDH_INTYPE_UINT8 | TDH_INTYPE_INT16 | TDH_INTYPE_UINT16
        | TDH_INTYPE_INT32 | TDH_INTYPE_UINT32 | TDH_INTYPE_INT64 | TDH_INTYPE_UINT64
        | TDH_INTYPE_HEXINT32 | TDH_INTYPE_HEXINT64 | TDH_INTYPE_POINTER | TDH_INTYPE_BOOLEAN => {
            EtwValue::Int(as_int(&raw), raw)
        }
        // Addresses and ports arrive as BINARY / network-order fields; keep the
        // raw bytes so etw_map decodes them.
        _ => EtwValue::Bytes(raw),
    }
}

unsafe fn wide_at(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 && len < 512 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

fn guid_to_u128(g: &GUID) -> u128 {
    ((g.data1 as u128) << 96)
        | ((g.data2 as u128) << 80)
        | ((g.data3 as u128) << 64)
        | (u64::from_be_bytes(g.data4) as u128)
}

/// Turns decoded records into events, enriching process starts and mapping the
/// device→drive table. Keeps the `sysinfo` handles for enrichment.
struct DecodeState {
    sys: System,
    users: Users,
    devices: DeviceMap,
    hash_cache: HashMap<String, (u64, String)>,
    /// pid → image path, so a network/DNS event can name its process.
    proc_images: HashMap<i32, String>,
}

impl DecodeState {
    fn new() -> Self {
        Self {
            sys: System::new(),
            users: Users::new_with_refreshed_list(),
            devices: device_map(),
            hash_cache: HashMap::new(),
            proc_images: HashMap::new(),
        }
    }

    fn map(&mut self, rec: &EtwRecord, agent_id: &str, hostname: &str) -> Vec<AgentEvent> {
        let mut out = Vec::new();
        let mut emit = |class, action, data| {
            out.push(AgentEvent::new(
                agent_id.to_string(),
                hostname.to_string(),
                class,
                action,
                Severity::Info,
                data,
            ));
        };
        match rec.provider {
            p if p == etw_map::KERNEL_PROCESS => match rec.id {
                1 => {
                    let pid = rec.int(&["ProcessID", "ProcessId"]).unwrap_or(0) as i32;
                    let enrich = self.enrich_process(pid);
                    if let Some(data) = etw_map::process_start(rec, &self.devices, enrich) {
                        crate::deception::activity::record_exec(&data.username, &data.exe);
                        self.proc_images.insert(data.pid, data.exe.clone());
                        emit(
                            EventClass::Process,
                            EventAction::Create,
                            EventData::ProcessCreate(data),
                        );
                    }
                }
                2 => {
                    if let Some(data) = etw_map::process_stop(rec, &self.devices) {
                        self.proc_images.remove(&data.pid);
                        emit(
                            EventClass::Process,
                            EventAction::Terminate,
                            EventData::ProcessTerminate(data),
                        );
                    }
                }
                5 => {
                    if let Some((pid, dll)) = etw_map::image_load(rec, &self.devices) {
                        if let Some(d) = crate::detection::windows_rules::inspect_image_load(
                            self.proc_images.get(&pid).map(String::as_str).unwrap_or(""),
                            &dll,
                        ) {
                            // Emitted straight as a detection (admit_external
                            // enriches + gates it like any collector finding).
                            emit(
                                EventClass::Detection,
                                EventAction::Detected,
                                EventData::Detection(Box::new(d)),
                            );
                        }
                    }
                }
                _ => {}
            },
            p if p == etw_map::KERNEL_NETWORK => {
                let pid = rec.int(&["PID"]).map(|p| p as i32);
                let process = pid
                    .and_then(|p| self.proc_images.get(&p))
                    .map(|e| e.rsplit('\\').next().unwrap_or(e).to_string());
                if let Some(data) = etw_map::network_connection(rec, process) {
                    emit(
                        EventClass::Network,
                        EventAction::Connection,
                        EventData::NetworkConnection(data),
                    );
                }
            }
            p if p == etw_map::DNS_CLIENT => {
                if let Some((_pid, data)) = etw_map::dns_query(rec) {
                    crate::deception::activity::record_hostname(&data.qname);
                    emit(
                        EventClass::Network,
                        EventAction::DnsResponse,
                        EventData::DnsResolution(data),
                    );
                }
            }
            _ => {}
        }
        out
    }

    /// Command line, account and image hash for a process that is (usually)
    /// still alive. Best-effort: a process gone before this runs still yields
    /// its start event without these.
    fn enrich_process(&mut self, pid: i32) -> ProcessEnrichment {
        if pid <= 0 {
            return ProcessEnrichment::default();
        }
        let spid = Pid::from_u32(pid as u32);
        self.sys.refresh_process_specifics(
            spid,
            ProcessRefreshKind::new()
                .with_cmd(UpdateKind::Always)
                .with_exe(UpdateKind::Always)
                .with_user(UpdateKind::Always),
        );
        let Some(proc_) = self.sys.process(spid) else {
            return ProcessEnrichment::default();
        };
        let exe = proc_.exe().map(|p| p.to_string_lossy().into_owned());
        let cmdline = {
            let c = proc_.cmd().join(" ");
            (!c.is_empty()).then_some(c)
        };
        let username = proc_
            .user_id()
            .and_then(|uid| self.users.get_user_by_id(uid))
            .map(|u| u.name().to_string());
        let exe_sha256 = exe.as_deref().and_then(|e| self.exe_sha256(e));
        ProcessEnrichment {
            exe,
            cmdline,
            username,
            exe_sha256,
        }
    }

    fn exe_sha256(&mut self, path: &str) -> Option<String> {
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() || meta.len() > MAX_HASH_BYTES {
            return None;
        }
        if let Some((len, hash)) = self.hash_cache.get(path) {
            if *len == meta.len() {
                return Some(hash.clone());
            }
        }
        let bytes = std::fs::read(path).ok()?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if self.hash_cache.len() >= MAX_HASH_CACHE {
            self.hash_cache.clear();
        }
        self.hash_cache
            .insert(path.to_string(), (meta.len(), digest.clone()));
        Some(digest)
    }
}

/// Map `\Device\HarddiskVolumeN` → `C:` for every drive letter, via
/// QueryDosDeviceW. Rebuilt once at startup (mounts rarely change).
fn device_map() -> DeviceMap {
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    let mut map = Vec::new();
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let wdrive = utf16(&drive);
        let mut target = [0u16; MAX_PATH as usize];
        let n =
            unsafe { QueryDosDeviceW(wdrive.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
        if n > 0 {
            let end = target.iter().position(|&c| c == 0).unwrap_or(target.len());
            let device = String::from_utf16_lossy(&target[..end]);
            if device.starts_with("\\Device\\") {
                map.push((device, drive));
            }
        }
    }
    map
}
