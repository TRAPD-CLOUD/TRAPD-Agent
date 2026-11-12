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

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;

use sysinfo::{Pid, ProcessRefreshKind, System, UpdateKind};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};
use windows_sys::core::{GUID, PWSTR};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS, MAX_PATH};
use windows_sys::Win32::System::Diagnostics::Etw::*;

use crate::collectors::etw_map::{self, DeviceMap, EtwRecord, EtwValue, ProcessEnrichment};
use crate::collectors::Collector;
use crate::schema::{AgentEvent, EventAction, EventClass, EventData, Severity};
use crate::telemetry::coverage;
use crate::telemetry::image_hash::{self, HashOutcome};

const SESSION_NAME: &str = "TRAPD-Agent";
/// Cap on a single property's decoded size (defensive).
const MAX_PROP_BYTES: usize = 64 * 1024;

/// Shared sink the C callback writes decoded records into, drained by the async
/// side. A plain channel keeps the `unsafe extern "system"` callback tiny.
struct Sink {
    tx: tokio::sync::mpsc::Sender<EtwRecord>,
    lost: std::sync::atomic::AtomicU64,
}

/// Stops the native session when its async consumer is cancelled or exits.
struct NativeControl {
    handle: CONTROLTRACE_HANDLE,
    stopped: std::sync::atomic::AtomicBool,
}
impl NativeControl {
    fn stop(&self) {
        if !self.stopped.swap(true, std::sync::atomic::Ordering::AcqRel) {
            unsafe {
                let _ = stop_control(self.handle);
            }
        }
    }
}
struct RunGuard(Arc<NativeControl>);
impl Drop for RunGuard {
    fn drop(&mut self) {
        self.0.stop();
        coverage::update(|c| c.etw_session = Some(false));
    }
}

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
        let (rec_tx, mut rec_rx) = tokio::sync::mpsc::channel::<EtwRecord>(8192);
        let sink = Arc::new(Sink {
            tx: rec_tx,
            lost: std::sync::atomic::AtomicU64::new(0),
        });
        // The blocking ProcessTrace loop owns a dedicated OS thread.
        let session = Session::start(sink).context("start ETW session")?;
        let _guard = RunGuard(Arc::clone(&session.control));
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
            .set_collector_mode(crate::telemetry::metrics::CollectorMode::WindowsEtw);

        let mut state = DecodeState::new();
        // The loop below wakes at least once a second, so a long silence means
        // it is blocked (full pipeline or a hung decode).
        // Dropped on every exit, including cancellation when a signed config
        // disables ETW while it runs.
        let _liveness = crate::telemetry::liveness::watch(
            "WindowsEtwCollector",
            std::time::Duration::from_secs(120),
        );
        // Records are decoded in batches: one blocking task per batch instead of
        // one per record, with the decode state moved in and out once. Order is
        // preserved (a batch is decoded sequentially, batches are sequential).
        let mut batch: Vec<EtwRecord> = Vec::with_capacity(DECODE_BATCH);
        loop {
            crate::telemetry::liveness::beat("WindowsEtwCollector");
            batch.clear();
            tokio::select! {
                n = rec_rx.recv_many(&mut batch, DECODE_BATCH) => if n == 0 { break },
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                    if trace_thread.is_finished() { break; }
                    continue;
                }
                _ = tx.closed() => return Ok(()),
            }
            let aid = agent_id.clone();
            let host = hostname.clone();
            let records = std::mem::take(&mut batch);
            let (next_state, recycled, events) = tokio::task::spawn_blocking(move || {
                let events = map_batch(&mut state, &records, &aid, &host);
                (state, records, events)
            })
            .await?;
            state = next_state;
            batch = recycled;
            for event in events {
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
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

/// Own session for Kernel-File: the volume (every create/write on the host)
/// must never compete with process events for the main session's buffers.
const FILE_SESSION_NAME: &str = "TRAPD-Agent-File";

/// Environment switch for the file-actor sensor. Off by default until its CPU
/// cost has been measured on a Windows host.
pub fn file_actor_enabled() -> bool {
    std::env::var("TRAPD_ETW_FILE_ACTOR")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Emits no events: it feeds `detection::file_actor` so the filesystem
/// collector can name the process that wrote a changed path.
pub struct EtwFileActorCollector;

struct FileActorState {
    devices: DeviceMap,
    objects: etw_map::FileObjects,
    /// pid → (creation FILETIME, lineage); an entry is used only while the
    /// pid's live creation time still equals the cached one.
    lineages: HashMap<i32, (u64, Arc<crate::schema::ProcessLineage>)>,
}

impl FileActorState {
    fn handle(&mut self, rec: &EtwRecord) {
        let Some(touch) = self.objects.observe(rec, &self.devices) else {
            return;
        };
        let Some(start) = crate::telemetry::identity::process_start_time(touch.pid) else {
            return;
        };
        // PID reuse guard: the process must have existed before the record.
        if !etw_map::same_process_generation(Some(start), Some(start), rec.timestamp) {
            return;
        }
        let actor = match self.lineages.get(&touch.pid) {
            Some((s, l)) if *s == start => Arc::clone(l),
            _ => {
                let exe = crate::telemetry::identity::windows_process_image(touch.pid);
                let comm = exe
                    .as_deref()
                    .and_then(|e| e.rsplit('\\').next())
                    .unwrap_or_default()
                    .to_string();
                let lineage = Arc::new(crate::schema::ProcessLineage {
                    pid: touch.pid,
                    process_start_time: Some(start),
                    uid: 0,
                    gid: 0,
                    username: crate::telemetry::identity::windows_process_account(touch.pid)
                        .unwrap_or_default(),
                    comm,
                    exe,
                    cmdline: None,
                    ancestors: Vec::new(),
                });
                if self.lineages.len() >= 1024 {
                    self.lineages.clear();
                }
                self.lineages
                    .insert(touch.pid, (start, Arc::clone(&lineage)));
                lineage
            }
        };
        crate::detection::file_actor::record(&touch.path, actor);
    }
}

struct FileSessionGuard(Arc<NativeControl>);
impl Drop for FileSessionGuard {
    fn drop(&mut self) {
        self.0.stop();
    }
}

#[async_trait]
impl Collector for EtwFileActorCollector {
    fn name(&self) -> &'static str {
        "WindowsEtwFileActorCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        _agent_id: String,
        _hostname: String,
    ) -> Result<()> {
        let (rec_tx, mut rec_rx) = tokio::sync::mpsc::channel::<EtwRecord>(8192);
        let sink = Arc::new(Sink {
            tx: rec_tx,
            lost: std::sync::atomic::AtomicU64::new(0),
        });
        let session = Session::start_named(
            sink,
            FILE_SESSION_NAME,
            &[(etw_map::KERNEL_FILE, etw_map::KERNEL_FILE_KEYWORDS)],
        )
        .context("start file-actor ETW session")?;
        let _guard = FileSessionGuard(Arc::clone(&session.control));
        let trace_thread = std::thread::Builder::new()
            .name("trapd-etw-file".into())
            .spawn(move || session.process())
            .context("spawn file-actor ETW thread")?;
        info!("WindowsEtwFileActorCollector: Kernel-File session started");
        let mut state = FileActorState {
            devices: device_map(),
            objects: etw_map::FileObjects::default(),
            lineages: HashMap::new(),
        };
        let mut batch: Vec<EtwRecord> = Vec::with_capacity(DECODE_BATCH);
        loop {
            batch.clear();
            tokio::select! {
                n = rec_rx.recv_many(&mut batch, DECODE_BATCH) => if n == 0 { break },
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                    if trace_thread.is_finished() { break; }
                    continue;
                }
                _ = tx.closed() => return Ok(()),
            }
            let records = std::mem::take(&mut batch);
            let (next_state, recycled) = tokio::task::spawn_blocking(move || {
                for rec in &records {
                    state.handle(rec);
                }
                (state, records)
            })
            .await?;
            state = next_state;
            batch = recycled;
        }
        warn!("WindowsEtwFileActorCollector: Kernel-File session ended");
        Err(anyhow!("Kernel-File ETW session ended"))
    }
}

/// Records decoded per blocking task.
const DECODE_BATCH: usize = 256;

/// Decode `records` in order with one shared state.
fn map_batch(
    state: &mut DecodeState,
    records: &[EtwRecord],
    agent_id: &str,
    hostname: &str,
) -> Vec<AgentEvent> {
    records
        .iter()
        .flat_map(|rec| state.map(rec, agent_id, hostname))
        .collect()
}

/// Owns the controller + consumer handles and the enabled providers.
struct Session {
    control: Arc<NativeControl>,
    trace: PROCESSTRACE_HANDLE,
    _sink: Arc<Sink>,
}

// The handles are process-wide kernel objects; the struct is only moved to the
// trace thread, never shared.
unsafe impl Send for Session {}

impl Session {
    fn start(sink: Arc<Sink>) -> Result<Self> {
        Self::start_named(
            sink,
            SESSION_NAME,
            &[
                (etw_map::KERNEL_PROCESS, etw_map::KERNEL_PROCESS_KEYWORDS),
                (etw_map::KERNEL_NETWORK, etw_map::KERNEL_NETWORK_KEYWORDS),
                (etw_map::DNS_CLIENT, 0u64),
            ],
        )
    }

    fn start_named(sink: Arc<Sink>, session: &str, providers: &[(u128, u64)]) -> Result<Self> {
        unsafe {
            // Stop a leftover session of the same name first.
            let _ = stop_named(session);

            let name = utf16(session);
            // EVENT_TRACE_PROPERTIES is followed in memory by the logger name.
            let buf_len = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + name.len() * 2;
            let mut buf = vec![0u8; buf_len];
            let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
            (*props).Wnode.BufferSize = buf_len as u32;
            (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props).Wnode.ClientContext = 2; // system time / FILETIME
            (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            (*props).BufferSize = 64; // KB
            (*props).MinimumBuffers = 8;
            (*props).MaximumBuffers = 64;
            (*props).FlushTimer = 1;

            let mut control = CONTROLTRACE_HANDLE { Value: 0 };
            let rc = StartTraceW(&mut control, name.as_ptr(), props);
            if rc == ERROR_ALREADY_EXISTS {
                return Err(anyhow!("an ETW session named {session} already exists"));
            }
            if rc != ERROR_SUCCESS {
                return Err(anyhow!("StartTraceW failed: {rc}"));
            }

            for &(guid, any_keyword) in providers {
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
                coverage::update(|c| match guid {
                    etw_map::KERNEL_PROCESS => c.etw_process_provider = Some(rc == ERROR_SUCCESS),
                    etw_map::KERNEL_NETWORK => c.etw_network_provider = Some(rc == ERROR_SUCCESS),
                    etw_map::DNS_CLIENT => c.etw_dns_provider = Some(rc == ERROR_SUCCESS),
                    _ => {}
                });
                if rc != ERROR_SUCCESS {
                    warn!(provider = %format!("{guid:032x}"), rc, "EnableTraceEx2 failed");
                    if guid == etw_map::KERNEL_PROCESS || guid == etw_map::KERNEL_FILE {
                        let _ = stop_control(control);
                        return Err(anyhow!("ETW provider {guid:032x} unavailable: {rc}"));
                    }
                }
            }

            // Open the real-time consumer.
            let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
            logfile.LoggerName = name.as_ptr() as PWSTR;
            logfile.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.Anonymous2.EventRecordCallback = Some(event_callback);
            logfile.Context = Arc::as_ptr(&sink) as *mut std::ffi::c_void;
            logfile.BufferCallback = Some(buffer_callback);
            let trace = OpenTraceW(&mut logfile);
            if trace.Value == u64::MAX {
                let _ = stop_named(session);
                return Err(anyhow!(
                    "OpenTraceW failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self {
                control: Arc::new(NativeControl {
                    handle: control,
                    stopped: std::sync::atomic::AtomicBool::new(false),
                }),
                trace,
                _sink: sink,
            })
        }
    }

    /// Blocks until the session stops (ProcessTrace returns).
    fn process(self) {
        unsafe {
            let handles = [self.trace];
            let _ = ProcessTrace(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null());
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            CloseTrace(self.trace);
            self.control.stop();
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
unsafe extern "system" fn buffer_callback(log: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if let Some(log) = log.as_ref() {
        if let Some(sink) = (log.Context as *const Sink).as_ref() {
            let count = log.EventsLost as u64;
            let before = sink
                .lost
                .fetch_max(count, std::sync::atomic::Ordering::Relaxed);
            let lost = count.saturating_sub(before);
            coverage::update(|c| c.etw_events_lost = c.etw_events_lost.saturating_add(lost));
            crate::telemetry::metrics::metrics()
                .events_dropped(crate::telemetry::DropReason::KernelRingbufferFull, lost);
        }
    }
    1
}

unsafe extern "system" fn event_callback(record: *mut EVENT_RECORD) {
    let Some(record) = record.as_ref() else {
        return;
    };
    let Some(sink) = (record.UserContext as *const Sink).as_ref() else {
        return;
    };
    if let Some(mut decoded) = decode_record(record) {
        if decoded.provider == etw_map::KERNEL_PROCESS && decoded.id == 1 {
            decoded.captured = Some(capture_at_start(&decoded));
        }
        // Full and Closed (consumer gone while ProcessTrace still delivers) both lose
        // the record; neither may vanish without a named counter.
        if sink.tx.try_send(decoded).is_err() {
            crate::telemetry::metrics::metrics()
                .event_dropped(crate::telemetry::DropReason::UserspaceChannelFull);
        }
    } else if [
        etw_map::KERNEL_PROCESS,
        etw_map::KERNEL_NETWORK,
        etw_map::DNS_CLIENT,
        etw_map::KERNEL_FILE,
    ]
    .contains(&guid_to_u128(&record.EventHeader.ProviderId))
    {
        crate::telemetry::metrics::metrics()
            .event_dropped(crate::telemetry::DropReason::InternalError);
    }
}

/// Reads command line and account of a just-started process on the ETW
/// delivery thread, the earliest user-mode point and before the record waits
/// in the channel behind other events. A one-shot `cmd /c echo` can exit within
/// milliseconds, so every hop of latency here costs command lines.
///
/// Both reads are bracketed by the process creation time: a PID recycled
/// meanwhile never lends its command line or account to the wrong start.
fn capture_at_start(rec: &EtwRecord) -> ProcessEnrichment {
    use crate::telemetry::identity::{
        process_start_time, windows_process_account, windows_process_command_line,
    };
    let pid = rec
        .int(&["ProcessID", "ProcessId"])
        .and_then(|p| i32::try_from(p).ok())
        .unwrap_or(0);
    let event_start = rec.int(&["CreateTime"]).filter(|t| *t > 0);
    if pid <= 0 || event_start.is_none() || process_start_time(pid) != event_start {
        return ProcessEnrichment::default();
    }
    let cmdline = windows_process_command_line(pid);
    let username = windows_process_account(pid);
    if process_start_time(pid) != event_start {
        return ProcessEnrichment::default();
    }
    ProcessEnrichment {
        cmdline,
        username,
        ..Default::default()
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
        && provider != etw_map::KERNEL_FILE
    {
        return None;
    }
    let id = header.EventDescriptor.Id;

    // Fetch the schema (TRACE_EVENT_INFO) to learn the property names/types.
    let mut size = 0u32;
    TdhGetEventInformation(record, 0, std::ptr::null(), std::ptr::null_mut(), &mut size);
    if size == 0 || size > 1024 * 1024 {
        return None;
    }
    let allocated = size as usize;
    let mut info_buf = vec![0u64; allocated.div_ceil(8)];
    let info = info_buf.as_mut_ptr() as *mut TRACE_EVENT_INFO;
    if TdhGetEventInformation(record, 0, std::ptr::null(), info, &mut size) != ERROR_SUCCESS {
        return None;
    }
    if size as usize > allocated {
        return None;
    }
    let count = (*info).TopLevelPropertyCount as usize;
    let prop_offset = std::mem::offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);
    if count > 128
        || prop_offset
            .checked_add(count.checked_mul(std::mem::size_of::<EVENT_PROPERTY_INFO>())?)?
            > allocated
    {
        return None;
    }
    let props_base =
        std::ptr::addr_of!((*info).EventPropertyInfoArray) as *const EVENT_PROPERTY_INFO;
    let mut props = HashMap::new();
    for i in 0..count {
        let pi = &*props_base.add(i);
        // Structs and arrays are not needed by our mappings; skip them.
        if pi.Flags & PropertyStruct != 0 {
            continue;
        }
        let offset = pi.NameOffset as usize;
        if !offset.is_multiple_of(2) || offset >= allocated {
            continue;
        }
        let raw = std::slice::from_raw_parts(
            (info as *const u8).add(offset) as *const u16,
            ((allocated - offset) / 2).min(512),
        );
        let Some(end) = raw.iter().position(|c| *c == 0) else {
            continue;
        };
        let name = String::from_utf16_lossy(&raw[..end]);
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
        captured: None,
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
        TDH_INTYPE_FILETIME => match raw.as_slice().try_into() {
            Ok(bytes) => EtwValue::Int(u64::from_le_bytes(bytes), raw),
            Err(_) => EtwValue::Bytes(raw),
        },
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

fn guid_to_u128(g: &GUID) -> u128 {
    ((g.data1 as u128) << 96)
        | ((g.data2 as u128) << 80)
        | ((g.data3 as u128) << 64)
        | (u64::from_be_bytes(g.data4) as u128)
}

/// Turns decoded records into events, enriching process starts and mapping the
/// device→drive table.
///
/// It deliberately holds no `sysinfo::System`: `refresh_process_specifics` adds
/// the process to the table and never removes it, and every entry keeps an open
/// process handle. A long-lived `System` here grew by every process that was
/// ever enriched (about 6 handles a minute on a workstation), and each held
/// handle keeps the exited process object alive in the kernel.
struct DecodeState {
    devices: DeviceMap,
    /// pid → image path, so a network/DNS event can name its process.
    proc_images: HashMap<i32, (String, u64)>,
    /// Per-connection byte totals (Kernel-Network send/receive).
    flows: etw_map::NetFlows,
    /// DNS server per recent query (DNS-Client "query sent" events).
    dns_servers: etw_map::DnsServerHints,
}

impl DecodeState {
    fn new() -> Self {
        Self {
            devices: device_map(),
            proc_images: HashMap::new(),
            flows: etw_map::NetFlows::default(),
            dns_servers: etw_map::DnsServerHints::default(),
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
            if let Some(time) = etw_map::filetime_timestamp(rec.timestamp) {
                if let Some(event) = out.last_mut() {
                    event.timestamp = time;
                }
            }
            if let Some(event) = out.last_mut() {
                if let Some(origin) = &mut event.origin {
                    origin.source = Some("windows_etw".into());
                }
            }
        };
        match rec.provider {
            p if p == etw_map::KERNEL_PROCESS => match rec.id {
                1 => {
                    let pid = rec
                        .int(&["ProcessID", "ProcessId"])
                        .and_then(|p| i32::try_from(p).ok())
                        .unwrap_or(0);
                    let event_start = rec.int(&["CreateTime"]).filter(|t| *t > 0);
                    let live_start = crate::telemetry::identity::process_start_time(pid);
                    let late = if event_start.is_some() && event_start == live_start {
                        let enrich = self.enrich_process(pid);
                        if crate::telemetry::identity::process_start_time(pid) == event_start {
                            enrich
                        } else {
                            ProcessEnrichment::default()
                        }
                    } else {
                        ProcessEnrichment::default()
                    };
                    // What the callback read at delivery time wins; the late
                    // lookup only fills the gaps (exe, hash, or a field the
                    // early read could not get).
                    let enrich = rec.captured.clone().unwrap_or_default().prefer_over(late);
                    if let Some(mut data) = etw_map::process_start(rec, &self.devices, enrich) {
                        data.parent_start_time =
                            crate::telemetry::identity::parent_generation_before_child(
                                data.process_start_time,
                                crate::telemetry::identity::process_start_time(data.ppid),
                            );
                        // Only the cached image of the very generation that created
                        // this child: a reused PID must not lend its predecessor's
                        // image to a different parent.
                        if let Some(parent_start) = data.parent_start_time {
                            data.parent_exe = self
                                .proc_images
                                .get(&data.ppid)
                                .filter(|(_, start)| *start == parent_start)
                                .map(|(image, _)| image.clone());
                        }
                        crate::deception::activity::record_exec(&data.username, &data.exe);
                        crate::detection::accessor_correlation::record_process(&data);
                        if self.proc_images.len() >= 8192 {
                            self.proc_images.clear();
                        }
                        if let Some(start) = event_start {
                            self.proc_images.insert(data.pid, (data.exe.clone(), start));
                        }
                        emit(
                            EventClass::Process,
                            EventAction::Create,
                            EventData::ProcessCreate(data),
                        );
                    }
                }
                2 => {
                    if let Some(data) = etw_map::process_stop(rec, &self.devices) {
                        if self.proc_images.get(&data.pid).is_some_and(|(_, start)| {
                            rec.timestamp >= 0 && rec.timestamp as u64 >= *start
                        }) {
                            self.proc_images.remove(&data.pid);
                        }
                        emit(
                            EventClass::Process,
                            EventAction::Terminate,
                            EventData::ProcessTerminate(data),
                        );
                    }
                }
                5 => {
                    if let Some((pid, dll)) = etw_map::image_load(rec, &self.devices) {
                        let process_exe = self
                            .proc_images
                            .get(&pid)
                            .filter(|(_, start)| {
                                etw_map::same_process_generation(
                                    Some(*start),
                                    crate::telemetry::identity::process_start_time(pid),
                                    rec.timestamp,
                                )
                            })
                            .map(|(image, _)| image.clone());
                        // Only side-load candidates are shipped (a volume filter,
                        // not a verdict); the backend judges them.
                        if let Some(exe) =
                            process_exe.filter(|exe| etw_map::is_side_load_candidate(exe, &dll))
                        {
                            emit(
                                EventClass::Kernel,
                                EventAction::ModuleLoad,
                                EventData::ModuleLoad(crate::schema::ModuleLoadData {
                                    pid,
                                    uid: 0,
                                    gid: 0,
                                    username: String::new(),
                                    name: dll.rsplit('\\').next().unwrap_or(&dll).to_string(),
                                    taints: 0,
                                    path: Some(dll),
                                    process_exe: Some(exe),
                                    process_start_time: None,
                                }),
                            );
                        }
                    }
                }
                _ => {}
            },
            p if p == etw_map::KERNEL_NETWORK => {
                // Send/receive/disconnect only fold into a tracked flow; the
                // disconnect yields the `closed` record with the byte totals.
                if let Some(closed) = self.flows.observe(rec) {
                    emit(
                        EventClass::Network,
                        EventAction::Connection,
                        EventData::NetworkConnection(closed),
                    );
                }
                let pid = rec.int(&["PID"]).and_then(|p| i32::try_from(p).ok());
                let process = pid
                    .and_then(|p| {
                        self.proc_images.get(&p).filter(|(_, start)| {
                            etw_map::same_process_generation(
                                Some(*start),
                                crate::telemetry::identity::process_start_time(p),
                                rec.timestamp,
                            )
                        })
                    })
                    .map(|(e, _)| e.rsplit('\\').next().unwrap_or(e).to_string());
                if let Some(mut data) = etw_map::network_connection(rec, process) {
                    // A live creation time must precede this ETW record. A PID
                    // recycled while the record waited cannot authorize action.
                    data.process_start_time = data.pid.and_then(|pid| {
                        crate::telemetry::identity::process_start_time(pid).filter(|start| {
                            etw_map::same_process_generation(
                                Some(*start),
                                Some(*start),
                                rec.timestamp,
                            )
                        })
                    });
                    if let Some(snapshot) = self.flows.open(&data, rec.timestamp) {
                        emit(
                            EventClass::Network,
                            EventAction::Connection,
                            EventData::NetworkConnection(snapshot),
                        );
                    }
                    emit(
                        EventClass::Network,
                        EventAction::Connection,
                        EventData::NetworkConnection(data),
                    );
                }
            }
            p if p == etw_map::DNS_CLIENT => {
                self.dns_servers.note(rec);
                if let Some((pid, mut data)) = etw_map::dns_query(rec) {
                    self.attribute_dns(rec.timestamp, pid, &mut data);
                    let qtype = rec.int(&["QueryType"]).unwrap_or(0);
                    if let Some(server) = self.dns_servers.take(&data.qname, qtype, rec.timestamp) {
                        data.server_addr = server;
                    }
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

    /// Names the process behind a DNS-Client event. The DNS-Client library runs
    /// in the requesting process, so the event's logging PID is the requester
    /// (or the Dnscache service host). Attribution is dropped when the PID's
    /// live creation time does not precede the record (PID reuse).
    fn attribute_dns(
        &mut self,
        observed: i64,
        pid: u32,
        data: &mut crate::schema::DnsResolutionData,
    ) {
        let Ok(pid) = i32::try_from(pid) else { return };
        if pid <= 0 {
            return;
        }
        let Some(start) = crate::telemetry::identity::process_start_time(pid) else {
            return;
        };
        if !etw_map::same_process_generation(Some(start), Some(start), observed) {
            return;
        }
        let known = self
            .proc_images
            .get(&pid)
            .filter(|(_, s)| *s == start)
            .map(|(image, _)| image.rsplit('\\').next().unwrap_or(image).to_string());
        let spid = Pid::from_u32(pid as u32);
        let name = known.or_else(|| {
            // A throwaway table: its handle is released on return.
            let mut sys = System::new();
            sys.refresh_process_specifics(spid, ProcessRefreshKind::new());
            sys.process(spid).map(|p| p.name().to_string())
        });
        data.pid = Some(pid);
        data.process = name.filter(|n| !n.is_empty());
        data.process_start_time = Some(start);
    }

    /// Command line, account and image hash for a process that is (usually)
    /// still alive. Best-effort: a process gone before this runs still yields
    /// its start event without these.
    fn enrich_process(&mut self, pid: i32) -> ProcessEnrichment {
        if pid <= 0 {
            return ProcessEnrichment::default();
        }
        let spid = Pid::from_u32(pid as u32);
        // A throwaway table: its handle is released when this function returns.
        let mut sys = System::new();
        sys.refresh_process_specifics(
            spid,
            ProcessRefreshKind::new()
                .with_cmd(UpdateKind::Always)
                .with_exe(UpdateKind::Always)
                .with_user(UpdateKind::Always),
        );
        let Some(proc_) = sys.process(spid) else {
            return ProcessEnrichment::default();
        };
        let exe = proc_.exe().map(|p| p.to_string_lossy().into_owned());
        let cmdline = {
            let c = proc_.cmd().join(" ");
            (!c.is_empty()).then_some(c)
        };
        let username = crate::telemetry::identity::windows_process_account(pid);
        // Runs inside `spawn_blocking` (see the decode loop), so the streaming
        // hash never occupies an async worker.
        let hash = exe
            .as_deref()
            .map(|e| image_hash::hash_image(std::path::Path::new(e)))
            .unwrap_or(HashOutcome::NoPath);
        ProcessEnrichment {
            exe,
            cmdline,
            username,
            exe_sha256: hash.digest().map(str::to_owned),
            exe_sha256_error: hash.failure(),
        }
    }
}

/// Map `\Device\HarddiskVolumeN` → `C:` for every drive letter, via
/// QueryDosDeviceW. Rebuilt once at startup (mounts rarely change).
pub(super) fn device_map() -> DeviceMap {
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

#[cfg(test)]
mod native_tests {
    use super::*;

    #[test]
    fn batch_of_unrelated_records_decodes_to_nothing() {
        let mut state = DecodeState::new();
        let records = vec![EtwRecord::default(), EtwRecord::default()];
        assert!(map_batch(&mut state, &records, "agent", "host").is_empty());
        assert!(map_batch(&mut state, &[], "agent", "host").is_empty());
    }

    #[test]
    fn tdh_filetime_preserves_create_time_generation() {
        let created = 133_400_000_000_000_000u64;
        let v = interpret(TDH_INTYPE_FILETIME as u16, created.to_le_bytes().to_vec());
        assert!(matches!(v, EtwValue::Int(n, _) if n == created));
        assert!(matches!(
            interpret(TDH_INTYPE_FILETIME as u16, vec![0; 7]),
            EtwValue::Bytes(_)
        ));
    }

    fn own_handle_count() -> u32 {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
        let mut count = 0u32;
        // SAFETY: the pseudo handle is always valid; `count` is a valid out slot.
        assert_ne!(
            unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) },
            0
        );
        count
    }

    /// Regression: the decoder kept a `sysinfo::System` that accumulated every
    /// enriched process together with an open handle to it. After the children
    /// have exited and been reaped, no handle to them may be left behind.
    #[test]
    fn enriching_processes_does_not_retain_their_handles() {
        const CHILDREN: usize = 40;
        // The count is for the whole test process, and hundreds of other tests
        // run in it concurrently, so a single reading can be pushed over the
        // threshold by unrelated handles. A real leak retains about one handle
        // per enrichment on *every* attempt; noise does not repeat, so one clean
        // attempt out of three shows there is no leak.
        let mut last = (0, 0);
        for _ in 0..3 {
            let mut state = DecodeState::new();
            // Warm up lazily initialised OS state, then take the baseline before
            // any child exists: Rust's own `Child` handles are part of the later
            // count only while the children are alive.
            let _ = state.enrich_process(std::process::id() as i32);
            let baseline = own_handle_count();
            let mut children: Vec<std::process::Child> = (0..CHILDREN)
                .map(|_| {
                    std::process::Command::new("cmd.exe")
                        .args(["/C", "ping -n 30 127.0.0.1 >NUL"])
                        .spawn()
                        .unwrap()
                })
                .collect();
            for child in &children {
                let _ = state.enrich_process(child.id() as i32);
            }
            for child in &mut children {
                let _ = child.kill();
                let _ = child.wait();
            }
            drop(children);
            let after = own_handle_count();
            if after < baseline + 8 {
                return;
            }
            last = (baseline, after);
        }
        panic!(
            "{} process handles were retained across {CHILDREN} enrichments ({} -> {}) on every one of 3 attempts",
            last.1.saturating_sub(last.0),
            last.0,
            last.1
        );
    }

    /// Requires elevation; deliberately fails instead of claiming a skipped sensor worked.
    #[tokio::test]
    #[ignore = "native ETW acceptance; run elevated on Windows"]
    async fn native_etw_two_sessions_deliver_to_their_own_sink() {
        for _ in 0..2 {
            let (tx, mut rx) = tokio::sync::mpsc::channel(8192);
            let sink = Arc::new(Sink {
                tx,
                lost: std::sync::atomic::AtomicU64::new(0),
            });
            let session =
                Session::start(sink).expect("ETW session requires an elevated Windows runner");
            let control = Arc::clone(&session.control);
            let trace = std::thread::spawn(move || session.process());
            let guard = RunGuard(control);
            let child = std::process::Command::new("cmd.exe")
                .args(["/C", "ping -n 4 127.0.0.1 >NUL"])
                .spawn()
                .unwrap();
            let pid = child.id() as u64;
            let received = tokio::time::timeout(std::time::Duration::from_secs(20), async {
                while let Some(record) = rx.recv().await {
                    if record.provider == etw_map::KERNEL_PROCESS
                        && record.id == 1
                        && record.int(&["ProcessID", "ProcessId"]) == Some(pid)
                    {
                        assert!(
                            record.int(&["CreateTime"]).is_some(),
                            "real FILETIME was not decoded"
                        );
                        assert!(etw_map::filetime_timestamp(record.timestamp).is_some());
                        return true;
                    }
                }
                false
            })
            .await;
            drop(guard);
            trace.join().unwrap();
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            assert!(
                received.unwrap(),
                "new session did not deliver the process start"
            );
        }
    }
}
