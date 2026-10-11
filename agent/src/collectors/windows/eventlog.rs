//! Native Windows Security/System/Application event logs with persisted cursors.
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc::Sender;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::EventLog::*;

use crate::collectors::Collector;
use crate::config::AgentConfig;
use crate::detection::windows_decoy;
use crate::schema::DetectionData;
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, HoneytokenAccessData, LogEventData, Severity,
    UserLogonData,
};

struct Handle(EVT_HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            EvtClose(self.0);
        }
    }
}

fn render(event: EVT_HANDLE) -> Result<String> {
    let mut bytes = 0;
    let mut properties = 0;
    // SAFETY: query size first; all out-pointers point to valid storage.
    unsafe {
        EvtRender(
            0,
            event,
            EvtRenderEventXml,
            0,
            std::ptr::null_mut(),
            &mut bytes,
            &mut properties,
        );
    }
    if bytes == 0 || bytes > 1024 * 1024 {
        bail!("invalid event-log XML size: {bytes}");
    }
    let mut data = vec![0u16; (bytes as usize).div_ceil(2)];
    // SAFETY: the live EVT_HANDLE comes from EvtNext, and buffer covers bytes.
    let ok = unsafe {
        EvtRender(
            0,
            event,
            EvtRenderEventXml,
            bytes,
            data.as_mut_ptr().cast(),
            &mut bytes,
            &mut properties,
        )
    };
    if ok == 0 {
        bail!("EvtRender failed: {}", unsafe { GetLastError() });
    }
    let length = data.iter().position(|c| *c == 0).unwrap_or(data.len());
    Ok(String::from_utf16(&data[..length])?)
}

/// Events requested from one `EvtNext` call.
const EVT_BATCH: usize = 64;
/// Events fetched and rendered by one blocking read.
const READ_LIMIT: usize = 512;
/// Events drained per channel in one tick before yielding to the other
/// channels and persisting the cursor. A backlog continues on the next pass
/// without waiting for the timer.
const MAX_PER_TICK: usize = 8192;

/// Result of one bounded read of a channel.
struct Batch {
    records: Vec<String>,
    /// The query reported no more items (`ERROR_NO_MORE_ITEMS`).
    exhausted: bool,
}

/// What a channel does after one batch.
#[derive(Debug, PartialEq, Eq)]
enum Drain {
    /// Read the channel again within this tick.
    Again,
    /// Channel is empty for now; wait for the next tick.
    Done,
    /// Per-tick cap reached with data left; continue without waiting.
    Backlog,
}

fn after_batch(batch_len: usize, exhausted: bool, drained: usize) -> Drain {
    if exhausted || batch_len == 0 {
        Drain::Done
    } else if drained >= MAX_PER_TICK {
        Drain::Backlog
    } else {
        Drain::Again
    }
}

/// A cleared log restarts record numbering: the newest record is older than
/// the persisted high-water mark.
fn log_was_cleared(newest_record: u64, cursor: u64) -> bool {
    newest_record < cursor
}

fn read(channel: &str, cursor: Option<u64>) -> Result<Vec<String>> {
    read_batch(channel, cursor, READ_LIMIT).map(|b| b.records)
}

/// Read at most `limit` events after `cursor` (or the single newest event when
/// there is no cursor yet), fetching them from the log in `EVT_BATCH` chunks.
fn read_batch(channel: &str, cursor: Option<u64>, limit: usize) -> Result<Batch> {
    let channel: Vec<u16> = channel.encode_utf16().chain(Some(0)).collect();
    let query = cursor
        .map(|id| format!("*[System[EventRecordID > {id}]]"))
        .unwrap_or_else(|| "*".into());
    let query: Vec<u16> = query.encode_utf16().chain(Some(0)).collect();
    // SAFETY: terminated strings; zero session selects the local machine.
    let query = Handle(unsafe {
        EvtQuery(
            0,
            channel.as_ptr(),
            query.as_ptr(),
            EvtQueryChannelPath
                | if cursor.is_some() {
                    EvtQueryForwardDirection
                } else {
                    EvtQueryReverseDirection
                },
        )
    });
    if query.0 == 0 {
        bail!("EvtQuery failed: {}", unsafe { GetLastError() });
    }
    let limit = if cursor.is_some() { limit } else { 1 };
    let mut out = Vec::with_capacity(limit.min(EVT_BATCH));
    let mut exhausted = false;
    while out.len() < limit {
        let want = (limit - out.len()).min(EVT_BATCH);
        let mut events: [EVT_HANDLE; EVT_BATCH] = [0; EVT_BATCH];
        let mut returned = 0u32;
        // SAFETY: `events` has room for `want` handles; EvtNext writes at most
        // `want` of them and reports the count in `returned`.
        let ok = unsafe {
            EvtNext(
                query.0,
                want as u32,
                events.as_mut_ptr(),
                0,
                0,
                &mut returned,
            )
        };
        if ok == 0 {
            let error = unsafe { GetLastError() };
            if error == 259 {
                exhausted = true;
                break;
            }
            bail!("EvtNext failed: {error}");
        }
        // Own every returned handle first so none leaks on a render failure.
        let handles: Vec<Handle> = events[..returned as usize]
            .iter()
            .map(|h| Handle(*h))
            .collect();
        for event in &handles {
            match render(event.0) {
                Ok(xml) => out.push(xml),
                // One unrenderable record must not wedge the channel.
                Err(e) => tracing::warn!(error = %e, "skipping unrenderable event-log record"),
            }
        }
    }
    Ok(Batch {
        records: out,
        exhausted,
    })
}

fn parse(xml: &str, channel: &str) -> Result<(u64, LogEventData, Option<UserLogonData>)> {
    let doc = roxmltree::Document::parse(xml)?;
    let system = doc
        .root_element()
        .children()
        .find(|n| n.has_tag_name("System"))
        .context("event has no System element")?;
    let text = |name: &str| {
        system
            .children()
            .find(|n| n.has_tag_name(name))
            .and_then(|n| n.text())
            .unwrap_or("")
    };
    let record_id = text("EventRecordID").parse::<u64>()?;
    let event_id = text("EventID").parse::<u32>()?;
    let mut fields = serde_json::Map::new();
    fields.insert("EventID".into(), event_id.into());
    fields.insert("EventRecordID".into(), record_id.into());
    for n in doc.descendants().filter(|n| n.has_tag_name("Data")) {
        if let Some(name) = n.attribute("Name") {
            fields.insert(
                name.into(),
                serde_json::Value::String(n.text().unwrap_or("").chars().take(16384).collect()),
            );
        }
    }
    let value = |name: &str| {
        fields
            .get(name)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let auth = if channel == "Security" && matches!(event_id, 4624 | 4625) {
        Some(UserLogonData {
            username: value("TargetUserName"),
            src_addr: match value("IpAddress").as_str() {
                "" | "-" => None,
                other => Some(other.into()),
            },
            src_port: value("IpPort").parse().ok(),
            auth_method: Some(value("AuthenticationPackageName")),
            success: event_id == 4624,
        })
    } else {
        None
    };
    let (message, truncation) = crate::telemetry::limits::truncate_str(xml, 64 * 1024);
    let truncated_fields = truncation.map(|t| BTreeMap::from([("message".into(), t)]));
    let log_timestamp = system
        .children()
        .find(|n| n.has_tag_name("TimeCreated"))
        .and_then(|n| n.attribute("SystemTime"))
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&chrono::Utc));
    let proc = system
        .children()
        .find(|n| n.has_tag_name("Provider"))
        .and_then(|n| n.attribute("Name"))
        .map(str::to_string);
    let pid = system
        .children()
        .find(|n| n.has_tag_name("Execution"))
        .and_then(|n| n.attribute("ProcessID"))
        .and_then(|p| p.parse().ok());
    let data = LogEventData {
        source: format!("windows_{channel}"),
        source_type: "windows_eventlog".into(),
        source_path: channel.into(),
        parser: "windows_eventlog_xml".into(),
        message,
        category: if channel == "Security" {
            "authentication"
        } else {
            "system"
        }
        .into(),
        log_timestamp,
        facility: None,
        log_severity: Some(
            match text("Level") {
                "1" => "critical",
                "2" => "error",
                "3" => "warning",
                "5" => "debug",
                _ => "info",
            }
            .into(),
        ),
        proc,
        pid,
        uid: None,
        username: auth.as_ref().map(|a| a.username.clone()),
        log_host: Some(text("Computer").into()),
        fields,
        mitre_tactic: None,
        mitre_technique: None,
        offset: Some(record_id),
        inode: None,
        truncated_fields,
    };
    Ok((record_id, data, auth))
}

/// Record the logon type of a 4624 success so later object-access events can
/// be graded by session kind. Bounded to 4096 entries.
fn capture_logon_type(
    fields: &serde_json::Map<String, serde_json::Value>,
    cache: &mut HashMap<String, u32>,
) {
    let id = fields.get("EventID").and_then(|v| v.as_u64());
    if id != Some(4624) {
        return;
    }
    let get = |k: &str| fields.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let logon_id = get("TargetLogonId");
    if let Ok(t) = get("LogonType").parse::<u32>() {
        if !logon_id.is_empty() {
            if cache.len() >= 4096 {
                cache.clear();
            }
            cache.insert(logon_id.to_string(), t);
        }
    }
}

/// Grade a 4663 object-access event against the planted-decoy registry.
/// Returns a honeytoken detection only when the access is on a decoy and the
/// grader did not treat it as a pure verified-sweeper metadata touch.
fn decoy_access(
    fields: &serde_json::Map<String, serde_json::Value>,
    logon_types: &HashMap<String, u32>,
    observed: Option<chrono::DateTime<chrono::Utc>>,
    devices: &crate::collectors::etw_map::DeviceMap,
) -> Option<HoneytokenAccessData> {
    if fields.get("EventID").and_then(|v| v.as_u64()) != Some(4663) {
        return None;
    }
    let get = |k: &str| {
        fields
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let object = get("ObjectName");
    if object.is_empty() {
        return None;
    }
    let decoy = windows_decoy::lookup_decoy(&object)?;
    let logon_type = {
        let id = get("SubjectLogonId");
        (!id.is_empty())
            .then(|| logon_types.get(&id).copied())
            .flatten()
    };
    let mut accessor = windows_decoy::accessor_from_4663(|k| get(k), logon_type, false);
    // Security auditing can report an NT device image while current_exe and
    // live process queries return DOS paths. Compare the full mapped identity.
    accessor.process_name =
        crate::collectors::etw_map::device_to_dos(&accessor.process_name, devices);
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let pid = std::process::id() as i32;
    let observed_filetime = observed
        .and_then(|t| t.timestamp_millis().checked_add(11_644_473_600_000))
        .and_then(|t| u64::try_from(t).ok())
        .and_then(|t| t.checked_mul(10_000));
    if windows_decoy::is_agent_self_read(
        &accessor,
        pid,
        &exe,
        crate::telemetry::identity::process_start_time(pid),
        observed_filetime,
    ) {
        return None;
    }
    accessor.signed_trusted = super::sweeper_identity::verified(&accessor, observed_filetime);
    let unusual = observed.and_then(|t| {
        use chrono::Timelike;
        crate::deception::activity::current_summaries()
            .get(&accessor.subject_user.to_lowercase())
            .and_then(|s| s.is_unusual_hour(t.hour()))
    });
    let verdict = windows_decoy::grade(&decoy, &accessor, unusual);
    let mut data = windows_decoy::to_access_data(&decoy, &accessor, &verdict);
    // A reused PID's creation time follows the historic audit record. Unknown
    // or unordered timestamps remain unattributed for destructive responses.
    data.accessor.process_start_time = crate::telemetry::identity::process_start_time(accessor.pid)
        .filter(|start| *start > 0 && observed_filetime.is_some_and(|observed| observed >= *start));
    Some(data)
}

/// Security-log clear (1102) or audit-policy change (4719): an attacker
/// blinding the host. Raised as a self-protection detection.
fn audit_tamper(fields: &serde_json::Map<String, serde_json::Value>) -> Option<DetectionData> {
    let id = fields.get("EventID").and_then(|v| v.as_u64())?;
    let (title, detail) = match id {
        1102 => (
            "Security event log cleared",
            "The Windows Security log was cleared",
        ),
        4719 => (
            "System audit policy changed",
            "The system audit policy was changed",
        ),
        _ => return None,
    };
    Some(DetectionData {
        rule_id: "selfprotect.audit_policy_changed".into(),
        title: title.into(),
        category: "defense_evasion".into(),
        mitre_tactic: Some("TA0005 Defense Evasion".into()),
        mitre_technique: Some(if id == 1102 { "T1070.001" } else { "T1562.002" }.into()),
        confidence: 80,
        subject: format!("event {id}"),
        detail: detail.into(),
        evidence: serde_json::json!({ "event_id": id }),
        ..Default::default()
    })
}

pub struct EventLogCollector {
    config: Arc<RwLock<AgentConfig>>,
}
impl EventLogCollector {
    pub fn new(config: Arc<RwLock<AgentConfig>>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Collector for EventLogCollector {
    fn name(&self) -> &'static str {
        "WindowsEventLogCollector"
    }
    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let path = crate::paths::state_dir().join("windows_eventlog_cursors.json");
        let mut cursors: HashMap<String, u64> = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        // Recent (SubjectLogonId -> LogonType) from 4624, so a 4663 decoy read
        // can be graded by how its subject logged on (interactive vs. RDP vs.
        // service). Bounded; oldest dropped on overflow.
        let mut logon_types: HashMap<String, u32> = HashMap::new();
        let devices = super::etw::device_map();
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
        // A channel hit the per-tick cap: read again without waiting.
        let mut backlog = false;
        loop {
            if !backlog {
                ticker.tick().await;
            }
            backlog = false;
            if !self.config.read().map(|c| c.logs_enabled).unwrap_or(true) {
                continue;
            }
            for channel in ["Security", "System", "Application"] {
                let mut drained = 0usize;
                loop {
                    let cursor = cursors.get(channel).copied();
                    let batch = match tokio::task::spawn_blocking(move || {
                        read_batch(channel, cursor, READ_LIMIT)
                    })
                    .await?
                    {
                        Ok(batch) => batch,
                        Err(e) => {
                            tracing::warn!(channel, error = %e, "Windows event log unavailable");
                            break;
                        }
                    };
                    let Batch { records, exhausted } = batch;
                    let batch_len = records.len();
                    if records.is_empty() && cursor.is_none() {
                        cursors.insert(channel.into(), 0);
                    }
                    // A cleared log can restart record numbering. Rebase visibly
                    // instead of waiting forever for the previous high-water mark.
                    if records.is_empty() && cursor.is_some() {
                        if let Ok(latest) =
                            tokio::task::spawn_blocking(move || read(channel, None)).await?
                        {
                            if let Some(xml) = latest.first() {
                                if let Ok((id, _, _)) = parse(xml, channel) {
                                    if log_was_cleared(id, cursor.unwrap_or(0)) {
                                        tracing::warn!(
                                            channel,
                                            "Windows event log was cleared; resetting cursor"
                                        );
                                        crate::telemetry::metrics::metrics().event_dropped(
                                            crate::telemetry::DropReason::InternalError,
                                        );
                                        cursors.insert(channel.into(), 0);
                                    }
                                }
                            }
                        }
                    }
                    for xml in records {
                        let (record, data, auth) = parse(&xml, channel)?;
                        if channel == "Security" {
                            capture_logon_type(&data.fields, &mut logon_types);
                            if cursor.is_some() {
                                if let Some(det) = audit_tamper(&data.fields) {
                                    let ev = AgentEvent::new(
                                        agent_id.clone(),
                                        hostname.clone(),
                                        EventClass::Detection,
                                        EventAction::Detected,
                                        Severity::High,
                                        EventData::Detection(Box::new(det)),
                                    );
                                    if tx.send(ev).await.is_err() {
                                        return Ok(());
                                    }
                                }
                            }
                            if cursor.is_some() {
                                if let Some(hit) = decoy_access(
                                    &data.fields,
                                    &logon_types,
                                    data.log_timestamp,
                                    &devices,
                                ) {
                                    let outcome = crate::detection::honeytoken_policy::assess(
                                        &hit,
                                        Severity::Critical,
                                    );
                                    let mut ev = AgentEvent::new(
                                        agent_id.clone(),
                                        hostname.clone(),
                                        EventClass::Detection,
                                        EventAction::HoneytokenAccess,
                                        outcome.severity,
                                        EventData::HoneytokenAccess(Box::new(hit)),
                                    );
                                    if let Some(time) = data.log_timestamp {
                                        ev.timestamp = time;
                                    }
                                    if tx.send(ev).await.is_err() {
                                        return Ok(());
                                    }
                                }
                            }
                        }
                        // First start tails from the newest record, avoiding a full
                        // historical replay. Subsequent starts resume the cursor.
                        if cursor.is_some() {
                            let event = AgentEvent::new(
                                agent_id.clone(),
                                hostname.clone(),
                                EventClass::Log,
                                EventAction::Log,
                                Severity::Info,
                                EventData::Log(Box::new(data)),
                            );
                            if tx.send(event).await.is_err() {
                                return Ok(());
                            }
                            if let Some(auth) = auth {
                                let event = AgentEvent::new(
                                    agent_id.clone(),
                                    hostname.clone(),
                                    EventClass::User,
                                    if auth.success {
                                        EventAction::Logon
                                    } else {
                                        EventAction::LogonFailed
                                    },
                                    if auth.success {
                                        Severity::Info
                                    } else {
                                        Severity::Low
                                    },
                                    EventData::UserLogon(auth),
                                );
                                if tx.send(event).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                        cursors.insert(channel.into(), record);
                    }
                    drained += batch_len;
                    // The first start only records the newest id (one read).
                    if cursor.is_none() {
                        break;
                    }
                    match after_batch(batch_len, exhausted, drained) {
                        Drain::Again => {}
                        Drain::Done => break,
                        Drain::Backlog => {
                            backlog = true;
                            break;
                        }
                    }
                }
                crate::paths::write_atomic(&path, &serde_json::to_vec(&cursors)?, 0o600)?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn drain_continues_until_exhausted_or_capped() {
        assert_eq!(after_batch(512, false, 512), Drain::Again);
        assert_eq!(after_batch(37, true, 549), Drain::Done);
        assert_eq!(after_batch(0, false, 512), Drain::Done);
        assert_eq!(after_batch(512, false, MAX_PER_TICK), Drain::Backlog);
        // Exhaustion wins over the cap: nothing is left to continue with.
        assert_eq!(after_batch(10, true, MAX_PER_TICK), Drain::Done);
    }
    #[test]
    fn rotated_log_is_detected_by_a_lower_newest_record() {
        assert!(log_was_cleared(5, 1000));
        assert!(!log_was_cleared(1000, 1000));
        assert!(!log_was_cleared(1001, 1000));
    }
    #[test]
    fn native_xml_preserves_unicode_auth_identity_and_record_id() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><EventRecordID>123</EventRecordID><Level>0</Level><Computer>host</Computer></System><EventData><Data Name="TargetUserName">Jörg &amp; Co</Data><Data Name="IpAddress">10.0.0.1</Data><Data Name="IpPort">445</Data></EventData></Event>"#;
        let (id, data, auth) = parse(xml, "Security").unwrap();
        assert_eq!(id, 123);
        assert_eq!(data.fields["EventID"], 4625);
        let auth = auth.unwrap();
        assert_eq!(auth.username, "Jörg & Co");
        assert_eq!(auth.src_addr.as_deref(), Some("10.0.0.1"));
        assert!(!auth.success);
    }
    #[test]
    #[ignore = "requires elevated native Windows with Audit File System success enabled"]
    fn native_4663_self_read_is_suppressed_and_foreign_read_alerts() {
        use super::super::decoy_audit;
        // Runners expose TEMP as an 8.3 short name (RUNNER~1) while other
        // processes are audited under the long name; register the long form.
        let canonical = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let temp = std::path::PathBuf::from(canonical.trim_start_matches(r"\\?\"));
        let path = temp.join(format!("trapd-4663-{}.txt", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"native audit fixture").unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                windows_decoy::forget_decoy(&self.0.to_string_lossy());
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let _cleanup = Cleanup(path.clone());
        assert_eq!(decoy_audit::file_audit_enabled(), Some(true));
        assert!(decoy_audit::set_read_audit_sacl(&path));
        windows_decoy::register_decoy(windows_decoy::DecoyInfo {
            token_id: uuid::Uuid::new_v4().to_string(),
            path: path.to_string_lossy().into_owned(),
            kind: "password_note".into(),
            owner_sid: decoy_audit::owner_sid(&path).unwrap(),
            audit_ready: true,
        });
        let newest = read("Security", None).unwrap();
        let mut cursor = newest
            .first()
            .map(|xml| parse(xml, "Security").unwrap().0)
            .unwrap_or(0);
        for _ in 0..3 {
            assert!(!std::fs::read(&path).unwrap().is_empty());
        }
        let mut child = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                "[void][System.IO.File]::ReadAllBytes($env:TRAPD_NATIVE_AUDIT_FILE); Start-Sleep -Seconds 3"])
            .env("TRAPD_NATIVE_AUDIT_FILE", &path).spawn().unwrap();
        let child_pid = child.id() as i32;
        let mut self_reads = 0;
        let devices = super::super::etw::device_map();
        let mut foreign_alert = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::time::Instant::now() < deadline && (self_reads < 3 || !foreign_alert) {
            for xml in read("Security", Some(cursor)).unwrap() {
                let (record, data, _) = parse(&xml, "Security").unwrap();
                cursor = cursor.max(record);
                if data.fields.get("EventID").and_then(|v| v.as_u64()) == Some(4663) {
                    let f = |k: &str| {
                        data.fields
                            .get(k)
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string()
                    };
                    let object = f("ObjectName");
                    if object.contains("trapd-4663") {
                        eprintln!(
                            "4663 raw: object={object:?} pid={} mask={} process={:?}",
                            f("ProcessId"),
                            f("AccessMask"),
                            f("ProcessName")
                        );
                    }
                }
                if data.fields.get("EventID").and_then(|v| v.as_u64()) != Some(4663)
                    || !data
                        .fields
                        .get("ObjectName")
                        .and_then(|v| v.as_str())
                        .is_some_and(|p| p.eq_ignore_ascii_case(&path.to_string_lossy()))
                {
                    continue;
                }
                let get = |key: &str| {
                    data.fields
                        .get(key)
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                };
                let accessor = windows_decoy::accessor_from_4663(get, None, false);
                if accessor.access_mask & windows_decoy::FILE_READ_DATA == 0 {
                    continue;
                }
                let hit = decoy_access(&data.fields, &HashMap::new(), data.log_timestamp, &devices);
                eprintln!(
                    "4663 read: pid={} (child={}, self={}) image={:?} mask={:#x} user={:?} hit={:?}",
                    accessor.pid,
                    child_pid,
                    std::process::id(),
                    accessor.process_name,
                    accessor.access_mask,
                    accessor.subject_user,
                    hit.as_ref().map(|h| (&h.access_kind, h.confidence, &h.assessment)),
                );
                if accessor.pid == std::process::id() as i32 {
                    self_reads += 1;
                    assert!(
                        hit.is_none(),
                        "live agent health read must be excluded: image={:?}, current={:?}, mask={:#x}, started={:?}, observed={:?}",
                        accessor.process_name,
                        std::env::current_exe(),
                        accessor.access_mask,
                        crate::telemetry::identity::process_start_time(accessor.pid),
                        data.log_timestamp,
                    );
                } else if accessor.pid == child_pid {
                    let hit = hit.expect("foreign read must remain visible");
                    let outcome = crate::detection::honeytoken_policy::assess(&hit, Severity::High);
                    assert_eq!(outcome.mode, crate::schema::DetectionMode::Alert);
                    foreign_alert = true;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(child.wait().unwrap().success());
        assert!(
            self_reads >= 3,
            "4663 stream must include every health read"
        );
        assert!(foreign_alert, "real PowerShell read must generate an Alert");
    }
}
