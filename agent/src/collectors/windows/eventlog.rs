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

fn read(channel: &str, cursor: Option<u64>) -> Result<Vec<String>> {
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
    let mut out = Vec::new();
    for _ in 0..if cursor.is_some() { 128 } else { 1 } {
        let mut event = 0;
        let mut returned = 0;
        let ok = unsafe { EvtNext(query.0, 1, &mut event, 0, 0, &mut returned) };
        if ok == 0 {
            let error = unsafe { GetLastError() };
            if error == 259 {
                break;
            }
            bail!("EvtNext failed: {error}");
        }
        let event = Handle(event);
        out.push(render(event.0)?);
    }
    Ok(out)
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
    Some(windows_decoy::to_access_data(&decoy, &accessor, &verdict))
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
        loop {
            ticker.tick().await;
            if !self.config.read().map(|c| c.logs_enabled).unwrap_or(true) {
                continue;
            }
            for channel in ["Security", "System", "Application"] {
                let cursor = cursors.get(channel).copied();
                let records =
                    match tokio::task::spawn_blocking(move || read(channel, cursor)).await? {
                        Ok(records) => records,
                        Err(e) => {
                            tracing::warn!(channel, error = %e, "Windows event log unavailable");
                            continue;
                        }
                    };
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
                                if id < cursor.unwrap_or(0) {
                                    tracing::warn!(
                                        channel,
                                        "Windows event log was cleared; resetting cursor"
                                    );
                                    crate::telemetry::metrics::metrics()
                                        .event_dropped(crate::telemetry::DropReason::InternalError);
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
            }
            crate::paths::write_atomic(&path, &serde_json::to_vec(&cursors)?, 0o600)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let path = std::env::temp_dir().join(format!("trapd-4663-{}.txt", uuid::Uuid::new_v4()));
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
