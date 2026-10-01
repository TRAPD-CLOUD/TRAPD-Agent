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
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, LogEventData, Severity, UserLogonData,
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
}
