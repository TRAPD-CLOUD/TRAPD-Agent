//! Parse one rendered Windows event (XML) into a log record.
//!
//! Platform-independent so `fuzz/fuzz_targets/eventlog_xml.rs` can exercise
//! it with arbitrary input. Kept free of Windows APIs on purpose.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;

use crate::schema::{LogEventData, UserLogonData};

pub(super) fn parse(
    xml: &str,
    channel: &str,
) -> Result<(u64, LogEventData, Option<UserLogonData>)> {
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
    let mut truncated_fields = BTreeMap::new();
    fields.insert("EventID".into(), event_id.into());
    fields.insert("EventRecordID".into(), record_id.into());
    let event_data = doc
        .root_element()
        .children()
        .find(|n| n.has_tag_name("EventData"));
    // Some providers (WMI-Activity 5861) write `<UserData><Operation>
    // <Field>text</Field>...` instead of named `<Data>`; flatten the first
    // operation element's children under the same limits.
    let user_fields: Vec<(String, String)> = if event_data.is_none() {
        doc.root_element()
            .children()
            .find(|n| n.has_tag_name("UserData"))
            .and_then(|u| u.children().find(|n| n.is_element()))
            .map(|op| {
                op.children()
                    .filter(|n| n.is_element())
                    .map(|n| {
                        (
                            n.tag_name().name().to_string(),
                            n.text().unwrap_or("").to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let named = event_data
        .into_iter()
        .flat_map(|n| n.children())
        .filter(|n| n.has_tag_name("Data"))
        .filter_map(|n| {
            n.attribute("Name")
                .map(|name| (name.to_string(), n.text().unwrap_or("").to_string()))
        });
    for (name, text) in named.chain(user_fields) {
        let name = name.as_str();
        if fields.len() >= 258 || name.len() > 256 || fields.contains_key(name) {
            bail!("invalid or duplicate event data field");
        }
        let (value, truncation) = crate::telemetry::limits::truncate_str(&text, 16 * 1024);
        if let Some(truncation) = truncation {
            truncated_fields.insert(format!("fields.{name}"), truncation);
            crate::telemetry::metrics::metrics().enrichment_truncation();
        }
        fields.insert(name.into(), serde_json::Value::String(value));
    }
    // 4624/4625 become structured logon events; the operating system's own
    // service/machine logons (SYSTEM, DWM, machine accounts) are dropped.
    // 4776 (NTLM validation) only gets readable fields on its raw record: it
    // accompanies 4625 on workstations and would double-count failures.
    let auth = if channel == "Security" {
        crate::detection::windows_logon::enrich_fields(event_id, &mut fields);
        crate::detection::windows_logon::normalize(event_id, &fields)
    } else {
        None
    };
    let (message, truncation) = crate::telemetry::limits::truncate_str(xml, 64 * 1024);
    if let Some(truncation) = truncation {
        truncated_fields.insert("message".into(), truncation);
    }
    let truncated_fields = (!truncated_fields.is_empty()).then_some(truncated_fields);
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
