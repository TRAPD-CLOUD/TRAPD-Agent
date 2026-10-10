//! Persisted native Windows records supplement live ETW without querying exited processes.
use crate::schema::*;

pub const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

fn number(value: &str) -> Option<u32> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}
fn pid(value: &str) -> Option<i32> {
    i32::try_from(number(value)?).ok().filter(|p| *p > 0)
}
fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}
fn registry_path(path: &str) -> Option<String> {
    for (prefix, hive) in [
        (r"\REGISTRY\MACHINE\", "HKLM\\"),
        (r"\REGISTRY\USER\", "HKU\\"),
        ("HKLM\\", "HKLM\\"),
        ("HKU\\", "HKU\\"),
        ("HKCR\\", "HKCR\\"),
    ] {
        if path
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
        {
            return Some(format!("{hive}{}", &path[prefix.len()..]));
        }
    }
    None
}
// Names identify registry objects; they are never interpreted as stored data.
fn rename_object(path: &str, is_value: bool) -> Option<RegistryRenameSource> {
    let path = registry_path(path)?;
    if path.contains('\0') || path.split('\\').any(str::is_empty) {
        return None;
    }
    let (key_path, value_name) = if is_value {
        let (key, value) = path.rsplit_once('\\')?;
        if !key.contains('\\') {
            return None;
        }
        (key.to_string(), Some(value.to_string()))
    } else {
        (path, None)
    };
    Some(RegistryRenameSource {
        key_path,
        value_name,
    })
}
fn rename_category(object: &RegistryRenameSource) -> Option<&'static str> {
    match object.value_name.as_deref() {
        Some(name) => crate::collectors::registry_watch::category_for_path(&object.key_path, name),
        None => crate::collectors::registry_watch::category_for_key_path(&object.key_path),
    }
}
fn account(user: &str, domain: &str) -> String {
    if user.is_empty() || user == "-" {
        String::new()
    } else if domain.is_empty() || domain == "-" {
        user.into()
    } else {
        format!("{domain}\\{user}")
    }
}

/// Only documented provider/channel combinations can produce structured records.
/// No live process query: historic PIDs may already belong to another process.
pub fn normalize(log: &LogEventData, agent: &str, host: &str) -> Option<AgentEvent> {
    let security = log.source_path == "Security"
        && log.proc.as_deref() == Some("Microsoft-Windows-Security-Auditing");
    let sysmon = log.source_path == SYSMON_CHANNEL
        && log.proc.as_deref() == Some("Microsoft-Windows-Sysmon");
    let id = log.fields.get("EventID")?.as_u64()?;
    let get = |key: &str| log.fields.get(key).and_then(|v| v.as_str()).unwrap_or("");
    let make = |class, action, severity, data| {
        let mut event = AgentEvent::new(agent.into(), host.into(), class, action, severity, data)
            .with_source(&format!("windows_eventlog:{}:{id}", log.source_path));
        event.timestamp = log.log_timestamp?;
        Some(event)
    };
    if (security && id == 4688) || (sysmon && id == 1) {
        let (process_id, parent_id, exe, cmdline, username) = if security {
            // Version 2 distinguishes the creator account from the child account.
            let target = get("TargetUserSid");
            let username = if !target.is_empty() && target != "S-1-0-0" && target != "-" {
                account(get("TargetUserName"), get("TargetDomainName"))
            } else {
                account(get("SubjectUserName"), get("SubjectDomainName"))
            };
            (
                get("NewProcessId"),
                get("ProcessId"),
                get("NewProcessName"),
                get("CommandLine"),
                username,
            )
        } else {
            (
                get("ProcessId"),
                get("ParentProcessId"),
                get("Image"),
                get("CommandLine"),
                get("User").into(),
            )
        };
        if exe.is_empty() {
            return None;
        }
        let mut enrichment = crate::telemetry::Enrichment::new();
        for (field, unavailable) in [
            ("cmdline", cmdline.is_empty()),
            ("username", username.is_empty()),
        ] {
            if unavailable {
                enrichment.fail(field, crate::telemetry::EnrichmentError::Unsupported);
            }
        }
        if let Some(markers) = &log.truncated_fields {
            for (field, source) in [
                ("cmdline", "CommandLine"),
                ("exe", "NewProcessName"),
                ("exe", "Image"),
                ("username", "User"),
                ("username", "SubjectUserName"),
                ("username", "SubjectDomainName"),
                ("username", "TargetUserName"),
                ("username", "TargetDomainName"),
            ] {
                enrichment.truncated(field, markers.get(&format!("fields.{source}")).cloned());
            }
        }
        return make(
            EventClass::Process,
            EventAction::Create,
            Severity::Info,
            EventData::ProcessCreate(ProcessCreateData {
                pid: pid(process_id)?,
                ppid: pid(parent_id).unwrap_or(0),
                name: basename(exe).into(),
                exe: exe.into(),
                cmdline: cmdline.into(),
                username,
                enrichment: enrichment.finish(2),
                ..Default::default()
            }),
        );
    }
    if sysmon && id == 10 {
        let target = get("TargetImage");
        let access = number(get("GrantedAccess"))?;
        // PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE. Query-only
        // rights do not establish memory access; memory rights do not prove a dump.
        if !basename(target).eq_ignore_ascii_case("lsass.exe") || access & 0x38 == 0 {
            return None;
        }
        let source_pid = pid(get("SourceProcessId"))?;
        let target_pid = pid(get("TargetProcessId"))?;
        return make(EventClass::Detection, EventAction::Detected, Severity::Low,
            EventData::Detection(Box::new(DetectionData {
                rule_id: "credential_access.lsass_memory_access".into(), title: "Observed memory-capable LSASS process access".into(),
                category: "credential_access".into(), mitre_tactic: Some("TA0006 Credential Access".into()),
                mitre_technique: Some("T1003.001".into()), confidence: 60,
                subject: format!("{} (pid {source_pid})", get("SourceImage")),
                detail: "Sysmon recorded a handle to LSASS with memory access rights. This can be legitimate and does not establish a credential dump.".into(),
                mode: Some(DetectionMode::Signal), evidence: serde_json::json!({
                    "event_id": id, "event_record_id": log.offset, "source_channel": log.source_path,
                    "source_pid": source_pid, "source_image": get("SourceImage"), "source_user": get("SourceUser"),
                    "source_process_guid": get("SourceProcessGUID"), "target_pid": target_pid,
                    "target_image": target, "target_process_guid": get("TargetProcessGUID"),
                    "granted_access": access, "call_trace": get("CallTrace"),
                    "truncated_fields": log.truncated_fields }), ..Default::default()
            })));
    }
    let mut rename_from = None;
    let mut rename_scope = None;
    let (path, value, action, old_value, new_value) = if security && id == 4657 {
        let action = match get("OperationType") {
            "%%1904" => EventAction::Create,
            "%%1905" => EventAction::Modify,
            "%%1906" => EventAction::Delete,
            _ => return None,
        };
        let old = (get("OperationType") != "%%1904" && log.fields.contains_key("OldValue"))
            .then(|| get("OldValue").to_string());
        let new = (get("OperationType") != "%%1906" && log.fields.contains_key("NewValue"))
            .then(|| get("NewValue").to_string());
        (
            registry_path(get("ObjectName"))?,
            get("ObjectValueName").to_string(),
            action,
            old,
            new,
        )
    } else if sysmon && id == 14 {
        let is_value = match get("EventType") {
            "RenameKey" => false,
            "RenameValue" => true,
            _ => return None,
        };
        if log.truncated_fields.as_ref().is_some_and(|fields| {
            fields.contains_key("fields.TargetObject") || fields.contains_key("fields.NewName")
        }) {
            return None;
        }
        let source = rename_object(get("TargetObject"), is_value)?;
        let destination = rename_object(get("NewName"), is_value)?;
        // Native rename changes a leaf name within its original key/parent.
        let same_parent = if is_value {
            source.key_path.eq_ignore_ascii_case(&destination.key_path)
        } else {
            source
                .key_path
                .rsplit_once('\\')?
                .0
                .eq_ignore_ascii_case(destination.key_path.rsplit_once('\\')?.0)
        };
        if !same_parent {
            return None;
        }
        rename_scope = rename_category(&destination).or_else(|| rename_category(&source));
        let value = destination.value_name.unwrap_or_else(|| "(Key)".into());
        rename_from = Some(source);
        (destination.key_path, value, EventAction::Modify, None, None)
    } else if sysmon && matches!(id, 12..=13) {
        let target = registry_path(get("TargetObject"))?;
        let kind = get("EventType");
        let (action, is_value) = match (id, kind) {
            (12, "CreateKey") => (EventAction::Create, false),
            (12, "DeleteKey") => (EventAction::Delete, false),
            (12, "CreateValue") => (EventAction::Create, true),
            (12, "DeleteValue") => (EventAction::Delete, true),
            (13, "SetValue") => (EventAction::Modify, true),
            _ => return None,
        };
        let (path, value) = if is_value {
            let (path, value) = target.rsplit_once('\\')?;
            (path.to_string(), value.to_string())
        } else {
            (target, "(Key)".into())
        };
        let new = (id == 13).then(|| get("Details").to_string());
        (path, value, action, None, new)
    } else {
        return None;
    };
    let sid = path
        .strip_prefix("HKU\\")
        .and_then(|p| p.split('\\').next())
        .filter(|p| p.starts_with("S-1-"));
    let category = rename_scope
        .or_else(|| crate::collectors::registry_watch::category_for_path(&path, &value))
        .unwrap_or("native_registry");
    make(
        EventClass::Registry,
        action,
        Severity::Info,
        EventData::Registry(RegistryEventData {
            key_path: path.clone(),
            value_name: if value.is_empty() {
                "(Default)".into()
            } else {
                value
            },
            category: category.into(),
            user_sid: sid.map(str::to_string),
            old_value: old_value.map(|v| crate::collectors::registry_watch::truncate_value(&v)),
            new_value: new_value.map(|v| crate::collectors::registry_watch::truncate_value(&v)),
            rename_from,
            suppressed: None,
        }),
    )
}

/// Trim source strings before deriving events. The conservative source budget
/// leaves room for duplicated image/subject text in normalized payloads and for
/// the journal frame. Raw `truncated_fields["fields.<Name>"]` (or `message`)
/// records original and captured UTF-8 byte lengths. IDs/channel/provider stay
/// intact; meaningful named values remain available for historical detection.
fn bound_source(data: &mut LogEventData) -> anyhow::Result<()> {
    use crate::telemetry::limits::{truncate_str, Truncation, MAX_EVENT_BYTES};
    let original_fields_bytes = serde_json::to_vec(&data.fields)?.len();
    let mut markers = data.truncated_fields.take().unwrap_or_default();
    let trim = |value: &mut String,
                limit: usize,
                name: &str,
                markers: &mut std::collections::BTreeMap<String, Truncation>| {
        let (bounded, cut) = truncate_str(value, limit);
        if let Some(cut) = cut {
            *value = bounded;
            let original = markers
                .get(name)
                .map_or(cut.original_length, |m| m.original_length);
            markers.insert(name.into(), Truncation::new(original, value.len()));
            crate::telemetry::metrics::metrics().enrichment_truncation();
        }
    };
    trim(&mut data.message, 64 * 1024, "message", &mut markers);
    for (key, value) in &mut data.fields {
        if let serde_json::Value::String(value) = value {
            trim(value, 16 * 1024, &format!("fields.{key}"), &mut markers);
        }
    }
    for (name, value) in [
        ("username", &mut data.username),
        ("log_host", &mut data.log_host),
    ] {
        if let Some(value) = value {
            trim(value, 1024, name, &mut markers);
        }
    }
    data.truncated_fields = (!markers.is_empty()).then_some(markers);
    // Prefer cutting redundant raw XML over the named fields used by rules.
    while serde_json::to_vec(data)?.len() > MAX_EVENT_BYTES / 3 {
        let mut markers = data.truncated_fields.take().unwrap_or_default();
        if data.message.len() > 1024 {
            let limit = data.message.len() / 2;
            trim(&mut data.message, limit, "message", &mut markers);
        } else if let Some(key) = data
            .fields
            .iter()
            .filter_map(|(key, value)| {
                value
                    .as_str()
                    .filter(|v| v.len() > 128)
                    .map(|v| (key, v.len()))
            })
            .max_by_key(|(_, length)| *length)
            .map(|(key, _)| key.clone())
        {
            if let Some(serde_json::Value::String(value)) = data.fields.get_mut(&key) {
                trim(
                    value,
                    value.len() / 2,
                    &format!("fields.{key}"),
                    &mut markers,
                );
            }
        } else {
            // Pathological extra names/non-string data can exceed the budget
            // even after value cuts. Preserve native identity and actor fields;
            // disclose any discarded extras with an aggregate `fields` marker.
            let key = data
                .fields
                .keys()
                .filter(|key| {
                    !matches!(
                        key.as_str(),
                        "EventID"
                            | "EventRecordID"
                            | "NewProcessId"
                            | "ProcessId"
                            | "ParentProcessId"
                            | "NewProcessName"
                            | "Image"
                            | "CommandLine"
                            | "User"
                            | "SubjectUserName"
                            | "SubjectDomainName"
                            | "SubjectUserSid"
                            | "TargetUserName"
                            | "TargetDomainName"
                            | "TargetUserSid"
                            | "SourceProcessId"
                            | "SourceImage"
                            | "SourceUser"
                            | "SourceProcessGUID"
                            | "TargetProcessId"
                            | "TargetImage"
                            | "TargetProcessGUID"
                            | "GrantedAccess"
                            | "ObjectName"
                            | "ObjectValueName"
                            | "OperationType"
                            | "OldValue"
                            | "NewValue"
                            | "TargetObject"
                            | "NewName"
                            | "EventType"
                            | "Details"
                    )
                })
                .max_by_key(|key| key.len())
                .cloned()
                .ok_or_else(|| {
                    anyhow::anyhow!("native source metadata exceeds bounded record budget")
                })?;
            data.fields.remove(&key);
            markers.remove(&format!("fields.{key}"));
            markers.insert(
                "fields".into(),
                Truncation::new(
                    original_fields_bytes,
                    serde_json::to_vec(&data.fields)?.len(),
                ),
            );
        }
        data.truncated_fields = (!markers.is_empty()).then_some(markers);
    }
    Ok(())
}

fn preflight(event: &AgentEvent) -> anyhow::Result<()> {
    let record = crate::pipeline::journal::JournalRecord::new(u64::MAX, event.clone());
    anyhow::ensure!(
        crate::pipeline::journal::encode(&record)?.len()
            <= crate::telemetry::limits::MAX_EVENT_BYTES,
        "native event exceeds journal record limit"
    );
    Ok(())
}

/// Forward native observation and its source evidence before advancing a cursor.
pub async fn emit_record(
    tx: &tokio::sync::mpsc::Sender<AgentEvent>,
    mut data: LogEventData,
    agent: &str,
    host: &str,
    durable_handoff: bool,
) -> anyhow::Result<()> {
    bound_source(&mut data)?;
    let normalized = normalize(&data, agent, host);
    if let Some(event) = &normalized {
        preflight(event)?;
    }
    if let Some(event) = normalized {
        // Derived findings may be coalesced by the detection gate. Their IDs
        // cannot carry a receipt for the original source record.
        tx.send(event)
            .await
            .map_err(|_| anyhow::anyhow!("pipeline closed"))?;
    }
    let observed = data.log_timestamp;
    let source = format!("windows_eventlog:{}", data.source_path);
    let mut raw = AgentEvent::new(
        agent.into(),
        host.into(),
        EventClass::Log,
        EventAction::Log,
        Severity::Info,
        EventData::Log(Box::new(data)),
    )
    .with_source(&source);
    if let Some(time) = observed {
        raw.timestamp = time;
    }
    preflight(&raw)?;
    // Raw logs bypass finding admission. Their fsync also covers any preceding
    // normalized record that the pipeline admitted to the same journal.
    if durable_handoff {
        crate::pipeline::receipt::send_durable(tx, raw).await?;
    } else {
        tx.send(raw)
            .await
            .map_err(|_| anyhow::anyhow!("pipeline closed"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn log(channel: &str, provider: &str, id: u32, fields: &[(&str, &str)]) -> LogEventData {
        let mut fields: serde_json::Map<String, serde_json::Value> = fields
            .iter()
            .map(|(k, v)| (k.to_string(), (*v).into()))
            .collect();
        fields.insert("EventID".into(), id.into());
        serde_json::from_value(serde_json::json!({"source":"windows_test", "source_type":"windows_eventlog", "source_path":channel, "parser":"windows_eventlog_xml", "message":"", "category":"system", "proc":provider, "log_timestamp":"2026-10-10T12:34:56Z", "fields":fields})).unwrap()
    }
    #[tokio::test]
    async fn oversized_native_source_and_normalized_process_are_durable_with_explicit_truncation() {
        let huge = "🦀\n".repeat(100_000);
        let mut record = log(
            "Security",
            "Microsoft-Windows-Security-Auditing",
            4688,
            &[
                ("NewProcessId", "0x123"),
                ("ProcessId", "0x45"),
                ("NewProcessName", &huge),
                ("CommandLine", &huge),
                ("SubjectUserName", "writer"),
                ("SubjectDomainName", "DOMAIN"),
            ],
        );
        record.message = huge.clone();
        record.offset = Some(912);
        record.fields.insert("EventRecordID".into(), 912.into());
        for i in 0..24 {
            record
                .fields
                .insert(format!("Extra{i}"), huge.clone().into());
        }
        let directory =
            std::env::temp_dir().join(format!("trapd-native-large-{}", uuid::Uuid::new_v4()));
        let path = directory.join("queue.journal");
        let mut spool = crate::pipeline::Spool::durable_at(path.clone(), 100);
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let producer =
            tokio::spawn(async move { emit_record(&tx, record, "agent", "host", true).await });
        let mut collected = Vec::new();
        while let Some(event) = rx.recv().await {
            let result = spool.push(event.clone());
            collected.push(event);
            assert!(
                result.is_ok(),
                "oversized native evidence must be bounded before journal admission: {result:?}"
            );
        }
        producer.await.unwrap().unwrap();
        assert_eq!(collected.len(), 2);
        let EventData::ProcessCreate(process) = &collected[0].data else {
            panic!("process expected")
        };
        assert_eq!(process.username, "DOMAIN\\writer");
        assert!(!process.cmdline.is_empty());
        assert!(
            process.enrichment.has_truncation(),
            "normalized fields must disclose source truncation"
        );
        let EventData::Log(raw) = &collected[1].data else {
            panic!("source log expected")
        };
        assert_eq!(raw.offset, Some(912));
        assert_eq!(raw.fields["EventRecordID"], 912);
        assert_eq!(
            raw.proc.as_deref(),
            Some("Microsoft-Windows-Security-Auditing")
        );
        assert_eq!(raw.source_path, "Security");
        assert_eq!(raw.fields["SubjectUserName"], "writer");
        let truncation = raw.truncated_fields.as_ref().unwrap();
        assert!(truncation.contains_key("message"));
        assert!(truncation.contains_key("fields.CommandLine"));
        assert_eq!(truncation["fields.CommandLine"].original_length, huge.len());
        assert_eq!(spool.fsyncs_total(), 1);
        drop(spool);
        let recovered = crate::pipeline::Spool::durable_at(path, 100);
        assert_eq!(recovered.len(), 2);
        drop(recovered);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn durable_source_receipts_survive_suppressed_repeated_signals() {
        let record = log(
            SYSMON_CHANNEL,
            "Microsoft-Windows-Sysmon",
            10,
            &[
                ("SourceProcessId", "101"),
                ("SourceImage", r"C:\tools\probe.exe"),
                ("TargetProcessId", "600"),
                ("TargetImage", r"C:\Windows\System32\lsass.exe"),
                ("GrantedAccess", "0x1010"),
            ],
        );
        let directory =
            std::env::temp_dir().join(format!("trapd-native-receipt-{}", uuid::Uuid::new_v4()));
        let path = directory.join("queue.journal");
        let mut spool = crate::pipeline::Spool::durable_at(path.clone(), 100);
        let engine = crate::detection::DetectionEngine::new("agent".into(), "host".into());
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let producer = tokio::spawn(async move {
            emit_record(&tx, record.clone(), "agent", "host", true).await?;
            emit_record(&tx, record, "agent", "host", true).await
        });
        let mut admitted = 0;
        let mut raw_ids = Vec::new();
        let processing = async {
            while let Some(event) = rx.recv().await {
                if matches!(event.class, EventClass::Detection) {
                    let findings = engine.admit_external(event);
                    admitted += findings.len();
                    for finding in findings {
                        spool.push(finding.event).unwrap();
                    }
                } else {
                    assert!(matches!(event.data, EventData::Log(_)));
                    raw_ids.push(event.event_id);
                    spool.push(event).unwrap();
                }
            }
        };
        let completed = tokio::time::timeout(std::time::Duration::from_secs(2), processing).await;
        if completed.is_err() {
            producer.abort();
        }
        assert!(
            completed.is_ok(),
            "a suppressed signal must not hold the source cursor waiting for a receipt"
        );
        producer.await.unwrap().unwrap();
        assert_eq!(
            admitted, 1,
            "real signal gate must suppress the repeated finding"
        );
        assert_eq!(
            raw_ids.len(),
            2,
            "both original source records must survive the gate"
        );
        assert_ne!(raw_ids[0], raw_ids[1]);
        assert_eq!(
            spool.fsyncs_total(),
            2,
            "each source receipt must force durability"
        );
        drop(spool);
        let recovered = crate::pipeline::Spool::durable_at(path, 100);
        let recovered_ids: Vec<_> = recovered
            .peek_batch(100)
            .iter()
            .map(|e| e.event.event_id)
            .collect();
        for id in raw_ids {
            assert!(
                recovered_ids.contains(&id),
                "receipted raw record must survive recovery"
            );
        }
        drop(recovered);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn exited_security_process_keeps_recorded_command_and_target_account() {
        let record = log(
            "Security",
            "Microsoft-Windows-Security-Auditing",
            4688,
            &[
                ("NewProcessId", "0x123"),
                ("ProcessId", "0x45"),
                ("NewProcessName", r"C:\Windows\cmd.exe"),
                ("CommandLine", "cmd /c whoami"),
                ("SubjectUserName", "creator"),
                ("SubjectDomainName", "DOMAIN"),
                ("TargetUserName", "child"),
                ("TargetDomainName", "DOMAIN"),
                ("TargetUserSid", "S-1-5-21-1"),
            ],
        );
        let event = normalize(&record, "agent", "host").unwrap();
        assert_eq!(event.timestamp, record.log_timestamp.unwrap());
        let EventData::ProcessCreate(p) = event.data else {
            panic!("process expected")
        };
        assert_eq!((p.pid, p.ppid), (291, 69));
        assert_eq!(p.username, "DOMAIN\\child");
        assert_eq!(p.cmdline, "cmd /c whoami");
        assert!(
            p.process_start_time.is_none(),
            "historical PID must never bind to current live process"
        );
    }
    #[test]
    fn registry_audit_reports_creation_and_deletion_even_without_poll_snapshot() {
        for (op, action) in [
            ("%%1904", EventAction::Create),
            ("%%1906", EventAction::Delete),
        ] {
            let record = log(
                "Security",
                "Microsoft-Windows-Security-Auditing",
                4657,
                &[
                    (
                        "ObjectName",
                        r"\REGISTRY\MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
                    ),
                    ("ObjectValueName", "Rapid"),
                    ("OperationType", op),
                    ("NewValue", "cmd.exe"),
                ],
            );
            let event = normalize(&record, "agent", "host").unwrap();
            assert_eq!(
                serde_json::to_value(event.action).unwrap(),
                serde_json::to_value(action).unwrap()
            );
            let EventData::Registry(r) = event.data else {
                panic!("registry expected")
            };
            assert_eq!(
                r.key_path,
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
            );
            assert_eq!(r.value_name, "Rapid");
            assert_eq!(r.new_value.is_none(), op == "%%1906");
        }
    }
    #[test]
    fn lsass_read_access_is_observed_signal_not_proof_of_dump() {
        let mut record = log(
            SYSMON_CHANNEL,
            "Microsoft-Windows-Sysmon",
            10,
            &[
                ("SourceProcessId", "101"),
                ("SourceImage", r"C:\tools\probe.exe"),
                ("TargetProcessId", "600"),
                ("TargetImage", r"C:\Windows\System32\lsass.exe"),
                ("GrantedAccess", "0x1010"),
            ],
        );
        let event = normalize(&record, "agent", "host").unwrap();
        let EventData::Detection(d) = event.data else {
            panic!("detection expected")
        };
        assert_eq!(d.rule_id, "credential_access.lsass_memory_access");
        assert_eq!(d.mode, Some(DetectionMode::Signal));
        assert_eq!(d.evidence["source_pid"], 101);
        assert!(!d.detail.contains("dumped"));
        record
            .fields
            .insert("GrantedAccess".into(), "0x1000".into());
        assert!(
            normalize(&record, "agent", "host").is_none(),
            "query-only access is not memory access"
        );
    }
    #[test]
    fn registry_audit_distinguishes_empty_data_from_unavailable_data() {
        let record = log(
            "Security",
            "Microsoft-Windows-Security-Auditing",
            4657,
            &[
                (
                    "ObjectName",
                    r"\REGISTRY\MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
                ),
                ("ObjectValueName", "Empty"),
                ("OperationType", "%%1905"),
                ("OldValue", ""),
                ("NewValue", ""),
            ],
        );
        let event = normalize(&record, "a", "h").unwrap();
        let EventData::Registry(r) = event.data else {
            panic!("registry expected")
        };
        assert_eq!(r.old_value.as_deref(), Some(""));
        assert_eq!(r.new_value.as_deref(), Some(""));
    }

    #[test]
    fn sysmon_key_event_does_not_invent_a_default_value_write() {
        let record = log(
            SYSMON_CHANNEL,
            "Microsoft-Windows-Sysmon",
            12,
            &[
                ("EventType", "CreateKey"),
                ("TargetObject", r"HKLM\Software\Transient"),
            ],
        );
        let event = normalize(&record, "a", "h").unwrap();
        let EventData::Registry(r) = event.data else {
            panic!("registry expected")
        };
        assert_eq!(r.key_path, r"HKLM\Software\Transient");
        assert_eq!(r.value_name, "(Key)");
        assert!(r.new_value.is_none());
    }

    #[test]
    fn provider_ids_and_invalid_process_ids_cannot_impersonate_native_records() {
        let mut record = log(
            "Application",
            "Fake",
            4688,
            &[("NewProcessId", "12"), ("NewProcessName", "cmd.exe")],
        );
        assert!(normalize(&record, "a", "h").is_none());
        record.source_path = "Security".into();
        record.proc = Some("Microsoft-Windows-Security-Auditing".into());
        for invalid in ["", "-1", "4294967295", "0"] {
            record.fields.insert("NewProcessId".into(), invalid.into());
            assert!(normalize(&record, "a", "h").is_none());
        }
    }
    #[test]
    fn sysmon_registry_key_rename_classifies_the_new_watched_destination_without_value_data() {
        let old = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Staged";
        let new = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run";
        let record = log(
            SYSMON_CHANNEL,
            "Microsoft-Windows-Sysmon",
            14,
            &[
                ("EventType", "RenameKey"),
                ("TargetObject", old),
                ("NewName", new),
            ],
        );
        let event = normalize(&record, "a", "h").unwrap();
        let EventData::Registry(r) = event.data else {
            panic!("registry expected")
        };
        assert_eq!(r.key_path, new);
        assert_eq!(r.value_name, "(Key)");
        assert_eq!(r.category, "run_key");
        let source = r.rename_from.as_ref().unwrap();
        assert_eq!(source.key_path, old);
        assert!(source.value_name.is_none());
        assert!(
            r.old_value.is_none() && r.new_value.is_none(),
            "names cannot be represented as value data"
        );
        let findings = crate::detection::registry_rules::inspect_registry(&r);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "persistence.registry_object_renamed");
        assert_eq!(findings[0].mode, Some(DetectionMode::Signal));
    }

    #[test]
    fn sysmon_registry_value_rename_classifies_the_destination_value_not_the_old_name() {
        let key = r"HKLM\SYSTEM\CurrentControlSet\Services\demo";
        let old = format!("{key}\\Unrelated");
        let new = format!("{key}\\ImagePath");
        let record = log(
            SYSMON_CHANNEL,
            "Microsoft-Windows-Sysmon",
            14,
            &[
                ("EventType", "RenameValue"),
                ("TargetObject", &old),
                ("NewName", &new),
            ],
        );
        let event = normalize(&record, "a", "h").unwrap();
        let EventData::Registry(r) = event.data else {
            panic!("registry expected")
        };
        assert_eq!(r.key_path, key);
        assert_eq!(r.value_name, "ImagePath");
        assert_eq!(r.category, "service");
        let source = r.rename_from.as_ref().unwrap();
        assert_eq!(source.key_path, key);
        assert_eq!(source.value_name.as_deref(), Some("Unrelated"));
        assert!(r.old_value.is_none() && r.new_value.is_none());
        let findings = crate::detection::registry_rules::inspect_registry(&r);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "persistence.registry_object_renamed");
        assert!(!findings[0].title.contains("installed"));
    }

    #[test]
    fn sysmon_registry_rename_rejects_missing_malformed_or_spoofed_destination() {
        let old = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Staged";
        for new in [
            "",
            "Run",
            "HKLM\\",
            r"HKLM\Software\\Run",
            r"HKLM\Software\..\Run",
            "HKLM\\Software\\Run\0",
        ] {
            let record = log(
                SYSMON_CHANNEL,
                "Microsoft-Windows-Sysmon",
                14,
                &[
                    ("EventType", "RenameKey"),
                    ("TargetObject", old),
                    ("NewName", new),
                ],
            );
            assert!(
                normalize(&record, "a", "h").is_none(),
                "malformed destination {new:?}"
            );
        }
        let mut record = log(
            SYSMON_CHANNEL,
            "Impostor",
            14,
            &[
                ("EventType", "RenameKey"),
                ("TargetObject", old),
                (
                    "NewName",
                    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                ),
            ],
        );
        assert!(normalize(&record, "a", "h").is_none());
        record.proc = Some("Microsoft-Windows-Sysmon".into());
        record.source_path = "Application".into();
        assert!(normalize(&record, "a", "h").is_none());
    }

    #[test]
    fn sysmon_registry_rename_preserves_watched_source_and_truncated_names_are_raw_only() {
        for (kind, old, new, category) in [
            (
                "RenameKey",
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Unwatched",
                "run_key",
            ),
            (
                "RenameValue",
                r"HKLM\SYSTEM\CurrentControlSet\Services\demo\ImagePath",
                r"HKLM\SYSTEM\CurrentControlSet\Services\demo\Unwatched",
                "service",
            ),
        ] {
            let mut record = log(
                SYSMON_CHANNEL,
                "Microsoft-Windows-Sysmon",
                14,
                &[("EventType", kind), ("TargetObject", old), ("NewName", new)],
            );
            let EventData::Registry(r) = normalize(&record, "a", "h").unwrap().data else {
                panic!("registry expected")
            };
            assert_eq!(r.category, category);
            assert_eq!(
                crate::detection::registry_rules::inspect_registry(&r).len(),
                1
            );
            for field in ["fields.NewName", "fields.TargetObject"] {
                record.truncated_fields = Some(std::collections::BTreeMap::from([(
                    field.into(),
                    crate::telemetry::limits::Truncation::new(100, 50),
                )]));
                assert!(normalize(&record, "a", "h").is_none());
            }
        }
    }

    #[test]
    fn sysmon_registry_value_set_retains_data_and_exact_value_path() {
        let record = log(
            SYSMON_CHANNEL,
            "Microsoft-Windows-Sysmon",
            13,
            &[
                ("EventType", "SetValue"),
                (
                    "TargetObject",
                    r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run\Rapid",
                ),
                ("Details", "powershell.exe"),
            ],
        );
        let event = normalize(&record, "a", "h").unwrap();
        let EventData::Registry(r) = event.data else {
            panic!("registry expected")
        };
        assert_eq!(r.value_name, "Rapid");
        assert_eq!(r.user_sid.as_deref(), Some("S-1-5-21-1"));
        assert_eq!(r.new_value.as_deref(), Some("powershell.exe"));
    }
}
