//! Post-restart forensic read-back (Windows System log).
//!
//! An admin who stops or reconfigures the agent, loads a vulnerable driver or
//! clears a log leaves the *cause* in the System log, but the agent was not
//! running to see it. At start this module reads the System log since the
//! previous run and turns the relevant records into findings, so an analyst
//! sees more than "the agent was silent".
//!
//! Scope of the read (all System channel):
//!
//! | Event | Provider | Finding |
//! |---|---|---|
//! | 7036 (state change), our service stopped | Service Control Manager | `selfprotect.service_stopped_while_down` |
//! | 7040 (start type change), our service | Service Control Manager | `selfprotect.service_start_type_changed` |
//! | 7045 (service/driver installed) | Service Control Manager | `selfprotect.driver_installed_while_down` / `selfprotect.service_installed_while_down` |
//! | 6008 (unexpected shutdown) | EventLog | `selfprotect.unclean_shutdown` (existing rule, host-level evidence) |
//!
//! Deliberately **not** read: 104 (log cleared). The live event-log collector
//! persists a record cursor, so a 104 written while the agent was down is read
//! after the restart and already becomes `selfprotect.audit_policy_changed`.
//!
//! Window: from the last successfully completed read-back (a watermark that
//! advances only after a full scan), else from the previous run's marker time
//! (see [`crate::heartbeat::lifecycle`]), never older than [`MAX_LOOKBACK`] and never more than a bounded
//! number of records per query. A watermark file keeps a restart loop from
//! re-reporting the same records.
//!
//! Trust: every field of an event record is attacker-influenced (any local
//! admin can register a provider and write records). Values are truncated,
//! stripped of control characters and only ever placed into structured
//! evidence as strings. The XPath sent to the log is built from constants and
//! formatted timestamps, never from record contents. Windows records do not
//! prove *who* acted for 7036 (the SCM writes it as SYSTEM), so `actor_sid` is
//! only reported for 7040/7045, whose `UserID` is the requesting account.
//!
//! The classification and window logic is platform independent and unit
//! tested; only the log read itself is Windows-only.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use trapd_schema::{DetectionData, Severity};

/// Oldest record considered, however long the agent was down.
pub const MAX_LOOKBACK: Duration = Duration::days(7);
/// Window used when there is no previous marker (first start or wiped state).
const UNKNOWN_PREVIOUS_LOOKBACK: Duration = Duration::hours(24);
/// Findings emitted per start; the rest are counted as dropped.
const MAX_FINDINGS: usize = 50;
/// Characters kept of any event field.
const FIELD_MAX_CHARS: usize = 256;
/// Data entries kept per record.
const MAX_DATA_ENTRIES: usize = 32;
const MAX_XML_BYTES: usize = 64 * 1024;
const WATERMARK_FILE: &str = "restart_forensics.json";
const MAX_WATERMARK_BYTES: u64 = 1024;

const SCM_PROVIDER: &str = "Service Control Manager";
const EVENTLOG_PROVIDER: &str = "EventLog";
/// Service key name and display name of this agent (MSI `ServiceInstall`).
const OWN_SERVICE_NAMES: [&str; 2] = ["trapd-agent", "TRAPD Agent"];
/// State words of 7036 `param2` meaning "stopped". The SCM inserts the
/// localized word, so other locales produce no 7036 finding; the heartbeat gap
/// and the 7040/7045 findings still apply there.
const STOPPED_STATES: [&str; 3] = ["stopped", "angehalten", "beendet"];

/// One System-log record, reduced to the fields this module judges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub record_id: u64,
    pub event_id: u32,
    pub provider: String,
    pub time: DateTime<Utc>,
    /// `Security/@UserID` of the record, validated as a SID.
    pub user_sid: Option<String>,
    /// `EventData/Data` by name; sanitized and length-limited.
    pub data: BTreeMap<String, String>,
}

/// Replace control characters and cut to [`FIELD_MAX_CHARS`] characters.
fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .take(FIELD_MAX_CHARS)
        .collect()
}

/// `S-1-<digits and hyphens>`, bounded; anything else is not a SID.
fn valid_sid(value: &str) -> Option<String> {
    let ok = value.len() <= 184
        && value.starts_with("S-1-")
        && value[4..].chars().all(|c| c.is_ascii_digit() || c == '-');
    ok.then(|| value.to_string())
}

impl Record {
    /// Parse the XML rendering of one event. `None` for anything malformed or
    /// oversized: a record this module cannot read is skipped, not guessed at.
    pub fn from_xml(xml: &str) -> Option<Self> {
        if xml.len() > MAX_XML_BYTES {
            return None;
        }
        let doc = roxmltree::Document::parse(xml).ok()?;
        let root = doc.root_element();
        let system = root.children().find(|n| n.has_tag_name("System"))?;
        let child = |name: &str| system.children().find(|n| n.has_tag_name(name));
        let record_id = child("EventRecordID")?.text()?.trim().parse().ok()?;
        let event_id = child("EventID")?.text()?.trim().parse().ok()?;
        let provider = sanitize(child("Provider")?.attribute("Name")?);
        let time = DateTime::parse_from_rfc3339(child("TimeCreated")?.attribute("SystemTime")?)
            .ok()?
            .with_timezone(&Utc);
        let user_sid = child("Security")
            .and_then(|n| n.attribute("UserID"))
            .and_then(valid_sid);
        let mut data = BTreeMap::new();
        if let Some(event_data) = root.children().find(|n| n.has_tag_name("EventData")) {
            for node in event_data.children().filter(|n| n.has_tag_name("Data")) {
                if data.len() >= MAX_DATA_ENTRIES {
                    break;
                }
                if let Some(name) = node.attribute("Name") {
                    data.insert(sanitize(name), sanitize(node.text().unwrap_or("")));
                }
            }
        }
        Some(Self {
            record_id,
            event_id,
            provider,
            time,
            user_sid,
            data,
        })
    }

    fn field(&self, name: &str) -> &str {
        self.data.get(name).map(String::as_str).unwrap_or("")
    }
}

/// A finding plus the event time and severity it is reported with.
#[derive(Debug, Clone)]
pub struct Finding {
    pub time: DateTime<Utc>,
    pub severity: Severity,
    pub record_id: u64,
    pub detection: DetectionData,
}

fn is_own_service(name: &str) -> bool {
    OWN_SERVICE_NAMES
        .iter()
        .any(|own| own.eq_ignore_ascii_case(name.trim()))
}

/// Executable of a service `ImagePath` (quoted, or up to the first `.exe`),
/// lower-cased with `\` separators, for comparing against our own path.
fn image_exe(image_path: &str) -> String {
    let p = image_path.trim();
    let exe = if let Some(rest) = p.strip_prefix('"') {
        rest.split('"').next().unwrap_or("")
    } else {
        let lower = p.to_ascii_lowercase();
        lower.find(".exe").map(|i| &p[..i + 4]).unwrap_or(p)
    };
    exe.replace('/', "\\").to_ascii_lowercase()
}

fn is_driver(service_type: &str, image_path: &str) -> bool {
    let ty = service_type.to_ascii_lowercase();
    image_path
        .trim()
        .trim_matches('"')
        .to_ascii_lowercase()
        .ends_with(".sys")
        || ty.contains("driver")
        || ty.contains("treiber")
}

fn in_user_writable_path(image_path: &str) -> bool {
    let p = image_path.replace('/', "\\").to_ascii_lowercase();
    ["\\users\\", "\\temp\\", "\\appdata\\", "\\programdata\\"]
        .iter()
        .any(|m| p.contains(m))
}

#[allow(clippy::too_many_arguments)]
fn base(
    rule_id: &str,
    title: &str,
    technique: &str,
    confidence: u8,
    subject: String,
    detail: String,
    record: &Record,
    mut evidence: serde_json::Value,
) -> DetectionData {
    if let Some(map) = evidence.as_object_mut() {
        map.insert("event_id".into(), record.event_id.into());
        map.insert("event_record_id".into(), record.record_id.into());
        map.insert("event_time".into(), record.time.to_rfc3339().into());
        map.insert("channel".into(), "System".into());
        map.insert("provider".into(), record.provider.clone().into());
        map.insert("source".into(), "system_log_readback".into());
    }
    DetectionData {
        rule_id: rule_id.into(),
        title: title.into(),
        category: "defense_evasion".into(),
        mitre_tactic: Some("TA0005 Defense Evasion".into()),
        mitre_technique: Some(technique.into()),
        confidence,
        subject,
        detail,
        evidence,
        // One finding per record: replaying the same record stays idempotent.
        dedup_key: Some(format!("{rule_id}:{}", record.record_id)),
        first_seen: Some(record.time),
        last_seen: Some(record.time),
        ..Default::default()
    }
}

/// Judge one record. `own_exe` is this process's executable, used so the
/// agent's own MSI service registration is not reported as a new service.
pub fn classify(record: &Record, own_exe: Option<&str>) -> Option<Finding> {
    let (severity, detection) = match (record.provider.as_str(), record.event_id) {
        (SCM_PROVIDER, 7036) => {
            let state = record.field("param2").trim().to_lowercase();
            if !is_own_service(record.field("param1")) || !STOPPED_STATES.contains(&state.as_str())
            {
                return None;
            }
            (
                Severity::High,
                base(
                    "selfprotect.service_stopped_while_down",
                    "Agent service was stopped",
                    "T1562.001",
                    70,
                    "trapd-agent".into(),
                    "The Service Control Manager recorded the TRAPD Agent service entering the stopped state before this start".into(),
                    record,
                    // No actor: the SCM writes 7036 itself, not the requester.
                    serde_json::json!({ "service": record.field("param1"), "state": record.field("param2") }),
                ),
            )
        }
        (SCM_PROVIDER, 7040) => {
            if !is_own_service(record.field("param1")) && !is_own_service(record.field("param4")) {
                return None;
            }
            let mut evidence = serde_json::json!({
                "service": record.field("param1"),
                "old_start_type": record.field("param2"),
                "new_start_type": record.field("param3"),
            });
            if let (Some(map), Some(sid)) = (evidence.as_object_mut(), &record.user_sid) {
                map.insert("actor_sid".into(), sid.clone().into());
            }
            (
                Severity::High,
                base(
                    "selfprotect.service_start_type_changed",
                    "Agent service start type was changed",
                    "T1562.001",
                    85,
                    "trapd-agent".into(),
                    "The start type of the TRAPD Agent service was changed while the agent was not running".into(),
                    record,
                    evidence,
                ),
            )
        }
        (SCM_PROVIDER, 7045) => {
            let name = record.field("ServiceName");
            let image = record.field("ImagePath");
            if is_own_service(name)
                && own_exe.is_some_and(|own| image_exe(image) == own.to_ascii_lowercase())
            {
                return None;
            }
            let driver = is_driver(record.field("ServiceType"), image);
            let mut evidence = serde_json::json!({
                "service_name": name,
                "image_path": image,
                "service_type": record.field("ServiceType"),
                "start_type": record.field("StartType"),
                "account_name": record.field("AccountName"),
                "is_driver": driver,
                "image_in_user_writable_path": in_user_writable_path(image),
            });
            if let (Some(map), Some(sid)) = (evidence.as_object_mut(), &record.user_sid) {
                map.insert("actor_sid".into(), sid.clone().into());
            }
            if driver {
                (
                    Severity::High,
                    base(
                        "selfprotect.driver_installed_while_down",
                        "Driver installed while the agent was not running",
                        "T1068",
                        60,
                        name.into(),
                        "A kernel driver was registered before this start (possible vulnerable-driver loading)".into(),
                        record,
                        evidence,
                    ),
                )
            } else {
                (
                    Severity::Low,
                    base(
                        "selfprotect.service_installed_while_down",
                        "Service installed while the agent was not running",
                        "T1543.003",
                        30,
                        name.into(),
                        "A service was registered before this start".into(),
                        record,
                        evidence,
                    ),
                )
            }
        }
        (EVENTLOG_PROVIDER, 6008) => (
            Severity::Low,
            base(
                "selfprotect.unclean_shutdown",
                "Windows recorded an unexpected shutdown",
                "T1562",
                40,
                "windows_system_event_6008".into(),
                "The previous system shutdown was unexpected (System event 6008)".into(),
                record,
                serde_json::json!({
                    "previous_shutdown": "unclean",
                    "reported_shutdown_time": record.field("param1"),
                    "reported_shutdown_date": record.field("param2"),
                }),
            ),
        ),
        _ => return None,
    };
    Some(Finding {
        time: record.time,
        severity,
        record_id: record.record_id,
        detection,
    })
}

/// Classify, dedupe by record id, order oldest first and cap. Returns the
/// findings to emit and the number dropped by the cap.
pub fn scan(
    records: impl IntoIterator<Item = Record>,
    own_exe: Option<&str>,
) -> (Vec<Finding>, usize) {
    let mut seen = HashSet::new();
    let mut findings: Vec<Finding> = records
        .into_iter()
        .filter(|r| seen.insert((r.record_id, r.event_id)))
        .filter_map(|r| classify(&r, own_exe))
        .collect();
    // Keep the newest on overflow; emit oldest first so the timeline reads in order.
    findings.sort_by(|a, b| b.time.cmp(&a.time).then(b.record_id.cmp(&a.record_id)));
    let dropped = findings.len().saturating_sub(MAX_FINDINGS);
    findings.truncate(MAX_FINDINGS);
    findings.reverse();
    (findings, dropped)
}

/// How the lookback start was chosen (reported in logs, not trusted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    PreviousRun,
    UnknownPreviousRun,
}

/// Start of the read-back window: the persisted scanned-until watermark, which
/// advances only after a fully successful scan. Only when there is none does
/// the previous run's marker time apply (the marker is rewritten at every
/// start, so it must not override a watermark: a failed scan would otherwise
/// skip the outage window for good). Clamped to [`MAX_LOOKBACK`]; an anchor in
/// the future (clock change, forged file) is ignored. No usable anchor yields
/// a 24 h window.
pub fn lookback_start(
    now: DateTime<Utc>,
    previous_marker_at: Option<DateTime<Utc>>,
    watermark: Option<DateTime<Utc>>,
) -> (DateTime<Utc>, Basis) {
    let floor = now - MAX_LOOKBACK;
    let usable = |t: Option<DateTime<Utc>>| t.filter(|t| *t <= now);
    let anchor = usable(watermark).or(usable(previous_marker_at));
    match anchor {
        Some(t) => (t.max(floor), Basis::PreviousRun),
        None => (
            (now - UNKNOWN_PREVIOUS_LOOKBACK).max(floor),
            Basis::UnknownPreviousRun,
        ),
    }
}

#[derive(Serialize, Deserialize)]
struct Watermark {
    scanned_until: DateTime<Utc>,
}

pub fn read_watermark(dir: &Path) -> Option<DateTime<Utc>> {
    let path = dir.join(WATERMARK_FILE);
    if std::fs::metadata(&path).ok()?.len() > MAX_WATERMARK_BYTES {
        return None;
    }
    let raw = std::fs::read(path).ok()?;
    serde_json::from_slice::<Watermark>(&raw)
        .ok()
        .map(|w| w.scanned_until)
}

pub fn write_watermark(dir: &Path, scanned_until: DateTime<Utc>) {
    let Ok(raw) = serde_json::to_vec(&Watermark { scanned_until }) else {
        return;
    };
    if let Err(e) = crate::paths::write_atomic(&dir.join(WATERMARK_FILE), &raw, 0o600) {
        // Losing it only risks re-reading (and idempotently re-reporting) a window.
        tracing::warn!(error = %e, "could not persist the restart read-back watermark");
    }
}

/// Outcome of the read-back queries. Queries read newest first up to a limit,
/// so a truncated query leaves an unread *older* gap that a "scanned until"
/// watermark cannot represent: advancing it would drop that gap for good.
#[derive(Debug, PartialEq, Eq)]
pub struct ReadOutcome {
    /// Every query ran and saw the end of its matches.
    pub complete: bool,
    /// Queries cut short by their limit; each is counted as a rate-limit drop.
    pub truncated: usize,
    failed: bool,
}

impl ReadOutcome {
    pub fn new() -> Self {
        Self {
            complete: true,
            truncated: 0,
            failed: false,
        }
    }

    /// Record one query: `Some(exhausted)` when it ran, `None` when it failed.
    pub fn record(&mut self, query: Option<bool>) {
        match query {
            Some(true) => {}
            Some(false) => self.truncated += 1,
            None => self.failed = true,
        }
        self.complete = !self.failed && self.truncated == 0;
    }
}

/// Record `now` as scanned, but only when every query succeeded. A partial
/// read, and any early return before this point, leaves the old watermark so
/// the next start reads the same window again.
pub fn advance_watermark(dir: &Path, now: DateTime<Utc>, complete: bool) {
    if complete {
        write_watermark(dir, now);
    }
}

/// Stable `event_id` for a replayed record: the same record yields the same id
/// on every restart (the backend deduplicates on it), a different agent,
/// channel, record or rule yields a different one. A SHA-256 over
/// length-prefixed parts, truncated to 16 bytes, with the UUIDv5 version and
/// variant bits set (the `uuid` crate has no `v5` feature enabled here).
pub fn stable_event_id(agent_id: &str, channel: &str, record_id: u64, rule_id: &str) -> uuid::Uuid {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"trapd.restart_forensics.v1");
    for part in [agent_id, channel, rule_id] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.update(record_id.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

/// Hand every finding to `send` (a durable handoff) in order and report
/// whether all were confirmed. Stops at the first failure so the caller keeps
/// the old watermark and the window is replayed (with identical event ids).
pub async fn deliver_all<F, Fut>(findings: Vec<Finding>, mut send: F) -> bool
where
    F: FnMut(Finding) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    for finding in findings {
        let record_id = finding.record_id;
        if let Err(e) = send(finding).await {
            tracing::warn!(record_id, error = %e, "restart forensic finding was not durably handed off; keeping the watermark");
            return false;
        }
    }
    true
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`, the form `TimeCreated/@SystemTime` compares in.
fn xpath_time(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// `(channel query, max records)` for each read. Only constants and the
/// formatted timestamp enter the text.
pub fn queries(since: DateTime<Utc>) -> Vec<(String, usize)> {
    let since = xpath_time(since);
    let time = format!("TimeCreated[@SystemTime>='{since}']");
    vec![
        (
            format!(
                "*[System[Provider[@Name='{SCM_PROVIDER}'] and (EventID=7036 or EventID=7040) and {time}]] \
                 and *[EventData[Data[@Name='param1']='trapd-agent' or Data[@Name='param1']='TRAPD Agent' \
                 or Data[@Name='param4']='trapd-agent']]"
            ),
            64,
        ),
        (
            format!("*[System[Provider[@Name='{SCM_PROVIDER}'] and EventID=7045 and {time}]]"),
            128,
        ),
        (
            format!("*[System[Provider[@Name='{EVENTLOG_PROVIDER}'] and EventID=6008 and {time}]]"),
            16,
        ),
    ]
}

#[cfg(windows)]
fn build_event(finding: Finding, agent_id: &str, hostname: &str) -> trapd_schema::AgentEvent {
    use trapd_schema::{AgentEvent, EventAction, EventClass, EventData};
    let event_id = stable_event_id(
        agent_id,
        "System",
        finding.record_id,
        &finding.detection.rule_id,
    );
    let mut event = AgentEvent::new(
        agent_id.into(),
        hostname.into(),
        EventClass::Detection,
        EventAction::Detected,
        finding.severity,
        EventData::Detection(Box::new(finding.detection)),
    );
    // Native time and source keep a replayed record from authorizing a live
    // response (see `is_historical_windows_record`).
    event.timestamp = finding.time;
    event.event_id = event_id;
    event.with_source(&format!("windows_eventlog:System:{}", finding.record_id))
}

/// Read the System log since the previous run and emit findings. Best effort:
/// a failed read is logged and costs only the forensic context.
#[cfg(windows)]
pub async fn run(
    tx: tokio::sync::mpsc::Sender<trapd_schema::AgentEvent>,
    agent_id: String,
    hostname: String,
) {
    let life = crate::heartbeat::lifecycle::begin_process();
    let state = crate::paths::state_dir();
    let now = Utc::now();
    let (since, basis) = lookback_start(now, life.previous_marker_at(), read_watermark(state));
    tracing::info!(since = %since, ?basis, "reading the System log for events since the previous run");

    let own_exe = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().to_ascii_lowercase());
    let mut records = Vec::new();
    let mut outcome = ReadOutcome::new();
    for (query, limit) in queries(since) {
        let result = tokio::task::spawn_blocking(move || {
            crate::collectors::windows::eventlog::read_matching("System", &query, limit)
        })
        .await;
        match result {
            Ok(Ok((xml, exhausted))) => {
                outcome.record(Some(exhausted));
                records.extend(xml.iter().filter_map(|x| Record::from_xml(x)));
            }
            Ok(Err(e)) => {
                outcome.record(None);
                tracing::warn!(error = %e, "System log read-back query failed");
            }
            Err(e) => {
                outcome.record(None);
                tracing::warn!(error = %e, "System log read-back task failed");
            }
        }
    }
    let (findings, dropped) = scan(records, own_exe.as_deref());
    // A truncated query hides an unknown number of older records: count one
    // drop per query and keep the old watermark so the window is not skipped.
    for _ in 0..dropped + outcome.truncated {
        crate::telemetry::metrics::metrics()
            .event_dropped(crate::telemetry::DropReason::RateLimitApplied);
    }
    tracing::info!(
        findings = findings.len(),
        dropped,
        truncated_queries = outcome.truncated,
        "System log read-back finished"
    );
    // The watermark moves only after the journal confirmed every finding; an
    // in-memory-only queue never confirms, so the window is then replayed.
    let delivered = deliver_all(findings, |finding| {
        let event = build_event(finding, &agent_id, &hostname);
        let tx = &tx;
        async move { crate::pipeline::receipt::send_durable(tx, event).await }
    })
    .await;
    advance_watermark(state, now, outcome.complete && delivered);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(record_id: u64, rule: &str) -> Finding {
        Finding {
            time: ts("2026-11-14T10:00:00Z"),
            severity: Severity::High,
            record_id,
            detection: DetectionData {
                rule_id: rule.into(),
                ..Default::default()
            },
        }
    }

    #[test]
    fn stable_event_id_is_deterministic_and_distinguishes_inputs() {
        let a = stable_event_id("agent-1", "System", 10, "r");
        assert_eq!(a, stable_event_id("agent-1", "System", 10, "r"));
        assert_ne!(a, stable_event_id("agent-1", "System", 11, "r"));
        assert_ne!(a, stable_event_id("agent-2", "System", 10, "r"));
        assert_ne!(a, stable_event_id("agent-1", "Other", 10, "r"));
        assert_ne!(a, stable_event_id("agent-1", "System", 10, "r2"));
        // Length prefixes keep part boundaries unambiguous.
        assert_ne!(
            stable_event_id("ab", "c", 1, "r"),
            stable_event_id("a", "bc", 1, "r")
        );
        assert_eq!(a.get_version_num(), 5);
    }

    #[tokio::test]
    async fn watermark_is_not_advanced_when_durable_handoff_fails() {
        let dir = std::env::temp_dir().join(format!("trapd_rf_durable_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = ts("2026-11-14T12:00:00Z");
        let mut sent = 0;
        let delivered = deliver_all(vec![finding(1, "a"), finding(2, "b")], |_| {
            sent += 1;
            async { Err(anyhow::anyhow!("event was not durably journaled")) }
        })
        .await;
        assert!(!delivered);
        assert_eq!(sent, 1, "stops at the first failure");
        advance_watermark(&dir, now, delivered);
        assert!(read_watermark(&dir).is_none());

        let delivered = deliver_all(vec![finding(1, "a")], |_| async { Ok(()) }).await;
        assert!(delivered);
        advance_watermark(&dir, now, delivered);
        assert_eq!(read_watermark(&dir), Some(now));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn xml(provider: &str, id: u32, rec: u64, sid: &str, data: &[(&str, &str)]) -> String {
        let data: String = data
            .iter()
            .map(|(k, v)| format!("<Data Name=\"{k}\">{v}</Data>"))
            .collect();
        format!(
            "<Event><System><Provider Name=\"{provider}\"/><EventID>{id}</EventID>\
             <TimeCreated SystemTime=\"2026-11-14T10:00:00.123456700Z\"/>\
             <EventRecordID>{rec}</EventRecordID><Security UserID=\"{sid}\"/></System>\
             <EventData>{data}</EventData></Event>"
        )
    }

    fn rec(provider: &str, id: u32, rec: u64, data: &[(&str, &str)]) -> Record {
        Record::from_xml(&xml(provider, id, rec, "S-1-5-21-1-2-3-1001", data)).unwrap()
    }

    #[test]
    fn stop_of_our_service_is_reported_without_an_actor() {
        let r = rec(
            SCM_PROVIDER,
            7036,
            10,
            &[("param1", "TRAPD Agent"), ("param2", "stopped")],
        );
        let f = classify(&r, None).unwrap();
        assert_eq!(
            f.detection.rule_id,
            "selfprotect.service_stopped_while_down"
        );
        assert_eq!(f.severity, Severity::High);
        assert!(f.detection.evidence.get("actor_sid").is_none());
        assert_eq!(f.time, ts("2026-11-14T10:00:00.123456700Z"));
    }

    #[test]
    fn other_services_and_running_states_are_ignored() {
        let other = rec(
            SCM_PROVIDER,
            7036,
            1,
            &[("param1", "Print Spooler"), ("param2", "stopped")],
        );
        let running = rec(
            SCM_PROVIDER,
            7036,
            2,
            &[("param1", "TRAPD Agent"), ("param2", "running")],
        );
        assert!(classify(&other, None).is_none());
        assert!(classify(&running, None).is_none());
    }

    #[test]
    fn german_stop_state_is_recognised() {
        let r = rec(
            SCM_PROVIDER,
            7036,
            3,
            &[("param1", "trapd-agent"), ("param2", "Angehalten")],
        );
        assert!(classify(&r, None).is_some());
    }

    #[test]
    fn spoofed_provider_is_ignored() {
        let r = rec(
            "Evil",
            7036,
            4,
            &[("param1", "TRAPD Agent"), ("param2", "stopped")],
        );
        assert!(classify(&r, None).is_none());
        let r = rec(
            "Evil",
            7045,
            5,
            &[("ServiceName", "x"), ("ImagePath", "c:\\x.sys")],
        );
        assert!(classify(&r, None).is_none());
    }

    #[test]
    fn start_type_change_carries_the_actor_sid() {
        let r = rec(
            SCM_PROVIDER,
            7040,
            6,
            &[
                ("param1", "TRAPD Agent"),
                ("param2", "auto start"),
                ("param3", "disabled"),
                ("param4", "trapd-agent"),
            ],
        );
        let f = classify(&r, None).unwrap();
        assert_eq!(
            f.detection.rule_id,
            "selfprotect.service_start_type_changed"
        );
        assert_eq!(f.detection.evidence["actor_sid"], "S-1-5-21-1-2-3-1001");
        assert_eq!(f.detection.evidence["new_start_type"], "disabled");
    }

    #[test]
    fn start_type_change_of_other_service_is_ignored() {
        let r = rec(
            SCM_PROVIDER,
            7040,
            7,
            &[("param1", "Spooler"), ("param4", "Spooler")],
        );
        assert!(classify(&r, None).is_none());
    }

    #[test]
    fn driver_install_is_high_and_flags_writable_paths() {
        let r = rec(
            SCM_PROVIDER,
            7045,
            8,
            &[
                ("ServiceName", "rtcore"),
                ("ImagePath", "C:\\Users\\bob\\AppData\\Local\\Temp\\rt.sys"),
                ("ServiceType", "kernel mode driver"),
            ],
        );
        let f = classify(&r, None).unwrap();
        assert_eq!(
            f.detection.rule_id,
            "selfprotect.driver_installed_while_down"
        );
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.detection.evidence["image_in_user_writable_path"], true);
        assert_eq!(f.detection.evidence["actor_sid"], "S-1-5-21-1-2-3-1001");
    }

    #[test]
    fn ordinary_service_install_is_low() {
        let r = rec(
            SCM_PROVIDER,
            7045,
            9,
            &[
                ("ServiceName", "Foo"),
                ("ImagePath", "\"C:\\Program Files\\Foo\\foo.exe\" -svc"),
                ("ServiceType", "user mode service"),
            ],
        );
        let f = classify(&r, None).unwrap();
        assert_eq!(
            f.detection.rule_id,
            "selfprotect.service_installed_while_down"
        );
        assert_eq!(f.severity, Severity::Low);
    }

    #[test]
    fn our_own_msi_registration_is_not_reported_but_a_foreign_image_is() {
        let own = "c:\\program files\\trapd agent\\trapd-agent.exe";
        let msi = rec(
            SCM_PROVIDER,
            7045,
            11,
            &[
                ("ServiceName", "trapd-agent"),
                (
                    "ImagePath",
                    "\"C:\\Program Files\\TRAPD Agent\\trapd-agent.exe\" service",
                ),
            ],
        );
        assert!(classify(&msi, Some(own)).is_none());
        let fake = rec(
            SCM_PROVIDER,
            7045,
            12,
            &[
                ("ServiceName", "trapd-agent"),
                ("ImagePath", "C:\\Temp\\evil.exe"),
            ],
        );
        assert!(classify(&fake, Some(own)).is_some());
    }

    #[test]
    fn unexpected_shutdown_reuses_the_existing_rule() {
        let r = rec(
            EVENTLOG_PROVIDER,
            6008,
            13,
            &[("param1", "10:00:00"), ("param2", "11/14/2026")],
        );
        let f = classify(&r, None).unwrap();
        assert_eq!(f.detection.rule_id, "selfprotect.unclean_shutdown");
        assert_eq!(f.severity, Severity::Low);
    }

    #[test]
    fn log_cleared_is_left_to_the_live_collector() {
        let r = rec("Microsoft-Windows-Eventlog", 104, 14, &[]);
        assert!(classify(&r, None).is_none());
    }

    #[test]
    fn untrusted_fields_are_bounded_and_stripped() {
        let long = "A".repeat(10_000);
        let r = rec(
            SCM_PROVIDER,
            7045,
            15,
            &[("ServiceName", "x\u{85}y"), ("ImagePath", &long)],
        );
        assert!(r.field("ImagePath").chars().count() <= FIELD_MAX_CHARS);
        assert!(!r.field("ServiceName").contains('\u{85}'));
    }

    #[test]
    fn malformed_sid_and_oversized_or_broken_xml_are_rejected() {
        let r =
            Record::from_xml(&xml(SCM_PROVIDER, 7040, 1, "S-1-5-21-&lt;script&gt;", &[])).unwrap();
        assert!(r.user_sid.is_none());
        assert!(Record::from_xml("<Event>").is_none());
        assert!(Record::from_xml(&"x".repeat(MAX_XML_BYTES + 1)).is_none());
    }

    #[test]
    fn scan_dedupes_orders_and_caps() {
        let a = rec(
            SCM_PROVIDER,
            7045,
            1,
            &[("ServiceName", "a"), ("ImagePath", "c:\\a.exe")],
        );
        let (f, dropped) = scan([a.clone(), a], None);
        assert_eq!((f.len(), dropped), (1, 0));

        let many = (0..(MAX_FINDINGS as u64 + 5)).map(|i| {
            let mut r = rec(
                SCM_PROVIDER,
                7045,
                i + 1,
                &[("ServiceName", "a"), ("ImagePath", "c:\\a.exe")],
            );
            r.time = ts("2026-11-14T10:00:00Z") + Duration::seconds(i as i64);
            r
        });
        let (f, dropped) = scan(many, None);
        assert_eq!((f.len(), dropped), (MAX_FINDINGS, 5));
        assert!(f.windows(2).all(|w| w[0].time <= w[1].time));
        // The newest survive.
        assert_eq!(f.last().unwrap().record_id, MAX_FINDINGS as u64 + 5);
    }

    #[test]
    fn lookback_is_anchored_clamped_and_distrusts_the_future() {
        let now = ts("2026-11-15T12:00:00Z");
        let (s, b) = lookback_start(now, Some(ts("2026-11-15T09:00:00Z")), None);
        assert_eq!((s, b), (ts("2026-11-15T09:00:00Z"), Basis::PreviousRun));
        // The watermark wins over a marker, even a newer one.
        let (s, _) = lookback_start(
            now,
            Some(ts("2026-11-15T11:00:00Z")),
            Some(ts("2026-11-15T09:00:00Z")),
        );
        assert_eq!(s, ts("2026-11-15T09:00:00Z"));
        // A future watermark falls back to the marker.
        let (s, _) = lookback_start(
            now,
            Some(ts("2026-11-15T11:00:00Z")),
            Some(ts("2027-01-01T00:00:00Z")),
        );
        assert_eq!(s, ts("2026-11-15T11:00:00Z"));
        // Ancient marker is clamped to seven days.
        let (s, _) = lookback_start(now, Some(ts("2026-01-01T00:00:00Z")), None);
        assert_eq!(s, now - MAX_LOOKBACK);
        // Future anchors are ignored.
        let (s, b) = lookback_start(
            now,
            Some(ts("2027-01-01T00:00:00Z")),
            Some(ts("2027-02-01T00:00:00Z")),
        );
        assert_eq!(
            (s, b),
            (now - UNKNOWN_PREVIOUS_LOOKBACK, Basis::UnknownPreviousRun)
        );
        // No anchor at all.
        let (s, b) = lookback_start(now, None, None);
        assert_eq!(
            (s, b),
            (now - UNKNOWN_PREVIOUS_LOOKBACK, Basis::UnknownPreviousRun)
        );
    }

    #[test]
    fn marker_moving_without_a_successful_scan_keeps_the_old_window() {
        let dir = std::env::temp_dir().join(format!("trapd_rf_adv_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let old = ts("2026-11-15T08:00:00Z");
        write_watermark(&dir, old);
        // Start 1: marker already rewritten, read-back failed.
        let t1 = ts("2026-11-15T10:00:00Z");
        advance_watermark(&dir, t1, false);
        assert_eq!(read_watermark(&dir), Some(old));
        // Start 2: the marker is now newer, the window still starts at `old`.
        let t2 = ts("2026-11-15T11:00:00Z");
        let (since, _) = lookback_start(t2, Some(t1), read_watermark(&dir));
        assert_eq!(since, old);
        // A successful scan advances it.
        advance_watermark(&dir, t2, true);
        assert_eq!(read_watermark(&dir), Some(t2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncated_query_is_incomplete_and_keeps_the_watermark() {
        let mut ok = ReadOutcome::new();
        for _ in 0..3 {
            ok.record(Some(true));
        }
        assert!(ok.complete && ok.truncated == 0);
        // More matches than the limit: not complete, counted, old watermark stays.
        let mut cut = ReadOutcome::new();
        cut.record(Some(true));
        cut.record(Some(false));
        cut.record(Some(true));
        assert!(!cut.complete);
        assert_eq!(cut.truncated, 1);
        let mut failed = ReadOutcome::new();
        failed.record(Some(true));
        failed.record(None);
        failed.record(Some(true));
        assert!(!failed.complete);
        let dir = std::env::temp_dir().join(format!("trapd_rf_trunc_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let old = ts("2026-11-15T08:00:00Z");
        write_watermark(&dir, old);
        advance_watermark(&dir, ts("2026-11-15T10:00:00Z"), cut.complete);
        assert_eq!(read_watermark(&dir), Some(old));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn queries_embed_only_constants_and_a_formatted_time() {
        let q = queries(ts("2026-11-14T10:00:00.5Z"));
        assert_eq!(q.len(), 3);
        for (text, limit) in &q {
            assert!(text.contains("TimeCreated[@SystemTime>='2026-11-14T10:00:00.500Z']"));
            assert!(*limit <= 128);
        }
        assert!(q[0].0.contains("EventID=7036 or EventID=7040"));
    }

    #[test]
    fn watermark_round_trips_and_rejects_garbage() {
        let dir = std::env::temp_dir().join(format!("trapd_wm_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(read_watermark(&dir).is_none());
        let t = ts("2026-11-14T10:00:00Z");
        write_watermark(&dir, t);
        assert_eq!(read_watermark(&dir), Some(t));
        std::fs::write(dir.join(WATERMARK_FILE), b"not json").unwrap();
        assert!(read_watermark(&dir).is_none());
        std::fs::write(dir.join(WATERMARK_FILE), vec![b' '; 4096]).unwrap();
        assert!(read_watermark(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
