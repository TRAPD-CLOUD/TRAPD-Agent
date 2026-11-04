//! Sensor-side policy for the TRAPD agent.
//!
//! **This crate no longer evaluates detection rules.** Rule matching
//! (behavioural, IOC, Sigma, correlation) happens in the backend, which
//! receives the raw telemetry in the canonical [`trapd_schema`] shape. What
//! remains here needs host access or is part of how telemetry is shaped:
//!
//!   * honeytoken / decoy access policy (kernel-side enforcement)
//!   * filesystem write heuristics (ransomware *indicator* measurements)
//!   * Windows log normalisation and object-access attribution
//!   * optional YARA scanning of process memory (`yara` feature)
//!
//! The pre-removal rule catalog is kept in `docs/legacy-agent-rules/` as the
//! migration reference for the backend rule set.

pub mod accessor_correlation;
pub mod fs_heuristics;
#[cfg(target_os = "linux")] // fed only by the eBPF file-open gate
pub mod honeytoken;
pub mod honeytoken_policy;
pub mod legacy_config;
pub mod sensitive_files;
#[cfg(any(windows, test))]
pub mod windows_decoy;
pub mod windows_logon;
pub mod windows_roots;
#[cfg(feature = "yara")]
pub mod yara_scanner;

use trapd_schema::{AgentEvent, EventData};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuleModeOverride {
    pub rule: String,
    pub mode: trapd_schema::DetectionMode,
}

/// True when a Log record is native Windows audit evidence for an event the
/// agent used to judge locally (process creation, service/task install, WMI).
fn is_native_audit_log(log: &trapd_schema::LogEventData) -> bool {
    let Some(id) = log.fields.get("EventID").and_then(|v| v.as_u64()) else {
        return false;
    };
    let (channel, provider) = match id {
        4688 | 4697 | 4698 => ("Security", "Microsoft-Windows-Security-Auditing"),
        7045 => ("System", "Service Control Manager"),
        5861 => (
            "Microsoft-Windows-WMI-Activity/Operational",
            "Microsoft-Windows-WMI-Activity",
        ),
        _ => return false,
    };
    log.source_type == "windows_eventlog"
        && log.log_timestamp.is_some()
        && log.source_path.eq_ignore_ascii_case(channel)
        && log
            .proc
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case(provider))
}

/// Native Windows process audit records have no verified live generation.
/// Findings keep this source marker so admission and response stay fail-closed.
pub fn is_historical_windows_process_event(event: &AgentEvent) -> bool {
    matches!(
        event.origin.as_ref().and_then(|o| o.source.as_deref()),
        Some("windows_eventlog:Security:4688")
            | Some("windows_eventlog:Microsoft-Windows-Sysmon/Operational:1")
    )
}

/// Windows Event Log records are persisted audit evidence, including their
/// derived findings; their PIDs are not verified live process identities.
pub fn is_historical_windows_record(event: &AgentEvent) -> bool {
    event
        .origin
        .as_ref()
        .and_then(|o| o.source.as_deref())
        .is_some_and(|source| source.starts_with("windows_eventlog:"))
        || matches!(&event.data, EventData::Log(log) if is_native_audit_log(log))
}

/// Serial native pollers retry their last record when a durable checkpoint
/// fails. Keep exactly one UUID per raw source, without suppressing the
/// normalized events paired with it or unrelated telemetry.
#[derive(Default)]
pub struct CheckpointTracker {
    last: [Option<uuid::Uuid>; 5],
}

impl CheckpointTracker {
    pub fn is_retry(&mut self, event: &AgentEvent) -> bool {
        let source = event
            .origin
            .as_ref()
            .and_then(|origin| origin.source.as_deref());
        let slot = match (&event.data, source) {
            (EventData::Log(log), Some(source)) if log.source_type == "windows_eventlog" => {
                match (source, log.source_path.as_str()) {
                    ("windows_eventlog:Security", "Security") => 0,
                    ("windows_eventlog:System", "System") => 1,
                    ("windows_eventlog:Application", "Application") => 2,
                    (
                        "windows_eventlog:Microsoft-Windows-Sysmon/Operational",
                        "Microsoft-Windows-Sysmon/Operational",
                    ) => 3,
                    _ => return false,
                }
            }
            (EventData::Registry(_), Some("windows_registry_snapshot")) => 4,
            _ => return false,
        };
        if self.last[slot] == Some(event.event_id) {
            return true;
        }
        self.last[slot] = Some(event.event_id);
        false
    }
}
