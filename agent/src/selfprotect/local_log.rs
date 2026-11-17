//! Local, SIEM-friendly record of every `selfprotect.*` finding.
//!
//! Every event passes `consume_batch_with` once on its way to the spool; that
//! is the single place [`record`] is called, so a new `selfprotect.*` rule is
//! logged without touching this module (unknown rules get the fallback id).
//!
//! * Windows: classic custom log `TRAPD-Agent-Security` (source of the same
//!   name). A slash is not usable in a classic log name (it is a registry path
//!   separator), so the dash form is the registered name. A manifest-based
//!   channel needs an installed manifest and resource DLL; the classic log
//!   reuses the service's self-registration and `EventCreate.exe` message file
//!   (ids 1..=1000), so the MSI is untouched and a failed registration can
//!   never block install or removal.
//! * Linux: native journald protocol on `/run/systemd/journal/socket` with
//!   `SYSLOG_IDENTIFIER=trapd-agent-security` and a `MESSAGE_ID` per type. No
//!   new crate; no journald (containers) means the write is skipped.
//!
//! Content: rule id, severity and event id only. Subjects, paths and command
//! lines stay out because the log is readable by ordinary users; the event id
//! joins the entry to the backend finding. IDs and MESSAGE_IDs are a public
//! contract for SIEM rules and must never be renumbered (see the table test).
//!
//! Optional user toast: a tamper event also shows a fixed-text toast when the
//! signed config sets `tamper_user_notification` (default off).

use trapd_schema::{AgentEvent, EventData, Severity};

#[cfg_attr(not(windows), allow(dead_code))]
pub const LOG_NAME: &str = "TRAPD-Agent-Security";
pub const JOURNAL_IDENTIFIER: &str = "trapd-agent-security";
/// Id for any `selfprotect.*` rule without a dedicated entry.
pub const FALLBACK_ID: u32 = 199;

/// `(rule id, event id, user-visible tamper)`. A tamper entry is one that can
/// mean somebody is working against the agent right now; posture drift and
/// restart forensics are logged but never raise a toast.
const TABLE: &[(&str, u32, bool)] = &[
    ("selfprotect.peer_lost", 101, true),
    ("selfprotect.peer_binary_tampered", 102, true),
    ("selfprotect.module_injected", 103, true),
    ("selfprotect.code_patched", 104, true),
    ("selfprotect.remote_thread", 105, true),
    ("selfprotect.debugger_attached", 106, true),
    ("selfprotect.handle_access", 107, true),
    ("selfprotect.network_silenced", 108, true),
    ("selfprotect.tls_pin_mismatch", 109, true),
    ("selfprotect.backend_redirected", 110, true),
    ("selfprotect.backend_unreachable_selective", 111, true),
    ("selfprotect.platform_posture_changed", 112, false),
    ("selfprotect.time_jump", 113, false),
    ("selfprotect.etw_session_stopped", 120, false),
    ("selfprotect.unclean_shutdown", 121, false),
    ("selfprotect.binary_tampered", 122, true),
    ("selfprotect.binary_modified", 123, true),
];

/// Resolved log identity of one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub id: u32,
    pub tamper: bool,
}

/// `None` for anything that is not a `selfprotect.*` rule.
pub fn lookup(rule_id: &str) -> Option<Entry> {
    if !rule_id.starts_with("selfprotect.") {
        return None;
    }
    Some(
        TABLE
            .iter()
            .find(|(rule, _, _)| *rule == rule_id)
            .map(|&(_, id, tamper)| Entry { id, tamper })
            .unwrap_or(Entry {
                id: FALLBACK_ID,
                tamper: false,
            }),
    )
}

/// Stable 128-bit journald `MESSAGE_ID` derived from the event id.
pub fn message_id(id: u32) -> String {
    format!("74726170640000000000000000{id:06x}")
}

/// Whether an entry shows a user toast under the given policy value.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn should_toast(entry: Entry, policy_enabled: bool) -> bool {
    policy_enabled && entry.tamper
}

/// Single line, bounded, free of control characters.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(120)
        .collect()
}

fn summary(rule_id: &str, severity: &Severity, event_id: &uuid::Uuid) -> String {
    format!(
        "TRAPD Agent self-protection finding {} (severity {severity:?}, event {event_id}). Details are in the TRAPD console.",
        clean(rule_id)
    )
}

#[cfg_attr(windows, allow(dead_code))]
fn journal_priority(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 2,
        Severity::High => 3,
        Severity::Medium => 4,
        Severity::Low => 5,
        Severity::Info => 6,
    }
}

/// Native journald datagram. Every value is single-line, so the simple
/// `KEY=value\n` form is enough.
#[cfg_attr(windows, allow(dead_code))]
fn journal_payload(rule_id: &str, entry: Entry, event: &AgentEvent) -> String {
    format!(
        "SYSLOG_IDENTIFIER={JOURNAL_IDENTIFIER}\nMESSAGE_ID={}\nPRIORITY={}\nTRAPD_RULE_ID={}\nTRAPD_EVENT_ID={}\nMESSAGE={}\n",
        message_id(entry.id),
        journal_priority(&event.severity),
        clean(rule_id),
        event.event_id,
        summary(rule_id, &event.severity, &event.event_id),
    )
}

/// Write the local record for `event` (and the optional toast). Never fails or
/// blocks the pipeline on error.
pub fn record(event: &AgentEvent) {
    let EventData::Detection(detection) = &event.data else {
        return;
    };
    let Some(entry) = lookup(&detection.rule_id) else {
        return;
    };
    #[cfg(windows)]
    {
        crate::winsvc::write_security_event(
            entry.id,
            &event.severity,
            &summary(&detection.rule_id, &event.severity, &event.event_id),
        );
        if should_toast(entry, toast_policy()) {
            crate::prevention::usernotify::notify_tamper();
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixDatagram;
        let payload = journal_payload(&detection.rule_id, entry, event);
        if let Ok(socket) = UnixDatagram::unbound() {
            // Missing socket (no journald) is expected in containers.
            let _ = socket.send_to(payload.as_bytes(), "/run/systemd/journal/socket");
        }
    }
}

#[cfg(windows)]
static CONFIG: std::sync::OnceLock<std::sync::Arc<std::sync::RwLock<crate::config::AgentConfig>>> =
    std::sync::OnceLock::new();

/// Hand the live config to the toast gate. Without it no toast is shown.
#[cfg(windows)]
pub fn init_policy(config: std::sync::Arc<std::sync::RwLock<crate::config::AgentConfig>>) {
    let _ = CONFIG.set(config);
}

#[cfg(windows)]
fn toast_policy() -> bool {
    CONFIG
        .get()
        .and_then(|c| c.read().ok().map(|c| c.tamper_user_notification))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trapd_schema::{DetectionData, EventAction, EventClass};

    #[test]
    fn id_table_is_stable_unique_and_in_the_custom_range() {
        // SIEM contract: pinned values, never renumber.
        assert_eq!(lookup("selfprotect.peer_lost").unwrap().id, 101);
        assert_eq!(lookup("selfprotect.time_jump").unwrap().id, 113);
        assert_eq!(lookup("selfprotect.unclean_shutdown").unwrap().id, 121);
        let mut ids: Vec<u32> = TABLE.iter().map(|t| t.1).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), TABLE.len());
        assert!(ids.iter().all(|id| (100..FALLBACK_ID).contains(id)));
    }

    #[test]
    fn unknown_selfprotect_rules_get_the_fallback_and_others_none() {
        assert_eq!(
            lookup("selfprotect.brand_new").unwrap(),
            Entry {
                id: FALLBACK_ID,
                tamper: false
            }
        );
        assert!(lookup("agent.liveness_echo").is_none());
        assert!(lookup("lolbin.x").is_none());
    }

    #[test]
    fn message_ids_are_32_hex_and_distinct() {
        let a = message_id(101);
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(a, message_id(102));
        assert!(a.ends_with("000065"));
    }

    #[test]
    fn toast_needs_policy_and_a_tamper_event() {
        let tamper = lookup("selfprotect.module_injected").unwrap();
        let drift = lookup("selfprotect.platform_posture_changed").unwrap();
        assert!(should_toast(tamper, true));
        assert!(!should_toast(tamper, false));
        assert!(!should_toast(drift, true));
    }

    #[test]
    fn journal_payload_is_single_line_fields_without_subject() {
        let mut event = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Detection,
            EventAction::Detected,
            Severity::High,
            EventData::Detection(Box::new(DetectionData {
                rule_id: "selfprotect.peer_lost".into(),
                title: "t".into(),
                category: "selfprotect".into(),
                mitre_tactic: None,
                mitre_technique: None,
                confidence: 90,
                subject: "C:\\secret\\path".into(),
                detail: "d\nINJECT=1".into(),
                evidence: serde_json::Value::Null,
                ..Default::default()
            })),
        );
        event.severity = Severity::High;
        let entry = lookup("selfprotect.peer_lost").unwrap();
        let payload = journal_payload("selfprotect.peer_lost\nX=1", entry, &event);
        assert!(payload.contains("SYSLOG_IDENTIFIER=trapd-agent-security\n"));
        assert!(payload.contains("PRIORITY=3\n"));
        assert!(!payload.contains("secret"));
        assert!(!payload.contains("INJECT"));
        assert_eq!(payload.matches('\n').count(), 6, "{payload}");
    }
}
