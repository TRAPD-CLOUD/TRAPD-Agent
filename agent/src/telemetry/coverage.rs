//! What the agent can currently see, and which rules ran silently.
//!
//! "No alert" only means "nothing happened" when the sensor was able to see
//! it. Collectors record their effective coverage here (ETW session healthy,
//! events lost, audit policy, how decoys are watched), and the heartbeat ships
//! it so the console can show coverage per host instead of implying it.
//!
//! The same heartbeat carries the shadow-mode counters: findings of rules that
//! are evaluated but not yet allowed to emit (`DetectionMode::Shadow`). The
//! backend aggregates them per rule to decide whether a rule is quiet enough
//! to be promoted to signal or alert.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::Serialize;

/// Maximum distinct rules counted between two heartbeats.
const MAX_SHADOW_RULES: usize = 512;

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct Coverage {
    /// Process telemetry source: `etw`, `polling`, `ebpf`, `proc`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_sensor: Option<String>,
    /// ETW real-time session is running and delivering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etw_session: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etw_process_provider: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etw_network_provider: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etw_dns_provider: Option<bool>,
    /// Events the ETW session dropped (cumulative since start).
    #[serde(skip_serializing_if = "is_zero")]
    pub etw_events_lost: u64,
    /// Processes seen by the poller but not by ETW (cross-view gaps).
    #[serde(skip_serializing_if = "is_zero")]
    pub sensor_gaps: u64,
    /// Advanced audit policy: Process Creation (success) enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_process_creation: Option<bool>,
    /// Command lines included in 4688 events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_command_line: Option<bool>,
    /// Audit Registry success enabled; target-key SACLs are still required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_registry: Option<bool>,
    /// Collector is enabled and its last Security channel read succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_eventlog_active: Option<bool>,
    /// Channel readable, not a claim that Sysmon filters cover every operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sysmon_eventlog_active: Option<bool>,
    /// Advanced audit policy: File System (success) enabled — decoy reads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_file_system: Option<bool>,
    /// How decoy reads are detected: `kernel`, `audit`, `last_access`,
    /// `tamper_only`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoy_detection: Option<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub decoy_audit_armed: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub decoy_audit_unavailable: u64,
    /// Actual attachment results, not capabilities inferred from the OS.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub ebpf_honeytoken_programs: BTreeMap<String, bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ebpf_honeytoken_inode: Option<bool>,
}

impl Coverage {
    #[cfg(any(windows, test))]
    pub fn set_eventlog_active(&mut self, channel: &str, active: bool) {
        match channel {
            "Security" => self.security_eventlog_active = Some(active),
            "Microsoft-Windows-Sysmon/Operational" => self.sysmon_eventlog_active = Some(active),
            _ => {}
        }
    }
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn clear_ebpf_attachments(&mut self) {
        for active in self.ebpf_honeytoken_programs.values_mut() {
            *active = false;
        }
        self.ebpf_honeytoken_inode = Some(false);
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn etw_process_active(&self) -> bool {
        self.etw_session == Some(true) && self.etw_process_provider == Some(true)
    }
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn etw_network_active(&self) -> bool {
        self.etw_session == Some(true) && self.etw_network_provider == Some(true)
    }
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

fn state() -> &'static Mutex<Coverage> {
    static S: std::sync::OnceLock<Mutex<Coverage>> = std::sync::OnceLock::new();
    S.get_or_init(|| Mutex::new(Coverage::default()))
}

/// Mutate the coverage record.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn update(f: impl FnOnce(&mut Coverage)) {
    if let Ok(mut c) = state().lock() {
        f(&mut c);
    }
}

pub fn snapshot() -> Coverage {
    state().lock().map(|c| c.clone()).unwrap_or_default()
}

fn shadow() -> &'static Mutex<BTreeMap<String, u64>> {
    static S: std::sync::OnceLock<Mutex<BTreeMap<String, u64>>> = std::sync::OnceLock::new();
    S.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Count one finding of a rule running in shadow mode.
pub fn shadow_hit(rule_id: &str) {
    if let Ok(mut m) = shadow().lock() {
        if let Some(n) = m.get_mut(rule_id) {
            *n = n.saturating_add(1);
        } else if m.len() < MAX_SHADOW_RULES {
            m.insert(rule_id.to_string(), 1);
        }
    }
}

/// Take the counters for a heartbeat (reset to zero).
pub fn take_shadow_hits() -> BTreeMap<String, u64> {
    shadow()
        .lock()
        .map(|mut m| std::mem::take(&mut *m))
        .unwrap_or_default()
}

/// Put counters back after a failed heartbeat so no count is lost.
pub fn restore_shadow_hits(hits: BTreeMap<String, u64>) {
    for (rule, n) in hits {
        if let Ok(mut m) = shadow().lock() {
            if m.len() < MAX_SHADOW_RULES || m.contains_key(&rule) {
                let e = m.entry(rule).or_insert(0);
                *e = e.saturating_add(n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_or_stopped_ebpf_sensor_cannot_keep_attachment_claims() {
        let mut c = Coverage {
            ebpf_honeytoken_inode: Some(true),
            ..Default::default()
        };
        c.ebpf_honeytoken_programs
            .insert("sys_enter_open".into(), true);
        c.ebpf_honeytoken_programs
            .insert("sys_enter_openat2".into(), false);
        c.clear_ebpf_attachments();
        assert!(c.ebpf_honeytoken_programs.values().all(|active| !active));
        assert_eq!(c.ebpf_honeytoken_inode, Some(false));
    }

    #[test]
    fn partial_etw_coverage_keeps_the_missing_sensor_fallback() {
        let mut c = Coverage::default();
        assert!(!c.etw_process_active());
        c.etw_session = Some(true);
        c.etw_process_provider = Some(true);
        assert!(c.etw_process_active());
        assert!(!c.etw_network_active());
        c.etw_network_provider = Some(true);
        assert!(c.etw_network_active());
        c.etw_session = Some(false);
        assert!(!c.etw_process_active());
        assert!(!c.etw_network_active());
    }

    #[test]
    fn shadow_counters_take_and_restore() {
        let _ = take_shadow_hits();
        shadow_hit("execution.powershell_encoded");
        shadow_hit("execution.powershell_encoded");
        shadow_hit("lolbin.mshta_remote");
        let taken = take_shadow_hits();
        assert_eq!(taken.get("execution.powershell_encoded"), Some(&2));
        assert!(take_shadow_hits().is_empty());
        restore_shadow_hits(taken);
        shadow_hit("lolbin.mshta_remote");
        let again = take_shadow_hits();
        assert_eq!(again.get("lolbin.mshta_remote"), Some(&2));
    }

    #[test]
    fn coverage_serialises_only_known_facts() {
        let c = Coverage {
            process_sensor: Some("etw".into()),
            etw_session: Some(true),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(&c).unwrap(),
            serde_json::json!({"process_sensor": "etw", "etw_session": true})
        );
    }

    #[test]
    fn native_channel_presence_is_explicit_and_does_not_claim_audit_policy() {
        let mut c = Coverage::default();
        c.set_eventlog_active("Security", true);
        c.set_eventlog_active("Microsoft-Windows-Sysmon/Operational", false);
        let value = serde_json::to_value(&c).unwrap();
        assert_eq!(value["security_eventlog_active"], true);
        assert_eq!(value["sysmon_eventlog_active"], false);
        assert!(value.get("audit_process_creation").is_none());
        assert!(value.get("audit_registry").is_none());
        c.set_eventlog_active("Security", false);
        assert_eq!(
            serde_json::to_value(c).unwrap()["security_eventlog_active"],
            false
        );
    }
}
