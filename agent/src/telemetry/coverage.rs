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
    /// Advanced audit policy: File System (success) enabled — decoy reads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_file_system: Option<bool>,
    /// How decoy reads are detected: `kernel`, `audit`, `last_access`,
    /// `tamper_only`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoy_detection: Option<String>,
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
}
