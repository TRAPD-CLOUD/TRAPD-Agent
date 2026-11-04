//! Classification of findings the agent still raises itself.
//!
//! Rule *matching* lives in the backend. Some findings, however, can only be
//! produced on the host (honeytoken access, rootkit cross-view, memory scan,
//! agent self-protection), and the local auto-response acts on them without a
//! backend round trip. That response must see the same alert/signal decision
//! and severity the backend will compute, so it is applied here, before the
//! finding is forwarded or acted on.
//!
//! The table is deliberately limited to rules the agent still emits
//! (`sensor-rules.json`, a subset of the retired catalog). Anything not listed
//! is treated as a signal and capped at `High`: an unknown finding never
//! triggers a response on its own.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use trapd_schema::{AgentEvent, DetectionData, DetectionMode, EventData, Severity};

use crate::honeytoken_policy;
use crate::legacy_config::{SuppressionAction, SuppressionRule};

/// Findings of these families may be lowered by a suppression, never dropped.
const UNDROPPABLE_PREFIXES: &[&str] = &["deception."];

#[derive(Deserialize)]
struct Entry {
    id: String,
    base: Severity,
    max: Severity,
    mode: DetectionMode,
    base_from_event: bool,
    tactic: String,
    technique: String,
}

fn table() -> &'static [Entry] {
    static TABLE: OnceLock<Vec<Entry>> = OnceLock::new();
    TABLE.get_or_init(|| {
        serde_json::from_str(include_str!("../sensor-rules.json"))
            .expect("sensor-rules.json is valid")
    })
}

fn overrides() -> &'static RwLock<HashMap<String, DetectionMode>> {
    static OVERRIDES: OnceLock<RwLock<HashMap<String, DetectionMode>>> = OnceLock::new();
    OVERRIDES.get_or_init(Default::default)
}

/// Replace the operator's per-rule mode overrides (signed config `rule_modes`).
/// They take precedence over the table, exactly as they did when the engine
/// classified these findings.
pub fn set_rule_modes(modes: &[crate::RuleModeOverride]) {
    if let Ok(mut map) = overrides().write() {
        *map = modes.iter().map(|m| (m.rule.clone(), m.mode)).collect();
    }
}

fn override_for(rule_id: &str) -> Option<DetectionMode> {
    overrides().read().ok()?.get(rule_id).copied()
}

fn suppressions() -> &'static RwLock<Vec<SuppressionRule>> {
    static SUPPRESSIONS: OnceLock<RwLock<Vec<SuppressionRule>>> = OnceLock::new();
    SUPPRESSIONS.get_or_init(Default::default)
}

/// Replace the operator's signed suppressions (`detection_suppressions`). They
/// must apply to host findings before local auto-response, because the backend
/// cannot undo an action the agent already took.
pub fn set_suppressions(rules: &[SuppressionRule]) {
    if let Ok(mut list) = suppressions().write() {
        *list = rules.to_vec();
    }
}

/// What to do with a classified event.
#[derive(Debug, PartialEq, Eq)]
pub enum Disposition {
    /// A drop suppression matched: counted, not emitted, not acted on.
    Suppressed,
    /// Persist, ship and let prevention see it.
    Forward,
    /// The rule runs in shadow mode: count it, never emit or act on it.
    Shadow(String),
}

/// Exact id first, then the longest matching `prefix.` entry.
fn lookup(rule_id: &str) -> Option<&'static Entry> {
    let t = table();
    t.iter().find(|e| e.id == rule_id).or_else(|| {
        t.iter()
            .filter(|e| e.id.ends_with('.') && rule_id.starts_with(&e.id))
            .max_by_key(|e| e.id.len())
    })
}

fn rank(s: Severity) -> i8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Below this confidence a finding is a signal, never an alert.
const ALERT_MIN_CONFIDENCE: u8 = 50;

fn classify_detection(emitted: Severity, d: &mut DetectionData) -> Severity {
    let entry = lookup(&d.rule_id);
    let (base, max, table_mode) = match entry {
        Some(e) => {
            if d.mitre_tactic.is_none() && !e.tactic.is_empty() {
                d.mitre_tactic = Some(e.tactic.clone());
            }
            if d.mitre_technique.is_none() && !e.technique.is_empty() {
                d.mitre_technique = Some(e.technique.clone());
            }
            let base = d
                .base_severity
                .unwrap_or(if e.base_from_event { emitted } else { e.base });
            (base.min(e.max), e.max, e.mode)
        }
        None => {
            let base = d.base_severity.unwrap_or(emitted).min(Severity::High);
            (base, Severity::High, DetectionMode::Signal)
        }
    };
    let configured = override_for(&d.rule_id).unwrap_or(table_mode);
    let mut reasons = vec![format!("base:{base:?}").to_lowercase()];
    let mut mode = if configured == DetectionMode::Shadow {
        DetectionMode::Alert
    } else {
        configured
    };
    // A finding may demote itself to a signal; it can never promote a signal.
    if mode == DetectionMode::Alert && d.mode == Some(DetectionMode::Signal) {
        mode = DetectionMode::Signal;
    }
    if mode == DetectionMode::Alert && d.confidence < ALERT_MIN_CONFIDENCE {
        mode = DetectionMode::Signal;
        reasons.push("signal:low_confidence".into());
    }
    if entry.is_none() {
        reasons.push("signal:uncatalogued".into());
    }
    let mut sev = rank(base).min(rank(max));
    if mode == DetectionMode::Alert {
        sev = sev.max(rank(Severity::Low));
    } else {
        sev = sev.min(rank(Severity::Low));
    }
    let severity = match sev {
        i8::MIN..=0 => Severity::Info,
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        _ => Severity::Critical,
    };
    d.mode = Some(if configured == DetectionMode::Shadow {
        DetectionMode::Shadow
    } else {
        mode
    });
    d.base_severity = Some(base);
    d.severity_reasons = reasons;
    severity
}

fn step_down(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low | Severity::Info => Severity::Info,
    }
}

/// Apply the first matching signed suppression. Returns `true` when the finding
/// is to be dropped.
fn apply_suppression(severity: &mut Severity, at: DateTime<Utc>, d: &mut DetectionData) -> bool {
    let Ok(list) = suppressions().read() else {
        return false;
    };
    let Some(rule) = list.iter().find(|r| suppression_matches(r, d, at)) else {
        return false;
    };
    let action = if rule.action == SuppressionAction::Drop
        && UNDROPPABLE_PREFIXES
            .iter()
            .any(|p| d.rule_id.starts_with(p))
    {
        SuppressionAction::Downgrade
    } else {
        rule.action
    };
    match action {
        SuppressionAction::Drop => return true,
        SuppressionAction::SignalOnly => {
            d.mode = Some(DetectionMode::Signal);
            *severity = (*severity).min(Severity::Low);
            d.severity_reasons.push("signal:suppression".into());
        }
        SuppressionAction::Downgrade => {
            let floor = if d.mode == Some(DetectionMode::Signal) {
                Severity::Info
            } else {
                Severity::Low
            };
            *severity = step_down(*severity).max(floor);
            d.severity_reasons.push("-suppression_downgrade".into());
        }
    }
    if let Some(obj) = d.evidence.as_object_mut() {
        obj.insert("suppression_id".into(), rule.id.clone().into());
    } else if d.evidence.is_null() {
        d.evidence = serde_json::json!({ "suppression_id": rule.id });
    }
    false
}

fn suppression_matches(r: &SuppressionRule, d: &DetectionData, at: DateTime<Utc>) -> bool {
    if r.expires_at.is_some_and(|t| t <= at) || !glob_match(&r.rule, &d.rule_id) {
        return false;
    }
    let corr = d.correlation.clone().unwrap_or_default();
    let evidence = |k: &str| d.evidence.get(k).and_then(|v| v.as_str()).map(String::from);
    let plain = |pattern: &Option<String>, value: Option<String>| match pattern {
        None => true,
        Some(p) => value.is_some_and(|v| glob_match(p, &v)),
    };
    let identity = |pattern: &Option<String>, value: Option<String>| match pattern {
        None => true,
        Some(p) => value.is_some_and(|v| glob_match_identity(p, &v)),
    };
    identity(&r.exe, corr.exe.clone().or_else(|| Some(d.subject.clone())))
        && plain(&r.cmdline, evidence("cmdline"))
        && identity(&r.user, corr.user.clone())
        // The agent no longer builds a process tree, so a parent-image
        // suppression cannot be evaluated here and does not match.
        && r.parent_exe.is_none()
        && identity(&r.path, corr.file_path.clone().or_else(|| evidence("path")))
        && match &r.sha256 {
            None => true,
            Some(h) => corr
                .exe_sha256
                .as_deref()
                .is_some_and(|x| digest_hex(x).eq_ignore_ascii_case(digest_hex(h))),
        }
        && match &r.remote {
            None => true,
            Some(p) => remote_match(p, corr.remote_ip.as_deref(), corr.domain.as_deref()),
        }
}

/// Windows spellings are compared the way Windows does: separators equal,
/// case ignored (a `\` in a glob would otherwise be an escape).
fn glob_match_identity(pattern: &str, value: &str) -> bool {
    let windows = value.contains('\\') || value.as_bytes().get(1) == Some(&b':');
    if windows {
        glob_match(
            &pattern.replace('\\', "/").to_ascii_lowercase(),
            &value.replace('\\', "/").to_ascii_lowercase(),
        )
    } else {
        glob_match(pattern, value)
    }
}

fn digest_hex(d: &str) -> &str {
    let d = d.trim();
    d.strip_prefix("sha256:")
        .or_else(|| d.strip_prefix("SHA256:"))
        .unwrap_or(d)
}

fn glob_match(pattern: &str, value: &str) -> bool {
    match globset::GlobBuilder::new(pattern)
        .literal_separator(false)
        .build()
    {
        Ok(g) => g.compile_matcher().is_match(value),
        Err(_) => pattern == value,
    }
}

fn remote_match(pattern: &str, ip: Option<&str>, domain: Option<&str>) -> bool {
    if let Some((net, bits)) = pattern.split_once('/') {
        let (Ok(net), Ok(bits), Some(Ok(ip))) = (
            net.parse::<std::net::IpAddr>(),
            bits.parse::<u8>(),
            ip.map(|i| i.parse::<std::net::IpAddr>()),
        ) else {
            return false;
        };
        return match (net, ip) {
            (std::net::IpAddr::V4(n), std::net::IpAddr::V4(i)) if bits <= 32 => {
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                u32::from(n) & mask == u32::from(i) & mask
            }
            (std::net::IpAddr::V6(n), std::net::IpAddr::V6(i)) if bits <= 128 => {
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                u128::from(n) & mask == u128::from(i) & mask
            }
            _ => false,
        };
    }
    ip == Some(pattern)
        || domain.is_some_and(|d| d == pattern || d.ends_with(&format!(".{pattern}")))
}

/// Stamp a collector-raised finding with its mode and severity. Events of any
/// other kind are left untouched. A finding whose rule runs in shadow mode is
/// reported as [`Disposition::Shadow`] and must not be forwarded.
pub fn classify(event: &mut AgentEvent) -> Disposition {
    match &mut event.data {
        EventData::HoneytokenAccess(data) => {
            let outcome = honeytoken_policy::assess(data, event.severity);
            event.severity = outcome.severity;
            data.mode = Some(outcome.mode);
            if matches!(
                data.access_kind.as_str(),
                "modify" | "unlink" | "rename" | "hardlink" | "exec"
            ) {
                data.confidence = data.confidence.max(90);
            }
            data.assessment_reasons = outcome.reasons;
        }
        EventData::Detection(d) => {
            let emitted = event.severity;
            event.severity = classify_detection(emitted, d);
            if d.mode == Some(DetectionMode::Shadow) {
                return Disposition::Shadow(d.rule_id.clone());
            }
            if apply_suppression(&mut event.severity, event.timestamp, d) {
                return Disposition::Suppressed;
            }
        }
        _ => {}
    }
    Disposition::Forward
}

#[cfg(test)]
mod tests {
    use super::*;
    use trapd_schema::{EventAction, EventClass};

    fn finding(rule: &str, confidence: u8, severity: Severity) -> AgentEvent {
        AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Detection,
            EventAction::Detected,
            severity,
            EventData::Detection(Box::new(DetectionData {
                rule_id: rule.into(),
                confidence,
                ..Default::default()
            })),
        )
    }

    fn mode(e: &AgentEvent) -> Option<DetectionMode> {
        match &e.data {
            EventData::Detection(d) => d.mode,
            _ => None,
        }
    }

    #[test]
    fn low_confidence_memory_observation_is_a_signal_not_an_alert() {
        let mut e = finding("memory.anon_exec", 30, Severity::High);
        classify(&mut e);
        assert_eq!(mode(&e), Some(DetectionMode::Signal));
        assert!(e.severity <= Severity::Low, "a signal never exceeds low");
    }

    #[test]
    fn confident_memory_finding_stays_an_alert_capped_by_the_rule() {
        let mut e = finding("memory.anon_exec", 80, Severity::Critical);
        classify(&mut e);
        assert_eq!(mode(&e), Some(DetectionMode::Alert));
        assert!(e.severity >= Severity::High);
    }

    #[test]
    fn rootkit_prefix_alerts_and_unknown_rules_never_do() {
        let mut r = finding("rootkit.hidden_process", 90, Severity::High);
        classify(&mut r);
        assert_eq!(mode(&r), Some(DetectionMode::Alert));
        assert!(r.severity >= Severity::Medium);

        let mut u = finding("made.up_rule", 99, Severity::Critical);
        classify(&mut u);
        assert_eq!(mode(&u), Some(DetectionMode::Signal));
        assert!(u.severity <= Severity::Low);
    }

    #[test]
    fn a_finding_can_demote_itself_but_not_promote_a_signal() {
        let mut e = finding("memory.deleted_exec", 95, Severity::High);
        classify(&mut e);
        assert_eq!(
            mode(&e),
            Some(DetectionMode::Signal),
            "catalog signal stays"
        );

        let mut e = finding("memory.anon_exec", 95, Severity::High);
        if let EventData::Detection(d) = &mut e.data {
            d.mode = Some(DetectionMode::Signal);
        }
        classify(&mut e);
        assert_eq!(mode(&e), Some(DetectionMode::Signal), "self-demotion holds");
    }

    #[test]
    fn signed_rule_modes_override_the_table_and_shadow_is_not_forwarded() {
        // The override map is process-global: keep every assertion on it in
        // one test so parallel tests never see each other's overrides.
        set_rule_modes(&[
            crate::RuleModeOverride {
                rule: "memory.memfd_exec".into(),
                mode: DetectionMode::Signal,
            },
            crate::RuleModeOverride {
                rule: "memory.injected_pe".into(),
                mode: DetectionMode::Shadow,
            },
        ]);
        let mut e = finding("memory.memfd_exec", 90, Severity::Critical);
        assert_eq!(classify(&mut e), Disposition::Forward);
        assert_eq!(mode(&e), Some(DetectionMode::Signal));
        assert!(e.severity <= Severity::Low, "operator-demoted: never acts");

        let mut e = finding("memory.injected_pe", 90, Severity::High);
        assert_eq!(
            classify(&mut e),
            Disposition::Shadow("memory.injected_pe".into())
        );
        set_rule_modes(&[]);
        let mut e = finding("memory.memfd_exec", 90, Severity::Critical);
        classify(&mut e);
        assert_eq!(mode(&e), Some(DetectionMode::Alert), "cleared overrides");
    }

    fn suppression(action: SuppressionAction, rule: &str) -> SuppressionRule {
        SuppressionRule {
            id: "s1".into(),
            rule: rule.into(),
            exe: None,
            cmdline: None,
            user: None,
            parent_exe: None,
            path: None,
            sha256: None,
            remote: None,
            action,
            expires_at: None,
        }
    }

    /// Suppressions are process-global like the rule modes: this test owns
    /// them and uses rule ids no other test classifies.
    #[test]
    fn signed_suppressions_apply_before_local_response() {
        set_suppressions(&[
            suppression(SuppressionAction::Drop, "yara_mem.*"),
            suppression(
                SuppressionAction::SignalOnly,
                "selfprotect.etw_session_stopped",
            ),
            suppression(SuppressionAction::Drop, "deception.*"),
        ]);
        let mut e = finding("yara_mem.injected_marker", 90, Severity::Critical);
        assert_eq!(classify(&mut e), Disposition::Suppressed);

        let mut e = finding("selfprotect.etw_session_stopped", 90, Severity::High);
        assert_eq!(classify(&mut e), Disposition::Forward);
        assert_eq!(mode(&e), Some(DetectionMode::Signal));
        assert!(
            e.severity <= Severity::Low,
            "suppressed to a signal: no response"
        );

        // deception findings can be lowered, never dropped
        let mut e = finding("deception.honeytoken_tamper", 90, Severity::Critical);
        assert_eq!(classify(&mut e), Disposition::Forward);
        assert!(e.severity < Severity::Critical);

        set_suppressions(&[]);
        let mut e = finding("yara_mem.injected_marker", 90, Severity::Critical);
        assert_eq!(classify(&mut e), Disposition::Forward, "cleared");
    }

    #[test]
    fn mitre_fields_are_filled_from_the_table_when_missing() {
        let mut e = finding("selfprotect.etw_session_stopped", 80, Severity::High);
        classify(&mut e);
        let EventData::Detection(d) = &e.data else {
            unreachable!()
        };
        assert!(d.mitre_technique.is_some());
    }

    #[test]
    fn table_parses_and_every_entry_is_consistent() {
        for e in table() {
            assert!(rank(e.base) <= rank(e.max), "{} base above max", e.id);
        }
    }
}
