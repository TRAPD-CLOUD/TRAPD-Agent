//! Automated response to *local detections* — the policy that turns the agent's
//! detection stream into active EDR action (kill / quarantine / isolate).
//!
//! The agent already raises high-signal local detections (IOC hash hits, reverse
//! shells, IOA attack-chains, ransomware indicators, `setuid(0)` privilege
//! escalation, credential-store access). Until now only honeytoken hits and
//! IoC-policy `ProcessExec` rules were *acted on*; every other detection was
//! emitted and shipped but never enforced. This module closes that gap.
//!
//! It is split into a **pure decision layer** (this file) and the
//! side-effecting executor (on the prevention [`super::engine::Engine`]). The
//! risky part — "should we really kill this process?" — is a pure function with
//! no I/O, so it is exhaustively unit-tested without touching a single PID.
//!
//! Safety posture: auto-response is **opt-in** (`auto_response_enabled`,
//! default off) and gated on severity *and* confidence thresholds plus an
//! allowlist, so a single false positive cannot silently kill a legitimate
//! process. Actions degrade gracefully when no concrete target is known.

use crate::schema::Severity;

/// What the engine should do about a detection, escalating in blast radius.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoAction {
    /// Take no active action (the detection is already emitted upstream).
    None,
    /// Emit a prevention alert only — no process / file / network action.
    Alert,
    /// SIGKILL the offending process.
    Kill,
    /// Kill the process **and** quarantine the offending file.
    Quarantine,
    /// Kill + quarantine + full host network isolation.
    Isolate,
}

impl AutoAction {
    /// Parse the configured action. Unknown values fall back to the safe
    /// `Alert` (never silently escalate to a destructive action on a typo).
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => AutoAction::None,
            "alert" => AutoAction::Alert,
            "kill" => AutoAction::Kill,
            "quarantine" => AutoAction::Quarantine,
            "isolate" | "isolate_network" => AutoAction::Isolate,
            _ => AutoAction::Alert,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AutoAction::None => "none",
            AutoAction::Alert => "alert",
            AutoAction::Kill => "kill",
            AutoAction::Quarantine => "quarantine",
            AutoAction::Isolate => "isolate",
        }
    }
}

/// Total order on severity for threshold comparisons.
fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Parse a configured minimum severity. Unknown values fall back to the
/// conservative `Critical` (act only on the strongest signals).
pub fn parse_severity(s: &str) -> Severity {
    match s.trim().to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        _ => Severity::Critical,
    }
}

/// The concrete things a response can act on, resolved from a detection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Targets {
    /// PID of the offending process, when known and safe to act on (> 1).
    pub pid: Option<i32>,
    /// Absolute path of the offending file, when known (for quarantine).
    pub file_path: Option<String>,
}

/// Resolve the response targets from a detection's `subject` + `evidence`.
///
/// The acting PID is, in priority order: an explicit `evidence.pid`, an
/// `accessor_pid`, or the head of the IOA-injected `process_lineage` (which the
/// detection engine attaches to every process-correlated finding). PID 0/1 are
/// never targets. The file path comes from `evidence.path`/`evidence.file`, or
/// the `subject` when it is itself an absolute path.
pub fn targets_from_detection(subject: &str, evidence: &serde_json::Value) -> Targets {
    let pid = evidence
        .get("pid")
        .and_then(|v| v.as_i64())
        .or_else(|| evidence.get("accessor_pid").and_then(|v| v.as_i64()))
        .or_else(|| {
            evidence
                .get("process_lineage")
                .and_then(|l| l.as_array())
                .and_then(|a| a.first())
                .and_then(|e| e.get("pid"))
                .and_then(|v| v.as_i64())
        })
        .filter(|p| *p > 1)
        .map(|p| p as i32);

    let file_path = evidence
        .get("path")
        .and_then(|v| v.as_str())
        .or_else(|| evidence.get("file").and_then(|v| v.as_str()))
        .map(String::from)
        .or_else(|| subject.starts_with('/').then(|| subject.to_string()));

    Targets { pid, file_path }
}

/// The outcome of the pure decision: which action to take and why (audited).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: AutoAction,
    pub reason: String,
}

impl Decision {
    fn skip(reason: impl Into<String>) -> Self {
        Decision { action: AutoAction::None, reason: reason.into() }
    }
}

/// Decide what to do about a detection — a pure function (no I/O).
///
/// Returns [`AutoAction::None`] unless auto-response is enabled, the event meets
/// the severity *and* confidence thresholds, and the rule is not allowlisted.
/// The configured action is then **clamped** to what the known targets allow:
/// `Kill`/`Quarantine` without a target PID degrade to `Alert`, and
/// `Quarantine` without a file path degrades to `Kill`.
#[allow(clippy::too_many_arguments)]
pub fn decide(
    enabled: bool,
    configured: AutoAction,
    min_severity: Severity,
    min_confidence: u8,
    allowlist: &[String],
    event_severity: Severity,
    rule_id: &str,
    category: &str,
    confidence: u8,
    targets: &Targets,
) -> Decision {
    if !enabled {
        return Decision::skip("auto-response disabled");
    }
    if configured == AutoAction::None {
        return Decision::skip("configured action is none");
    }
    if severity_rank(event_severity) < severity_rank(min_severity) {
        return Decision::skip(format!(
            "severity {:?} below threshold {:?}",
            event_severity, min_severity
        ));
    }
    if confidence < min_confidence {
        return Decision::skip(format!(
            "confidence {} below threshold {}",
            confidence, min_confidence
        ));
    }
    if allowlist
        .iter()
        .any(|a| a.eq_ignore_ascii_case(rule_id) || a.eq_ignore_ascii_case(category))
    {
        return Decision::skip("rule allowlisted");
    }

    let has_pid = targets.pid.is_some();
    let has_path = targets.file_path.is_some();

    // Clamp the configured action to what the available targets support.
    let action = match configured {
        AutoAction::None | AutoAction::Alert => AutoAction::Alert,
        // Network isolation needs no per-process target; keep it regardless.
        AutoAction::Isolate => AutoAction::Isolate,
        AutoAction::Quarantine => {
            if has_path {
                AutoAction::Quarantine
            } else if has_pid {
                AutoAction::Kill
            } else {
                AutoAction::Alert
            }
        }
        AutoAction::Kill => {
            if has_pid {
                AutoAction::Kill
            } else {
                AutoAction::Alert
            }
        }
    };

    let reason = if action != configured {
        format!("{} (clamped from {})", action.as_str(), configured.as_str())
    } else {
        format!("{} per policy", action.as_str())
    };
    Decision { action, reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn t(pid: Option<i32>, path: Option<&str>) -> Targets {
        Targets { pid, file_path: path.map(String::from) }
    }

    #[test]
    fn parse_action_is_safe_on_garbage() {
        assert_eq!(AutoAction::parse("kill"), AutoAction::Kill);
        assert_eq!(AutoAction::parse("ISOLATE"), AutoAction::Isolate);
        assert_eq!(AutoAction::parse("quarantine"), AutoAction::Quarantine);
        assert_eq!(AutoAction::parse("none"), AutoAction::None);
        assert_eq!(AutoAction::parse("wat"), AutoAction::Alert);
    }

    #[test]
    fn disabled_never_acts() {
        let d = decide(
            false, AutoAction::Kill, Severity::Critical, 90, &[],
            Severity::Critical, "ioc.process_hash", "ioc", 95, &t(Some(42), None),
        );
        assert_eq!(d.action, AutoAction::None);
    }

    #[test]
    fn below_severity_threshold_skips() {
        let d = decide(
            true, AutoAction::Kill, Severity::Critical, 90, &[],
            Severity::High, "x", "y", 99, &t(Some(42), None),
        );
        assert_eq!(d.action, AutoAction::None);
    }

    #[test]
    fn below_confidence_threshold_skips() {
        let d = decide(
            true, AutoAction::Kill, Severity::High, 90, &[],
            Severity::Critical, "x", "y", 80, &t(Some(42), None),
        );
        assert_eq!(d.action, AutoAction::None);
    }

    #[test]
    fn allowlist_by_rule_id_or_category_skips() {
        let by_rule = decide(
            true, AutoAction::Kill, Severity::High, 0, &["lolbin.shell".into()],
            Severity::Critical, "lolbin.shell", "lolbin", 99, &t(Some(42), None),
        );
        assert_eq!(by_rule.action, AutoAction::None);

        let by_cat = decide(
            true, AutoAction::Kill, Severity::High, 0, &["IOC".into()],
            Severity::Critical, "ioc.process_hash", "ioc", 99, &t(Some(42), None),
        );
        assert_eq!(by_cat.action, AutoAction::None);
    }

    #[test]
    fn kill_requires_pid_else_alerts() {
        let with_pid = decide(
            true, AutoAction::Kill, Severity::Critical, 90, &[],
            Severity::Critical, "x", "y", 95, &t(Some(42), None),
        );
        assert_eq!(with_pid.action, AutoAction::Kill);

        let no_pid = decide(
            true, AutoAction::Kill, Severity::Critical, 90, &[],
            Severity::Critical, "x", "y", 95, &t(None, None),
        );
        assert_eq!(no_pid.action, AutoAction::Alert);
    }

    #[test]
    fn quarantine_without_path_degrades_to_kill() {
        let d = decide(
            true, AutoAction::Quarantine, Severity::Critical, 90, &[],
            Severity::Critical, "ransomware.high_entropy", "ransomware", 95,
            &t(Some(42), None),
        );
        assert_eq!(d.action, AutoAction::Kill);
    }

    #[test]
    fn quarantine_with_path_stays_quarantine() {
        let d = decide(
            true, AutoAction::Quarantine, Severity::Critical, 90, &[],
            Severity::Critical, "ransomware.high_entropy", "ransomware", 95,
            &t(Some(42), Some("/tmp/evil")),
        );
        assert_eq!(d.action, AutoAction::Quarantine);
    }

    #[test]
    fn isolate_keeps_even_without_target() {
        let d = decide(
            true, AutoAction::Isolate, Severity::Critical, 90, &[],
            Severity::Critical, "ioc.network_ip", "ioc", 95, &t(None, None),
        );
        assert_eq!(d.action, AutoAction::Isolate);
    }

    #[test]
    fn targets_prefers_explicit_pid_then_lineage() {
        let ev = json!({ "pid": 4242, "process_lineage": [{ "pid": 9 }] });
        assert_eq!(targets_from_detection("/usr/bin/curl", &ev).pid, Some(4242));

        let ev2 = json!({ "process_lineage": [{ "pid": 777, "comm": "bash" }] });
        let tg = targets_from_detection("bash", &ev2);
        assert_eq!(tg.pid, Some(777));
        assert_eq!(tg.file_path, None);
    }

    #[test]
    fn targets_never_takes_pid_0_or_1() {
        let ev = json!({ "pid": 1 });
        assert_eq!(targets_from_detection("init", &ev).pid, None);
    }

    #[test]
    fn targets_path_from_evidence_or_absolute_subject() {
        let from_ev = targets_from_detection("something", &json!({ "path": "/etc/shadow" }));
        assert_eq!(from_ev.file_path.as_deref(), Some("/etc/shadow"));

        let from_subject = targets_from_detection("/tmp/payload", &json!({}));
        assert_eq!(from_subject.file_path.as_deref(), Some("/tmp/payload"));

        let none = targets_from_detection("curl", &json!({}));
        assert_eq!(none.file_path, None);
    }
}
