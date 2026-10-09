//! Finding gate — the single exit every detection passes before it leaves the
//! agent.
//!
//! Two jobs:
//!   * **Suppression**: operator-defined rules (signed config) drop a finding,
//!     demote it to a `signal`, or lower it one severity step. Every decision
//!     except `drop` stays visible: the finding carries the `suppression_id`.
//!   * **Aggregation**: repeats of the same finding (same `dedup_key`) inside
//!     the rule's catalog window are counted, not re-emitted. The first
//!     occurrence leaves immediately; an escalation (higher severity) leaves
//!     immediately; everything else is summarised by an aggregate update that
//!     carries the cumulative `occurrence_count` and `first_seen`/`last_seen`
//!     under the same `dedup_key`, which the backend folds into one signal.
//!
//! Pure and clock-injected, so it is unit-tested without sleeping.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::schema::{AgentEvent, DetectionData, DetectionMode, EventData, Severity};

use super::severity::FLAG_SUPPRESSION_DOWNGRADE;

/// Rule-id prefixes whose findings a suppression may lower but never drop.
/// The backend refuses such suppressions; this is the agent's own guard in
/// case a signed config carries one anyway (defense in depth).
const UNDROPPABLE_PREFIXES: &[&str] = &["deception."];

/// Max distinct findings tracked; the least recently seen is evicted (and its
/// pending aggregate flushed) beyond this.
const MAX_ENTRIES: usize = 8_192;
/// Context (signal-mode) rules may open this many distinct findings per window;
/// further ones fold into one overflow finding per rule. Alerts are never limited.
const SIGNAL_NEW_FINDINGS_PER_WINDOW: u32 = 20;
const SIGNAL_RATE_WINDOW: Duration = Duration::from_secs(600);
/// A long-running storm still reports progress at this cadence.
const PROGRESS_EVERY: Duration = Duration::from_secs(300);

/// What a matching suppression does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionAction {
    /// Drop the finding entirely (counted in metrics only).
    Drop,
    /// Keep it as correlation context; it never alerts on its own.
    SignalOnly,
    /// Lower it by one severity step.
    Downgrade,
}

/// One operator-defined suppression, delivered over the signed config. Every
/// set field must match; globs use shell syntax (`*`, `?`, `[..]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionRule {
    pub id: String,
    /// Glob over `rule_id` (e.g. `persistence.*`).
    pub rule: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Remote endpoint: an IP, a CIDR (`10.0.0.0/8`) or a domain suffix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    pub action: SuppressionAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl SuppressionRule {
    fn matches(&self, d: &DetectionData, now: DateTime<Utc>) -> bool {
        if self.expires_at.is_some_and(|t| t <= now) {
            return false;
        }
        if !glob_match(&self.rule, &d.rule_id) {
            return false;
        }
        let corr = d.correlation.clone().unwrap_or_default();
        let evidence_str = |k: &str| d.evidence.get(k).and_then(|v| v.as_str()).map(String::from);
        let field_ok = |pattern: &Option<String>, value: Option<String>| match pattern {
            None => true,
            Some(p) => value.is_some_and(|v| glob_match(p, &v)),
        };
        let parent_exe = d
            .evidence
            .get("process_lineage")
            .and_then(|l| l.as_array())
            .and_then(|a| a.get(1))
            .and_then(|e| e.get("exe"))
            .and_then(|v| v.as_str())
            .map(String::from);
        field_ok(&self.exe, corr.exe.clone().or_else(|| Some(d.subject.clone())))
            && field_ok(&self.cmdline, evidence_str("cmdline"))
            && field_ok(&self.user, corr.user.clone())
            && field_ok(&self.parent_exe, parent_exe)
            && field_ok(&self.path, corr.file_path.clone().or_else(|| evidence_str("path")))
            && match &self.sha256 {
                None => true,
                Some(h) => corr.exe_sha256.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(h)),
            }
            && match &self.remote {
                None => true,
                Some(r) => remote_match(r, corr.remote_ip.as_deref(), corr.domain.as_deref()),
            }
    }
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
                let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                u32::from(n) & mask == u32::from(i) & mask
            }
            (std::net::IpAddr::V6(n), std::net::IpAddr::V6(i)) if bits <= 128 => {
                let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                u128::from(n) & mask == u128::from(i) & mask
            }
            _ => false,
        };
    }
    if ip == Some(pattern) {
        return true;
    }
    domain.is_some_and(|d| d == pattern || d.ends_with(&format!(".{pattern}")))
}

/// One finding leaving the gate.
#[derive(Debug, Clone)]
pub struct Emitted {
    pub event: AgentEvent,
    /// `true` for an aggregate update of an already-emitted finding. Updates
    /// are persisted and shipped but never re-trigger auto-response.
    pub aggregate: bool,
}

struct Entry {
    template: AgentEvent,
    count: u32,
    emitted_count: u32,
    emitted_severity: Severity,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    window: Duration,
    window_end: Instant,
    last_emit: Instant,
    last_touch: Instant,
}

/// The gate. Not `Sync`; the engine keeps it behind a `Mutex`.
#[derive(Default)]
pub struct FindingGate {
    entries: HashMap<String, Entry>,
    suppressions: Vec<SuppressionRule>,
    /// Per rule: start of the current window and findings opened in it.
    signal_opened: HashMap<String, (Instant, u32)>,
}

impl FindingGate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_suppressions(&mut self, rules: Vec<SuppressionRule>) {
        self.suppressions = rules;
    }

    /// Admit one detection event. Non-`DetectionData` detections (honeytoken
    /// hits) and non-detection events pass through untouched.
    pub fn admit(&mut self, mut event: AgentEvent, now: Instant) -> Vec<Emitted> {
        let EventData::Detection(d) = &mut event.data else {
            return vec![Emitted {
                event,
                aggregate: false,
            }];
        };

        // Shadow-mode rules are counted for the backend's promotion decision
        // and never leave the agent (nor trigger auto-response).
        if d.mode == Some(DetectionMode::Shadow) {
            crate::telemetry::coverage::shadow_hit(&d.rule_id);
            return Vec::new();
        }

        if let Some(rule) = self
            .suppressions
            .iter()
            .find(|r| r.matches(d, event.timestamp))
        {
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
                SuppressionAction::Drop => {
                    crate::telemetry::metrics::metrics().detection_suppressed();
                    return Vec::new();
                }
                SuppressionAction::SignalOnly => {
                    d.mode = Some(DetectionMode::Signal);
                    event.severity = event.severity.min(Severity::Low);
                    d.severity_reasons.push("signal:suppression".into());
                }
                SuppressionAction::Downgrade => {
                    let lowered = step_down(event.severity);
                    let floor = if d.mode == Some(DetectionMode::Signal) {
                        Severity::Info
                    } else {
                        Severity::Low
                    };
                    event.severity = lowered.max(floor);
                    d.context_flags.push(FLAG_SUPPRESSION_DOWNGRADE.into());
                    d.severity_reasons.push(format!("-{FLAG_SUPPRESSION_DOWNGRADE}"));
                }
            }
            set_evidence(&mut d.evidence, "suppression_id", rule.id.clone().into());
        }

        let key = d
            .dedup_key
            .clone()
            .unwrap_or_else(|| format!("{}|{}", d.rule_id, d.subject));
        let key = if d.mode == Some(DetectionMode::Signal)
            && !self.entries.contains_key(&key)
            && self.signal_budget_exhausted(&d.rule_id, now)
        {
            d.severity_reasons.push("signal:rate_limited".into());
            format!("{}:overflow", d.rule_id)
        } else {
            key
        };
        d.dedup_key = Some(key.clone());
        let window = Duration::from_secs(super::catalog::lookup(&d.rule_id).window_s.max(1));
        let ts = event.timestamp;

        let mut out = Vec::new();
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.count = entry.count.saturating_add(1);
            entry.last_seen = ts;
            entry.last_touch = now;
            let escalated = event.severity > entry.emitted_severity;
            if now < entry.window_end && !escalated {
                crate::telemetry::metrics::metrics().detection_aggregated();
                return out;
            }
            // New window or escalation: emit this occurrence carrying the
            // cumulative count, and restart the window from it.
            stamp(&mut event, entry.count, entry.first_seen, ts);
            entry.template = event.clone();
            entry.emitted_count = entry.count;
            entry.emitted_severity = entry.emitted_severity.max(event.severity);
            entry.window_end = now + entry.window;
            entry.last_emit = now;
            out.push(Emitted {
                event,
                aggregate: false,
            });
            return out;
        }

        if self.entries.len() >= MAX_ENTRIES {
            out.extend(self.evict_oldest(now));
        }
        stamp(&mut event, 1, ts, ts);
        self.entries.insert(
            key,
            Entry {
                template: event.clone(),
                count: 1,
                emitted_count: 1,
                emitted_severity: event.severity,
                first_seen: ts,
                last_seen: ts,
                window,
                window_end: now + window,
                last_emit: now,
                last_touch: now,
            },
        );
        out.push(Emitted {
            event,
            aggregate: false,
        });
        out
    }

    /// Counts one more distinct finding of a context rule; true once the
    /// window's budget is spent (the overflow finding itself is not counted).
    fn signal_budget_exhausted(&mut self, rule_id: &str, now: Instant) -> bool {
        let slot = self
            .signal_opened
            .entry(rule_id.to_string())
            .or_insert((now, 0));
        if now.duration_since(slot.0) >= SIGNAL_RATE_WINDOW {
            *slot = (now, 0);
        }
        if slot.1 >= SIGNAL_NEW_FINDINGS_PER_WINDOW {
            return true;
        }
        slot.1 += 1;
        false
    }

    /// Emit aggregate updates for windows that closed (or long storms due a
    /// progress report) and forget findings that have been quiet for a full
    /// window after their last report. `force` flushes everything pending —
    /// used on shutdown so no count is lost.
    pub fn flush(&mut self, now: Instant, force: bool) -> Vec<Emitted> {
        let mut out = Vec::new();
        for entry in self.entries.values_mut() {
            let due = force
                || now >= entry.window_end
                || now.duration_since(entry.last_emit) >= PROGRESS_EVERY;
            if due && entry.count > entry.emitted_count {
                out.push(aggregate_of(entry));
                entry.emitted_count = entry.count;
                entry.last_emit = now;
            }
        }
        self.entries.retain(|_, e| {
            !(e.count == e.emitted_count && now >= e.window_end + e.window)
        });
        out
    }

    fn evict_oldest(&mut self, _now: Instant) -> Vec<Emitted> {
        let Some(key) = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_touch)
            .map(|(k, _)| k.clone())
        else {
            return Vec::new();
        };
        let entry = self.entries.remove(&key).expect("key just found");
        if entry.count > entry.emitted_count {
            vec![aggregate_of(&entry)]
        } else {
            Vec::new()
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn aggregate_of(entry: &Entry) -> Emitted {
    let mut ev = entry.template.clone();
    ev.event_id = uuid::Uuid::new_v4();
    ev.timestamp = Utc::now();
    ev.origin = Some(crate::telemetry::identity::EventOrigin::unsourced());
    stamp(&mut ev, entry.count, entry.first_seen, entry.last_seen);
    crate::telemetry::metrics::metrics().detection_aggregated();
    Emitted {
        event: ev,
        aggregate: true,
    }
}

fn stamp(ev: &mut AgentEvent, count: u32, first: DateTime<Utc>, last: DateTime<Utc>) {
    if let EventData::Detection(d) = &mut ev.data {
        d.occurrence_count = Some(count);
        d.first_seen = Some(first);
        d.last_seen = Some(last);
    }
}

fn step_down(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low | Severity::Info => Severity::Info,
    }
}

fn set_evidence(evidence: &mut serde_json::Value, key: &str, value: serde_json::Value) {
    if evidence.is_null() {
        *evidence = serde_json::json!({});
    }
    if let Some(obj) = evidence.as_object_mut() {
        obj.insert(key.to_string(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{CorrelationKeys, EventAction, EventClass};

    fn det(rule: &str, key: &str, sev: Severity) -> AgentEvent {
        AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Detection,
            EventAction::Detected,
            sev,
            EventData::Detection(Box::new(DetectionData {
                rule_id: rule.into(),
                title: "t".into(),
                category: "c".into(),
                confidence: 80,
                subject: "/usr/bin/cat".into(),
                detail: "d".into(),
                evidence: serde_json::json!({ "cmdline": "cat /etc/shadow" }),
                dedup_key: Some(key.into()),
                correlation: Some(CorrelationKeys {
                    exe: Some("/usr/bin/cat".into()),
                    user: Some("root".into()),
                    remote_ip: Some("10.1.2.3".into()),
                    ..Default::default()
                }),
                ..Default::default()
            })),
        )
    }

    fn count_of(e: &Emitted) -> u32 {
        match &e.event.data {
            EventData::Detection(d) => d.occurrence_count.unwrap(),
            _ => 0,
        }
    }

    #[test]
    fn first_emits_repeats_aggregate() {
        let mut g = FindingGate::new();
        let t0 = Instant::now();
        let first = g.admit(det("creds.shadow_read", "k", Severity::Medium), t0);
        assert_eq!(first.len(), 1);
        assert!(!first[0].aggregate);
        assert_eq!(count_of(&first[0]), 1);
        for i in 1..5 {
            let out = g.admit(
                det("creds.shadow_read", "k", Severity::Medium),
                t0 + Duration::from_secs(i),
            );
            assert!(out.is_empty(), "repeat {i} inside the window is folded");
        }
        // Nothing due yet.
        assert!(g.flush(t0 + Duration::from_secs(10), false).is_empty());
        // Window (1h for creds.shadow_read) closes → one aggregate with count 5.
        let agg = g.flush(t0 + Duration::from_secs(3601), false);
        assert_eq!(agg.len(), 1);
        assert!(agg[0].aggregate);
        assert_eq!(count_of(&agg[0]), 5);
        let EventData::Detection(d) = &agg[0].event.data else {
            panic!()
        };
        assert_eq!(d.dedup_key.as_deref(), Some("k"));
        assert_ne!(agg[0].event.event_id, first[0].event.event_id);
    }

    #[test]
    fn storms_report_progress() {
        let mut g = FindingGate::new();
        let t0 = Instant::now();
        g.admit(det("creds.shadow_read", "k", Severity::Medium), t0);
        g.admit(det("creds.shadow_read", "k", Severity::Medium), t0 + Duration::from_secs(5));
        let out = g.flush(t0 + PROGRESS_EVERY, false);
        assert_eq!(out.len(), 1, "a storm reports every PROGRESS_EVERY");
        assert!(g.flush(t0 + PROGRESS_EVERY + Duration::from_secs(1), false).is_empty());
    }

    #[test]
    fn escalation_passes_through() {
        let mut g = FindingGate::new();
        let t0 = Instant::now();
        g.admit(det("creds.shadow_read", "k", Severity::Medium), t0);
        let out = g.admit(
            det("creds.shadow_read", "k", Severity::High),
            t0 + Duration::from_secs(1),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(count_of(&out[0]), 2);
        assert_eq!(out[0].event.severity, Severity::High);
    }

    #[test]
    fn distinct_keys_are_independent() {
        let mut g = FindingGate::new();
        let t0 = Instant::now();
        assert_eq!(g.admit(det("creds.shadow_read", "a", Severity::Medium), t0).len(), 1);
        assert_eq!(g.admit(det("creds.shadow_read", "b", Severity::Medium), t0).len(), 1);
    }

    #[test]
    fn new_window_emits_with_cumulative_count() {
        let mut g = FindingGate::new();
        let t0 = Instant::now();
        g.admit(det("privesc.gtfobin", "k", Severity::High), t0);
        g.admit(det("privesc.gtfobin", "k", Severity::High), t0 + Duration::from_secs(1));
        // gtfobin window is 10 min; the next occurrence after it is emitted.
        let out = g.admit(
            det("privesc.gtfobin", "k", Severity::High),
            t0 + Duration::from_secs(601),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(count_of(&out[0]), 3);
    }

    #[test]
    fn quiet_entries_are_forgotten() {
        let mut g = FindingGate::new();
        let t0 = Instant::now();
        g.admit(det("privesc.gtfobin", "k", Severity::High), t0);
        g.flush(t0 + Duration::from_secs(1201), false);
        assert_eq!(g.len(), 0);
    }

    #[test]
    fn force_flush_on_shutdown() {
        let mut g = FindingGate::new();
        let t0 = Instant::now();
        g.admit(det("creds.shadow_read", "k", Severity::Medium), t0);
        g.admit(det("creds.shadow_read", "k", Severity::Medium), t0);
        let out = g.flush(t0, true);
        assert_eq!(out.len(), 1);
        assert_eq!(count_of(&out[0]), 2);
    }

    fn rule(action: SuppressionAction) -> SuppressionRule {
        SuppressionRule {
            id: "s1".into(),
            rule: "creds.*".into(),
            exe: Some("/usr/bin/*".into()),
            cmdline: None,
            user: Some("root".into()),
            parent_exe: None,
            path: None,
            sha256: None,
            remote: Some("10.0.0.0/8".into()),
            action,
            expires_at: None,
        }
    }

    #[test]
    fn deception_findings_are_never_dropped() {
        let mut r = rule(SuppressionAction::Drop);
        r.rule = "deception.*".into();
        r.exe = None;
        r.user = None;
        r.remote = None;
        let mut g = FindingGate::new();
        g.set_suppressions(vec![r]);
        let out = g.admit(
            det("deception.honeytoken_tamper", "k", Severity::High),
            Instant::now(),
        );
        assert_eq!(out.len(), 1, "a drop must degrade to a downgrade");
        assert_eq!(out[0].event.severity, Severity::Medium);
    }

    #[test]
    fn suppression_drop() {
        let mut g = FindingGate::new();
        g.set_suppressions(vec![rule(SuppressionAction::Drop)]);
        assert!(g
            .admit(det("creds.shadow_read", "k", Severity::Medium), Instant::now())
            .is_empty());
        // A different rule family is untouched.
        assert_eq!(
            g.admit(det("privesc.gtfobin", "k2", Severity::High), Instant::now())
                .len(),
            1
        );
    }

    #[test]
    fn suppression_signal_only_and_downgrade_are_audited() {
        let mut g = FindingGate::new();
        g.set_suppressions(vec![rule(SuppressionAction::SignalOnly)]);
        let out = g.admit(det("creds.shadow_read", "k", Severity::High), Instant::now());
        let EventData::Detection(d) = &out[0].event.data else {
            panic!()
        };
        assert_eq!(d.mode, Some(DetectionMode::Signal));
        assert_eq!(out[0].event.severity, Severity::Low);
        assert_eq!(d.evidence["suppression_id"], "s1");

        let mut g = FindingGate::new();
        g.set_suppressions(vec![rule(SuppressionAction::Downgrade)]);
        let out = g.admit(det("creds.shadow_read", "k", Severity::High), Instant::now());
        assert_eq!(out[0].event.severity, Severity::Medium);
    }

    #[test]
    fn suppression_fields_must_all_match() {
        let mut r = rule(SuppressionAction::Drop);
        r.user = Some("alice".into());
        let mut g = FindingGate::new();
        g.set_suppressions(vec![r]);
        assert_eq!(
            g.admit(det("creds.shadow_read", "k", Severity::Medium), Instant::now())
                .len(),
            1
        );
    }

    #[test]
    fn expired_suppression_is_ignored() {
        let mut r = rule(SuppressionAction::Drop);
        r.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
        let mut g = FindingGate::new();
        g.set_suppressions(vec![r]);
        assert_eq!(
            g.admit(det("creds.shadow_read", "k", Severity::Medium), Instant::now())
                .len(),
            1
        );
    }

    #[test]
    fn remote_matching() {
        assert!(remote_match("10.0.0.0/8", Some("10.9.9.9"), None));
        assert!(!remote_match("10.0.0.0/8", Some("11.0.0.1"), None));
        assert!(remote_match("1.2.3.4", Some("1.2.3.4"), None));
        assert!(remote_match("example.com", None, Some("api.example.com")));
        assert!(!remote_match("example.com", None, Some("badexample.com")));
    }

    #[test]
    fn honeytoken_and_raw_events_pass_through() {
        let mut g = FindingGate::new();
        let raw = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::System,
            EventAction::Snapshot,
            Severity::Info,
            EventData::EbpfDrops(crate::schema::EbpfDropsData {
                per_program: Default::default(),
                total: 0,
                delta: 0,
            }),
        );
        assert_eq!(g.admit(raw.clone(), Instant::now()).len(), 1);
        assert_eq!(g.admit(raw, Instant::now()).len(), 1);
    }

    fn signal_det(key: &str) -> AgentEvent {
        let mut e = det("anomaly.rare_binary_for_user", key, Severity::Low);
        if let EventData::Detection(d) = &mut e.data {
            d.mode = Some(DetectionMode::Signal);
        }
        e
    }

    #[test]
    fn context_findings_beyond_the_budget_fold_into_one_overflow_finding() {
        let mut g = FindingGate::new();
        let t = Instant::now();
        let mut emitted = 0;
        for i in 0..(SIGNAL_NEW_FINDINGS_PER_WINDOW + 30) {
            emitted += g.admit(signal_det(&format!("k{i}")), t).len();
        }
        // The budget, plus the first overflow finding; the rest only count.
        assert_eq!(emitted as u32, SIGNAL_NEW_FINDINGS_PER_WINDOW + 1);
        let flushed = g.flush(t + Duration::from_secs(7200), true);
        assert!(flushed.iter().any(|e| count_of(e) == 30));
    }

    #[test]
    fn alerts_are_never_rate_limited() {
        let mut g = FindingGate::new();
        let t = Instant::now();
        let mut emitted = 0;
        for i in 0..(SIGNAL_NEW_FINDINGS_PER_WINDOW + 30) {
            emitted += g
                .admit(det("creds.shadow_read", &format!("k{i}"), Severity::High), t)
                .len();
        }
        assert_eq!(emitted as u32, SIGNAL_NEW_FINDINGS_PER_WINDOW + 30);
    }

    #[test]
    fn an_already_open_context_finding_keeps_folding_after_the_budget_is_spent() {
        let mut g = FindingGate::new();
        let t = Instant::now();
        assert_eq!(g.admit(signal_det("first"), t).len(), 1);
        for i in 0..SIGNAL_NEW_FINDINGS_PER_WINDOW {
            g.admit(signal_det(&format!("k{i}")), t);
        }
        // Not a new finding: counted into its own entry, not the overflow one.
        assert!(g.admit(signal_det("first"), t).is_empty());
        let flushed = g.flush(t + Duration::from_secs(7200), true);
        assert!(flushed.iter().any(|e| count_of(e) == 2));
    }

    #[test]
    fn the_budget_renews_with_the_next_window() {
        let mut g = FindingGate::new();
        let t = Instant::now();
        for i in 0..(SIGNAL_NEW_FINDINGS_PER_WINDOW + 5) {
            g.admit(signal_det(&format!("k{i}")), t);
        }
        let later = t + SIGNAL_RATE_WINDOW + Duration::from_secs(1);
        assert_eq!(g.admit(signal_det("fresh"), later).len(), 1);
    }
}
