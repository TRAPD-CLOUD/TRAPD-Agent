//! Runtime self-protection for the Windows service (the Linux agent has a
//! watchdog subprocess; Windows relies on SCM recovery for process death).
//!
//! * [`BinaryIntegrityMonitor`] re-hashes the executable periodically and
//!   raises a detection when it no longer matches the recorded baseline. It
//!   only reports: stopping the sensor on a mismatch would hand an attacker a
//!   one-file way to disable it, and the next start fails closed anyway
//!   (`binary_integrity::check`).
//! * [`run_health_watchdog`] publishes components whose liveness beat stopped
//!   (`telemetry::liveness`) through coverage, so a wedged collector or
//!   consumer is visible to the console.

// Compiled on Linux only so the pure logic is unit-tested there.
#![cfg_attr(not(windows), allow(dead_code))]

use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tracing::{error, info, warn};

use super::binary_integrity::{self, Drift};
use crate::collectors::Collector;
use crate::schema::{AgentEvent, DetectionData, EventAction, EventClass, EventData, Severity};
use crate::telemetry::{coverage, liveness};

const FIRST_CHECK_DELAY: Duration = Duration::from_secs(60);
const CHECK_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// A mismatch is confirmed after this delay, so a replacement caught between
/// "binary swapped" and "baseline rewritten" by the update helper is not
/// mistaken for tampering.
const CONFIRM_DELAY: Duration = Duration::from_secs(30);

/// What the monitor should do after one observation.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Healthy,
    /// Mismatch seen for the first time: look again shortly.
    Recheck,
    /// Mismatch confirmed (and not yet reported for this hash).
    Alert {
        expected: String,
        current: String,
    },
    /// Nothing to do (no baseline, or already reported).
    Quiet,
}

#[derive(Default)]
struct IntegrityTracker {
    pending: Option<String>,
    reported: Option<String>,
}

impl IntegrityTracker {
    fn observe(&mut self, drift: Drift) -> Verdict {
        match drift {
            Drift::Unchanged => {
                self.pending = None;
                self.reported = None;
                Verdict::Healthy
            }
            Drift::NoBaseline => {
                self.pending = None;
                Verdict::Quiet
            }
            Drift::Modified { expected, current } => {
                if self.reported.as_deref() == Some(current.as_str()) {
                    Verdict::Quiet
                } else if self.pending.as_deref() == Some(current.as_str()) {
                    self.pending = None;
                    self.reported = Some(current.clone());
                    Verdict::Alert { expected, current }
                } else {
                    self.pending = Some(current);
                    Verdict::Recheck
                }
            }
        }
    }
}

fn tamper_detection(exe: &str, expected: &str, current: &str) -> DetectionData {
    DetectionData {
        rule_id: "selfprotect.binary_modified".into(),
        title: "TRAPD agent binary modified while running".into(),
        category: "defense_evasion".into(),
        mitre_tactic: Some("TA0005 Defense Evasion".into()),
        mitre_technique: Some("T1562.001".into()),
        confidence: 85,
        subject: exe.into(),
        detail: "The agent executable on disk no longer matches its recorded SHA-256 baseline"
            .into(),
        evidence: serde_json::json!({
            "path": exe,
            "baseline": expected,
            "current": current,
        }),
        ..Default::default()
    }
}

pub struct BinaryIntegrityMonitor;

async fn drift_now() -> Result<Drift> {
    tokio::task::spawn_blocking(binary_integrity::recheck).await?
}

#[async_trait]
impl Collector for BinaryIntegrityMonitor {
    fn name(&self) -> &'static str {
        "BinaryIntegrityMonitor"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut tracker = IntegrityTracker::default();
        let mut wait = FIRST_CHECK_DELAY;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = tx.closed() => return Ok(()),
            }
            wait = CHECK_INTERVAL;
            let mut drift = match drift_now().await {
                Ok(d) => d,
                Err(e) => {
                    warn!(error = %e, "runtime binary integrity check failed");
                    continue;
                }
            };
            loop {
                match tracker.observe(drift) {
                    Verdict::Healthy => {
                        coverage::update(|c| c.binary_integrity = Some(true));
                    }
                    Verdict::Recheck => {
                        tokio::time::sleep(CONFIRM_DELAY).await;
                        match drift_now().await {
                            Ok(d) => {
                                drift = d;
                                continue;
                            }
                            Err(e) => warn!(error = %e, "binary integrity recheck failed"),
                        }
                    }
                    Verdict::Alert { expected, current } => {
                        coverage::update(|c| c.binary_integrity = Some(false));
                        error!(%expected, %current, "agent binary changed while running");
                        let ev = AgentEvent::new(
                            agent_id.clone(),
                            hostname.clone(),
                            EventClass::Detection,
                            EventAction::Detected,
                            Severity::Critical,
                            EventData::Detection(Box::new(tamper_detection(
                                &exe, &expected, &current,
                            ))),
                        );
                        if tx.send(ev).await.is_err() {
                            return Ok(());
                        }
                    }
                    Verdict::Quiet => {}
                }
                break;
            }
        }
    }
}

/// Components added to / removed from the stalled set.
fn stalled_diff(previous: &[String], now: &[String]) -> (Vec<String>, Vec<String>) {
    let added = now
        .iter()
        .filter(|n| !previous.contains(n))
        .cloned()
        .collect();
    let recovered = previous
        .iter()
        .filter(|p| !now.contains(p))
        .cloned()
        .collect();
    (added, recovered)
}

/// Publish stalled components every 15 s. Never returns.
pub async fn run_health_watchdog() {
    let mut ticker = tokio::time::interval(Duration::from_secs(15));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut previous: Vec<String> = Vec::new();
    loop {
        ticker.tick().await;
        let mut now = liveness::stalled_at(Instant::now());
        now.sort();
        let (added, recovered) = stalled_diff(&previous, &now);
        for name in &added {
            warn!(component = %name, "component stalled: no progress within its liveness window");
        }
        for name in &recovered {
            info!(component = %name, "component is making progress again");
        }
        if !added.is_empty() || !recovered.is_empty() {
            coverage::set_stalled_components(now.clone());
        }
        previous = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modified(current: &str) -> Drift {
        Drift::Modified {
            expected: "sha256:good".into(),
            current: current.into(),
        }
    }

    #[test]
    fn mismatch_alerts_only_after_confirmation_and_only_once() {
        let mut t = IntegrityTracker::default();
        assert_eq!(t.observe(modified("sha256:evil")), Verdict::Recheck);
        assert_eq!(
            t.observe(modified("sha256:evil")),
            Verdict::Alert {
                expected: "sha256:good".into(),
                current: "sha256:evil".into()
            }
        );
        assert_eq!(t.observe(modified("sha256:evil")), Verdict::Quiet);
        // A different replacement is a new event.
        assert_eq!(t.observe(modified("sha256:evil2")), Verdict::Recheck);
    }

    #[test]
    fn transient_mismatch_during_an_update_does_not_alert() {
        let mut t = IntegrityTracker::default();
        assert_eq!(t.observe(modified("sha256:new")), Verdict::Recheck);
        // The helper rewrote the baseline in the meantime.
        assert_eq!(t.observe(Drift::Unchanged), Verdict::Healthy);
        assert_eq!(t.observe(modified("sha256:new")), Verdict::Recheck);
    }

    #[test]
    fn missing_baseline_is_not_a_verdict() {
        let mut t = IntegrityTracker::default();
        assert_eq!(t.observe(Drift::NoBaseline), Verdict::Quiet);
    }

    #[test]
    fn detection_names_the_catalogued_rule() {
        let det = tamper_detection("C:\\Program Files\\TRAPD Agent\\trapd-agent.exe", "a", "b");
        assert_eq!(det.rule_id, "selfprotect.binary_modified");
        assert_eq!(det.evidence["current"], "b");
    }

    #[test]
    fn stalled_diff_reports_transitions() {
        let a = vec!["x".to_string(), "y".to_string()];
        let b = vec!["y".to_string(), "z".to_string()];
        let (added, recovered) = stalled_diff(&a, &b);
        assert_eq!(added, ["z"]);
        assert_eq!(recovered, ["x"]);
    }
}
