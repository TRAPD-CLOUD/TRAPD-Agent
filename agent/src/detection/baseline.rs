//! Statistical behavioural baseline — local anomaly detection without a backend.
//!
//! Two complementary, low-noise analytics learn "normal" online and only score
//! once a baseline has formed:
//!
//!   * **Per-user binary novelty** — per user, the set of executables ever
//!     observed. A brand-new binary for an established user (e.g. `www-data`
//!     suddenly running `/tmp/x`) is a classic abuse signal. Novelty is only
//!     raised once the user has a stable history, so start-up churn does not
//!     flood findings.
//!   * **Per-user exec-rate z-score** — an EWMA mean/variance of each user's
//!     per-minute process-creation count; a burst far above the learned mean
//!     (high z-score) flags scripted/automated activity.
//!
//! Everything is bounded (entity caps) and allocation-light, so it runs inline
//! in the detection path.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::schema::DetectionData;

/// Max distinct parents / users tracked (memory bound).
const MAX_ENTITIES: usize = 8192;
/// Distinct children a parent must have shown before novelty is trusted.
const NOVELTY_WARMUP: usize = 3;
/// Max children remembered per parent.
const MAX_CHILDREN: usize = 64;
/// Exec-rate samples (minutes) needed before z-scoring.
const RATE_WARMUP: u32 = 5;
/// Z-score above which an exec-rate burst is anomalous.
const RATE_Z_THRESHOLD: f64 = 4.0;

/// Exponentially-weighted rolling mean + variance (Welford-style EWMA).
#[derive(Debug, Clone)]
struct Ewma {
    mean: f64,
    var: f64,
    count: u32,
    alpha: f64,
}

impl Ewma {
    fn new(alpha: f64) -> Self {
        Self {
            mean: 0.0,
            var: 0.0,
            count: 0,
            alpha,
        }
    }

    /// Z-score of `x` against the current distribution (0 until warmed up).
    ///
    /// Count data tends to be Poisson-like, so the standard deviation is floored
    /// at `sqrt(mean)`: this prevents a perfectly-constant baseline (measured
    /// variance ≈ 0) from making every deviation infinite, while still scaling
    /// the tolerance with the baseline volume (a high-traffic user needs a much
    /// bigger absolute jump to look anomalous).
    fn zscore(&self, x: f64) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        let std = self.var.sqrt().max(self.mean.max(1.0).sqrt());
        (x - self.mean) / std
    }

    fn update(&mut self, x: f64) {
        if self.count == 0 {
            self.mean = x;
            self.var = 0.0;
        } else {
            let diff = x - self.mean;
            let incr = self.alpha * diff;
            self.mean += incr;
            // EWMA variance (West, 1979).
            self.var = (1.0 - self.alpha) * (self.var + diff * incr);
        }
        self.count = self.count.saturating_add(1);
    }
}

/// Per-user exec-rate accounting over a sliding one-minute window.
#[derive(Debug, Clone)]
struct RateProfile {
    window_start: Instant,
    window_count: u32,
    stat: Ewma,
}

pub struct BaselineEngine {
    /// user → set of executables ever seen.
    binaries: HashMap<String, HashSet<String>>,
    /// user → exec-rate profile.
    rates: HashMap<String, RateProfile>,
}

impl BaselineEngine {
    pub fn new() -> Self {
        Self {
            binaries: HashMap::new(),
            rates: HashMap::new(),
        }
    }

    /// Observe one process execution. Returns at most one anomaly detection.
    pub fn observe_exec(&mut self, user: &str, exe: &str, now: Instant) -> Option<DetectionData> {
        let novelty = self.check_novelty(user, exe);
        // Rate is always updated (learning) but only one finding per event, so
        // novelty (more specific) wins over a rate burst.
        let rate = self.update_rate(user, now);
        novelty.or(rate)
    }

    fn check_novelty(&mut self, user: &str, exe: &str) -> Option<DetectionData> {
        if user.is_empty() || exe.is_empty() {
            return None;
        }
        if self.binaries.len() >= MAX_ENTITIES && !self.binaries.contains_key(user) {
            return None; // bound reached; do not learn new users
        }
        let set = self.binaries.entry(user.to_string()).or_default();
        let known = set.contains(exe);
        let warmed = set.len() >= NOVELTY_WARMUP;
        if !known && set.len() < MAX_CHILDREN {
            set.insert(exe.to_string());
        }
        if known || !warmed {
            return None;
        }
        Some(DetectionData {
            rule_id: "anomaly.rare_binary_for_user".into(),
            title: "Anomalous binary for user".into(),
            category: "anomaly".into(),
            mitre_tactic: Some("TA0002 Execution".into()),
            mitre_technique: Some("T1059".into()),
            confidence: 55,
            subject: format!("{user}: {exe}"),
            detail: format!(
                "User '{user}' executed '{exe}', never seen in its learned baseline \
                 of {} distinct binaries",
                self.binaries.get(user).map(|s| s.len()).unwrap_or(0)
            ),
            evidence: serde_json::json!({
                "user": user,
                "exe": exe,
                "baseline_kind": "per_user_binary_novelty",
            }),
        })
    }

    fn update_rate(&mut self, user: &str, now: Instant) -> Option<DetectionData> {
        if user.is_empty() {
            return None;
        }
        if self.rates.len() >= MAX_ENTITIES && !self.rates.contains_key(user) {
            return None;
        }
        let prof = self
            .rates
            .entry(user.to_string())
            .or_insert_with(|| RateProfile {
                window_start: now,
                window_count: 0,
                stat: Ewma::new(0.3),
            });

        // Same minute → just count.
        if now.duration_since(prof.window_start) < Duration::from_secs(60) {
            prof.window_count += 1;
            return None;
        }

        // Minute rolled over: score the completed window, then fold it in.
        let completed = prof.window_count as f64;
        let z = prof.stat.zscore(completed);
        let warmed = prof.stat.count >= RATE_WARMUP;
        prof.stat.update(completed);
        prof.window_start = now;
        prof.window_count = 1;

        if warmed && z >= RATE_Z_THRESHOLD {
            return Some(DetectionData {
                rule_id: "anomaly.exec_rate_spike".into(),
                title: "Anomalous process-creation rate for user".into(),
                category: "anomaly".into(),
                mitre_tactic: Some("TA0002 Execution".into()),
                mitre_technique: None,
                confidence: 50,
                subject: user.to_string(),
                detail: format!(
                    "User '{user}' created {completed:.0} processes in the last minute \
                     (z-score {z:.1} above the learned baseline mean {:.1})",
                    prof.stat.mean
                ),
                evidence: serde_json::json!({
                    "user": user,
                    "window_count": completed,
                    "zscore": z,
                    "baseline_kind": "exec_rate",
                }),
            });
        }
        None
    }
}

impl Default for BaselineEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ewma_zscore_is_zero_until_warmed() {
        let mut e = Ewma::new(0.3);
        assert_eq!(e.zscore(10.0), 0.0);
        e.update(5.0);
        // One sample: variance ~0 → still no meaningful z.
        assert_eq!(e.zscore(100.0), 0.0);
    }

    #[test]
    fn novelty_needs_warmup_then_flags_new_binary() {
        let mut b = BaselineEngine::new();
        let t = Instant::now();
        // Warm up the user's binary set with three known executables.
        for c in ["/bin/ls", "/bin/cat", "/usr/bin/grep"] {
            assert!(b.observe_exec("alice", c, t).is_none());
        }
        // A repeat of a known binary is silent.
        assert!(b.observe_exec("alice", "/bin/ls", t).is_none());
        // A brand-new binary for the now-warmed user is anomalous.
        let d = b
            .observe_exec("alice", "/tmp/x", t)
            .expect("novel binary flagged");
        assert_eq!(d.rule_id, "anomaly.rare_binary_for_user");
    }

    #[test]
    fn novelty_silent_before_warmup() {
        let mut b = BaselineEngine::new();
        let t = Instant::now();
        // First-ever binary for a user: learning, never an alert.
        assert!(b.observe_exec("www", "/usr/sbin/nginx", t).is_none());
    }

    #[test]
    fn exec_rate_spike_flags_burst_after_baseline() {
        let mut b = BaselineEngine::new();
        let mut t = Instant::now();
        // Establish a calm baseline: ~2 execs/minute for several minutes.
        for _ in 0..8 {
            b.update_rate("svc", t);
            b.update_rate("svc", t);
            t += Duration::from_secs(61); // roll the window
        }
        // Now a large burst in one window.
        for _ in 0..200 {
            b.update_rate("svc", t);
        }
        t += Duration::from_secs(61);
        let d = b.update_rate("svc", t);
        assert!(
            d.map(|d| d.rule_id == "anomaly.exec_rate_spike")
                .unwrap_or(false),
            "a 200/min burst over a 2/min baseline must be flagged"
        );
    }
}
