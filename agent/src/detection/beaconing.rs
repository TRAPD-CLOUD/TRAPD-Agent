//! C2 beaconing detection.
//!
//! Malware command-and-control channels "beacon" home at regular intervals.
//! We track, per destination `(ip, port)`, the timestamps of new connections
//! and flag a beacon when:
//!
//!   * at least [`MIN_SAMPLES`] connections were observed, and
//!   * the inter-arrival intervals are highly regular — the coefficient of
//!     variation (stddev / mean) is below [`MAX_CV`].
//!
//! Low CV = clockwork timing = classic beacon.  Human / app traffic is bursty
//! and irregular, so it has a high CV and is not flagged.  Each destination
//! only fires once per [`ALERT_COOLDOWN_SECS`] window, preventing alert storms.
//!
//! Timestamps are supplied by the caller (monotonic seconds) so this module is
//! pure, deterministic and unit-testable — and reusable by the Windows agent.
//!
//! ## Bounded memory
//!
//! The tracker is long-lived, so it must never grow without limit — otherwise a
//! host that connects to very many unique destinations (a build server, a proxy)
//! or an attacker deliberately fanning out to fresh `ip:port` pairs could exhaust
//! its memory (a DoS against the very agent meant to protect the host).  Two
//! mechanisms keep the destination map bounded:
//!
//!   * a time-based sweep that drops destinations idle longer than
//!     [`IDLE_TTL_SECS`] and alerts older than [`ALERT_COOLDOWN_SECS`], run at
//!     most once per [`PRUNE_INTERVAL_SECS`]; and
//!   * a hard [`MAX_TRACKED`] cap enforced immediately, evicting the
//!     least-recently-seen destinations down to a low-water mark.

use std::collections::HashMap;
use std::collections::VecDeque;

/// Minimum number of connections before a verdict is possible.
const MIN_SAMPLES: usize = 5;
/// Maximum coefficient of variation for the intervals to count as "regular".
const MAX_CV: f64 = 0.20;
/// Ignore beacons slower than this (s) — too sparse to distinguish from noise.
const MAX_INTERVAL_SECS: f64 = 3600.0;
/// Keep at most this many recent samples per destination.
const MAX_SAMPLES: usize = 32;

/// Hard cap on the number of destinations tracked simultaneously.  At a few
/// hundred bytes per entry this bounds the tracker to a few MB even under a
/// deliberate fan-out flood.
const MAX_TRACKED: usize = 16_384;
/// When the cap is exceeded, evict the least-recently-seen destinations down to
/// this low-water mark in a single pass, so eviction is amortised across many
/// insertions rather than paid on every one past the cap.
const EVICT_TARGET: usize = MAX_TRACKED / 8 * 7;
/// Drop a destination that has been silent for this long (s).  It must exceed
/// the slowest beacon we still want to detect ([`MAX_INTERVAL_SECS`]) so that an
/// active but slow beacon is never evicted mid-collection.
const IDLE_TTL_SECS: f64 = 2.0 * MAX_INTERVAL_SECS;
/// After a destination alerts, keep it only this long to suppress duplicate
/// alerts, then forget it.  A destination that resumes beaconing afterwards can
/// re-alert instead of being silenced forever.
const ALERT_COOLDOWN_SECS: f64 = 3600.0;
/// Run the O(n) time-based sweep at most this often (s).  The hard cap is
/// enforced separately and immediately, regardless of this interval.
const PRUNE_INTERVAL_SECS: f64 = 300.0;

/// A confirmed beacon, returned when a destination crosses the threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct BeaconVerdict {
    pub mean_interval_secs: f64,
    pub coefficient_of_variation: f64,
    pub samples: usize,
}

#[derive(Debug, Default)]
struct DestState {
    times: VecDeque<f64>,
    /// Monotonic time of the most recent observation (for idle eviction).
    last_seen: f64,
    alerted: bool,
    /// Monotonic time the alert fired (for cooldown eviction).
    alerted_at: f64,
}

/// Tracks connection cadence per destination.
#[derive(Debug, Default)]
pub struct BeaconTracker {
    dests: HashMap<String, DestState>,
    /// Monotonic time the time-based sweep last ran (`None` until the first
    /// observation), used to rate-limit the O(n) sweep.
    last_prune: Option<f64>,
}

impl BeaconTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a connection to `key` (e.g. `"203.0.113.5:443"`) at monotonic
    /// time `now_secs`.  Returns `Some(verdict)` the first time the destination
    /// is judged to be beaconing.
    pub fn observe(&mut self, key: &str, now_secs: f64) -> Option<BeaconVerdict> {
        let st = self.dests.entry(key.to_string()).or_default();
        st.times.push_back(now_secs);
        st.last_seen = now_secs;
        while st.times.len() > MAX_SAMPLES {
            st.times.pop_front();
        }

        let verdict = if st.alerted || st.times.len() < MIN_SAMPLES {
            None
        } else {
            let intervals = intervals_of(&st.times);
            match mean_and_cv(&intervals) {
                Some((mean, cv)) if mean > 0.0 && mean <= MAX_INTERVAL_SECS && cv <= MAX_CV => {
                    st.alerted = true;
                    st.alerted_at = now_secs;
                    Some(BeaconVerdict {
                        mean_interval_secs: mean,
                        coefficient_of_variation: cv,
                        samples: st.times.len(),
                    })
                }
                _ => None,
            }
        };

        self.prune(now_secs);
        verdict
    }

    /// Number of destinations currently tracked (for diagnostics / metrics).
    #[allow(dead_code)]
    pub fn tracked(&self) -> usize {
        self.dests.len()
    }

    /// Keep the destination map bounded.  Runs the (linear) time-based sweep at
    /// most once per [`PRUNE_INTERVAL_SECS`], but always enforces the hard
    /// [`MAX_TRACKED`] cap so a burst of unique destinations cannot blow past it
    /// between sweeps.
    fn prune(&mut self, now: f64) {
        let over_cap = self.dests.len() > MAX_TRACKED;
        let due = self
            .last_prune
            .is_none_or(|t| now - t >= PRUNE_INTERVAL_SECS);
        if !over_cap && !due {
            return;
        }
        self.last_prune = Some(now);

        // Time-based sweep: forget silent destinations and expired alerts.
        self.dests.retain(|_, st| {
            if st.alerted {
                now - st.alerted_at < ALERT_COOLDOWN_SECS
            } else {
                now - st.last_seen < IDLE_TTL_SECS
            }
        });

        // Hard-cap backstop: evict the least-recently-seen destinations down to
        // the low-water mark.  Only runs while over the cap, so the O(n log n)
        // sort is amortised across the inserts that filled the headroom.
        if self.dests.len() > MAX_TRACKED {
            let mut by_age: Vec<(f64, String)> = self
                .dests
                .iter()
                .map(|(k, st)| (st.last_seen, k.clone()))
                .collect();
            by_age.sort_unstable_by(|a, b| a.0.total_cmp(&b.0));
            let remove = self.dests.len() - EVICT_TARGET;
            for (_, k) in by_age.into_iter().take(remove) {
                self.dests.remove(&k);
            }
        }
    }
}

fn intervals_of(times: &VecDeque<f64>) -> Vec<f64> {
    times
        .iter()
        .zip(times.iter().skip(1))
        .map(|(a, b)| b - a)
        .collect()
}

/// Returns `(mean, coefficient_of_variation)` or `None` if undefined.
fn mean_and_cv(intervals: &[f64]) -> Option<(f64, f64)> {
    if intervals.is_empty() {
        return None;
    }
    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;
    if mean <= 0.0 {
        return None;
    }
    let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let stddev = variance.sqrt();
    Some((mean, stddev / mean))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_regular_beacon() {
        let mut t = BeaconTracker::new();
        let mut verdict = None;
        // Perfectly regular 60s beacon.
        for i in 0..8 {
            verdict = t.observe("203.0.113.5:443", i as f64 * 60.0).or(verdict);
        }
        let v = verdict.expect("should detect beacon");
        assert!((v.mean_interval_secs - 60.0).abs() < 1e-6);
        assert!(v.coefficient_of_variation < 0.20);
    }

    #[test]
    fn ignores_irregular_traffic() {
        let mut t = BeaconTracker::new();
        // Bursty, irregular human-like timings.
        let times = [0.0, 3.0, 4.0, 50.0, 51.0, 400.0, 405.0, 1000.0];
        let mut verdict = None;
        for &ts in &times {
            verdict = t.observe("198.51.100.9:80", ts).or(verdict);
        }
        assert!(verdict.is_none(), "irregular traffic must not be flagged");
    }

    #[test]
    fn needs_minimum_samples() {
        let mut t = BeaconTracker::new();
        // Only 4 samples — below MIN_SAMPLES even though perfectly regular.
        let mut verdict = None;
        for i in 0..4 {
            verdict = t.observe("d:1", i as f64 * 30.0).or(verdict);
        }
        assert!(verdict.is_none());
    }

    #[test]
    fn fires_only_once_per_destination() {
        let mut t = BeaconTracker::new();
        let mut hits = 0;
        for i in 0..20 {
            if t.observe("c2:443", i as f64 * 10.0).is_some() {
                hits += 1;
            }
        }
        assert_eq!(hits, 1, "a destination should alert at most once");
    }

    #[test]
    fn tolerates_small_jitter() {
        let mut t = BeaconTracker::new();
        // 60s beacon with ±2s jitter — CV stays well under threshold.
        let offsets = [0.0, 61.0, 119.0, 181.0, 240.0, 301.0, 359.0];
        let mut verdict = None;
        for &ts in &offsets {
            verdict = t.observe("x:9001", ts).or(verdict);
        }
        assert!(verdict.is_some(), "small jitter should still be a beacon");
    }

    #[test]
    fn tracked_count_stays_within_cap() {
        let mut t = BeaconTracker::new();
        // Fan out to far more unique destinations than the cap, all "active"
        // (distinct, increasing timestamps within the idle TTL) so only the
        // hard cap — not the time sweep — can hold the map down.
        for i in 0..(MAX_TRACKED * 2) {
            t.observe(
                &format!("10.0.{}.{}:443", i / 256, i % 256),
                i as f64 * 0.001,
            );
        }
        assert!(
            t.tracked() <= MAX_TRACKED,
            "tracked {} exceeded cap {MAX_TRACKED}",
            t.tracked()
        );
    }

    #[test]
    fn idle_destinations_age_out() {
        let mut t = BeaconTracker::new();
        t.observe("a:1", 0.0);
        assert_eq!(t.tracked(), 1);
        // Long after the idle TTL, the next observation triggers a sweep that
        // drops the now-silent "a:1" and keeps only the fresh destination.
        t.observe("b:2", IDLE_TTL_SECS + PRUNE_INTERVAL_SECS + 1.0);
        assert_eq!(t.tracked(), 1, "silent destination should be evicted");
    }

    #[test]
    fn alerted_destinations_expire_after_cooldown() {
        let mut t = BeaconTracker::new();
        // Drive "c2:443" to an alert (fires at the MIN_SAMPLES-th sample, t=240).
        let mut alerted = false;
        for i in 0..MIN_SAMPLES {
            alerted |= t.observe("c2:443", i as f64 * 60.0).is_some();
        }
        assert!(alerted, "destination should have alerted");
        assert_eq!(t.tracked(), 1);
        // Well past the cooldown, a sweep forgets the stale alert rather than
        // pinning it forever.
        let later = (MIN_SAMPLES as f64) * 60.0 + ALERT_COOLDOWN_SECS + PRUNE_INTERVAL_SECS + 1.0;
        t.observe("other:1", later);
        assert_eq!(t.tracked(), 1, "expired alert should be evicted");
    }
}
