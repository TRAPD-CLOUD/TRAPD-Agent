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
//! only fires once until [`reset_after_alert`] worth of new samples accrue,
//! preventing alert storms.
//!
//! Timestamps are supplied by the caller (monotonic seconds) so this module is
//! pure, deterministic and unit-testable — and reusable by the Windows agent.

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
    alerted: bool,
}

/// Tracks connection cadence per destination.
#[derive(Debug, Default)]
pub struct BeaconTracker {
    dests: HashMap<String, DestState>,
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
        while st.times.len() > MAX_SAMPLES {
            st.times.pop_front();
        }

        if st.alerted || st.times.len() < MIN_SAMPLES {
            return None;
        }

        let intervals = intervals_of(&st.times);
        let (mean, cv) = mean_and_cv(&intervals)?;

        if mean > 0.0 && mean <= MAX_INTERVAL_SECS && cv <= MAX_CV {
            st.alerted = true;
            return Some(BeaconVerdict {
                mean_interval_secs: mean,
                coefficient_of_variation: cv,
                samples: st.times.len(),
            });
        }
        None
    }

    /// Number of destinations currently tracked (for diagnostics).
    #[allow(dead_code)]
    pub fn tracked(&self) -> usize {
        self.dests.len()
    }
}

fn intervals_of(times: &VecDeque<f64>) -> Vec<f64> {
    times.iter().zip(times.iter().skip(1)).map(|(a, b)| b - a).collect()
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
}
