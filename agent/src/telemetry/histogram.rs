//! Lock-free latency histogram with log-linear buckets.
//!
//! End-to-end latency is an SLO (`p99 < 500 ms` with the backend connected), so
//! it has to be measured on the hot path — which rules out keeping every sample.
//! Instead each observation bumps one atomic counter, and percentiles are
//! reconstructed from the cumulative distribution at read time.
//!
//! ## Bucketing
//!
//! Values below 8 land in their own exact bucket.  Above that the layout is
//! log-linear: four sub-buckets per octave, giving a **worst-case relative error
//! of 25 %** (a reported p99 of 500 ms means the true value is in
//! `(400, 500]`).  That is well inside what a latency SLO needs, and the whole
//! histogram is ~2 KiB of atomics regardless of throughput.
//!
//! Percentiles are reported as the bucket's **upper bound**, so the value is a
//! conservative over-estimate — an SLO that passes here cannot be failing in
//! reality because of bucket rounding.

use std::sync::atomic::{AtomicU64, Ordering};

/// Buckets 0..8 are exact; above that, 4 sub-buckets per octave up to `u64::MAX`.
pub const BUCKET_COUNT: usize = 252;

/// Bucket index for `v`.  Monotonic in `v`, which is what makes the cumulative
/// scan in [`LatencyHistogram::percentile`] valid.
#[inline]
fn bucket_of(v: u64) -> usize {
    if v < 8 {
        return v as usize;
    }
    // msb >= 3 here, so `msb - 2 >= 1` and the shifts below are in range.
    let msb = 63 - v.leading_zeros() as usize;
    let sub = ((v >> (msb - 2)) & 0b11) as usize;
    let idx = 8 + (msb - 3) * 4 + sub;
    idx.min(BUCKET_COUNT - 1)
}

/// Inclusive upper bound of bucket `i` — the value a percentile reports.
fn upper_bound(i: usize) -> u64 {
    if i < 8 {
        return i as u64;
    }
    let k = i - 8;
    let msb = 3 + k / 4;
    let sub = (k % 4) as u64;
    if msb >= 63 {
        return u64::MAX;
    }
    let shift = msb - 2;
    let base = (4 + sub) << shift;
    base + (1u64 << shift) - 1
}

/// A histogram of millisecond observations.
pub struct LatencyHistogram {
    buckets: [AtomicU64; BUCKET_COUNT],
    count: AtomicU64,
    sum: AtomicU64,
    max: AtomicU64,
}

impl LatencyHistogram {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);

    pub const fn new() -> Self {
        Self {
            buckets: [Self::ZERO; BUCKET_COUNT],
            count: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            max: AtomicU64::new(0),
        }
    }

    /// Record one observation, in milliseconds.
    pub fn observe_ms(&self, ms: u64) {
        self.buckets[bucket_of(ms)].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(ms, Ordering::Relaxed);
        self.max.fetch_max(ms, Ordering::Relaxed);
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn sum_ms(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }

    pub fn max_ms(&self) -> u64 {
        self.max.load(Ordering::Relaxed)
    }

    /// Mean observation in milliseconds, or `None` with no samples.
    pub fn mean_ms(&self) -> Option<u64> {
        let n = self.count();
        (n > 0).then(|| self.sum_ms() / n)
    }

    /// Approximate percentile (`q` in `0.0..=1.0`) as the containing bucket's
    /// upper bound.  `None` when nothing has been observed yet.
    pub fn percentile(&self, q: f64) -> Option<u64> {
        let total = self.count();
        if total == 0 {
            return None;
        }
        let q = q.clamp(0.0, 1.0);
        // Rank of the sample we want, 1-based, rounded up.
        let target = ((total as f64) * q).ceil().max(1.0) as u64;
        let mut cumulative = 0u64;
        for i in 0..BUCKET_COUNT {
            cumulative += self.buckets[i].load(Ordering::Relaxed);
            if cumulative >= target {
                return Some(upper_bound(i));
            }
        }
        Some(self.max_ms())
    }

    /// Snapshot of the percentiles the diagnostics command reports.
    pub fn snapshot(&self) -> LatencySnapshot {
        LatencySnapshot {
            count: self.count(),
            p50_ms: self.percentile(0.50),
            p95_ms: self.percentile(0.95),
            p99_ms: self.percentile(0.99),
            max_ms: (self.count() > 0).then(|| self.max_ms()),
        }
    }
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable view of a [`LatencyHistogram`].
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LatencySnapshot {
    pub count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p50_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p95_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p99_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_index_is_monotonic() {
        let mut prev = 0;
        for v in 0..100_000u64 {
            let b = bucket_of(v);
            assert!(b >= prev, "bucket_of must be monotonic (v={v})");
            prev = b;
        }
    }

    #[test]
    fn bucket_index_stays_in_range() {
        for v in [0, 1, 7, 8, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
            assert!(bucket_of(v) < BUCKET_COUNT, "v={v} escaped the bucket array");
        }
    }

    #[test]
    fn value_never_exceeds_its_bucket_upper_bound() {
        // The percentile contract: reported value >= true value.
        for v in (0..200_000u64).step_by(7) {
            let b = bucket_of(v);
            assert!(
                upper_bound(b) >= v,
                "v={v} bucket={b} upper={} must not under-report",
                upper_bound(b)
            );
        }
    }

    #[test]
    fn relative_error_stays_within_25_percent() {
        for v in (8..500_000u64).step_by(13) {
            let ub = upper_bound(bucket_of(v));
            let err = (ub - v) as f64 / v as f64;
            assert!(err <= 0.25, "v={v} ub={ub} error {err} exceeds 25%");
        }
    }

    #[test]
    fn empty_histogram_reports_none() {
        let h = LatencyHistogram::new();
        assert_eq!(h.percentile(0.5), None);
        assert_eq!(h.mean_ms(), None);
        assert_eq!(h.snapshot().count, 0);
        assert_eq!(h.snapshot().p99_ms, None);
    }

    #[test]
    fn uniform_distribution_percentiles_are_close() {
        let h = LatencyHistogram::new();
        for v in 1..=1000u64 {
            h.observe_ms(v);
        }
        let p50 = h.percentile(0.50).unwrap();
        let p99 = h.percentile(0.99).unwrap();
        // Conservative upper bounds, so allow the 25 % over-estimate.
        assert!((500..=625).contains(&p50), "p50={p50} off");
        assert!((990..=1250).contains(&p99), "p99={p99} off");
        assert_eq!(h.count(), 1000);
        assert_eq!(h.max_ms(), 1000);
    }

    #[test]
    fn single_observation_is_reported_at_every_percentile() {
        let h = LatencyHistogram::new();
        h.observe_ms(42);
        for q in [0.0, 0.5, 0.95, 0.99, 1.0] {
            let v = h.percentile(q).unwrap();
            assert!((42..=53).contains(&v), "q={q} gave {v}");
        }
    }

    #[test]
    fn tail_dominates_high_percentiles() {
        // 980 fast + 20 slow: the 990th-smallest sample (p99) falls in the tail.
        let h = LatencyHistogram::new();
        for _ in 0..980 {
            h.observe_ms(10);
        }
        for _ in 0..20 {
            h.observe_ms(5_000);
        }
        assert!(h.percentile(0.50).unwrap() <= 13, "p50 must track the bulk");
        assert!(
            h.percentile(0.99).unwrap() >= 5_000,
            "p99 must surface the slow tail"
        );
    }

    #[test]
    fn percentile_boundary_is_exact_not_rounded_into_the_tail() {
        // Exactly 1 % of samples are slow, so the 990th-smallest — the p99
        // sample — is still the last *fast* one.  Reporting the tail here would
        // mean the percentile is off by one and would fail an SLO spuriously.
        let h = LatencyHistogram::new();
        for _ in 0..990 {
            h.observe_ms(10);
        }
        for _ in 0..10 {
            h.observe_ms(5_000);
        }
        assert!(
            h.percentile(0.99).unwrap() <= 13,
            "p99 of a 990/10 split is the fast value, not the tail"
        );
        assert!(
            h.percentile(1.0).unwrap() >= 5_000,
            "p100 must still reach the tail"
        );
    }

    #[test]
    fn zero_is_observable() {
        let h = LatencyHistogram::new();
        h.observe_ms(0);
        assert_eq!(h.percentile(0.5), Some(0));
        assert_eq!(h.count(), 1);
    }
}
