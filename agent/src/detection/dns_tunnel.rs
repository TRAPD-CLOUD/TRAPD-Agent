//! DNS tunneling detection.
//!
//! Data-exfiltration and C2 channels tunneled over DNS encode payload bytes
//! into the queried name: long, high-cardinality sub-domain labels are sent as
//! a rapid burst of look-ups under one parent (registrable) domain.  We track,
//! per registrable domain, a sliding [`WINDOW_SECS`] window of look-ups and
//! flag tunneling when either:
//!
//!   * the average sub-domain label length exceeds [`MAX_AVG_LABEL_LEN`]
//!     (encoded payload — the registrable domain's own labels are excluded so a
//!     normal short TLD/SLD does not dilute the signal), or
//!   * the look-up rate exceeds [`MAX_QUERIES_PER_MIN`] (high-throughput tunnel).
//!
//! Each domain only fires once (until evicted) to avoid alert storms.
//!
//! Timestamps are supplied by the caller (monotonic seconds) so this module is
//! pure, deterministic and unit-testable — and reusable by the Windows agent,
//! exactly like [`super::beaconing`].

use std::collections::HashMap;
use std::collections::VecDeque;

/// Length of the sliding window, in seconds.
const WINDOW_SECS: f64 = 60.0;
/// Average sub-domain label length (chars) above which a domain looks like an
/// encoded tunnel payload.
const MAX_AVG_LABEL_LEN: f64 = 45.0;
/// Look-ups per window above which a domain looks like a high-throughput tunnel.
const MAX_QUERIES_PER_MIN: usize = 100;

/// A confirmed DNS-tunneling verdict, returned the first time a domain crosses
/// either threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct TunnelVerdict {
    pub domain: String,
    pub queries_per_min: usize,
    pub avg_label_length: f64,
    pub reason: &'static str,
}

#[derive(Debug, Default)]
struct DomainState {
    /// `(timestamp, sum_of_label_lengths, label_count)` for each look-up.
    queries: VecDeque<(f64, usize, usize)>,
    alerted: bool,
}

/// Tracks per-domain look-up cadence and label statistics.
#[derive(Debug, Default)]
pub struct DnsTunnelTracker {
    domains: HashMap<String, DomainState>,
}

impl DnsTunnelTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a DNS look-up for `name` (e.g. a fully-qualified query name) at
    /// monotonic time `now_secs`.  Look-ups are grouped by their registrable
    /// (last two labels) domain.  Returns `Some(verdict)` the first time that
    /// domain is judged to be tunneling.
    pub fn observe(&mut self, name: &str, now_secs: f64) -> Option<TunnelVerdict> {
        let (sum_len, n_labels) = label_stats(name);
        let key = registrable_domain(name);

        let st = self.domains.entry(key.clone()).or_default();
        st.queries.push_back((now_secs, sum_len, n_labels));

        // Drop look-ups that have aged out of the window.
        while st
            .queries
            .front()
            .is_some_and(|&(t, _, _)| now_secs - t > WINDOW_SECS)
        {
            st.queries.pop_front();
        }

        if st.alerted {
            return None;
        }

        let queries_per_min = st.queries.len();
        let total_len: usize = st.queries.iter().map(|&(_, s, _)| s).sum();
        let total_labels: usize = st.queries.iter().map(|&(_, _, c)| c).sum();
        let avg_label_length = if total_labels > 0 {
            total_len as f64 / total_labels as f64
        } else {
            0.0
        };

        let reason = if avg_label_length > MAX_AVG_LABEL_LEN {
            Some("avg_label_length")
        } else if queries_per_min > MAX_QUERIES_PER_MIN {
            Some("queries_per_min")
        } else {
            None
        };

        if let Some(reason) = reason {
            st.alerted = true;
            return Some(TunnelVerdict {
                domain: key,
                queries_per_min,
                avg_label_length,
                reason,
            });
        }
        None
    }

    /// Number of domains currently tracked (for diagnostics).
    #[allow(dead_code)]
    pub fn tracked(&self) -> usize {
        self.domains.len()
    }
}

/// Sum of label lengths and label count for the *sub-domain* portion of a DNS
/// name — every label except the last two (the registrable domain).  Names with
/// no sub-domain (≤ 2 labels) contribute `(0, 0)`, so a bare `example.com` never
/// trips the label-length threshold; the look-up still counts toward the rate.
fn label_stats(name: &str) -> (usize, usize) {
    let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return (0, 0);
    }
    labels[..labels.len() - 2]
        .iter()
        .fold((0usize, 0usize), |(sum, n), l| (sum + l.len(), n + 1))
}

/// The registrable domain — the last two labels (e.g. `evil.com` from
/// `aGVsbG8.payload.evil.com`).  Falls back to the whole name when it has
/// fewer than two labels.
fn registrable_domain(name: &str) -> String {
    let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() >= 2 {
        format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1])
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_long_label_payload() {
        let mut t = DnsTunnelTracker::new();
        // A single look-up whose sub-domain label is an encoded payload.
        let name = format!("{}.evil.com", "a".repeat(60));
        let v = t.observe(&name, 0.0).expect("long labels should be flagged");
        assert_eq!(v.reason, "avg_label_length");
        assert_eq!(v.domain, "evil.com");
        assert!(v.avg_label_length > 45.0);
    }

    #[test]
    fn flags_high_query_volume() {
        let mut t = DnsTunnelTracker::new();
        let mut verdict = None;
        // 150 short look-ups under one domain within the window.
        for i in 0..150 {
            let name = format!("h{i}.tunnel.net");
            verdict = t.observe(&name, i as f64 * 0.1).or(verdict);
        }
        let v = verdict.expect("a burst of look-ups should be flagged");
        assert_eq!(v.reason, "queries_per_min");
        assert_eq!(v.domain, "tunnel.net");
    }

    #[test]
    fn ignores_normal_dns_traffic() {
        let mut t = DnsTunnelTracker::new();
        // A handful of normal look-ups with short labels — nothing to flag.
        let names = ["www.example.com", "api.example.com", "cdn.example.com"];
        let mut verdict = None;
        for (i, n) in names.iter().enumerate() {
            verdict = t.observe(n, i as f64 * 5.0).or(verdict);
        }
        assert!(verdict.is_none(), "benign DNS must not be flagged");
    }

    #[test]
    fn old_queries_age_out_of_window() {
        let mut t = DnsTunnelTracker::new();
        // Spread 80 look-ups across well over a minute — never >100 in any
        // 60s window, so the rate threshold is never crossed.
        let mut verdict = None;
        for i in 0..80 {
            let name = format!("h{i}.slow.net");
            verdict = t.observe(&name, i as f64 * 2.0).or(verdict);
        }
        assert!(verdict.is_none(), "spread-out look-ups must not be flagged");
    }

    #[test]
    fn fires_only_once_per_domain() {
        let mut t = DnsTunnelTracker::new();
        let mut hits = 0;
        for i in 0..300 {
            let name = format!("h{i}.c2.org");
            if t.observe(&name, i as f64 * 0.05).is_some() {
                hits += 1;
            }
        }
        assert_eq!(hits, 1, "a domain should alert at most once");
    }
}
