//! Token-bucket rate limiter used by the log collector.
//!
//! Two layers: a process-wide bucket (protects the pipeline) and an optional
//! per-source bucket (a chatty docker json-file log must not starve auditd).
//! Refill is continuous so a short burst up to `burst` is admitted and a
//! sustained flood is shed as `rate_limit_applied`.

use std::time::Instant;

pub struct TokenBucket {
    rate_per_sec: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_sec: u32) -> Self {
        let rate = rate_per_sec.max(1) as f64;
        // One second of headroom: a restart or logrotate burst is admitted
        // without dropping the first second of the incident.
        Self {
            rate_per_sec: rate,
            burst: rate,
            tokens: rate,
            last: Instant::now(),
        }
    }

    pub fn allow(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate_per_sec).min(self.burst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn admits_up_to_burst_then_rejects() {
        let mut b = TokenBucket::new(5);
        let mut ok = 0;
        for _ in 0..20 {
            if b.allow() {
                ok += 1;
            }
        }
        assert_eq!(ok, 5, "burst equals one second of rate");
    }

    #[test]
    fn refills_over_time() {
        let mut b = TokenBucket::new(10);
        for _ in 0..10 {
            assert!(b.allow());
        }
        assert!(!b.allow());
        b.last = Instant::now() - Duration::from_millis(500);
        assert!(b.allow(), "half a second must restore ~5 tokens");
    }
}
