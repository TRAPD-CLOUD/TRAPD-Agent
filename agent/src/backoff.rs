//! Shared capped-exponential-backoff-with-jitter helper for retry loops.
//!
//! Originally lived only in [`crate::enrollment`]; factored out so
//! [`crate::transport`]'s post-failure flush retry can reuse the exact same
//! (correct) logic instead of hammering the backend on a fixed ticker.

use std::time::Duration;

/// Capped exponential backoff: `base * 2^(attempt-1)`, capped at `max`, plus
/// up to ~1s of CSPRNG jitter so a fleet of agents retrying together (e.g.
/// after a shared backend outage) does not clump into the same sub-second
/// retry window. `attempt` is 1-based (the first retry is `attempt == 1`).
pub fn backoff(attempt: u32, base: Duration, max: Duration) -> Duration {
    let exp = base.saturating_mul(2u32.saturating_pow(attempt.saturating_sub(1).min(16)));
    let capped = exp.min(max);
    capped + Duration::from_millis(jitter_ms())
}

/// Uniform-ish jitter in `[0, 1000)` ms from the OS CSPRNG, falling back to
/// the wall clock if the RNG is somehow unavailable (never fails the
/// backoff).
fn jitter_ms() -> u64 {
    let mut buf = [0u8; 8];
    let raw = match getrandom::fill(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf),
        Err(_) => now_nanos() as u64,
    };
    raw % 1000
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_exponentially_before_the_cap() {
        let base = Duration::from_secs(2);
        let max = Duration::from_secs(600);
        // Strip jitter (< 1s) for the exponential-growth comparison by using a
        // base large enough that the doubling dominates.
        let d1 = backoff(1, base, max);
        let d2 = backoff(2, base, max);
        let d3 = backoff(3, base, max);
        assert!(d1 >= base && d1 < base + Duration::from_secs(1));
        assert!(d2 >= base * 2 && d2 < base * 2 + Duration::from_secs(1));
        assert!(d3 >= base * 4 && d3 < base * 4 + Duration::from_secs(1));
    }

    #[test]
    fn caps_at_max_and_never_exceeds_max_plus_jitter() {
        let base = Duration::from_secs(2);
        let max = Duration::from_secs(60);
        for attempt in [10, 20, 100, u32::MAX] {
            let d = backoff(attempt, base, max);
            assert!(
                d >= max && d < max + Duration::from_secs(1),
                "attempt {attempt}: {d:?} must be within [max, max+1s)"
            );
        }
    }

    #[test]
    fn jitter_ms_stays_in_expected_range() {
        for _ in 0..100 {
            let ms = jitter_ms();
            assert!(ms < 1000, "jitter {ms} must be < 1000ms");
        }
    }
}
