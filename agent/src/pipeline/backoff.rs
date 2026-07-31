//! Exponential backoff with jitter for redelivery.
//!
//! Two failure modes are being avoided here. Without backoff, a fleet retrying
//! an unreachable backend hammers it continuously and delays its recovery.
//! With backoff but *without* jitter, every agent that lost the connection at
//! the same moment retries at the same moment — a thundering herd that can
//! knock the backend straight back over as it comes up.
//!
//! Delay grows as `base * 2^(attempts-1)`, capped, then has **full jitter**
//! applied: the actual wait is uniform in `[0, delay]`. Full jitter spreads
//! retries far better than a narrow ± band, and its lower expected wait
//! compensates for the wider spread.

use std::time::Duration;

/// First retry delay.
pub const BASE_DELAY: Duration = Duration::from_secs(1);

/// Ceiling on the exponential term. Five minutes keeps a recovering backend
/// from waiting long for the fleet to notice while still shedding most load
/// during a lengthy outage.
pub const MAX_DELAY: Duration = Duration::from_secs(300);

/// Attempts beyond which the delay stops growing. `2^16 * 1s` already exceeds
/// [`MAX_DELAY`]; the cap exists to keep the shift itself in range.
const MAX_SHIFT: u32 = 16;

/// Uncapped exponential delay for `attempts` failures, before jitter.
pub fn delay_for(attempts: u32) -> Duration {
    if attempts == 0 {
        return Duration::ZERO;
    }
    let shift = (attempts - 1).min(MAX_SHIFT);
    let millis = BASE_DELAY
        .as_millis()
        .saturating_mul(1u128 << shift)
        .min(MAX_DELAY.as_millis()) as u64;
    Duration::from_millis(millis)
}

/// [`delay_for`] with full jitter applied — the value to actually wait.
///
/// Returns a duration uniform in `[0, delay_for(attempts)]`.
pub fn jittered_delay(attempts: u32) -> Duration {
    let ceiling = delay_for(attempts);
    if ceiling.is_zero() {
        return Duration::ZERO;
    }
    let span = ceiling.as_millis() as u64;
    Duration::from_millis(random_below(span.saturating_add(1)))
}

/// Uniform random `u64` in `[0, bound)`, or `0` when `bound <= 1`.
///
/// Falls back to a monotonic-clock-derived value if the OS entropy source is
/// unavailable. Jitter is a load-spreading measure, not a security control, so
/// a degraded source is acceptable here — it must merely not be constant.
fn random_below(bound: u64) -> u64 {
    if bound <= 1 {
        return 0;
    }
    let mut buf = [0u8; 8];
    let raw = match getrandom::fill(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf),
        Err(_) => crate::telemetry::identity::monotonic_ns(),
    };
    raw % bound
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_attempts_means_no_wait() {
        assert_eq!(delay_for(0), Duration::ZERO);
        assert_eq!(jittered_delay(0), Duration::ZERO);
    }

    #[test]
    fn delay_doubles_per_attempt() {
        assert_eq!(delay_for(1), Duration::from_secs(1));
        assert_eq!(delay_for(2), Duration::from_secs(2));
        assert_eq!(delay_for(3), Duration::from_secs(4));
        assert_eq!(delay_for(4), Duration::from_secs(8));
        assert_eq!(delay_for(5), Duration::from_secs(16));
    }

    #[test]
    fn delay_is_capped() {
        assert_eq!(delay_for(100), MAX_DELAY);
        assert_eq!(delay_for(u32::MAX), MAX_DELAY, "must not overflow the shift");
    }

    #[test]
    fn delay_never_decreases() {
        let mut prev = Duration::ZERO;
        for attempts in 0..64 {
            let d = delay_for(attempts);
            assert!(d >= prev, "delay went backwards at attempt {attempts}");
            prev = d;
        }
    }

    #[test]
    fn jitter_stays_within_the_exponential_bound() {
        for attempts in 1..12 {
            let ceiling = delay_for(attempts);
            for _ in 0..200 {
                let d = jittered_delay(attempts);
                assert!(d <= ceiling, "jittered {d:?} exceeded ceiling {ceiling:?}");
            }
        }
    }

    #[test]
    fn jitter_actually_varies() {
        // A constant "jitter" would leave the thundering herd intact, so this
        // is the property that matters, not the exact distribution.
        let samples: std::collections::BTreeSet<u128> = (0..200)
            .map(|_| jittered_delay(8).as_millis())
            .collect();
        assert!(
            samples.len() > 50,
            "expected a spread of delays, got {} distinct values",
            samples.len()
        );
    }

    #[test]
    fn jitter_spreads_across_the_range() {
        // With full jitter over a 128 s ceiling, samples should appear in both
        // the lower and upper halves.
        let ceiling = delay_for(8).as_millis();
        let mut low = 0;
        let mut high = 0;
        for _ in 0..400 {
            if jittered_delay(8).as_millis() * 2 < ceiling {
                low += 1;
            } else {
                high += 1;
            }
        }
        assert!(low > 20 && high > 20, "distribution is lopsided: {low}/{high}");
    }

    #[test]
    fn random_below_respects_its_bound() {
        for bound in [2u64, 3, 10, 1000, u64::MAX] {
            for _ in 0..100 {
                assert!(random_below(bound) < bound);
            }
        }
    }

    #[test]
    fn random_below_degenerate_bounds_are_zero() {
        assert_eq!(random_below(0), 0);
        assert_eq!(random_below(1), 0);
    }
}
