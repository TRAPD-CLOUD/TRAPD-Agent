//! Liveness beats for components that must keep making progress.
//!
//! A task that is alive but wedged (blocked native call, full channel, stuck
//! consumer) never exits, so exit supervision cannot see it. Components that
//! loop on a timer register an allowed silence and call [`beat`] on every
//! iteration; the health watchdog reports the ones that went quiet through the
//! coverage record shipped with the heartbeat.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Entry {
    max_silence: Duration,
    last_beat: Instant,
}

fn registry() -> &'static Mutex<BTreeMap<&'static str, Entry>> {
    static R: std::sync::OnceLock<Mutex<BTreeMap<&'static str, Entry>>> =
        std::sync::OnceLock::new();
    R.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Start watching `name`: it is stalled once `max_silence` passes without a beat.
pub fn expect(name: &'static str, max_silence: Duration) {
    if let Ok(mut r) = registry().lock() {
        r.insert(
            name,
            Entry {
                max_silence,
                last_beat: Instant::now(),
            },
        );
    }
}

/// Stop watching `name` (it ended on purpose or is restarted by its owner).
pub fn forget(name: &'static str) {
    if let Ok(mut r) = registry().lock() {
        r.remove(name);
    }
}

/// Record progress of `name`. Unregistered names are ignored.
pub fn beat(name: &'static str) {
    if let Ok(mut r) = registry().lock() {
        if let Some(e) = r.get_mut(name) {
            e.last_beat = Instant::now();
        }
    }
}

/// Components whose last beat is older than their allowed silence at `now`.
pub fn stalled_at(now: Instant) -> Vec<String> {
    registry()
        .lock()
        .map(|r| {
            r.iter()
                .filter(|(_, e)| now.saturating_duration_since(e.last_beat) > e.max_silence)
                .map(|(n, _)| (*n).to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silent_component_is_reported_until_it_beats_again() {
        expect("liveness_test_component", Duration::from_secs(30));
        let now = Instant::now();
        assert!(!stalled_at(now).contains(&"liveness_test_component".to_string()));
        let later = now + Duration::from_secs(31);
        assert!(stalled_at(later).contains(&"liveness_test_component".to_string()));
        beat("liveness_test_component");
        let after_beat = Instant::now() + Duration::from_secs(10);
        assert!(!stalled_at(after_beat).contains(&"liveness_test_component".to_string()));
    }

    #[test]
    fn unregistered_beats_are_ignored() {
        beat("liveness_never_registered");
        let far = Instant::now() + Duration::from_secs(3600);
        assert!(!stalled_at(far).contains(&"liveness_never_registered".to_string()));
    }
}
