//! Announcements of the agent's own, deliberate touches of its decoy files.
//!
//! The agent's living-decoy upkeep changes the attributes of a token (its access time). The
//! token-FIM watcher reports any attribute change of a token as tamper, and inotify says nothing
//! about who made the change. So the upkeep announces the touch just before it happens, and the
//! watcher consults this list. Only the exact path, only briefly, only for attribute changes: a
//! content change is never covered, and an announcement that was not made cannot silence anything.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long an announcement covers the attribute change it announces.
pub const WINDOW: Duration = Duration::from_secs(3);
const MAX_ENTRIES: usize = 64;

static EXPECTED: Mutex<Vec<(String, Instant)>> = Mutex::new(Vec::new());

fn lock() -> std::sync::MutexGuard<'static, Vec<(String, Instant)>> {
    EXPECTED.lock().unwrap_or_else(|e| e.into_inner())
}

/// The agent is about to change the attributes of `path` itself.
pub fn expect(path: &str) {
    let now = Instant::now();
    let mut list = lock();
    list.retain(|(_, until)| *until > now);
    if list.len() >= MAX_ENTRIES {
        list.remove(0);
    }
    list.push((path.to_string(), now + WINDOW));
}

/// Whether an attribute change of `path` happening now is the agent's own announced touch.
pub fn is_expected(path: &str) -> bool {
    let now = Instant::now();
    lock().iter().any(|(p, until)| p == path && *until > now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_announced_path_is_covered_and_only_briefly() {
        assert!(!is_expected("/never/announced"));
        expect("/root/.pgpass");
        assert!(is_expected("/root/.pgpass"));
        assert!(
            !is_expected("/root/.pgpass.bak"),
            "another path is not covered"
        );
        // Expiry is by clock; here only that the entry list stays bounded.
        for i in 0..(MAX_ENTRIES * 2) {
            expect(&format!("/p/{i}"));
        }
        assert!(lock().len() <= MAX_ENTRIES);
    }
}
