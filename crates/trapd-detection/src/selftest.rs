//! In-process registry of the agent's own honeytoken self-test.
//!
//! A self-test makes a child process of the agent open one deployed token so the
//! whole alarm path (sensor, agent, gateway, backend) is proven end to end. The
//! sensors consult this registry when they build the access event: an access by
//! exactly the armed child to exactly the armed path is marked `selftest`, so the
//! backend does not alert on it. Nothing a monitored process does can set the
//! mark: it comes from this registry, which only the agent writes.
//!
//! One test at a time; it expires on its own, so a test that never runs cannot
//! leave a window open.

use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct Pending {
    pid: i32,
    path: String,
    deadline: Instant,
    observed: bool,
}

/// A finished test whose late sensor events may still arrive.
#[derive(Debug)]
struct Retained {
    pid: i32,
    path: String,
    until: Instant,
}

/// Sensor events are built in userspace some time after the kernel saw the access, and a busy host
/// can delay them well past the end of the test. A finished test therefore stays attributable for
/// this long. Bounded, tied to the exact pid and path, so it cannot mask an unrelated access.
pub const RETAIN: Duration = Duration::from_secs(120);
const MAX_RETAINED: usize = 8;

static PENDING: Mutex<Option<Pending>> = Mutex::new(None);
static RETAINED: Mutex<Vec<Retained>> = Mutex::new(Vec::new());

fn lock_retained() -> std::sync::MutexGuard<'static, Vec<Retained>> {
    RETAINED.lock().unwrap_or_else(|e| e.into_inner())
}

fn lock() -> std::sync::MutexGuard<'static, Option<Pending>> {
    // A poisoned lock only means another thread panicked mid-update; the data is
    // plain state, so keep going rather than disabling the sensor.
    PENDING.lock().unwrap_or_else(|e| e.into_inner())
}

/// Arm the registry for one child process opening one path. Replaces a previous
/// test. Returns `false` (and arms nothing) for an invalid pid.
pub fn arm(pid: i32, path: &str, ttl: Duration) -> bool {
    if pid <= 0 || path.is_empty() {
        return false;
    }
    *lock() = Some(Pending {
        pid,
        path: path.to_string(),
        deadline: Instant::now() + ttl,
        observed: false,
    });
    true
}

/// Called by a sensor for every access it reports. `true` marks the access as the
/// self-test (the registry stays armed so every access of the child, e.g. an open
/// followed by a metadata call, is marked as part of the same test).
pub fn claim(pid: i32, path: &str) -> bool {
    {
        let mut guard = lock();
        if let Some(pending) = guard.as_mut() {
            if Instant::now() > pending.deadline {
                *guard = None;
            } else if pending.pid == pid && pending.path == path {
                pending.observed = true;
                return true;
            }
        }
    }
    // A finished test whose delayed events are still arriving.
    let now = Instant::now();
    let mut retained = lock_retained();
    retained.retain(|r| r.until > now);
    retained.iter().any(|r| r.pid == pid && r.path == path)
}

/// The armed `(pid, path)`, for the agent's own tests that stand in for a sensor.
pub fn armed() -> Option<(i32, String)> {
    lock().as_ref().map(|p| (p.pid, p.path.clone()))
}

/// Whether the sensor reported an access of the armed child.
pub fn observed() -> bool {
    lock().as_ref().is_some_and(|p| p.observed)
}

/// The test is over: stop treating it as running, but keep its pid and path attributable for
/// [`RETAIN`] so that delayed sensor events of the child are still marked. Always called when a
/// test ends, whatever its outcome.
pub fn finish() {
    if let Some(done) = lock().take() {
        let mut retained = lock_retained();
        retained.retain(|r| r.until > Instant::now());
        if retained.len() >= MAX_RETAINED {
            retained.remove(0);
        }
        retained.push(Retained {
            pid: done.pid,
            path: done.path,
            until: Instant::now() + RETAIN,
        });
    }
}

/// Forget everything, retained tests included. For tests.
pub fn reset() {
    *lock() = None;
    lock_retained().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as TestMutex;

    // The registry is process-global; tests must not interleave.
    static SERIAL: TestMutex<()> = TestMutex::new(());

    #[test]
    fn only_the_armed_pid_and_path_are_marked() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        assert!(!claim(10, "/a"), "nothing armed");
        assert!(arm(10, "/a", Duration::from_secs(30)));
        assert!(!claim(11, "/a"), "another process is a real access");
        assert!(!claim(10, "/b"), "another path is a real access");
        assert!(!observed());
        assert!(claim(10, "/a"));
        assert!(
            claim(10, "/a"),
            "every access of the child belongs to the test"
        );
        assert!(observed());
        finish();
        assert!(!observed(), "no longer running");
        // A late sensor event of the same child is still the test; another pid or path is not.
        assert!(
            claim(10, "/a"),
            "delayed events of the finished test stay marked"
        );
        assert!(!claim(11, "/a"));
        assert!(!claim(10, "/b"));
        reset();
        assert!(!claim(10, "/a"));
    }

    #[test]
    fn retention_is_bounded() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        for pid in 1..=(MAX_RETAINED as i32 + 4) {
            assert!(arm(pid, "/a", Duration::from_secs(30)));
            finish();
        }
        assert!(lock_retained().len() <= MAX_RETAINED);
        assert!(!claim(1, "/a"), "the oldest was dropped");
        assert!(claim(MAX_RETAINED as i32 + 4, "/a"));
        reset();
    }

    #[test]
    fn it_expires_and_rejects_bad_input() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        assert!(!arm(0, "/a", Duration::from_secs(1)));
        assert!(!arm(-5, "/a", Duration::from_secs(1)));
        assert!(!arm(5, "", Duration::from_secs(1)));
        assert!(arm(5, "/a", Duration::from_millis(0)));
        std::thread::sleep(Duration::from_millis(5));
        assert!(!claim(5, "/a"), "an expired test marks nothing");
        assert!(!observed());
    }
}
