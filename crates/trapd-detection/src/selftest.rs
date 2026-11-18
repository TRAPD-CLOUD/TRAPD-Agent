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

static PENDING: Mutex<Option<Pending>> = Mutex::new(None);

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
    let mut guard = lock();
    let Some(pending) = guard.as_mut() else {
        return false;
    };
    if Instant::now() > pending.deadline {
        *guard = None;
        return false;
    }
    if pending.pid == pid && pending.path == path {
        pending.observed = true;
        return true;
    }
    false
}

/// The armed `(pid, path)`, for the agent's own tests that stand in for a sensor.
pub fn armed() -> Option<(i32, String)> {
    lock().as_ref().map(|p| (p.pid, p.path.clone()))
}

/// Whether the sensor reported an access of the armed child.
pub fn observed() -> bool {
    lock().as_ref().is_some_and(|p| p.observed)
}

/// Disarm. Always called when a test ends, whatever its outcome.
pub fn disarm() {
    *lock() = None;
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
        disarm();
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
        disarm();
        assert!(!claim(10, "/a"), "disarmed");
        assert!(!observed());
    }

    #[test]
    fn it_expires_and_rejects_bad_input() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        disarm();
        assert!(!arm(0, "/a", Duration::from_secs(1)));
        assert!(!arm(-5, "/a", Duration::from_secs(1)));
        assert!(!arm(5, "", Duration::from_secs(1)));
        assert!(arm(5, "/a", Duration::from_millis(0)));
        std::thread::sleep(Duration::from_millis(5));
        assert!(!claim(5, "/a"), "an expired test marks nothing");
        assert!(!observed());
    }
}
