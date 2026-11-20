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
    /// The child's start time (clock ticks since boot) when it could be read: its identity apart from
    /// the pid, which the OS reuses.
    start: Option<u64>,
    deadline: Instant,
    observed: bool,
}

/// The start time of process `pid` in clock ticks since boot (Linux: field 22 of `/proc/<pid>/stat`).
/// `None` when the process does not exist or the platform cannot tell.
#[cfg(target_os = "linux")]
pub fn process_start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name is in parentheses and may contain spaces and parentheses: the fields
    // after the LAST ')' are fixed. starttime is field 22 overall, i.e. index 19 after "state".
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(not(target_os = "linux"))]
pub fn process_start_time(_pid: i32) -> Option<u64> {
    None
}

/// A finished test whose late sensor events may still arrive.
#[derive(Debug)]
struct Retained {
    pid: i32,
    path: String,
    /// Required: a finished test is only remembered when the child's identity is known.
    start: u64,
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
        start: process_start_time(pid),
        deadline: Instant::now() + ttl,
        observed: false,
    });
    true
}

/// Called by a sensor for every access it reports. `true` marks the access as the
/// self-test (the registry stays armed so every access of the child, e.g. an open
/// followed by a metadata call, is marked as part of the same test).
///
/// `observed_start` is the accessor's start time as the sensor established it for the
/// access itself (`None` when the sensor cannot tell). A process identity that cannot be
/// established never matches a finished test: an unknown process stays uncorrelated.
pub fn claim(pid: i32, path: &str, observed_start: Option<u64>) -> bool {
    {
        let mut guard = lock();
        if let Some(pending) = guard.as_mut() {
            if Instant::now() > pending.deadline {
                *guard = None;
            } else if pending.pid == pid
                && pending.path == path
                && generation_compatible(pending.start, observed_start)
            {
                pending.observed = true;
                return true;
            }
        }
    }
    // A finished test whose delayed events are still arriving. The pid may have been reused by
    // an unrelated process, so the accessor's identity must be proven to be the child's: by the
    // sensor's own observation, or else by the still-running process. A process that is gone
    // and was never identified proves nothing.
    let identity = observed_start.or_else(|| process_start_time(pid));
    let Some(identity) = identity else {
        return false;
    };
    let now = Instant::now();
    let mut retained = lock_retained();
    retained.retain(|r| r.until > now);
    retained
        .iter()
        .any(|r| r.pid == pid && r.path == path && r.start == identity)
}

/// While the test runs, the armed pid is the child unless both start times are known and differ.
fn generation_compatible(armed: Option<u64>, observed: Option<u64>) -> bool {
    match (armed, observed) {
        (Some(a), Some(o)) => a == o,
        _ => true,
    }
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
        // Without the child's identity (a platform that cannot tell) nothing is retained: a pid
        // alone is not enough to attribute a later access.
        let Some(start) = done.start else {
            return;
        };
        let mut retained = lock_retained();
        retained.retain(|r| r.until > Instant::now());
        if retained.len() >= MAX_RETAINED {
            retained.remove(0);
        }
        retained.push(Retained {
            pid: done.pid,
            path: done.path,
            start,
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
        assert!(!claim(10, "/a", None), "nothing armed");
        assert!(arm(10, "/a", Duration::from_secs(30)));
        assert!(!claim(11, "/a", None), "another process is a real access");
        assert!(!claim(10, "/b", None), "another path is a real access");
        assert!(!observed());
        assert!(claim(10, "/a", None));
        assert!(
            claim(10, "/a", None),
            "every access of the child belongs to the test"
        );
        assert!(observed());
        finish();
        assert!(!observed(), "no longer running");
        reset();
        assert!(!claim(10, "/a", None));
    }

    // Retention needs a real process (its start time is its identity), so these tests use this one.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_finished_test_keeps_marking_delayed_events_of_the_same_process_only() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let me = std::process::id() as i32;
        assert!(arm(me, "/a", Duration::from_secs(30)));
        finish();
        assert!(!observed(), "no longer running");
        assert!(
            claim(me, "/a", None),
            "a delayed event of the finished test stays marked"
        );
        assert!(!claim(me, "/b", None), "another path is not");
        assert!(!claim(me + 1, "/a", None), "another pid is not");
        reset();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_reused_pid_is_not_the_test() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let me = std::process::id() as i32;
        let start = process_start_time(me).expect("own start time");
        // A test child that had this pid but another start time: the pid was reused since.
        lock_retained().push(Retained {
            pid: me,
            path: "/a".into(),
            start: start.wrapping_add(1),
            until: Instant::now() + RETAIN,
        });
        assert!(
            !claim(me, "/a", None),
            "same pid, different process: a real access"
        );
        reset();
    }

    #[test]
    fn without_a_known_identity_nothing_is_retained() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        // A pid that cannot exist: no start time, so the finished test is simply forgotten.
        assert!(arm(i32::MAX, "/a", Duration::from_secs(30)));
        finish();
        assert!(!claim(i32::MAX, "/a", None));
        reset();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retention_is_bounded() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        let me = std::process::id() as i32;
        for _ in 0..(MAX_RETAINED + 4) {
            assert!(arm(me, "/a", Duration::from_secs(30)));
            finish();
        }
        assert!(lock_retained().len() <= MAX_RETAINED);
        reset();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn own_start_time_is_readable() {
        assert!(process_start_time(std::process::id() as i32).is_some());
        assert_eq!(process_start_time(i32::MAX), None);
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
        assert!(!claim(5, "/a", None), "an expired test marks nothing");
        assert!(!observed());
    }

    #[test]
    fn a_gone_process_without_sensor_identity_is_not_the_test() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        // The child finished and its pid is free (or reused by a process that also exited).
        let gone = i32::MAX - 1;
        lock_retained().push(Retained {
            pid: gone,
            path: "/a".into(),
            start: 42,
            until: Instant::now() + RETAIN,
        });
        assert!(
            !claim(gone, "/a", None),
            "an access whose process identity is unknown stays a real access"
        );
        assert!(
            !claim(gone, "/a", Some(43)),
            "the sensor saw another process generation"
        );
        assert!(
            claim(gone, "/a", Some(42)),
            "the sensor proves the delayed event is the child's"
        );
        reset();
    }

    #[test]
    fn a_running_test_rejects_a_different_observed_generation() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        assert!(arm(10, "/a", Duration::from_secs(30)));
        if let Some(p) = lock().as_mut() {
            p.start = Some(7);
        }
        assert!(!claim(10, "/a", Some(8)));
        assert!(claim(10, "/a", Some(7)));
        assert!(claim(10, "/a", None));
        reset();
    }
}
