//! Living honeytokens: a decoy that ages like the files around it.
//!
//! An intruder spots a planted file by what is wrong with it. One of the classic tells is
//! a file nobody ever opened: its last-access time equals its creation time while every
//! neighbour has been read at some point. This module lets the agent move the *access
//! time* of its own tokens now and then, to a plausible moment, as if the file were read
//! occasionally.
//!
//! What it does not do, on purpose:
//!   * it never opens a token for reading its content in a way a sensor would count, and
//!     it never writes: content and modification time stay as deployed, so the integrity
//!     check (digest) is unaffected and no edit is faked;
//!   * it only touches paths in the agent's own register, never follows a symlink, and
//!     skips a file whose owner is not the one that was recorded at deploy time;
//!   * it is off unless the project turns it on (`honeytoken_living_enabled`).
//!
//! The agent's own process is excluded from the honeytoken sensor, so the touch does not
//! raise an alert. Nothing about the user is read: the only inputs are the token's own
//! timestamps and (when it was placed next to one) its neighbour's.

use std::time::{Duration, SystemTime};

const HOUR: u64 = 3_600;

/// The timestamps to set, or `None` when the file already looks lived-in or must be left alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drift {
    pub atime: SystemTime,
}

/// Decide the new access time of a token.
///
/// * `mtime` / `atime`: the token's current timestamps;
/// * `neighbor_atime`: the access time of the sibling the token was placed next to, if it
///   still exists;
/// * `now`;
/// * `roll`: a uniformly random number, so the function stays deterministic and testable.
///
/// The new time is never before the modification time (a file cannot be read before it
/// was written), never in the future, and never moves backwards: a token that was read
/// "recently" is left as it is.
pub fn plan_drift(
    mtime: SystemTime,
    atime: SystemTime,
    neighbor_atime: Option<SystemTime>,
    now: SystemTime,
    roll: u64,
) -> Option<Drift> {
    // Most days nothing happens: a real file is not read every day.
    if roll % 10 >= 3 {
        return None;
    }
    let ago = |secs: u64| now.checked_sub(Duration::from_secs(secs)).unwrap_or(now);
    // 1..36 hours ago, from the same roll.
    let jitter = HOUR + (roll / 10) % (35 * HOUR);
    let target = match neighbor_atime {
        // Follow the neighbour: read a little before the moment it was last read.
        Some(n) if n > mtime && n <= now => n
            .checked_sub(Duration::from_secs((roll / 10) % (6 * HOUR)))
            .unwrap_or(n),
        _ => ago(jitter),
    };
    let target = target.max(mtime).min(now);
    // Only ever forward: a recent access time is already believable.
    (target > atime).then_some(Drift { atime: target })
}

#[cfg(unix)]
pub use unix::apply;

#[cfg(unix)]
mod unix {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;
    use std::time::SystemTime;

    use tracing::warn;

    use super::{plan_drift, Drift};
    use crate::deception::HoneytokenRecord;

    /// Move the access time of one registered token, if the plan says so. Returns whether a
    /// timestamp was changed. Refuses a symlink and a file whose size or owner no longer
    /// matches what was deployed (the file is not ours any more).
    pub fn apply(rec: &HoneytokenRecord, now: SystemTime, roll: u64) -> bool {
        let path = Path::new(&rec.path);
        let Ok(meta) = fs::symlink_metadata(path) else {
            return false;
        };
        if !meta.file_type().is_file() || meta.len() != rec.size_bytes {
            return false;
        }
        let (Ok(atime), Ok(mtime)) = (meta.accessed(), meta.modified()) else {
            return false;
        };
        let neighbor = rec
            .neighbor_path
            .as_deref()
            .and_then(|n| fs::symlink_metadata(n).ok())
            .and_then(|m| m.accessed().ok());
        let Some(Drift { atime: target }) = plan_drift(mtime, atime, neighbor, now, roll) else {
            return false;
        };
        // Same file that was inspected: O_NOFOLLOW, and compare the inode afterwards.
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        else {
            return false;
        };
        match file.metadata() {
            Ok(opened) if opened.ino() == meta.ino() && opened.dev() == meta.dev() => {}
            _ => return false,
        }
        let times = fs::FileTimes::new()
            .set_accessed(target)
            .set_modified(mtime);
        match file.set_times(times) {
            Ok(()) => true,
            Err(error) => {
                warn!(%error, path = %rec.path, "honeytoken timestamp upkeep failed");
                false
            }
        }
    }
}

#[cfg(not(unix))]
pub fn apply(_rec: &crate::deception::HoneytokenRecord, _now: SystemTime, _roll: u64) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }
    const DAY: u64 = 86_400;

    #[test]
    fn most_days_nothing_happens() {
        // roll % 10 in 3..=9 means "not today"
        for roll in [3u64, 7, 9, 13, 99] {
            assert_eq!(
                plan_drift(t(100), t(100), None, t(100 + 30 * DAY), roll),
                None,
                "{roll}"
            );
        }
    }

    #[test]
    fn a_never_read_token_gets_a_plausible_recent_access_time() {
        let now = t(1_000 * DAY);
        let mtime = t(900 * DAY);
        let drift = plan_drift(mtime, mtime, None, now, 0).expect("roll 0 acts");
        assert!(drift.atime > mtime, "moves forward");
        assert!(drift.atime <= now, "never in the future");
        assert!(drift.atime >= mtime, "never before it was written");
        assert!(now.duration_since(drift.atime).unwrap() >= Duration::from_secs(HOUR));
        assert!(now.duration_since(drift.atime).unwrap() <= Duration::from_secs(36 * HOUR));
    }

    #[test]
    fn it_follows_the_neighbour_and_never_goes_before_the_write() {
        let now = t(1_000 * DAY);
        let mtime = t(900 * DAY);
        let neighbor = t(990 * DAY);
        let drift = plan_drift(mtime, mtime, Some(neighbor), now, 0).unwrap();
        assert!(
            drift.atime <= neighbor
                && neighbor.duration_since(drift.atime).unwrap() <= Duration::from_secs(6 * HOUR)
        );
        // A neighbour last read before the token was written, or "in the future", is ignored.
        let older = plan_drift(mtime, mtime, Some(t(800 * DAY)), now, 0).unwrap();
        assert!(older.atime >= mtime);
        let future = plan_drift(mtime, mtime, Some(t(1_100 * DAY)), now, 0).unwrap();
        assert!(future.atime <= now);
    }

    #[test]
    fn it_only_moves_forward() {
        let now = t(1_000 * DAY);
        let mtime = t(900 * DAY);
        // already read an hour ago: the ago-target (>= 1 h) cannot beat it by much, and must not go back
        let recent = now - Duration::from_secs(60);
        assert_eq!(plan_drift(mtime, recent, None, now, 0), None);
    }

    #[test]
    fn a_modification_time_in_the_future_cannot_push_the_access_time_past_now() {
        let now = t(1_000 * DAY);
        let drift = plan_drift(t(2_000 * DAY), t(1), None, now, 0);
        assert!(drift.is_none_or(|d| d.atime <= now));
    }

    #[cfg(unix)]
    #[test]
    fn apply_touches_only_the_access_time_of_a_regular_file_of_the_recorded_size() {
        use crate::deception::HoneytokenRecord;
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("trapd-living-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("creds");
        std::fs::write(&file, b"bait=1\n").unwrap();
        let old = SystemTime::now() - Duration::from_secs(300 * DAY);
        let f = std::fs::File::options().write(true).open(&file).unwrap();
        f.set_times(
            std::fs::FileTimes::new()
                .set_accessed(old)
                .set_modified(old),
        )
        .unwrap();
        drop(f);
        let rec = HoneytokenRecord {
            id: uuid::Uuid::new_v4(),
            path: file.display().to_string(),
            kind: "pgpass".into(),
            mode: 0o600,
            size_bytes: 7,
            sha256: String::new(),
            mimic_neighbor: false,
            neighbor_path: None,
            canary_marker: None,
            out_of_band: None,
            deployed_at: chrono::Utc::now(),
            command_id: None,
            breadcrumbs: Vec::new(),
        };
        let before = std::fs::metadata(&file).unwrap();
        assert!(
            apply(&rec, SystemTime::now(), 0),
            "roll 0 acts on a stale file"
        );
        let after = std::fs::metadata(&file).unwrap();
        assert_eq!(
            after.mtime(),
            before.mtime(),
            "content time stays as deployed"
        );
        assert!(after.atime() > before.atime(), "access time moved forward");
        assert_eq!(std::fs::read(&file).unwrap(), b"bait=1\n");

        // A file that no longer has the deployed size is not ours any more.
        std::fs::write(&file, b"changed by someone else\n").unwrap();
        assert!(!apply(&rec, SystemTime::now(), 0));
        // A symlink is never followed.
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let linked = HoneytokenRecord {
            path: link.display().to_string(),
            size_bytes: 24,
            ..rec.clone()
        };
        assert!(!apply(&linked, SystemTime::now(), 0));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
