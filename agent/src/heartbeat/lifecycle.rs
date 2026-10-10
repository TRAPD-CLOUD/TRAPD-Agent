//! Agent process lifecycle: when this process started, how long it has been
//! up, and how the previous run ended.
//!
//! The heartbeat used to carry only *host* uptime, so a service restart was
//! invisible in telemetry. This module records the process start once and
//! keeps a small marker file in the state directory:
//!
//! - written as `running` at start,
//! - rewritten as `clean` on an orderly shutdown (SIGTERM/SIGINT, SCM stop).
//!
//! At the next start, a marker still reading `running` means the previous run
//! was killed, crashed or lost power ([`PreviousShutdown::Unclean`]); no marker
//! at all is a first run or a wiped state dir ([`PreviousShutdown::Unknown`]).
//! The marker is a hint for operators, not an authenticated record: anyone who
//! can write the (owner-only) state dir can already do far worse.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Instant;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tracing::warn;

const MARKER_FILE: &str = "run_state";
const RUNNING: &str = "running";
const CLEAN: &str = "clean";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviousShutdown {
    /// The previous run recorded an orderly shutdown.
    Clean,
    /// The previous run never recorded one: kill, crash, power loss.
    Unclean,
    /// No (readable) marker: first start or wiped state.
    Unknown,
}

impl PreviousShutdown {
    fn classify(marker: Option<&str>) -> Self {
        match marker.map(str::trim) {
            Some(CLEAN) => Self::Clean,
            Some(RUNNING) => Self::Unclean,
            _ => Self::Unknown,
        }
    }
}

/// Immutable facts about this process run.
#[derive(Debug, Clone)]
pub struct Lifecycle {
    started_at: DateTime<Utc>,
    started: Instant,
    previous: PreviousShutdown,
    marker: PathBuf,
}

impl Lifecycle {
    /// Read the previous marker, then claim it for this run.
    fn begin(marker: PathBuf) -> Self {
        let previous = PreviousShutdown::classify(std::fs::read_to_string(&marker).ok().as_deref());
        write_marker(&marker, RUNNING);
        Self {
            started_at: Utc::now(),
            started: Instant::now(),
            previous,
            marker,
        }
    }

    /// RFC 3339 process start time.
    pub fn last_restart(&self) -> String {
        self.started_at.to_rfc3339()
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn previous_shutdown(&self) -> PreviousShutdown {
        self.previous
    }

    fn mark_clean(&self) {
        write_marker(&self.marker, CLEAN);
    }
}

fn write_marker(path: &Path, value: &str) {
    if let Err(e) = crate::paths::write_atomic(path, value.as_bytes(), 0o600) {
        // Losing the marker only costs the unclean-shutdown hint.
        warn!(error = %e, "could not write the run-state marker");
    }
}

static LIFECYCLE: OnceLock<Lifecycle> = OnceLock::new();

/// Record the process start. Idempotent: only the first call reads and
/// rewrites the marker, so the heartbeat can call it defensively.
pub fn begin_process() -> &'static Lifecycle {
    LIFECYCLE.get_or_init(|| Lifecycle::begin(crate::paths::state_dir().join(MARKER_FILE)))
}

/// Record an orderly shutdown. A no-op if the process never began.
pub fn mark_clean_shutdown() {
    if let Some(l) = LIFECYCLE.get() {
        l.mark_clean();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_marker(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trapd_lifecycle_{tag}_{}_{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        dir.join(MARKER_FILE)
    }

    #[test]
    fn classification() {
        assert_eq!(PreviousShutdown::classify(None), PreviousShutdown::Unknown);
        assert_eq!(
            PreviousShutdown::classify(Some("clean\n")),
            PreviousShutdown::Clean
        );
        assert_eq!(
            PreviousShutdown::classify(Some("running")),
            PreviousShutdown::Unclean
        );
        assert_eq!(
            PreviousShutdown::classify(Some("garbage")),
            PreviousShutdown::Unknown
        );
    }

    #[test]
    fn first_start_is_unknown_and_claims_the_marker() {
        let marker = temp_marker("first");
        let l = Lifecycle::begin(marker.clone());
        assert_eq!(l.previous_shutdown(), PreviousShutdown::Unknown);
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), RUNNING);
        let _ = std::fs::remove_dir_all(marker.parent().unwrap());
    }

    #[test]
    fn restart_after_orderly_stop_is_clean() {
        let marker = temp_marker("clean");
        let first = Lifecycle::begin(marker.clone());
        first.mark_clean();
        let second = Lifecycle::begin(marker.clone());
        assert_eq!(second.previous_shutdown(), PreviousShutdown::Clean);
        let _ = std::fs::remove_dir_all(marker.parent().unwrap());
    }

    #[test]
    fn restart_without_orderly_stop_is_unclean() {
        let marker = temp_marker("unclean");
        let _killed = Lifecycle::begin(marker.clone());
        let second = Lifecycle::begin(marker.clone());
        assert_eq!(second.previous_shutdown(), PreviousShutdown::Unclean);
        let _ = std::fs::remove_dir_all(marker.parent().unwrap());
    }

    #[test]
    fn restart_time_is_the_process_start_in_rfc3339() {
        let marker = temp_marker("time");
        let l = Lifecycle::begin(marker.clone());
        let parsed = DateTime::parse_from_rfc3339(&l.last_restart()).unwrap();
        assert!((Utc::now() - parsed.with_timezone(&Utc)).num_seconds() < 5);
        assert!(!l.last_restart().is_empty());
        let _ = std::fs::remove_dir_all(marker.parent().unwrap());
    }

    #[test]
    fn uptime_grows_from_zero() {
        let marker = temp_marker("uptime");
        let l = Lifecycle::begin(marker.clone());
        assert!(l.uptime_seconds() < 5);
        let _ = std::fs::remove_dir_all(marker.parent().unwrap());
    }
}
