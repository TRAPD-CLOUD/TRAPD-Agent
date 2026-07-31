//! The diagnostics report behind `trapd-agent diagnostics telemetry`.
//!
//! The diagnostics command runs in a **separate process** from the agent, so it
//! cannot read the in-process metric registry directly.  The running agent
//! therefore publishes a [`TelemetryReport`] to `<state>/telemetry.json` on a
//! short interval; the CLI reads that file and renders it.
//!
//! Two consequences are handled explicitly rather than papered over: the report
//! is always slightly stale (its `age` is shown, and a stale file is called
//! out), and it may be missing entirely when no agent is running (which the CLI
//! reports as such instead of printing zeroes that look like a healthy idle
//! agent).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::health::HealthState;
use super::metrics::{metrics, now_unix_ms, MetricsSnapshot};

/// Report older than this is called out as stale by the CLI.
pub const STALE_AFTER_MS: u64 = 30_000;

/// Format version of the on-disk report.  Bumped when the shape changes so an
/// older CLI reading a newer file says so instead of mis-parsing it.
pub const REPORT_VERSION: u32 = 1;

/// A point-in-time view of the whole telemetry pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryReport {
    pub version: u32,
    pub agent_version: String,
    pub agent_pid: u32,
    pub boot_id: String,
    /// Sequence numbers issued this run — the denominator for gap detection.
    pub sequences_issued: u64,
    pub captured_at_unix_ms: u64,
    pub uptime_secs: u64,
    pub offline_mode: bool,
    pub health: HealthState,
    pub metrics: MetricsSnapshot,
}

impl TelemetryReport {
    /// Capture the current state of the global registry.
    pub fn capture(offline_mode: bool, uptime_secs: u64) -> Self {
        let snap = metrics().snapshot();
        let now = now_unix_ms();
        Self {
            version: REPORT_VERSION,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            agent_pid: std::process::id(),
            boot_id: super::identity::boot_id().to_string(),
            sequences_issued: super::identity::issued_sequences(),
            captured_at_unix_ms: now,
            uptime_secs,
            offline_mode,
            health: HealthState::evaluate(&snap, offline_mode, now),
            metrics: snap,
        }
    }

    /// Default report location inside the agent state directory.
    pub fn default_path() -> PathBuf {
        crate::paths::state_dir().join("telemetry.json")
    }

    /// Write the report atomically (temp file + rename), `0600`.
    ///
    /// The rename makes a reader either see the previous complete report or the
    /// new one, never a half-written file — the CLI can run at any moment.
    pub fn write_atomic(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Distinct temp name per process so two agents cannot interleave writes.
        let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
        let body = serde_json::to_vec_pretty(self)
            .map_err(std::io::Error::other)?;

        let result = (|| -> std::io::Result<()> {
            let mut f = create_private(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// Read a report from disk.
    pub fn read(path: &Path) -> anyhow::Result<Self> {
        let body = std::fs::read(path)?;
        let report: TelemetryReport = serde_json::from_slice(&body)?;
        if report.version > REPORT_VERSION {
            anyhow::bail!(
                "telemetry report is version {} but this build understands at most {} — \
                 the running agent is newer than this CLI",
                report.version,
                REPORT_VERSION
            );
        }
        Ok(report)
    }

    /// Age of this report in milliseconds relative to `now`.
    pub fn age_ms(&self, now_unix_ms: u64) -> u64 {
        now_unix_ms.saturating_sub(self.captured_at_unix_ms)
    }

    /// Whether the report is too old to describe a live agent.
    pub fn is_stale(&self, now_unix_ms: u64) -> bool {
        self.age_ms(now_unix_ms) > STALE_AFTER_MS
    }
}

/// Create a file readable only by the owning user.
///
/// The report names hostnames, paths and queue contents metadata, so it is
/// created `0600` from the start rather than being chmod-ed afterwards — a
/// world-readable window between `create` and `chmod` would be a real leak on a
/// multi-user host.
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "trapd_report_{}_{}_{tag}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn sample() -> TelemetryReport {
        TelemetryReport {
            version: REPORT_VERSION,
            agent_version: "0.0.0-test".into(),
            agent_pid: 4242,
            boot_id: "boot-test".into(),
            sequences_issued: 1234,
            captured_at_unix_ms: 1_000_000,
            uptime_secs: 60,
            offline_mode: false,
            health: HealthState::Healthy,
            metrics: MetricsSnapshot::default(),
        }
    }

    #[test]
    fn capture_reflects_the_global_registry() {
        let r = TelemetryReport::capture(true, 5);
        assert_eq!(r.version, REPORT_VERSION);
        assert_eq!(r.agent_pid, std::process::id());
        assert_eq!(r.boot_id, super::super::identity::boot_id());
        assert!(r.offline_mode);
        assert_eq!(r.uptime_secs, 5);
    }

    #[test]
    fn write_then_read_round_trips() {
        let path = tmp_path("roundtrip");
        let r = sample();
        r.write_atomic(&path).unwrap();

        let back = TelemetryReport::read(&path).unwrap();
        assert_eq!(back.agent_pid, 4242);
        assert_eq!(back.boot_id, "boot-test");
        assert_eq!(back.health, HealthState::Healthy);
        assert_eq!(back.sequences_issued, 1234);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn written_report_is_owner_only() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let path = tmp_path("perms");
            sample().write_atomic(&path).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the report must never be world-readable");
            let _ = std::fs::remove_file(&path);
        }
    }

    #[test]
    fn rewrite_replaces_the_previous_report() {
        let path = tmp_path("rewrite");
        sample().write_atomic(&path).unwrap();

        let mut second = sample();
        second.uptime_secs = 999;
        second.write_atomic(&path).unwrap();

        assert_eq!(TelemetryReport::read(&path).unwrap().uptime_secs, 999);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn no_temp_file_is_left_behind() {
        let path = tmp_path("notemp");
        sample().write_atomic(&path).unwrap();
        let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
        assert!(!tmp.exists(), "temp file must be renamed away, not orphaned");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_newer_report_version_is_refused_not_misparsed() {
        let path = tmp_path("version");
        let mut r = sample();
        r.version = REPORT_VERSION + 1;
        r.write_atomic(&path).unwrap();

        let err = TelemetryReport::read(&path).unwrap_err().to_string();
        assert!(err.contains("newer than this CLI"), "got: {err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_report_is_an_error_not_a_default() {
        // Reporting zeroes here would look exactly like a healthy idle agent.
        let err = TelemetryReport::read(Path::new("/nonexistent/trapd/telemetry.json"));
        assert!(err.is_err());
    }

    #[test]
    fn a_corrupt_report_is_an_error() {
        let path = tmp_path("corrupt");
        std::fs::write(&path, b"{not json at all").unwrap();
        assert!(TelemetryReport::read(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn staleness_is_measured_against_the_capture_time() {
        let r = sample(); // captured at 1_000_000
        assert!(!r.is_stale(1_000_000 + STALE_AFTER_MS));
        assert!(r.is_stale(1_000_000 + STALE_AFTER_MS + 1));
        assert_eq!(r.age_ms(1_000_500), 500);
    }

    #[test]
    fn a_clock_that_jumped_backwards_reports_zero_age() {
        let r = sample();
        assert_eq!(
            r.age_ms(0),
            0,
            "a backwards clock step must not produce a negative age"
        );
        assert!(!r.is_stale(0));
    }
}
