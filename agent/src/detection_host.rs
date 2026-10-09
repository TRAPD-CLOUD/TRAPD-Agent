//! Agent adapters for reusable detection and schema libraries.
use std::sync::Arc;
pub struct HostRuntime;
impl trapd_schema::runtime::Runtime for HostRuntime {
    fn boot_id(&self) -> String {
        crate::telemetry::identity::boot_id().to_string()
    }
    fn monotonic_ns(&self) -> u64 {
        crate::telemetry::identity::monotonic_ns()
    }
    fn enrichment_failure(&self) {
        crate::telemetry::metrics::metrics().enrichment_failure();
    }
    fn enrichment_truncation(&self) {
        crate::telemetry::metrics::metrics().enrichment_truncation();
    }
    fn enrichment_partial(&self) {
        crate::telemetry::metrics::metrics().enrichment_partial();
    }
}
impl trapd_detection::runtime::Runtime for HostRuntime {
    fn detection_uncatalogued(&self) {
        crate::telemetry::metrics::metrics().detection_uncatalogued();
    }
    fn detection_suppressed(&self) {
        crate::telemetry::metrics::metrics().detection_suppressed();
    }
    fn detection_aggregated(&self) {
        crate::telemetry::metrics::metrics().detection_aggregated();
    }
    fn shadow_hit(&self, rule_id: &str) {
        crate::telemetry::coverage::shadow_hit(rule_id);
    }
    fn write_baseline(&self, path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
        crate::paths::write_atomic(path, bytes, 0o600)
    }
}
pub fn initialize() {
    trapd_schema::runtime::install(Arc::new(HostRuntime))
        .unwrap_or_else(|_| panic!("schema runtime initialized after event creation"));
}
pub fn engine(agent_id: String, hostname: String) -> trapd_detection::DetectionEngine {
    trapd_detection::DetectionEngine::with_runtime(
        agent_id,
        hostname,
        trapd_detection::runtime::Paths {
            iocs: Some(crate::paths::config_dir().join("iocs.json")),
            sigma: Some(crate::paths::config_dir().join("sigma")),
            baseline: Some(crate::paths::state_dir().join("baseline.json")),
        },
        Arc::new(HostRuntime),
    )
}
#[cfg(target_os = "linux")]
mod process {
    use trapd_detection::honeytoken::ProcInfo;
    use trapd_schema::SessionContext;
    /// Reads the live `/proc` and `/etc/passwd`.
    pub struct RealProc;

    impl ProcInfo for RealProc {
        fn process_start_time(&self, pid: i32) -> Option<u64> {
            crate::telemetry::identity::process_start_time(pid)
        }
        fn ppid(&self, pid: i32) -> Option<i32> {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            trapd_detection::honeytoken::parse_stat_ppid(&stat)
        }
        fn comm(&self, pid: i32) -> Option<String> {
            std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .map(|s| s.trim_end().to_string())
                .filter(|s| !s.is_empty())
        }
        fn exe(&self, pid: i32) -> Option<String> {
            std::fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
        }
        fn cmdline(&self, pid: i32) -> Option<String> {
            let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
            if raw.is_empty() {
                return None;
            }
            // argv is NUL-separated; render as a space-joined command line.
            let s: String = raw
                .split(|&b| b == 0)
                .filter(|p| !p.is_empty())
                .map(|p| String::from_utf8_lossy(p))
                .collect::<Vec<_>>()
                .join(" ");
            (!s.is_empty()).then_some(s)
        }
        fn username(&self, uid: u32) -> String {
            username_for_uid(uid)
        }
        fn session(&self, pid: i32) -> Option<SessionContext> {
            crate::forensics::capture_session_opt(pid)
        }
    }

    fn username_for_uid(uid: u32) -> String {
        std::fs::read_to_string("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .find_map(|line| {
                let mut f = line.splitn(7, ':');
                let name = f.next()?;
                let _ = f.next();
                let u = f.next()?.parse::<u32>().ok()?;
                (u == uid).then(|| name.to_string())
            })
            .unwrap_or_else(|| format!("uid:{uid}"))
    }
}
#[cfg(target_os = "linux")]
pub use process::RealProc;
