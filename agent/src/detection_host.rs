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
    fn state_capacity_dropped(&self, n: u64) {
        crate::telemetry::metrics::metrics().state_capacity_dropped(n);
    }
    fn enrichment_partial(&self) {
        crate::telemetry::metrics::metrics().enrichment_partial();
    }
}
pub fn initialize() {
    trapd_schema::runtime::install(Arc::new(HostRuntime))
        .unwrap_or_else(|_| panic!("schema runtime initialized after event creation"));
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
            let file = std::fs::File::open(format!("/proc/{pid}/cmdline")).ok()?;
            bounded_cmdline(file)
        }
        fn username(&self, uid: u32) -> String {
            username_for_uid(uid)
        }
        fn session(&self, pid: i32) -> Option<SessionContext> {
            crate::forensics::capture_session_opt(pid)
        }
    }

    fn bounded_cmdline(reader: impl std::io::Read) -> Option<String> {
        use std::io::Read;
        use trapd_schema::limits::MAX_CMDLINE_BYTES;
        let mut raw = Vec::new();
        reader
            .take(MAX_CMDLINE_BYTES as u64 + 1)
            .read_to_end(&mut raw)
            .ok()?;
        let mut truncated = raw.len() > MAX_CMDLINE_BYTES;
        raw.truncate(MAX_CMDLINE_BYTES);
        let mut joined = String::with_capacity(raw.len());
        for arg in raw.split(|&byte| byte == 0).filter(|arg| !arg.is_empty()) {
            if !joined.is_empty() {
                if joined.len() == MAX_CMDLINE_BYTES {
                    truncated = true;
                    break;
                }
                joined.push(' ');
            }
            let arg = String::from_utf8_lossy(arg);
            let remaining = MAX_CMDLINE_BYTES - joined.len();
            if arg.len() > remaining {
                joined.push_str(&arg[..arg.floor_char_boundary(remaining)]);
                truncated = true;
                break;
            }
            joined.push_str(&arg);
        }
        if truncated {
            trapd_schema::runtime::runtime().enrichment_truncation();
        }
        (!joined.is_empty()).then_some(joined)
    }

    fn username_for_uid(uid: u32) -> String {
        let passwd =
            crate::paths::bounded_regular_bytes(std::path::Path::new("/etc/passwd"), 1024 * 1024)
                .unwrap_or_default();
        std::str::from_utf8(&passwd)
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

    #[cfg(test)]
    mod tests {
        use super::bounded_cmdline;
        use trapd_schema::limits::MAX_CMDLINE_BYTES;

        #[test]
        fn argv_limits_raw_reads_and_lossy_output() {
            let mut source = std::io::Cursor::new(vec![0xff; MAX_CMDLINE_BYTES * 4]);
            let result = bounded_cmdline(&mut source).unwrap();
            assert_eq!(source.position(), MAX_CMDLINE_BYTES as u64 + 1);
            assert!(result.len() <= MAX_CMDLINE_BYTES);
            assert_eq!(
                bounded_cmdline(&b"one\0\0two three\0"[..]).as_deref(),
                Some("one two three")
            );
            assert_eq!(bounded_cmdline(&b"\0"[..]), None);
        }
    }
}
#[cfg(target_os = "linux")]
pub use process::RealProc;
