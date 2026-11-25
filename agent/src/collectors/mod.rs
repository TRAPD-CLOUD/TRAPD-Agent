use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::schema::AgentEvent;

/// Read a regular host/state file within a hard allocation budget, including
/// procfs files whose reported length is zero.
pub(crate) fn read_capped(
    path: impl AsRef<std::path::Path>,
    limit: usize,
) -> std::io::Result<Vec<u8>> {
    let (bytes, overflowed) = read_prefix(path, limit)?;
    if overflowed {
        crate::telemetry::metrics::metrics().state_capacity_dropped(1);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds collector byte limit",
        ));
    }
    Ok(bytes)
}

/// Like [`read_capped`], but a longer file yields its first `limit` bytes and
/// `true` instead of an error. For evidence where a prefix is still useful.
pub(crate) fn read_prefix(
    path: impl AsRef<std::path::Path>,
    limit: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    let overflowed = bytes.len() > limit;
    bytes.truncate(limit);
    Ok((bytes, overflowed))
}

pub(crate) fn read_text_capped(
    path: impl AsRef<std::path::Path>,
    limit: usize,
) -> std::io::Result<String> {
    String::from_utf8(read_capped(path, limit)?)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[async_trait]
pub trait Collector: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    // async_trait adds #[must_use] even though the returned Future is already must-use.
    #[allow(clippy::double_must_use)]
    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()>;
}

/// Record a collector failure in metrics and coverage.
pub(super) fn report_failure(name: &str) {
    crate::telemetry::metrics::metrics().collector_failed();
    if name == "WindowsProcessCollector" {
        crate::telemetry::metrics::metrics()
            .set_collector_mode(crate::telemetry::metrics::CollectorMode::Failed);
    }
    crate::telemetry::coverage::set_collector_failed(name, true);
}

/// Tokio isolates a task panic. Record the lost collector even when its owner
/// is waiting for service shutdown rather than polling the task handle.
pub(crate) struct ObservePanic(pub(crate) &'static str);

impl Drop for ObservePanic {
    fn drop(&mut self) {
        if std::thread::panicking() {
            report_failure(self.0);
        }
    }
}

#[cfg(test)]
mod panic_tests {
    use super::ObservePanic;

    #[tokio::test]
    async fn unwinding_marks_the_collector_failed_but_cancellation_does_not() {
        let result = tokio::spawn(async {
            let _guard = ObservePanic("test-unwind");
            panic!("simulated collector failure");
        })
        .await;
        assert!(result.unwrap_err().is_panic());
        drop(ObservePanic("test-normal-drop"));
        let failed = crate::telemetry::coverage::snapshot().failed_collectors;
        assert!(failed.iter().any(|name| name == "test-unwind"));
        assert!(!failed.iter().any(|name| name == "test-normal-drop"));
        crate::telemetry::coverage::set_collector_failed("test-unwind", false);
    }
}

// OS-neutral collectors (sysinfo-backed), shared by every platform build.
pub mod system;

// Ransomware / coalescing / tamper-timing rules shared by the Linux and Windows
// filesystem collectors.
pub mod critical_file;
pub mod fs_heuristics;
pub mod fs_plan;

// Memory-scan finding shared by the Linux and Windows scanners.
pub mod mem_finding;

// Bounded baseline of processes already running at agent start (Linux and
// Windows process collectors).
pub mod process_baseline;

// Generic log collector (file tail, journal, syslog → parsers → events), shared by
// Linux and Windows; each platform supplies its own built-in source catalogue.
pub mod logs;

// Registry persistence watcher core (pure; the Windows collector does the reads).
pub mod registry_watch;

// Change-notification scheduling and handle bookkeeping for the registry watcher
// (pure; the Windows collector supplies the RegNotifyChangeKeyValue backend).
pub mod registry_notify;

// Windows memory classification rules (pure; the scanner does the I/O).
pub mod win_mem_rules;

// Restart-with-backoff wrapper for collectors; used by the Windows runtime.
#[cfg(any(target_os = "windows", test))]
pub mod supervisor;

// Device attach/detach parsing and bookkeeping shared by Linux and Windows.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub mod device;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

// ETW record decoding for the Windows sensor; platform-neutral so it is
// tested on every build host.
#[cfg(any(target_os = "windows", test))]
pub mod etw_map;

// Persisted Windows event normalization; tested independently of native APIs.
#[cfg(any(target_os = "windows", test))]
pub mod windows_native;
