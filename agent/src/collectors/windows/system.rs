//! Periodic system snapshot — the Windows counterpart of
//! `collectors::linux::system`, emitting the same [`SystemSnapshotData`]
//! shape (CPU count/usage, memory, uptime, OS + kernel version).

use anyhow::Result;
use async_trait::async_trait;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};

use crate::collectors::Collector;
use crate::schema::{AgentEvent, EventAction, EventClass, EventData, Severity, SystemSnapshotData};

pub struct SystemCollector;

impl SystemCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SystemCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn collect_system_info() -> Result<SystemSnapshotData> {
    let mut sys = System::new_with_specifics(
        RefreshKind::new()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything()),
    );

    // Two CPU refreshes a beat apart so the usage delta is meaningful.
    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_cpu();
    sys.refresh_memory();

    let cpu_count = sys.cpus().len();
    let cpu_usage = sys.global_cpu_info().cpu_usage();
    let total_mem_mb = sys.total_memory() / (1024 * 1024);
    let used_mem_mb = sys.used_memory() / (1024 * 1024);
    let free_mem_mb = sys.free_memory() / (1024 * 1024);
    let uptime_secs = System::uptime();
    // Windows has no Unix-style load average; sysinfo reports zeros, which the
    // backend already treats as "not available".
    let load = System::load_average();
    // kernel_version() is the NT build number; long_os_version() is the
    // human-readable edition, the same role PRETTY_NAME plays on Linux.
    let kernel = System::kernel_version().unwrap_or_default();
    let os_name = System::name().unwrap_or_else(|| "Windows".to_string());
    let edition = System::long_os_version().unwrap_or_default();

    Ok(SystemSnapshotData {
        os: os_name,
        kernel,
        distro: edition,
        cpu_count,
        cpu_usage_pct: cpu_usage,
        memory_total_mb: total_mem_mb,
        memory_used_mb: used_mem_mb,
        memory_free_mb: free_mem_mb,
        uptime_secs,
        load_avg: [load.one, load.five, load.fifteen],
    })
}

#[async_trait]
impl Collector for SystemCollector {
    fn name(&self) -> &'static str {
        "SystemCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let mut ticker = interval(Duration::from_secs(60));

        loop {
            ticker.tick().await;

            let snapshot = tokio::task::spawn_blocking(collect_system_info).await??;

            let event = AgentEvent::new(
                agent_id.clone(),
                hostname.clone(),
                EventClass::System,
                EventAction::Snapshot,
                Severity::Info,
                EventData::SystemSnapshot(snapshot),
            );

            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }
    }
}
