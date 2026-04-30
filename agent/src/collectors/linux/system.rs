use std::fs;

use anyhow::Result;
use async_trait::async_trait;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use uuid::Uuid;

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

fn read_distro() -> String {
    let content = match fs::read_to_string("/etc/os-release") {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
            return val.trim_matches('"').to_string();
        }
    }
    String::new()
}

fn collect_system_info() -> Result<SystemSnapshotData> {
    let mut sys = System::new_with_specifics(
        RefreshKind::new()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything()),
    );

    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_cpu();
    sys.refresh_memory();

    let cpu_count    = sys.cpus().len();
    let cpu_usage    = sys.global_cpu_info().cpu_usage();
    let total_mem_mb = sys.total_memory() / (1024 * 1024);
    let used_mem_mb  = sys.used_memory() / (1024 * 1024);
    let free_mem_mb  = sys.free_memory() / (1024 * 1024);
    let uptime_secs  = System::uptime();
    let load         = System::load_average();
    let kernel       = System::kernel_version().unwrap_or_default();
    let os_name      = System::name().unwrap_or_else(|| "Linux".to_string());
    let distro       = read_distro();

    Ok(SystemSnapshotData {
        os:              os_name,
        kernel,
        distro,
        cpu_count,
        cpu_usage_pct:   cpu_usage,
        memory_total_mb: total_mem_mb,
        memory_used_mb:  used_mem_mb,
        memory_free_mb:  free_mem_mb,
        uptime_secs,
        load_avg:        [load.one, load.five, load.fifteen],
    })
}

#[async_trait]
impl Collector for SystemCollector {
    fn name(&self) -> &'static str {
        "SystemCollector"
    }

    async fn run(
        &mut self,
        tx:       Sender<AgentEvent>,
        agent_id: Uuid,
        hostname: String,
    ) -> Result<()> {
        let mut ticker = interval(Duration::from_secs(60));

        loop {
            ticker.tick().await;

            let snapshot = tokio::task::spawn_blocking(collect_system_info).await??;

            let event = AgentEvent::new(
                agent_id,
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
