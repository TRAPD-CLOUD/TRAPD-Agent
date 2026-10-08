use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::schema::AgentEvent;

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

// OS-neutral collectors (sysinfo-backed), shared by every platform build.
pub mod system;

// Ransomware / coalescing / tamper-timing rules shared by the Linux and Windows
// filesystem collectors.
pub mod fs_heuristics;
pub mod fs_plan;

// Memory-scan finding shared by the Linux and Windows scanners.
pub mod mem_finding;

// Generic log collector (file tail, journal, syslog → parsers → events), shared by
// Linux and Windows; each platform supplies its own built-in source catalogue.
pub mod logs;

// Windows memory classification rules (pure; the scanner does the I/O).
pub mod win_mem_rules;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;

// ETW record decoding for the Windows sensor; platform-neutral so it is
// tested on every build host.
#[cfg(any(target_os = "windows", test))]
pub mod etw_map;
