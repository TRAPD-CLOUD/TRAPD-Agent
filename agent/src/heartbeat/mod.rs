//! Liveness + live resource metrics heartbeat.
//!
//! `POST /api/v1/agents/{agent_id}/heartbeat` every [`HEARTBEAT_INTERVAL`].
//!
//! Beyond proving the agent is alive, each beat carries the host's current
//! resource utilisation (CPU, memory, swap, root-disk, load average, uptime,
//! process count) so the backend can drive **asset-management dashboards and
//! alerting** without waiting for the slower full inventory snapshot.
//!
//! The metrics struct is OS-neutral so the future Windows agent reports the
//! same shape.

use std::sync::Mutex;

use chrono::Utc;
use serde::Serialize;
use sysinfo::{Disks, System};
use tokio::time::{interval, Duration};
use tracing::{debug, warn};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Serialize)]
struct HeartbeatPayload {
    agent_id:  String,
    hostname:  String,
    agent_version: String,
    timestamp: chrono::DateTime<Utc>,
    metrics:   Metrics,
}

/// Live host resource utilisation sampled at beat time.
#[derive(Serialize, Default)]
struct Metrics {
    cpu_usage_pct:    f32,
    cpu_logical_cores: usize,
    memory_total_mb:  u64,
    memory_used_mb:   u64,
    memory_used_pct:  f32,
    swap_total_mb:    u64,
    swap_used_mb:     u64,
    disk_total_mb:    u64,
    disk_used_mb:     u64,
    disk_used_pct:    f32,
    load_avg:         [f64; 3],
    uptime_secs:      u64,
    process_count:    usize,
}

pub struct Heartbeat {
    client:        reqwest::Client,
    heartbeat_url: String,
    token:         String,
    agent_id:      String,
    hostname:      String,
    /// `System` is reused across beats so CPU deltas are meaningful.
    sys:           Mutex<System>,
}

impl Heartbeat {
    pub fn new(
        backend_url: &str,
        agent_id:    String,
        token:       String,
        hostname:    String,
    ) -> Self {
        let base = crate::http::normalize_base_url(backend_url);
        Self {
            client:        crate::http::control_client(),
            heartbeat_url: format!("{base}/api/v1/agents/{agent_id}/heartbeat"),
            token,
            agent_id,
            hostname,
            sys:           Mutex::new(System::new()),
        }
    }

    pub async fn run(self) {
        let mut ticker = interval(HEARTBEAT_INTERVAL);
        loop {
            ticker.tick().await;
            self.send().await;
        }
    }

    async fn send(&self) {
        let metrics = self.sample_metrics();
        let payload = HeartbeatPayload {
            agent_id:  self.agent_id.clone(),
            hostname:  self.hostname.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: Utc::now(),
            metrics,
        };
        match self
            .client
            .post(&self.heartbeat_url)
            .bearer_auth(&self.token)
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                debug!("Heartbeat sent successfully");
            }
            Ok(resp) => {
                warn!("Heartbeat rejected by backend: HTTP {}", resp.status());
            }
            Err(e) => {
                warn!("Heartbeat request failed: {e}");
            }
        }
    }

    fn sample_metrics(&self) -> Metrics {
        let mut sys = match self.sys.lock() {
            Ok(s) => s,
            Err(_) => return Metrics::default(),
        };

        sys.refresh_cpu();
        sys.refresh_memory();

        let cpu_usage = sys.global_cpu_info().cpu_usage();
        let cpu_cores = sys.cpus().len();

        let mem_total = sys.total_memory();
        let mem_used = sys.used_memory();
        let swap_total = sys.total_swap();
        let swap_used = sys.used_swap();
        let proc_count = count_processes();

        // Root filesystem usage (the disk backing "/").
        let (disk_total, disk_avail) = root_disk_bytes();
        let disk_used = disk_total.saturating_sub(disk_avail);

        let load = System::load_average();

        Metrics {
            cpu_usage_pct: cpu_usage,
            cpu_logical_cores: cpu_cores,
            memory_total_mb: mem_total / 1024 / 1024,
            memory_used_mb: mem_used / 1024 / 1024,
            memory_used_pct: pct(mem_used, mem_total),
            swap_total_mb: swap_total / 1024 / 1024,
            swap_used_mb: swap_used / 1024 / 1024,
            disk_total_mb: disk_total / 1024 / 1024,
            disk_used_mb: disk_used / 1024 / 1024,
            disk_used_pct: pct(disk_used, disk_total),
            load_avg: [load.one, load.five, load.fifteen],
            uptime_secs: System::uptime(),
            process_count: proc_count,
        }
    }
}

/// Total + available bytes of the filesystem mounted at `/`.
fn root_disk_bytes() -> (u64, u64) {
    let disks = Disks::new_with_refreshed_list();
    disks
        .iter()
        .find(|d| d.mount_point().to_string_lossy() == "/")
        .map(|d| (d.total_space(), d.available_space()))
        .unwrap_or((0, 0))
}

fn pct(used: u64, total: u64) -> f32 {
    if total == 0 {
        0.0
    } else {
        (used as f64 / total as f64 * 100.0) as f32
    }
}

/// Count running processes by enumerating numeric entries in `/proc`.
/// Cheap and avoids a full sysinfo process refresh on every beat.
fn count_processes() -> usize {
    match std::fs::read_dir("/proc") {
        Ok(rd) => rd
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.bytes().all(|b| b.is_ascii_digit()))
                    .unwrap_or(false)
            })
            .count(),
        Err(_) => 0,
    }
}
