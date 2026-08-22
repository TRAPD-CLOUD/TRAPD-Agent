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

use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde::Serialize;
use sysinfo::{Disks, System};
use tokio::time::{interval, Duration};
use tracing::{debug, warn};

use crate::pipeline::Spool;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Serialize)]
struct HeartbeatPayload {
    agent_id: String,
    hostname: String,
    agent_version: String,
    timestamp: chrono::DateTime<Utc>,
    metrics: Metrics,
}

/// Live host resource utilisation sampled at beat time.
#[derive(Serialize, Default)]
struct Metrics {
    cpu_usage_pct: f32,
    cpu_logical_cores: usize,
    memory_total_mb: u64,
    memory_used_mb: u64,
    memory_used_pct: f32,
    swap_total_mb: u64,
    swap_used_mb: u64,
    disk_total_mb: u64,
    disk_used_mb: u64,
    disk_used_pct: f32,
    load_avg: [f64; 3],
    uptime_secs: u64,
    process_count: usize,
    /// Total events dropped from the backend outbox because the spool was
    /// full (backend unreachable / falling behind) — see
    /// `pipeline::Spool::dropped_total`. Surfaced here so operators can see
    /// telemetry loss on the backend/dashboard side, not just in agent logs.
    spool_dropped_total: u64,
}

/// Attach the spool's cumulative dropped-event count to a sampled `Metrics`.
/// Pulled out as a small pure step so it is unit-testable without the
/// network client `Heartbeat::new` requires.
fn attach_spool_metrics(mut metrics: Metrics, spool: &Mutex<Spool>) -> Metrics {
    metrics.spool_dropped_total = spool.lock().map(|s| s.dropped_total()).unwrap_or(0);
    metrics
}

pub struct Heartbeat {
    client: reqwest::Client,
    heartbeat_url: String,
    token: String,
    agent_id: String,
    hostname: String,
    /// `System` is reused across beats so CPU deltas are meaningful.
    sys: Mutex<System>,
    /// Backend outbox — read-only here, to surface `dropped_total()` on the
    /// beat so operators see telemetry loss on the backend side too.
    spool: Arc<Mutex<Spool>>,
}

impl Heartbeat {
    pub fn new(
        backend_url: &str,
        agent_id: String,
        token: String,
        hostname: String,
        spool: Arc<Mutex<Spool>>,
    ) -> anyhow::Result<Self> {
        let base = crate::http::normalize_base_url(backend_url);
        Ok(Self {
            client: crate::http::control_client()?,
            heartbeat_url: format!("{base}/api/v1/agents/{agent_id}/heartbeat"),
            token,
            agent_id,
            hostname,
            sys: Mutex::new(System::new()),
            spool,
        })
    }

    pub async fn run(self) {
        let mut ticker = interval(HEARTBEAT_INTERVAL);
        loop {
            ticker.tick().await;
            self.send().await;
        }
    }

    async fn send(&self) {
        let metrics = attach_spool_metrics(self.sample_metrics(), &self.spool);
        let payload = HeartbeatPayload {
            agent_id: self.agent_id.clone(),
            hostname: self.hostname.clone(),
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
            spool_dropped_total: 0, // filled in by attach_spool_metrics below
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_field_serializes_as_spool_dropped_total() {
        let metrics = Metrics {
            spool_dropped_total: 42,
            ..Default::default()
        };
        let json = serde_json::to_value(&metrics).unwrap();
        assert_eq!(json["spool_dropped_total"], 42);
    }

    #[test]
    fn attach_spool_metrics_surfaces_the_spools_dropped_total() {
        let spool = Mutex::new(Spool::in_memory(2));
        {
            let mut s = spool.lock().unwrap();
            for _ in 0..5 {
                s.push(dummy_event());
            }
        }
        assert_eq!(
            spool.lock().unwrap().dropped_total(),
            3,
            "sanity: 5 pushes into a cap-2 spool drop 3"
        );

        let metrics = attach_spool_metrics(Metrics::default(), &spool);
        assert_eq!(metrics.spool_dropped_total, 3);
    }

    #[test]
    fn attach_spool_metrics_reports_zero_when_nothing_dropped() {
        let spool = Mutex::new(Spool::in_memory(10));
        spool.lock().unwrap().push(dummy_event());
        let metrics = attach_spool_metrics(Metrics::default(), &spool);
        assert_eq!(metrics.spool_dropped_total, 0);
    }

    fn dummy_event() -> crate::schema::AgentEvent {
        crate::schema::AgentEvent::new(
            uuid::Uuid::new_v4().to_string(),
            "test-host".to_string(),
            crate::schema::EventClass::System,
            crate::schema::EventAction::Snapshot,
            crate::schema::Severity::Info,
            crate::schema::EventData::SystemSnapshot(crate::schema::SystemSnapshotData {
                os: "Linux".to_string(),
                kernel: "6.0.0".to_string(),
                distro: "Test".to_string(),
                cpu_count: 1,
                cpu_usage_pct: 0.0,
                memory_total_mb: 1024,
                memory_used_mb: 512,
                memory_free_mb: 512,
                uptime_secs: 100,
                load_avg: [0.0, 0.0, 0.0],
            }),
        )
    }
}
