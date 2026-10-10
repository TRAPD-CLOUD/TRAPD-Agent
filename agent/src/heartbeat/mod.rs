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

pub mod lifecycle;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use chrono::Utc;
use serde::Serialize;
use sysinfo::{Disks, System};
use tokio::time::Duration;
use tracing::{debug, warn};

use crate::config::AgentConfig;

/// Fallback cadence when the config lock is poisoned.
const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 30;

#[derive(Serialize)]
struct HeartbeatPayload {
    agent_id: String,
    hostname: String,
    agent_version: String,
    timestamp: chrono::DateTime<Utc>,
    metrics: Metrics,
    /// Seconds since this agent process started (not host uptime).
    agent_uptime_seconds: u64,
    /// RFC 3339 start time of this agent process, i.e. the last (re)start.
    agent_last_restart: String,
    /// How the previous run ended: clean, unclean (killed/crashed) or unknown.
    previous_shutdown: lifecycle::PreviousShutdown,
    /// Delivery accounting since process start, to verify loss after outages.
    pipeline: PipelineCounters,
    /// What the sensors can currently see (empty object when unknown).
    coverage: crate::telemetry::coverage::Coverage,
    /// Findings of shadow-mode rules since the last accepted beat.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    shadow_hits: std::collections::BTreeMap<String, u64>,
}

/// Cumulative (since process start) event accounting. For every accepted
/// event exactly one of acknowledged / still queued / dropped holds, so
/// `produced - dropped_total - acknowledged == queued` can be checked by the
/// backend per heartbeat. Counters reset on a restart; `agent_last_restart`
/// tells the reader when.
#[derive(Serialize, Debug, PartialEq, Eq)]
struct PipelineCounters {
    /// Events accepted by the pipeline.
    produced: u64,
    /// Per-sensor split of `produced`, keyed by event class.
    produced_by_class: BTreeMap<String, u64>,
    /// Events accepted into the delivery queue.
    spooled: u64,
    /// Events put on the wire (attempts; a retry counts again).
    sent: u64,
    /// Events the backend confirmed durable.
    acked: u64,
    /// Events discarded, all reasons.
    dropped_total: u64,
    dropped_by_reason: BTreeMap<String, u64>,
    /// Detection/prevention events lost to queue overflow (subset of dropped).
    priority_evicted: u64,
    /// Events recovered from the on-disk queue at start (replayed after a restart).
    replayed_from_disk: u64,
    /// Events re-queued for another attempt after a failed send.
    retried: u64,
    /// Current queue depth / bytes / age of the oldest queued event.
    queued: u64,
    queued_bytes: u64,
    oldest_queued_age_ms: u64,
}

impl PipelineCounters {
    fn from_snapshot(s: &crate::telemetry::metrics::MetricsSnapshot) -> Self {
        Self {
            produced: s.collector_events_received_total,
            produced_by_class: s.events_by_class.clone(),
            spooled: s.spool_accepted_total,
            sent: s.transport_events_sent_total,
            acked: s.transport_events_acknowledged_total,
            dropped_total: s.collector_events_dropped_total,
            dropped_by_reason: s.collector_events_dropped_by_reason.clone(),
            priority_evicted: s.spool_priority_evicted_total,
            replayed_from_disk: s.spool_recovered_records_total,
            retried: s.transport_events_retried_total,
            queued: s.spool_events,
            queued_bytes: s.spool_bytes,
            oldest_queued_age_ms: s.spool_oldest_event_age_ms,
        }
    }
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
}

pub struct Heartbeat {
    client: reqwest::Client,
    heartbeat_url: String,
    token: String,
    agent_id: String,
    hostname: String,
    /// Live agent config; `heartbeat_interval_secs` is re-read every beat so a
    /// backend-delivered change takes effect without a restart.
    config: Arc<RwLock<AgentConfig>>,
    /// `System` is reused across beats so CPU deltas are meaningful.
    sys: Mutex<System>,
}

impl Heartbeat {
    pub fn new(
        backend_url: &str,
        agent_id: String,
        token: String,
        hostname: String,
        config: Arc<RwLock<AgentConfig>>,
    ) -> anyhow::Result<Self> {
        let base = crate::http::normalize_base_url(backend_url);
        // Idempotent; guarantees the start time exists even if the caller
        // forgot to record it earlier.
        lifecycle::begin_process();
        Ok(Self {
            client: crate::http::control_client()?,
            heartbeat_url: format!("{base}/api/v1/agents/{agent_id}/heartbeat"),
            token,
            agent_id,
            hostname,
            config,
            sys: Mutex::new(System::new()),
        })
    }

    pub async fn run(self) {
        // Beat immediately on startup, then on the configured cadence (floored
        // at 5s so a bad config cannot flood the backend).
        loop {
            self.send().await;
            let secs = self
                .config
                .read()
                .map(|c| c.heartbeat_interval_secs)
                .unwrap_or(DEFAULT_HEARTBEAT_INTERVAL_SECS)
                .max(5);
            tokio::time::sleep(Duration::from_secs(secs)).await;
        }
    }

    async fn send(&self) {
        let metrics = self.sample_metrics();
        let life = lifecycle::begin_process();
        let payload = HeartbeatPayload {
            agent_id: self.agent_id.clone(),
            hostname: self.hostname.clone(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: Utc::now(),
            metrics,
            agent_uptime_seconds: life.uptime_seconds(),
            agent_last_restart: life.last_restart(),
            previous_shutdown: life.previous_shutdown(),
            pipeline: PipelineCounters::from_snapshot(
                &crate::telemetry::metrics::metrics().snapshot(),
            ),
            coverage: crate::telemetry::coverage::snapshot(),
            shadow_hits: crate::telemetry::coverage::take_shadow_hits(),
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
                crate::update::confirm_healthy();
            }
            Ok(resp) => {
                warn!("Heartbeat rejected by backend: HTTP {}", resp.status());
                crate::telemetry::coverage::restore_shadow_hits(payload.shadow_hits);
            }
            Err(e) => {
                warn!("Heartbeat request failed: {e}");
                crate::telemetry::coverage::restore_shadow_hits(payload.shadow_hits);
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

/// Total + available bytes of the filesystem backing the OS — `/` on unix,
/// the system drive (`C:\` unless relocated) on Windows.
fn root_disk_bytes() -> (u64, u64) {
    #[cfg(windows)]
    let root = std::env::var("SystemDrive")
        .map(|d| format!("{d}\\"))
        .unwrap_or_else(|_| "C:\\".to_string());
    #[cfg(not(windows))]
    let root = "/".to_string();

    let disks = Disks::new_with_refreshed_list();
    disks
        .iter()
        .find(|d| d.mount_point().to_string_lossy() == root)
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
#[cfg(target_os = "linux")]
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

/// No `/proc` here — take a one-shot sysinfo process refresh instead.
#[cfg(not(target_os = "linux"))]
fn count_processes() -> usize {
    use sysinfo::{ProcessRefreshKind, RefreshKind};
    System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()))
        .processes()
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::metrics::MetricsSnapshot;

    #[test]
    fn pipeline_counters_mirror_the_metrics_snapshot() {
        let snap = MetricsSnapshot {
            collector_events_received_total: 10,
            events_by_class: BTreeMap::from([
                ("process".to_string(), 7),
                ("network".to_string(), 3),
            ]),
            spool_accepted_total: 9,
            transport_events_sent_total: 8,
            transport_events_acknowledged_total: 6,
            collector_events_dropped_total: 1,
            collector_events_dropped_by_reason: BTreeMap::from([(
                "persistent_queue_full".to_string(),
                1,
            )]),
            spool_events: 3,
            ..Default::default()
        };
        let c = PipelineCounters::from_snapshot(&snap);
        assert_eq!(c.produced, 10);
        assert_eq!(c.produced_by_class["process"], 7);
        assert_eq!((c.spooled, c.sent, c.acked, c.queued), (9, 8, 6, 3));
        assert_eq!(c.dropped_by_reason["persistent_queue_full"], 1);
        // The invariant the backend can check per heartbeat.
        assert_eq!(c.produced, c.acked + c.queued + c.dropped_total);
    }

    #[test]
    fn payload_carries_the_agent_lifecycle_fields() {
        let json =
            serde_json::to_value(PipelineCounters::from_snapshot(&MetricsSnapshot::default()))
                .unwrap();
        for k in [
            "produced",
            "spooled",
            "sent",
            "acked",
            "dropped_total",
            "replayed_from_disk",
            "queued",
        ] {
            assert!(json.get(k).is_some(), "missing {k}");
        }
        assert_eq!(
            serde_json::to_value(lifecycle::PreviousShutdown::Unclean).unwrap(),
            "unclean"
        );
    }
}
