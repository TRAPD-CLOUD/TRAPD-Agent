//! Asset inventory reporting.
//!
//! Collects a full asset profile of the host — hardware, OS, network
//! interfaces, installed software packages and local user accounts — and posts
//! it to the backend so it can drive **asset management**:
//!
//!   `POST /api/v1/agents/{agent_id}/inventory`   →  `InventorySnapshot`
//!
//! Cadence: once shortly after startup, then every [`INVENTORY_INTERVAL`].
//! Inventory changes slowly, so a long interval keeps the backend current
//! without noise; the live `CPU/RAM/uptime` metrics ride the faster heartbeat
//! instead (see [`crate::heartbeat`]).
//!
//! Offline behaviour: when the agent has no backend (test mode) the snapshot is
//! written to `<state>/inventory.json` so it can still be inspected locally.
//!
//! Cross-platform: the [`InventorySnapshot`] data model is OS-neutral by design
//! (the future Windows agent fills the same fields from WMI / the registry);
//! only the gathering helpers in this module are Linux-specific.

mod collect;

use std::sync::Arc;
use std::sync::RwLock;

use serde::Serialize;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

use crate::config::AgentConfig;

/// How often a full inventory snapshot is (re)sent.
const INVENTORY_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60); // 6h
/// Small delay after startup before the first snapshot, so the agent has
/// finished initialising and the system has settled.
const STARTUP_DELAY: Duration = Duration::from_secs(15);

// ── Data model (OS-neutral) ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct InventorySnapshot {
    /// Schema version so the backend can evolve the contract safely.
    pub schema_version: u32,
    pub agent_id: String,
    pub device_id: String,
    pub hostname: String,
    pub agent_version: String,
    pub collected_at: chrono::DateTime<chrono::Utc>,
    pub os: OsInfo,
    pub hardware: HardwareInfo,
    pub network: Vec<NetInterface>,
    pub software: SoftwareInventory,
    pub users: Vec<UserAccount>,
    /// Deception recon profile: honeytoken candidates derived deterministically
    /// from the observed context above. The backend turns these into believable
    /// content and ranks them before issuing `deploy_honeytoken` commands.
    pub recon_profile: crate::deception::ReconProfile,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsInfo {
    pub family: String,           // "linux"
    pub name: String,             // "Ubuntu"
    pub version: String,          // "24.04.3 LTS"
    pub pretty_name: String,      // "Ubuntu 24.04.3 LTS"
    pub kernel: String,           // "6.6.87.2-microsoft-standard-WSL2"
    pub arch: String,             // "x86_64"
    pub machine_id: Option<String>,
    pub timezone: Option<String>,
    pub boot_time_unix: u64,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HardwareInfo {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    pub bios_vendor: Option<String>,
    pub bios_version: Option<String>,
    pub chassis: Option<String>,    // "vm" / "laptop" / "desktop" / "server"
    pub virtualization: Option<String>, // "wsl" / "kvm" / "none" …
    pub cpu_model: String,
    pub cpu_physical_cores: usize,
    pub cpu_logical_cores: usize,
    pub memory_total_mb: u64,
    pub swap_total_mb: u64,
    pub disks: Vec<DiskInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskInfo {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub total_mb: u64,
    pub available_mb: u64,
    pub removable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetInterface {
    pub name: String,
    pub mac: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub up: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SoftwareInventory {
    /// Package manager that produced the list ("dpkg", "rpm", "none", …).
    pub source: String,
    pub package_count: usize,
    pub packages: Vec<SoftwarePackage>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SoftwarePackage {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserAccount {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
    /// True if the account can log in (has a real shell + uid >= 1000 or root).
    pub is_human: bool,
}

// ── Reporter ────────────────────────────────────────────────────────────────

pub struct InventoryReporter {
    client: reqwest::Client,
    url: String,
    token: String,
    agent_id: String,
    device_id: String,
    hostname: String,
    /// None in offline mode — snapshot is written locally instead of POSTed.
    offline: bool,
    config: Arc<RwLock<AgentConfig>>,
}

impl InventoryReporter {
    pub fn new(
        backend_url: &str,
        agent_id: String,
        device_id: String,
        token: String,
        hostname: String,
        offline: bool,
        config: Arc<RwLock<AgentConfig>>,
    ) -> Self {
        let base = crate::http::normalize_base_url(backend_url);
        Self {
            client: crate::http::control_client(),
            url: format!("{base}/api/v1/agents/{agent_id}/inventory"),
            token,
            agent_id,
            device_id,
            hostname,
            offline,
            config,
        }
    }

    pub async fn run(self) {
        let mut ticker = interval(INVENTORY_INTERVAL);

        tokio::time::sleep(STARTUP_DELAY).await;
        self.collect_and_report().await;

        loop {
            ticker.tick().await;
            self.collect_and_report().await;
        }
    }

    async fn collect_and_report(&self) {
        if !self.inventory_enabled() {
            return;
        }

        // Gathering touches the filesystem and shells out to the package
        // manager, so run it on the blocking pool.
        let agent_id = self.agent_id.clone();
        let device_id = self.device_id.clone();
        let hostname = self.hostname.clone();
        let snapshot = match tokio::task::spawn_blocking(move || {
            collect::gather(agent_id, device_id, hostname)
        })
        .await
        {
            Ok(s) => s,
            Err(e) => {
                warn!("inventory: gather task panicked: {e}");
                return;
            }
        };

        info!(
            packages = snapshot.software.package_count,
            disks = snapshot.hardware.disks.len(),
            interfaces = snapshot.network.len(),
            "inventory: snapshot collected"
        );

        if self.offline {
            self.write_local(&snapshot);
        } else {
            self.post(&snapshot).await;
        }
    }

    fn inventory_enabled(&self) -> bool {
        self.config.read().map(|c| c.inventory_enabled).unwrap_or(true)
    }

    async fn post(&self, snapshot: &InventorySnapshot) {
        match self
            .client
            .post(&self.url)
            .bearer_auth(&self.token)
            .json(snapshot)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                info!("inventory: snapshot sent to backend");
            }
            Ok(resp) => warn!("inventory: backend rejected snapshot: HTTP {}", resp.status()),
            Err(e) => warn!("inventory: send failed: {e}"),
        }
    }

    fn write_local(&self, snapshot: &InventorySnapshot) {
        let path = crate::paths::state_dir().join("inventory.json");
        match serde_json::to_vec_pretty(snapshot) {
            Ok(bytes) => match crate::paths::write_atomic(&path, &bytes, 0o600) {
                Ok(()) => info!(path = %path.display(), "inventory: snapshot written locally (offline)"),
                Err(e) => warn!("inventory: local write failed: {e}"),
            },
            Err(e) => warn!("inventory: serialize failed: {e}"),
        }
    }
}
