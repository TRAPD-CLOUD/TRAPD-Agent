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
pub mod compliance;

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
    /// Security posture baseline: SUID/SGID binaries, file capabilities,
    /// listening ports and loaded kernel modules — the attack-surface snapshot a
    /// Falcon-class sensor maintains so the backend can diff against it.
    pub security_posture: SecurityPosture,
    /// Deception recon profile: honeytoken candidates derived deterministically
    /// from the observed context above. The backend turns these into believable
    /// content and ranks them before issuing `deploy_honeytoken` commands.
    pub recon_profile: crate::deception::ReconProfile,
    /// Vulnerability & compliance assessment: CycloneDX SBOM, CVE correlation
    /// against the local feed, and CIS-style host-hardening checks.
    pub compliance: compliance::ComplianceReport,
}

/// Host attack-surface baseline. Every field is a point-in-time inventory the
/// backend can diff: a new SUID binary, a freshly-opened listening port or an
/// unsigned kernel module appearing between snapshots is a high-value signal.
#[derive(Debug, Clone, Serialize, Default)]
pub struct SecurityPosture {
    /// Binaries carrying the setuid / setgid bit (privilege-escalation surface).
    pub suid_sgid: Vec<SuidSgidBinary>,
    /// Files carrying Linux file capabilities (`security.capability` xattr).
    pub file_capabilities: Vec<FileCapability>,
    /// Sockets in the LISTEN state (TCP) or bound (UDP) — the network surface.
    pub listening_ports: Vec<ListeningPort>,
    /// Loaded kernel modules with their taint/signature status (rootkit surface).
    pub kernel_modules: Vec<KernelModule>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuidSgidBinary {
    pub path: String,
    /// Octal mode string, e.g. `"4755"`.
    pub mode: String,
    pub setuid: bool,
    pub setgid: bool,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub size: u64,
    /// SHA256 of the binary (`sha256:<hex>`), for reputation matching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileCapability {
    pub path: String,
    /// Human-readable capability set, e.g. `"cap_net_raw,cap_net_admin+ep"`.
    pub capabilities: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListeningPort {
    pub protocol: String, // "tcp" | "tcp6" | "udp" | "udp6"
    pub address: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KernelModule {
    pub name: String,
    /// Memory size in bytes (from `/proc/modules`).
    pub size: u64,
    /// Module load state (`Live`, `Loading`, `Unloading`).
    pub state: String,
    /// Signature status derived from the kernel taint flags / sysfs:
    /// `signed`, `unsigned`, or `unknown`.
    pub signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsInfo {
    pub family: String,      // "linux"
    pub name: String,        // "Ubuntu"
    pub version: String,     // "24.04.3 LTS"
    pub pretty_name: String, // "Ubuntu 24.04.3 LTS"
    pub kernel: String,      // "6.6.87.2-microsoft-standard-WSL2"
    pub arch: String,        // "x86_64"
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
    pub chassis: Option<String>, // "vm" / "laptop" / "desktop" / "server"
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
    ) -> anyhow::Result<Self> {
        let base = crate::http::normalize_base_url(backend_url);
        // The inventory reporter runs in BOTH modes; offline it only writes a
        // local snapshot and never touches `client`. Build a fail-closed,
        // pinned control client only when online — so a pinning misconfig never
        // breaks pure-offline telemetry, while online stays fail-closed.
        let client = if offline {
            reqwest::Client::new()
        } else {
            crate::http::control_client()?
        };
        Ok(Self {
            client,
            url: format!("{base}/api/v1/agents/{agent_id}/inventory"),
            token,
            agent_id,
            device_id,
            hostname,
            offline,
            config,
        })
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
        let flags = self
            .config
            .read()
            .map(|c| compliance::ComplianceFlags {
                vuln_scan: c.vuln_scan_enabled,
                cis: c.cis_benchmark_enabled,
            })
            .unwrap_or_default();
        let snapshot = match tokio::task::spawn_blocking(move || {
            collect::gather_with_flags(agent_id, device_id, hostname, flags)
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
        self.config
            .read()
            .map(|c| c.inventory_enabled)
            .unwrap_or(true)
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
            Ok(resp) => warn!(
                "inventory: backend rejected snapshot: HTTP {}",
                resp.status()
            ),
            Err(e) => warn!("inventory: send failed: {e}"),
        }
    }

    fn write_local(&self, snapshot: &InventorySnapshot) {
        let path = crate::paths::state_dir().join("inventory.json");
        match serde_json::to_vec_pretty(snapshot) {
            Ok(bytes) => match crate::paths::write_atomic(&path, &bytes, 0o600) {
                Ok(()) => {
                    info!(path = %path.display(), "inventory: snapshot written locally (offline)")
                }
                Err(e) => warn!("inventory: local write failed: {e}"),
            },
            Err(e) => warn!("inventory: serialize failed: {e}"),
        }
    }
}
