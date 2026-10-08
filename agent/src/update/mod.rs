//! Signed, rollback-protected agent self-update.
//!
//! Flow: the agent polls the backend for an update offer ([`Updater`]),
//! verifies it ([`manifest`]), downloads and hash-checks the artifact
//! ([`download`]) into `<state>/update/`, then hands over to a separate helper
//! process ([`run_apply_helper`], `trapd-agent --apply-update`) that re-verifies,
//! swaps the binary, restarts the service and rolls back if the new version
//! does not report healthy ([`apply`]).

pub mod apply;
pub mod download;
pub mod manifest;
#[cfg(windows)]
pub mod windows;

use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::{error, info, warn};

#[cfg(target_os = "linux")]
use apply::Platform;
use apply::{apply_staged, ApplyContext, Outcome};
use apply::{StagingPaths, UpdateState};
use manifest::{verify_offer, UpdateOffer, VerifyContext};

const CHECK_INTERVAL: Duration = Duration::from_secs(3600);
/// A staged update younger than this is considered in flight.
const STAGED_RETRY_AFTER: Duration = Duration::from_secs(6 * 3600);
/// How long the helper waits for the new version's first good heartbeat.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(120);

/// Where the release public key lives.
///
/// On Linux this is deliberately **outside** `/etc/trapd`: that directory is in
/// the agent unit's `ReadWritePaths`, so a compromised agent could replace a key
/// kept there (and `command_signing.pub`, which is also agent-writable) and get a
/// self-signed update installed by the root helper. `/etc/trapd-release` is
/// read-only for the agent under `ProtectSystem=strict`, so forging an update
/// needs the real release key. Override with `TRAPD_RELEASE_KEY_DIR` (tests,
/// non-standard layouts).
fn release_pubkey_path() -> std::path::PathBuf {
    let dir = std::env::var_os("TRAPD_RELEASE_KEY_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            if cfg!(target_os = "linux") {
                std::path::PathBuf::from("/etc/trapd-release")
            } else {
                crate::paths::config_dir().to_path_buf()
            }
        });
    dir.join("release_signing.pub")
}

fn staging() -> StagingPaths {
    StagingPaths::new(crate::paths::state_dir())
}

pub struct Updater {
    control: reqwest::Client,
    download: reqwest::Client,
    update_url: String,
    token: String,
    agent_id: String,
    release_key: ed25519_dalek::VerifyingKey,
    command_key: ed25519_dalek::VerifyingKey,
    paths: StagingPaths,
}

impl Updater {
    /// Fails closed: without both pinned keys no update is ever accepted, and
    /// the caller should simply not start the updater.
    pub fn new(backend_url: &str, agent_id: String, token: String) -> Result<Self> {
        let release_key = crate::prevention::commands::load_verifying_key(&release_pubkey_path())
            .context("update: release signing key unavailable")?;
        let command_key = crate::prevention::commands::load_verifying_key(
            &crate::prevention::command_pubkey_path(),
        )
        .context("update: command signing key unavailable")?;
        let base = crate::http::normalize_base_url(backend_url);
        Ok(Self {
            control: crate::http::control_client()?,
            download: download::download_client()?,
            update_url: format!("{base}/api/v1/agents/{agent_id}/update"),
            token,
            agent_id,
            release_key,
            command_key,
            paths: staging(),
        })
    }

    pub async fn run(self) {
        // Stagger fleets so every agent does not poll on the hour.
        let jitter = Duration::from_secs(u64::from(rand_u32() % 300));
        tokio::time::sleep(jitter).await;
        loop {
            if let Err(e) = self.check_once().await {
                warn!(error = %e, "update: check failed");
            }
            tokio::time::sleep(CHECK_INTERVAL + jitter).await;
        }
    }

    async fn check_once(&self) -> Result<()> {
        // A failed stop/restore/restart must keep its original signed offer and
        // artifact. A later release cannot supersede an unfinished recovery.
        if self.paths.recovery().exists() {
            #[cfg(windows)]
            if !file_is_fresh(&self.paths.recovery(), Duration::from_secs(300)) {
                windows::spawn_apply_helper(&self.paths.dir)
                    .context("update: relaunch pending recovery helper")?;
            }
            return Ok(());
        }

        // The replay watermark already covers this offer. Windows must retry
        // its staged artifact directly, before the fresh-offer skip or polling
        // for a directive that would be rejected as a replay.
        #[cfg(windows)]
        if resume_staged_update(&self.paths, windows::spawn_apply_helper)? {
            return Ok(());
        }

        // Linux's path unit watches a staged offer. Avoid re-downloading it
        // while the helper is expected to run; stale staging may be re-offered.
        // Windows relaunches its existing artifact in the branch above.
        if staged_within(&self.paths, STAGED_RETRY_AFTER) {
            return Ok(());
        }
        let state = UpdateState::load(&self.paths);
        let mut req = self
            .control
            .get(&self.update_url)
            .bearer_auth(&self.token)
            .query(&[
                ("version", env!("CARGO_PKG_VERSION")),
                ("os", std::env::consts::OS),
                ("arch", std::env::consts::ARCH),
            ]);
        if let Some(bad) = &state.blocked_version {
            // Lets the backend pause a rollout that fails on real hosts.
            req = req.query(&[("last_failed", bad.as_str())]);
        }
        let resp = req.send().await.context("update: offer request failed")?;
        match resp.status().as_u16() {
            204 => return Ok(()),
            200 => {}
            s => anyhow::bail!("update: offer endpoint returned HTTP {s}"),
        }
        let offer: UpdateOffer = resp.json().await.context("update: malformed offer")?;

        let ctx = VerifyContext {
            release_key: &self.release_key,
            command_key: &self.command_key,
            agent_id: &self.agent_id,
            current_version: env!("CARGO_PKG_VERSION"),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            last_issued_at: state.last_issued_at,
        };
        let verified = match verify_offer(&offer, &ctx) {
            Ok(v) => v,
            Err(reason) => {
                // A rejected offer is a security signal, not a routine miss.
                error!(%reason, "update: offer rejected");
                return Ok(());
            }
        };
        if state.blocked_version.as_deref() == Some(verified.version.as_str()) {
            warn!(version = %verified.version, "update: version previously failed its health check, skipping");
            return Ok(());
        }

        info!(version = %verified.version, "update: downloading verified release");
        std::fs::create_dir_all(&self.paths.dir)?;
        // Offer file is written last: it is what triggers the apply helper.
        let _ = std::fs::remove_file(self.paths.offer());
        let _ = std::fs::remove_file(self.paths.ebpf_artifact());
        let main = manifest::VerifiedArtifact {
            url: verified.url.clone(),
            sha256: verified.sha256,
            size: verified.size,
        };
        download::download_verified(&self.download, &main, &self.paths.artifact()).await?;
        if let Some(ebpf) = &verified.ebpf {
            download::download_verified(&self.download, ebpf, &self.paths.ebpf_artifact()).await?;
        }

        // Advance the replay watermark only once the artifact is safely staged,
        // so a transient download failure can retry the same offer.
        UpdateState {
            last_issued_at: verified.issued_at,
            ..state
        }
        .save(&self.paths)?;
        crate::paths::write_atomic(
            &self.paths.offer(),
            serde_json::to_string(&serde_json::json!({
                "payload": offer.payload, "signature": offer.signature,
            }))?
            .as_bytes(),
            0o600,
        )?;
        info!(version = %verified.version, "update: staged, waiting for the apply helper");
        // Linux has a root path unit watching the staged offer; Windows has no
        // equivalent, so the service starts the helper itself. The helper
        // re-verifies everything, so launching it grants a compromised agent
        // nothing it could not already stage.
        #[cfg(windows)]
        if let Err(e) = windows::spawn_apply_helper(&self.paths.dir) {
            warn!(error = %e, "update: could not start the apply helper; the staged update is retried later");
        }
        Ok(())
    }
}

/// Resume a Windows staged update after a failed launch or an early helper
/// exit. The helper re-verifies the existing offer, replay watermark and bytes;
/// retrying never changes the accepted directive or download state.
#[cfg_attr(not(windows), allow(dead_code))]
fn resume_staged_update(
    paths: &StagingPaths,
    launch: impl FnOnce(&std::path::Path) -> Result<()>,
) -> Result<bool> {
    if paths.recovery().exists() || !paths.offer().is_file() {
        return Ok(false);
    }
    launch(&paths.dir).context("update: relaunch staged apply helper")?;
    Ok(true)
}

fn staged_within(paths: &StagingPaths, window: Duration) -> bool {
    paths.recovery().exists() || file_is_fresh(&paths.offer(), window)
}

fn file_is_fresh(path: &std::path::Path, window: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|age| age < window)
        .unwrap_or(false)
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    let _ = getrandom::fill(&mut b);
    u32::from_le_bytes(b)
}

/// Whether a verified update is staged or being applied. Other components use
/// it to tell the update helper's file changes from tampering.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn update_in_flight() -> bool {
    staging().offer().exists()
}

/// Called by the heartbeat after a successful beat. While an update is being
/// applied (staged offer still present) this tells the helper that the new
/// version came up and can reach the backend.
pub fn confirm_healthy() {
    let paths = staging();
    if !paths.offer().exists() {
        return;
    }
    let version = env!("CARGO_PKG_VERSION");
    if std::fs::read_to_string(paths.healthy_marker())
        .map(|v| v.trim() == version)
        .unwrap_or(false)
    {
        return;
    }
    if let Err(e) = crate::paths::write_atomic(&paths.healthy_marker(), version.as_bytes(), 0o600) {
        warn!(error = %e, "update: could not write health marker");
    }
}

#[cfg(target_os = "linux")]
struct SystemdPlatform;

#[cfg(target_os = "linux")]
impl Platform for SystemdPlatform {
    fn restart_service(&self) -> Result<()> {
        let status = std::process::Command::new("systemctl")
            .args(["restart", "trapd-agent.service"])
            .status()
            .context("update: run systemctl")?;
        anyhow::ensure!(status.success(), "systemctl restart exited with {status}");
        Ok(())
    }
}

#[derive(Deserialize)]
struct CredentialsFile {
    agent_id: String,
}

/// `trapd-agent --apply-update`: run by a root unit (Linux) or spawned by the
/// service (Windows). Applies the staged update, or rolls it back.
pub fn run_apply_helper() -> Result<()> {
    let paths = staging();
    if !paths.offer().exists() {
        info!("update: nothing staged");
        return Ok(());
    }
    let agent_id = std::fs::read(crate::paths::credentials_file())
        .ok()
        .and_then(|b| serde_json::from_slice::<CredentialsFile>(&b).ok())
        .context("update: cannot read agent credentials")?
        .agent_id;
    let release_key = crate::prevention::commands::load_verifying_key(&release_pubkey_path())?;
    let command_key =
        crate::prevention::commands::load_verifying_key(&crate::prevention::command_pubkey_path())?;

    // Linux replaces the binary the helper itself runs from; Windows runs the
    // helper from a copy and takes the install path from the SCM.
    #[cfg(target_os = "linux")]
    let target = std::env::current_exe().context("update: locate running binary")?;
    #[cfg(windows)]
    let target = windows::installed_binary_path()?;

    // Where `install.sh` puts the eBPF object (first entry of the loaders' search
    // path). Overridable for non-standard layouts. Linux only.
    #[cfg(target_os = "linux")]
    let ebpf_target = Some(
        std::env::var_os("TRAPD_EBPF_INSTALL_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("/usr/lib/trapd-agent/trapd-agent-exec")),
    );
    #[cfg(not(target_os = "linux"))]
    let ebpf_target: Option<std::path::PathBuf> = None;

    let baseline = crate::selfprotect::binary_integrity::hash_store_path();

    let ctx = ApplyContext {
        verify: VerifyContext {
            release_key: &release_key,
            command_key: &command_key,
            agent_id: &agent_id,
            current_version: env!("CARGO_PKG_VERSION"),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            last_issued_at: 0,
        },
        target: &target,
        ebpf_target: ebpf_target.as_deref(),
        baseline: Some(&baseline),
        paths: &paths,
        health_timeout: HEALTH_TIMEOUT,
    };
    #[cfg(target_os = "linux")]
    let platform = SystemdPlatform;
    #[cfg(windows)]
    let platform = windows::ScmPlatform;
    match apply_staged(&ctx, &platform)? {
        Outcome::Applied { version } => info!(%version, "update: applied"),
        Outcome::RolledBack { attempted } => error!(%attempted, "update: rolled back"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_helper_launch_failure_retries_without_changing_replay_watermark() {
        let paths = StagingPaths {
            dir: std::env::temp_dir().join(format!("trapd-relaunch-{}", uuid::Uuid::new_v4())),
        };
        std::fs::create_dir_all(&paths.dir).unwrap();
        std::fs::write(paths.offer(), b"existing signed offer").unwrap();
        std::fs::write(paths.artifact(), b"existing verified artifact").unwrap();
        UpdateState {
            last_issued_at: 500,
            blocked_version: None,
        }
        .save(&paths)
        .unwrap();
        assert!(staged_within(&paths, STAGED_RETRY_AFTER));
        assert!(resume_staged_update(&paths, |dir| {
            assert_eq!(dir, paths.dir);
            anyhow::bail!("process launch failed")
        })
        .is_err());
        let launched = std::cell::Cell::new(false);
        assert!(resume_staged_update(&paths, |dir| {
            assert_eq!(dir, paths.dir);
            launched.set(true);
            Ok(())
        })
        .unwrap());
        assert!(launched.get());
        // Also retry an early helper exit before it can create recovery.json.
        assert!(!paths.recovery().exists());
        assert!(resume_staged_update(&paths, |_| Ok(())).unwrap());
        assert_eq!(UpdateState::load(&paths).last_issued_at, 500);
        assert_eq!(
            std::fs::read(paths.offer()).unwrap(),
            b"existing signed offer"
        );
        assert_eq!(
            std::fs::read(paths.artifact()).unwrap(),
            b"existing verified artifact"
        );
        std::fs::remove_dir_all(paths.dir).unwrap();
    }

    #[test]
    fn staged_helper_retry_does_not_replace_pending_recovery_or_poll_empty_staging() {
        let paths = StagingPaths {
            dir: std::env::temp_dir().join(format!("trapd-relaunch-{}", uuid::Uuid::new_v4())),
        };
        std::fs::create_dir_all(&paths.dir).unwrap();
        assert!(!resume_staged_update(&paths, |_| panic!("no offer to apply")).unwrap());
        std::fs::write(paths.offer(), b"offer").unwrap();
        std::fs::write(paths.recovery(), b"recovery").unwrap();
        assert!(!resume_staged_update(&paths, |_| panic!(
            "recovery has a separate guarded launch path"
        ))
        .unwrap());
        assert_eq!(std::fs::read(paths.recovery()).unwrap(), b"recovery");
        std::fs::remove_dir_all(paths.dir).unwrap();
    }

    #[test]
    fn pending_recovery_never_expires_into_a_new_download() {
        let dir =
            std::env::temp_dir().join(format!("trapd-recovery-test-{}", uuid::Uuid::new_v4()));
        let paths = StagingPaths { dir };
        std::fs::create_dir_all(&paths.dir).unwrap();
        std::fs::write(paths.offer(), b"{}").unwrap();
        std::fs::write(paths.recovery(), b"{}").unwrap();
        assert!(
            staged_within(&paths, Duration::ZERO),
            "recovery must preserve its signed offer indefinitely"
        );
        std::fs::remove_dir_all(paths.dir).unwrap();
    }

    #[test]
    fn staged_update_is_in_flight_only_while_fresh() {
        let dir = std::env::temp_dir().join(format!("trapd-staged-test-{}", uuid::Uuid::new_v4()));
        let paths = StagingPaths { dir };
        std::fs::create_dir_all(&paths.dir).unwrap();

        assert!(
            !staged_within(&paths, Duration::from_secs(60)),
            "nothing staged"
        );
        std::fs::write(paths.offer(), b"{}").unwrap();
        assert!(staged_within(&paths, Duration::from_secs(60)));
        assert!(
            !staged_within(&paths, Duration::ZERO),
            "expired window retries"
        );
    }
}
