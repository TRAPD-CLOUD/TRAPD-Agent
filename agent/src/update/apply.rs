//! Applying a staged update: swap the binary, restart, confirm health, roll
//! back on failure.
//!
//! This runs in a **helper process**, never inside the service that is being
//! replaced. The helper is the *old* binary invoked as `trapd-agent
//! --apply-update`: it is known good, it keeps running from its own inode/handle
//! after the swap, and it can therefore watch the new binary and put the old
//! one back. On Linux the hardened unit mounts `/usr/local/bin` read-only for
//! the agent (`ProtectSystem=strict`), so the helper is started by a separate
//! root unit; the agent itself can only *stage* an update.
//!
//! The helper does not trust the staged files: it re-verifies both signatures
//! and the artifact digest before touching the install path, so a compromised
//! agent process cannot get an arbitrary binary installed by writing to the
//! staging directory.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::manifest::{verify_offer, UpdateOffer, VerifyContext};

/// Files under `<state>/update/`.
pub struct StagingPaths {
    pub dir: PathBuf,
}

impl StagingPaths {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            dir: state_dir.join("update"),
        }
    }
    pub fn artifact(&self) -> PathBuf {
        self.dir.join("staged.bin")
    }
    pub fn ebpf_artifact(&self) -> PathBuf {
        self.dir.join("staged.ebpf")
    }
    pub fn offer(&self) -> PathBuf {
        self.dir.join("staged.offer.json")
    }
    pub fn state(&self) -> PathBuf {
        self.dir.join("state.json")
    }
    /// Written by the *new* agent after its first successful heartbeat.
    pub fn healthy_marker(&self) -> PathBuf {
        self.dir.join("healthy")
    }
}

/// Persisted update state. `last_issued_at` is the replay watermark.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UpdateState {
    pub last_issued_at: i64,
    /// Version that was installed but failed its health check and was rolled
    /// back. The updater refuses it so a bad release cannot loop forever.
    #[serde(default)]
    pub blocked_version: Option<String>,
}

impl UpdateState {
    pub fn load(paths: &StagingPaths) -> Self {
        std::fs::read(paths.state())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
    pub fn save(&self, paths: &StagingPaths) -> Result<()> {
        crate::paths::write_atomic(&paths.state(), &serde_json::to_vec(self)?, 0o600)
    }
}

pub struct ApplyContext<'a> {
    pub verify: VerifyContext<'a>,
    /// Install path of the running binary.
    pub target: &'a Path,
    /// Install path of the eBPF object (Linux). Required when the update ships
    /// one, since binary and object must be replaced together.
    pub ebpf_target: Option<&'a Path>,
    /// The agent's binary self-integrity baseline (`binary.sha256`). The new
    /// binary has a different hash, so the baseline is rewritten together with
    /// it: the restarted agent aborts on a mismatch (`binary_integrity::check`).
    /// Left alone when the file does not exist, since the agent then writes a
    /// baseline for whatever binary it first runs as.
    pub baseline: Option<&'a Path>,
    pub paths: &'a StagingPaths,
    pub health_timeout: Duration,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Applied { version: String },
    RolledBack { attempted: String },
}

/// Hooks that differ per platform (and are replaced in tests).
pub trait Platform {
    /// Restart the agent service so it picks up the new binary.
    fn restart_service(&self) -> Result<()>;
}

/// Path next to `target` used for the previous version of the file.
pub fn prev_path(target: &Path) -> PathBuf {
    let mut name = target.file_name().unwrap_or_default().to_os_string();
    name.push(".prev");
    target.with_file_name(name)
}

/// Install `new` as `target`, keeping the current file at `prev`.
///
/// Linux: hard-link the current file to `prev`, then atomically rename `new`
/// over `target`, so `target` is never missing. Windows cannot replace a running
/// executable but can rename it, so the swap is two renames.
fn swap_in(target: &Path, new: &Path, prev: &Path) -> Result<()> {
    let _ = std::fs::remove_file(prev);
    #[cfg(unix)]
    {
        std::fs::hard_link(target, prev).context("update: keep previous file")?;
        std::fs::rename(new, target).context("update: install new file")?;
    }
    #[cfg(not(unix))]
    {
        std::fs::rename(target, prev).context("update: keep previous file")?;
        if let Err(e) = std::fs::rename(new, target) {
            let _ = std::fs::rename(prev, target);
            return Err(e).context("update: install new file");
        }
    }
    Ok(())
}

/// A file that was replaced and can be put back.
struct Installed {
    target: PathBuf,
    /// The previous version, or `None` when the file did not exist before.
    prev: Option<PathBuf>,
}

impl Installed {
    fn restore(&self) -> Result<()> {
        match &self.prev {
            Some(prev) => {
                // Both platforms: put the saved file back at the install path.
                #[cfg(not(unix))]
                let _ = std::fs::remove_file(&self.target);
                std::fs::rename(prev, &self.target).context("update: restore previous file")
            }
            None => {
                let _ = std::fs::remove_file(&self.target);
                Ok(())
            }
        }
    }
}

/// Write `bytes` next to `target`, fsync, and swap it in.
fn install_file(target: &Path, bytes: &[u8], mode: u32) -> Result<Installed> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).context("update: create install dir")?;
    }
    // Next to the target, so the final rename stays on one filesystem.
    let new = target.with_file_name(format!(
        ".{}.new",
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("trapd-agent")
    ));
    std::fs::write(&new, bytes).context("update: write new file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    // Windows requires write access for FlushFileBuffers (used by sync_all).
    std::fs::OpenOptions::new()
        .write(true)
        .open(&new)
        .context("update: open new file for sync")?
        .sync_all()
        .context("update: sync new file")?;

    if target.exists() {
        let prev = prev_path(target);
        swap_in(target, &new, &prev)?;
        Ok(Installed {
            target: target.to_path_buf(),
            prev: Some(prev),
        })
    } else {
        std::fs::rename(&new, target).context("update: install new file")?;
        Ok(Installed {
            target: target.to_path_buf(),
            prev: None,
        })
    }
}

/// Put every replaced file back and remember that `version` is bad.
fn abort_update(ctx: &ApplyContext<'_>, installed: &[Installed], version: &str) -> Result<()> {
    // Attempt every restore even if one fails, then report the first error.
    let mut first_err = None;
    for i in installed {
        if let Err(e) = i.restore() {
            tracing::error!(error = %e, target = %i.target.display(), "update: restore failed");
            first_err.get_or_insert(e);
        }
    }
    let mut state = UpdateState::load(ctx.paths);
    state.blocked_version = Some(version.to_string());
    state.save(ctx.paths)?;
    clear_staging(ctx.paths);
    first_err.map_or(Ok(()), Err)
}

fn clear_staging(paths: &StagingPaths) {
    let _ = std::fs::remove_file(paths.artifact());
    let _ = std::fs::remove_file(paths.ebpf_artifact());
    let _ = std::fs::remove_file(paths.offer());
}

/// Read a staged file and require it to match the signed size and digest.
fn read_verified(path: &Path, size: u64, sha256: &[u8; 32], what: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| format!("update: read staged {what}"))?;
    if bytes.len() as u64 != size || Sha256::digest(&bytes).as_slice() != sha256 {
        bail!("update: staged {what} does not match the signed digest");
    }
    Ok(bytes)
}

/// Re-verify the staged update, install it, and wait for the new agent to
/// report healthy; otherwise restore the previous files.
pub fn apply_staged(ctx: &ApplyContext<'_>, platform: &dyn Platform) -> Result<Outcome> {
    let offer_bytes = std::fs::read(ctx.paths.offer()).context("update: read staged offer")?;
    let offer: UpdateOffer =
        serde_json::from_slice(&offer_bytes).context("update: parse staged offer")?;

    // The watermark was advanced when the offer was accepted, so verify as if
    // it were still one below and require the offer to be exactly that one.
    let state = UpdateState::load(ctx.paths);
    let verify = VerifyContext {
        last_issued_at: state.last_issued_at - 1,
        ..clone_ctx(&ctx.verify)
    };
    let verified = verify_offer(&offer, &verify)
        .map_err(|r| anyhow::anyhow!("update: staged offer rejected: {r}"))?;
    if verified.issued_at != state.last_issued_at {
        bail!("update: staged offer is not the most recently accepted one");
    }

    // Everything is read and checked before the first file is touched, so a bad
    // staged file can never leave the host half-updated.
    let bin = read_verified(
        &ctx.paths.artifact(),
        verified.size,
        &verified.sha256,
        "artifact",
    )?;
    let ebpf = match &verified.ebpf {
        None => None,
        Some(spec) => {
            let target = ctx
                .ebpf_target
                .context("update: release ships an eBPF object but no install path is known")?;
            let bytes = read_verified(
                &ctx.paths.ebpf_artifact(),
                spec.size,
                &spec.sha256,
                "eBPF object",
            )?;
            Some((target, bytes))
        }
    };

    let _ = std::fs::remove_file(ctx.paths.healthy_marker());
    let mut installed = Vec::new();
    // Object first: if the binary install then fails, only the object needs undoing.
    if let Some((target, bytes)) = &ebpf {
        installed.push(install_file(target, bytes, 0o644)?);
    }
    match install_file(ctx.target, &bin, 0o755) {
        Ok(i) => installed.push(i),
        Err(e) => {
            let _ = abort_update(ctx, &installed, &verified.version);
            return Err(e);
        }
    }
    // The baseline is the signed digest of the file just installed. It is
    // restored on rollback like the other files; a failed write aborts the
    // update, because the new binary would refuse to start against the old one.
    if let Some(baseline) = ctx.baseline.filter(|p| p.exists()) {
        let line =
            crate::selfprotect::binary_integrity::baseline_line(&hex::encode(verified.sha256));
        match install_file(baseline, line.as_bytes(), 0o600) {
            Ok(i) => installed.push(i),
            Err(e) => {
                let _ = abort_update(ctx, &installed, &verified.version);
                return Err(e).context("update: refresh binary integrity baseline");
            }
        }
    }

    if let Err(e) = platform.restart_service() {
        tracing::error!(error = %e, "update: restart failed, rolling back");
        abort_update(ctx, &installed, &verified.version)?;
        let _ = platform.restart_service();
        return Ok(Outcome::RolledBack {
            attempted: verified.version,
        });
    }

    if wait_for_healthy(ctx.paths, &verified.version, ctx.health_timeout) {
        clear_staging(ctx.paths);
        Ok(Outcome::Applied {
            version: verified.version,
        })
    } else {
        tracing::error!(version = %verified.version, "update: new agent not healthy in time, rolling back");
        abort_update(ctx, &installed, &verified.version)?;
        let _ = platform.restart_service();
        Ok(Outcome::RolledBack {
            attempted: verified.version,
        })
    }
}

fn clone_ctx<'a>(c: &VerifyContext<'a>) -> VerifyContext<'a> {
    VerifyContext {
        release_key: c.release_key,
        command_key: c.command_key,
        agent_id: c.agent_id,
        current_version: c.current_version,
        os: c.os,
        arch: c.arch,
        last_issued_at: c.last_issued_at,
    }
}

fn wait_for_healthy(paths: &StagingPaths, version: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if std::fs::read_to_string(paths.healthy_marker())
            .map(|v| v.trim() == version)
            .unwrap_or(false)
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use std::cell::Cell;

    struct FakePlatform {
        /// Marker content the "new agent" writes after restart, if any.
        report_healthy_as: Option<&'static str>,
        paths: StagingPaths,
        restarts: Cell<u32>,
        fail_restart: bool,
    }

    impl Platform for FakePlatform {
        fn restart_service(&self) -> Result<()> {
            self.restarts.set(self.restarts.get() + 1);
            if self.fail_restart && self.restarts.get() == 1 {
                bail!("systemctl failed");
            }
            // Only the first restart starts the *new* binary.
            if self.restarts.get() == 1 {
                if let Some(v) = self.report_healthy_as {
                    std::fs::write(self.paths.healthy_marker(), v).unwrap();
                }
            }
            Ok(())
        }
    }

    /// eBPF companion for a test release.
    struct Ebpf<'a> {
        /// Bytes the release statement is signed over.
        signed: &'a [u8],
        /// Bytes actually staged on disk (differs from `signed` when tampered).
        staged: &'a [u8],
        /// Whether an older object is already installed.
        old_exists: bool,
    }

    struct Env {
        _root: PathBuf,
        target: PathBuf,
        ebpf_target: PathBuf,
        /// Self-integrity baseline of the OLD binary, as the installer wrote it.
        baseline: PathBuf,
        paths: StagingPaths,
        release: SigningKey,
        command: SigningKey,
    }

    fn setup(artifact: &[u8], tamper_staged: Option<&[u8]>) -> Env {
        setup_full(artifact, tamper_staged, None)
    }

    fn setup_full(artifact: &[u8], tamper_staged: Option<&[u8]>, ebpf: Option<Ebpf<'_>>) -> Env {
        let root = std::env::temp_dir().join(format!("trapd-apply-test-{}", uuid::Uuid::new_v4()));
        let bin_dir = root.join("bin");
        let paths = StagingPaths::new(&root.join("state"));
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(&paths.dir).unwrap();
        let target = bin_dir.join("trapd-agent");
        std::fs::write(&target, b"OLD BINARY").unwrap();
        let ebpf_target = root.join("lib/trapd-agent/trapd-agent-exec");
        if let Some(e) = &ebpf {
            if e.old_exists {
                std::fs::create_dir_all(ebpf_target.parent().unwrap()).unwrap();
                std::fs::write(&ebpf_target, b"OLD EBPF").unwrap();
            }
        }

        let baseline = root.join("etc/binary.sha256");
        std::fs::create_dir_all(baseline.parent().unwrap()).unwrap();
        std::fs::write(&baseline, old_baseline()).unwrap();

        let release = SigningKey::from_bytes(&[1; 32]);
        let command = SigningKey::from_bytes(&[2; 32]);
        let mut rel = serde_json::json!({
            "version": "0.5.0", "os": "linux", "arch": "x86_64",
            "url": "https://github.com/trapd-cloud/trapd-agent/releases/download/v0.5.0/a",
            "sha256": hex::encode(Sha256::digest(artifact)), "size": artifact.len(),
        });
        if let Some(e) = &ebpf {
            rel["ebpf"] = serde_json::json!({
                "url": "https://github.com/trapd-cloud/trapd-agent/releases/download/v0.5.0/e",
                "sha256": hex::encode(Sha256::digest(e.signed)), "size": e.signed.len(),
            });
            std::fs::write(paths.ebpf_artifact(), e.staged).unwrap();
        }
        let rel = rel.to_string();
        let dir = serde_json::json!({
            "agent_id": "agent-1", "issued_at": 500,
            "release": { "payload": rel, "signature": STANDARD.encode(release.sign(rel.as_bytes()).to_bytes()) },
        })
        .to_string();
        let offer = serde_json::json!({
            "payload": dir, "signature": STANDARD.encode(command.sign(dir.as_bytes()).to_bytes()),
        });
        std::fs::write(paths.offer(), offer.to_string()).unwrap();
        std::fs::write(paths.artifact(), tamper_staged.unwrap_or(artifact)).unwrap();
        UpdateState {
            last_issued_at: 500,
            blocked_version: None,
        }
        .save(&paths)
        .unwrap();
        Env {
            _root: root,
            target,
            ebpf_target,
            baseline,
            paths,
            release,
            command,
        }
    }

    fn baseline_for(bytes: &[u8]) -> String {
        crate::selfprotect::binary_integrity::baseline_line(&hex::encode(Sha256::digest(bytes)))
    }

    fn old_baseline() -> String {
        baseline_for(b"OLD BINARY")
    }

    fn run(env: &Env, platform: &dyn Platform, timeout_ms: u64) -> Result<Outcome> {
        run_with_baseline(env, platform, timeout_ms, Some(&env.baseline))
    }

    fn run_with_baseline(
        env: &Env,
        platform: &dyn Platform,
        timeout_ms: u64,
        baseline: Option<&Path>,
    ) -> Result<Outcome> {
        let (rk, ck) = (env.release.verifying_key(), env.command.verifying_key());
        let ctx = ApplyContext {
            verify: VerifyContext {
                release_key: &rk,
                command_key: &ck,
                agent_id: "agent-1",
                current_version: "0.4.4",
                os: "linux",
                arch: "x86_64",
                last_issued_at: 0,
            },
            target: &env.target,
            ebpf_target: Some(&env.ebpf_target),
            baseline,
            paths: &env.paths,
            health_timeout: Duration::from_millis(timeout_ms),
        };
        apply_staged(&ctx, platform)
    }

    fn platform(env: &Env, healthy: Option<&'static str>, fail_restart: bool) -> FakePlatform {
        FakePlatform {
            report_healthy_as: healthy,
            paths: StagingPaths {
                dir: env.paths.dir.clone(),
            },
            restarts: Cell::new(0),
            fail_restart,
        }
    }

    #[test]
    fn healthy_update_replaces_binary_and_keeps_previous() {
        let env = setup(b"NEW BINARY", None);
        let out = run(&env, &platform(&env, Some("0.5.0"), false), 2000).unwrap();
        assert_eq!(
            out,
            Outcome::Applied {
                version: "0.5.0".into()
            }
        );
        assert_eq!(std::fs::read(&env.target).unwrap(), b"NEW BINARY");
        assert_eq!(
            std::fs::read(prev_path(&env.target)).unwrap(),
            b"OLD BINARY"
        );
        assert!(
            !env.paths.artifact().exists(),
            "staged files are cleaned up"
        );
    }

    #[test]
    fn unhealthy_update_is_rolled_back() {
        let env = setup(b"NEW BINARY", None);
        let p = platform(&env, None, false);
        let out = run(&env, &p, 300).unwrap();
        assert_eq!(
            out,
            Outcome::RolledBack {
                attempted: "0.5.0".into()
            }
        );
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
        assert_eq!(p.restarts.get(), 2, "restart into new, then back into old");
        assert_eq!(
            UpdateState::load(&env.paths).blocked_version.as_deref(),
            Some("0.5.0")
        );
        assert!(
            !env.paths.offer().exists(),
            "a rolled-back offer must not be retried"
        );
    }

    #[test]
    fn stale_health_marker_from_other_version_does_not_count() {
        let env = setup(b"NEW BINARY", None);
        let out = run(&env, &platform(&env, Some("0.4.4"), false), 300).unwrap();
        assert!(matches!(out, Outcome::RolledBack { .. }));
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
    }

    #[test]
    fn failed_restart_rolls_back() {
        let env = setup(b"NEW BINARY", None);
        let out = run(&env, &platform(&env, None, true), 300).unwrap();
        assert!(matches!(out, Outcome::RolledBack { .. }));
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
    }

    #[test]
    fn swapped_staged_artifact_is_never_installed() {
        // A compromised agent process overwrites the staged file after download.
        let env = setup(b"NEW BINARY", Some(b"EVIL BINARY"));
        let err = run(&env, &platform(&env, Some("0.5.0"), false), 300).unwrap_err();
        assert!(
            err.to_string().contains("does not match the signed digest"),
            "{err}"
        );
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
    }

    #[test]
    fn offer_older_than_watermark_is_rejected() {
        let env = setup(b"NEW BINARY", None);
        UpdateState {
            last_issued_at: 900,
            blocked_version: None,
        }
        .save(&env.paths)
        .unwrap();
        let err = run(&env, &platform(&env, Some("0.5.0"), false), 300).unwrap_err();
        assert!(err.to_string().contains("staged offer rejected"), "{err}");
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
    }

    #[test]
    fn healthy_update_installs_binary_and_ebpf_object_together() {
        let env = setup_full(
            b"NEW BINARY",
            None,
            Some(Ebpf {
                signed: b"NEW EBPF",
                staged: b"NEW EBPF",
                old_exists: true,
            }),
        );
        let out = run(&env, &platform(&env, Some("0.5.0"), false), 2000).unwrap();
        assert!(matches!(out, Outcome::Applied { .. }));
        assert_eq!(std::fs::read(&env.target).unwrap(), b"NEW BINARY");
        assert_eq!(std::fs::read(&env.ebpf_target).unwrap(), b"NEW EBPF");
        assert!(!env.paths.ebpf_artifact().exists());
    }

    #[test]
    fn rollback_restores_binary_and_ebpf_object() {
        let env = setup_full(
            b"NEW BINARY",
            None,
            Some(Ebpf {
                signed: b"NEW EBPF",
                staged: b"NEW EBPF",
                old_exists: true,
            }),
        );
        let out = run(&env, &platform(&env, None, false), 300).unwrap();
        assert!(matches!(out, Outcome::RolledBack { .. }));
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
        assert_eq!(std::fs::read(&env.ebpf_target).unwrap(), b"OLD EBPF");
    }

    #[test]
    fn rollback_removes_an_ebpf_object_that_did_not_exist_before() {
        let env = setup_full(
            b"NEW BINARY",
            None,
            Some(Ebpf {
                signed: b"NEW EBPF",
                staged: b"NEW EBPF",
                old_exists: false,
            }),
        );
        let out = run(&env, &platform(&env, None, false), 300).unwrap();
        assert!(matches!(out, Outcome::RolledBack { .. }));
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
        assert!(
            !env.ebpf_target.exists(),
            "first-time object must be removed again"
        );
    }

    #[test]
    fn swapped_staged_ebpf_object_blocks_the_whole_update() {
        // Binary is fine, only the object was replaced: nothing may be installed.
        let env = setup_full(
            b"NEW BINARY",
            None,
            Some(Ebpf {
                signed: b"NEW EBPF",
                staged: b"EVIL EBPF",
                old_exists: true,
            }),
        );
        let err = run(&env, &platform(&env, Some("0.5.0"), false), 300).unwrap_err();
        assert!(
            err.to_string().contains("eBPF object does not match"),
            "{err}"
        );
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
        assert_eq!(std::fs::read(&env.ebpf_target).unwrap(), b"OLD EBPF");
    }

    // Regression: the restarted agent compares its own hash with
    // `binary.sha256` and aborts on a mismatch (`binary_integrity::check`), so an
    // update that leaves the old baseline in place can never become healthy.
    #[test]
    fn healthy_update_refreshes_the_integrity_baseline_to_the_new_binary() {
        let env = setup(b"NEW BINARY", None);
        let out = run(&env, &platform(&env, Some("0.5.0"), false), 2000).unwrap();
        assert!(matches!(out, Outcome::Applied { .. }));
        assert_eq!(
            std::fs::read_to_string(&env.baseline).unwrap(),
            baseline_for(b"NEW BINARY")
        );
        assert_ne!(baseline_for(b"NEW BINARY"), old_baseline());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&env.baseline)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "baseline must stay private");
        }
    }

    #[test]
    fn baseline_is_already_fresh_when_the_new_agent_restarts() {
        // The new agent checks the baseline right after the restart, i.e. before
        // the health marker exists. Capture what it would see at that moment.
        struct Probe {
            inner: FakePlatform,
            baseline: PathBuf,
            seen: std::cell::RefCell<Option<String>>,
        }
        impl Platform for Probe {
            fn restart_service(&self) -> Result<()> {
                if self.inner.restarts.get() == 0 {
                    *self.seen.borrow_mut() = std::fs::read_to_string(&self.baseline).ok();
                }
                self.inner.restart_service()
            }
        }
        let env = setup(b"NEW BINARY", None);
        let probe = Probe {
            inner: platform(&env, Some("0.5.0"), false),
            baseline: env.baseline.clone(),
            seen: Default::default(),
        };
        run(&env, &probe, 2000).unwrap();
        assert_eq!(
            probe.seen.borrow().as_deref(),
            Some(baseline_for(b"NEW BINARY").as_str())
        );
    }

    #[test]
    fn rollback_restores_the_old_integrity_baseline() {
        // Otherwise the restored OLD binary would fail against the NEW baseline.
        let env = setup(b"NEW BINARY", None);
        let out = run(&env, &platform(&env, None, false), 300).unwrap();
        assert!(matches!(out, Outcome::RolledBack { .. }));
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
        assert_eq!(
            std::fs::read_to_string(&env.baseline).unwrap(),
            old_baseline()
        );
    }

    #[test]
    fn failed_restart_restores_the_old_integrity_baseline() {
        let env = setup(b"NEW BINARY", None);
        let out = run(&env, &platform(&env, None, true), 300).unwrap();
        assert!(matches!(out, Outcome::RolledBack { .. }));
        assert_eq!(
            std::fs::read_to_string(&env.baseline).unwrap(),
            old_baseline()
        );
    }

    #[test]
    fn missing_baseline_is_not_created() {
        // First run writes it for whichever binary runs; the helper must not
        // invent one.
        let env = setup(b"NEW BINARY", None);
        std::fs::remove_file(&env.baseline).unwrap();
        let out = run(&env, &platform(&env, Some("0.5.0"), false), 2000).unwrap();
        assert!(matches!(out, Outcome::Applied { .. }));
        assert!(!env.baseline.exists());
    }

    #[test]
    fn baseline_that_cannot_be_updated_aborts_before_restart() {
        // A directory in place of the file makes the swap fail.
        let env = setup(b"NEW BINARY", None);
        std::fs::remove_file(&env.baseline).unwrap();
        std::fs::create_dir(&env.baseline).unwrap();
        let p = platform(&env, Some("0.5.0"), false);
        let err = run(&env, &p, 300).unwrap_err();
        assert!(err.to_string().contains("integrity baseline"), "{err:#}");
        assert_eq!(
            p.restarts.get(),
            0,
            "must not restart into an unverifiable binary"
        );
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
        assert_eq!(
            UpdateState::load(&env.paths).blocked_version.as_deref(),
            Some("0.5.0")
        );
    }
}
