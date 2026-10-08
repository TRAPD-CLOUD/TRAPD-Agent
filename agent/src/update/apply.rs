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
    /// Durable rollback journal; retained until old files and service recover.
    pub fn recovery(&self) -> PathBuf {
        self.dir.join("recovery.json")
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
    /// Bind terminal cleanup to the exact offer. Persisted before removing
    /// recovery/staging so a crash cannot turn completion into another apply.
    #[serde(default)]
    pub completion: Option<CompletedUpdate>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompletedUpdate {
    pub offer_sha256: String,
    pub outcome: Outcome,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Applied { version: String },
    RolledBack { attempted: String },
}

/// Hooks that differ per platform (and are replaced in tests).
pub trait Platform {
    /// Restart the agent service so it picks up the new binary.
    fn restart_service(&self) -> Result<()>;

    /// Stop the agent service and wait until it has exited. Called before a
    /// rollback puts the previous files back: Windows cannot delete the image of
    /// a running service, so the failed version must be gone first. A no-op on
    /// platforms where replacing a running file is safe (Unix: rename over it).
    fn stop_service(&self) -> Result<()> {
        Ok(())
    }
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

/// Evidence of original absence lives beside the protected executable, outside
/// the service-writable staging/config directories. It binds a specific signed
/// directive, target and installed bytes; a forged journal cannot create it.
#[derive(Debug)]
struct ProtectedAbsence {
    path: PathBuf,
    expected: Vec<u8>,
}

impl ProtectedAbsence {
    fn new(authority: &Path, target: &Path, directive: &str, new_digest: &str) -> Result<Self> {
        let parent = authority
            .parent()
            .context("update: executable has no protected parent")?;
        let identity = serde_json::to_vec(&(authority, target))?;
        let name = format!(
            ".trapd-update-absence-{}.json",
            hex::encode(Sha256::digest(identity))
        );
        let expected = serde_json::to_vec(&serde_json::json!({
            "directive_sha256": directive, "target": target, "new_sha256": new_digest,
        }))?;
        Ok(Self {
            path: parent.join(name),
            expected,
        })
    }

    /// Only called during a fresh, authenticated installation after confirming
    /// no pending recovery exists and the original target is actually absent.
    fn create(&self) -> Result<()> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&self.path) {
            Ok(mut file) => {
                file.write_all(&self.expected)
                    .context("update: write protected absence evidence")?;
                file.sync_all()
                    .context("update: sync protected absence evidence")?;
                #[cfg(unix)]
                std::fs::File::open(self.path.parent().unwrap())?.sync_all()?;
                Ok(())
            }
            // An old completed update can leave a marker after cleanup failure.
            // Fresh installation has independently confirmed absence, so replace
            // it atomically with evidence for this signed directive.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                crate::paths::write_atomic(&self.path, &self.expected, 0o600)
            }
            Err(error) => Err(error).context("update: create protected absence evidence"),
        }
    }

    fn verify(&self) -> Result<()> {
        let observed = crate::paths::bounded_regular_sha256(&self.path, 4096)
            .context("update: read protected original-absence evidence")?;
        if observed != hex::encode(Sha256::digest(&self.expected)) {
            bail!("update: original-absence evidence does not match signed directive and target");
        }
        Ok(())
    }
}

/// A file that was replaced and can be put back.
#[derive(Debug, Serialize, Deserialize)]
struct Installed {
    target: PathBuf,
    /// The previous version, or `None` when the file did not exist before.
    prev: Option<PathBuf>,
    /// Digest distinguishes a planned-but-unswapped file from a failed release.
    original_sha256: Option<String>,
    /// Bound from the verified update in memory; never accepted from the journal.
    #[serde(skip)]
    authorized_new_sha256: Option<String>,
    #[serde(skip)]
    absence_evidence: Option<ProtectedAbsence>,
}

impl Installed {
    fn verify_newly_installed(&self) -> Result<bool> {
        self.absence_evidence
            .as_ref()
            .context("update: missing protected absence evidence")?
            .verify()?;
        match std::fs::symlink_metadata(&self.target) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).context("update: inspect newly installed recovery file")
            }
            Ok(_) => {}
        }
        let expected = self
            .authorized_new_sha256
            .as_deref()
            .context("update: missing authenticated new-file digest")?;
        if original_digest(&self.target)? != expected {
            bail!("update: absent-original recovery target does not match authenticated new bytes");
        }
        Ok(true)
    }

    fn restore(&self) -> Result<()> {
        match &self.prev {
            Some(prev) => {
                let original = self
                    .original_sha256
                    .as_deref()
                    .context("update: missing original digest")?;
                // A journal is written before a swap. If it never happened (or
                // a prior retry already restored it), the original is in place.
                if original_digest(&self.target).ok().as_deref() == Some(original) {
                    return Ok(());
                }
                if original_digest(prev)?.as_str() != original {
                    bail!("update: previous file no longer matches recovery digest");
                }
                // Keep the known-good backup until the service restart succeeds.
                // Recovery can then retry any partial restore without replacing
                // it with the failed release or losing a consumed .prev file.
                let temporary = self.target.with_file_name(format!(
                    ".{}.rollback",
                    self.target
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                ));
                std::fs::copy(prev, &temporary)
                    .context("update: copy previous file for restore")?;
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&temporary)?
                    .sync_all()?;
                #[cfg(not(unix))]
                if self.target.exists() {
                    std::fs::remove_file(&self.target).context("update: remove failed file")?;
                }
                std::fs::rename(temporary, &self.target).context("update: restore previous file")
            }
            None => {
                if !self.verify_newly_installed()? {
                    return Ok(());
                }
                match std::fs::remove_file(&self.target) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(e).context("update: remove newly installed file"),
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Recovery {
    version: String,
    /// Revalidation on recovery must also work from the failed new helper.
    previous_version: String,
    installed: Vec<Installed>,
    #[serde(skip)]
    signed_directive_sha256: String,
}

impl Recovery {
    fn save(&self, paths: &StagingPaths) -> Result<()> {
        crate::paths::write_atomic(&paths.recovery(), &serde_json::to_vec(self)?, 0o600)
    }

    fn validate(
        &mut self,
        ctx: &ApplyContext<'_>,
        version: &str,
        intended: &std::collections::HashMap<PathBuf, String>,
        signed_directive: &str,
    ) -> Result<()> {
        if self.version != version {
            bail!("update: recovery version does not match staged offer");
        }
        let mut seen = std::collections::HashSet::new();
        for installed in &mut self.installed {
            let intended_digest = intended
                .get(&installed.target)
                .context("update: recovery target is absent from the authenticated update plan")?;
            // The executable always existed before an update. A protected
            // backup also disproves an "absent original" claim for ancillary
            // files: never let such a journal turn recovery into deletion.
            if installed.prev.is_none()
                && (installed.target == ctx.target
                    || prev_path(&installed.target)
                        .try_exists()
                        .context("update: inspect recovery backup")?)
            {
                bail!("update: recovery incorrectly claims an absent original");
            }
            if !seen.insert(installed.target.clone())
                || installed.prev.is_some() != installed.original_sha256.is_some()
                || installed.original_sha256.as_ref().is_some_and(|digest| {
                    digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit())
                })
                || installed
                    .prev
                    .as_ref()
                    .is_some_and(|prev| *prev != prev_path(&installed.target))
            {
                bail!("update: invalid recovery target or backup path");
            }
            // Bind only the authenticated plan digest, ignoring any digest a
            // malicious journal may attempt to supply for newly installed data.
            installed.authorized_new_sha256 = Some(intended_digest.clone());
            if installed.prev.is_none() {
                installed.absence_evidence = Some(ProtectedAbsence::new(
                    ctx.target,
                    &installed.target,
                    signed_directive,
                    intended_digest,
                )?);
                installed.verify_newly_installed()?;
            }
        }
        Ok(())
    }
}

fn original_digest(path: &Path) -> Result<String> {
    crate::paths::bounded_regular_sha256(path, super::manifest::MAX_ARTIFACT_BYTES)
        .context("update: hash original file for recovery")
}

/// Write and sync new bytes, journal the original identity, then perform the
/// first destructive mutation. Crashes on either side of the swap can recover.
fn install_file(
    target: &Path,
    bytes: &[u8],
    mode: u32,
    recovery: &mut Recovery,
    paths: &StagingPaths,
    authority: &Path,
) -> Result<()> {
    // Windows can rename an existing directory out of the way and replace it
    // with a file. Reject invalid install targets consistently on all hosts.
    if target.exists() && !target.is_file() {
        bail!(
            "update: install target {} is not a regular file",
            target.display()
        );
    }
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

    let installed = if target.exists() {
        Installed {
            target: target.to_path_buf(),
            prev: Some(prev_path(target)),
            original_sha256: Some(original_digest(target)?),
            authorized_new_sha256: Some(hex::encode(Sha256::digest(bytes))),
            absence_evidence: None,
        }
    } else {
        let new_digest = hex::encode(Sha256::digest(bytes));
        let evidence = ProtectedAbsence::new(
            authority,
            target,
            &recovery.signed_directive_sha256,
            &new_digest,
        )?;
        evidence.create()?;
        Installed {
            target: target.to_path_buf(),
            prev: None,
            original_sha256: None,
            authorized_new_sha256: Some(new_digest),
            absence_evidence: Some(evidence),
        }
    };
    recovery.installed.push(installed);
    if let Err(error) = recovery.save(paths) {
        // Nothing at this target was changed; previous journal entries remain
        // valid for the earlier swaps if persistence fails midway through.
        recovery.installed.pop();
        return Err(error).context("update: persist recovery before file swap");
    }
    let installed = recovery.installed.last().unwrap();
    match &installed.prev {
        Some(prev) => swap_in(target, &new, prev),
        None => std::fs::rename(&new, target).context("update: install new file"),
    }
}

/// Put every replaced file back, retaining recovery material on any failure.
fn restore_files(installed: &[Installed]) -> Result<()> {
    let mut first_err = None;
    for i in installed {
        if let Err(e) = i.restore() {
            tracing::error!(error = %e, target = %i.target.display(), "update: restore failed");
            first_err.get_or_insert(e);
        }
    }
    first_err.map_or(Ok(()), Err)
}

fn finish_rollback(ctx: &ApplyContext<'_>, version: &str) -> Result<()> {
    finish_update(
        ctx.paths,
        Outcome::RolledBack {
            attempted: version.to_string(),
        },
    )?;
    Ok(())
}

fn finish_update(paths: &StagingPaths, outcome: Outcome) -> Result<Outcome> {
    let mut state = UpdateState::load(paths);
    if let Outcome::RolledBack { attempted } = &outcome {
        state.blocked_version = Some(attempted.clone());
    }
    state.completion = Some(CompletedUpdate {
        offer_sha256: hex::encode(Sha256::digest(std::fs::read(paths.offer())?)),
        outcome: outcome.clone(),
    });
    state
        .save(paths)
        .context("update: persist completed transaction")?;
    clear_completed_staging(paths)?;
    Ok(outcome)
}

/// Only removes fixed staging paths; the completion record never authorizes
/// installed-file changes. Match the exact offer so an old record cannot
/// discard a newly accepted directive, even for the same release version.
pub(super) fn resume_completed_staging(paths: &StagingPaths) -> Result<Option<Outcome>> {
    let Some(completion) = UpdateState::load(paths).completion else {
        return Ok(None);
    };
    let offer = match std::fs::read(paths.offer()) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("update: inspect completed offer"),
    };
    if hex::encode(Sha256::digest(offer)) != completion.offer_sha256 {
        return Ok(None);
    }
    clear_completed_staging(paths)?;
    Ok(Some(completion.outcome))
}

fn clear_completed_staging(paths: &StagingPaths) -> Result<()> {
    // Remove the journal before the signed offer: a retained journal without
    // its offer would be impossible to authenticate on the next helper run.
    match std::fs::remove_file(paths.recovery()) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("update: clear completed recovery"),
    }
    clear_staging(paths)
}

fn clear_absence_evidence(installed: &[Installed]) -> Result<()> {
    for entry in installed {
        if let Some(evidence) = &entry.absence_evidence {
            match std::fs::remove_file(&evidence.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).context("update: clear completed absence evidence")
                }
            }
        }
    }
    Ok(())
}

/// Undo a failed file installation before any restart of the new service.
fn abort_update(ctx: &ApplyContext<'_>, installed: &[Installed], version: &str) -> Result<()> {
    restore_files(installed)?;
    finish_rollback(ctx, version)?;
    clear_absence_evidence(installed)
}

fn recover_update(
    ctx: &ApplyContext<'_>,
    platform: &dyn Platform,
    recovery: &Recovery,
) -> Result<Outcome> {
    platform
        .stop_service()
        .context("update: rollback requires a confirmed service stop; recovery retained")?;
    restore_files(&recovery.installed).context("update: rollback incomplete; recovery retained")?;
    platform
        .restart_service()
        .context("update: restored service could not restart; recovery retained")?;
    finish_rollback(ctx, &recovery.version)?;
    clear_absence_evidence(&recovery.installed)?;
    Ok(Outcome::RolledBack {
        attempted: recovery.version.clone(),
    })
}

fn clear_staging(paths: &StagingPaths) -> Result<()> {
    // Offer last: retain a retry trigger if deleting any artifact fails.
    for path in [paths.artifact(), paths.ebpf_artifact(), paths.offer()] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("update: clear completed staging"),
        }
    }
    Ok(())
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
    if let Some(outcome) = resume_completed_staging(ctx.paths)? {
        return Ok(outcome);
    }
    let offer_bytes = std::fs::read(ctx.paths.offer()).context("update: read staged offer")?;
    let offer: UpdateOffer =
        serde_json::from_slice(&offer_bytes).context("update: parse staged offer")?;

    let pending_recovery = match std::fs::read(ctx.paths.recovery()) {
        Ok(bytes) => Some(
            serde_json::from_slice::<Recovery>(&bytes).context("update: parse recovery journal")?,
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).context("update: read recovery journal"),
    };

    // The watermark was advanced when the offer was accepted, so verify as if
    // it were still one below and require the offer to be exactly that one.
    let state = UpdateState::load(ctx.paths);
    let verify = VerifyContext {
        last_issued_at: state.last_issued_at - 1,
        current_version: pending_recovery
            .as_ref()
            .map_or(ctx.verify.current_version, |r| r.previous_version.as_str()),
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

    // Preserve the host's independently provisioned binary-signing trust
    // anchor. Missing/invalid replacement signatures fail BEFORE any swap;
    // never remove an old signature to bypass the startup integrity check.
    let signature_install = match ctx.baseline.and_then(Path::parent) {
        Some(config) if config.join("signing.pub").exists() => {
            let target = config.join("binary.sig");
            match verified.binary_signature {
                Some(bytes) => {
                    let raw = std::fs::read(config.join("signing.pub"))?;
                    let raw: [u8; 32] = raw
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("update: signing.pub must be 32 raw bytes"))?;
                    let key = ed25519_dalek::VerifyingKey::from_bytes(&raw)?;
                    key.verify_strict(
                        &verified.sha256,
                        &ed25519_dalek::Signature::from_bytes(&bytes),
                    )
                    .context("update: invalid binary signature")?;
                    Some((target, bytes))
                }
                None if target.exists() => {
                    bail!("update: release is missing the required binary signature")
                }
                None => None,
            }
        }
        _ => None,
    };

    // The journal cannot authorize a removal merely by claiming the original
    // file was absent. Bind such claims to the actual signed release artifacts,
    // its independently verified signature and the derived integrity baseline.
    let mut intended = std::collections::HashMap::new();
    intended.insert(ctx.target.to_path_buf(), hex::encode(verified.sha256));
    if let Some((target, bytes)) = &ebpf {
        intended.insert(target.to_path_buf(), hex::encode(Sha256::digest(bytes)));
    }
    if let Some((target, bytes)) = &signature_install {
        intended.insert(target.to_path_buf(), hex::encode(Sha256::digest(bytes)));
    }
    if let Some(target) = ctx.baseline {
        let line = crate::paths::binary_baseline_line(&hex::encode(verified.sha256));
        intended.insert(
            target.to_path_buf(),
            hex::encode(Sha256::digest(line.as_bytes())),
        );
    }

    // A previous helper may have failed to stop/restore/restart the service.
    // Authenticate its staged offer above, then resume recovery instead of
    // reinstalling the failed artifact over the known-good .prev backups.
    if let Some(mut recovery) = pending_recovery {
        recovery.validate(
            ctx,
            &verified.version,
            &intended,
            &hex::encode(Sha256::digest(offer.payload.as_bytes())),
        )?;
        return recover_update(ctx, platform, &recovery);
    }

    let _ = std::fs::remove_file(ctx.paths.healthy_marker());
    let mut recovery = Recovery {
        version: verified.version.clone(),
        previous_version: ctx.verify.current_version.to_string(),
        installed: Vec::new(),
        signed_directive_sha256: hex::encode(Sha256::digest(offer.payload.as_bytes())),
    };
    let mut install = |target: &Path, bytes: &[u8], mode| -> Result<()> {
        if let Err(error) = install_file(target, bytes, mode, &mut recovery, ctx.paths, ctx.target)
        {
            abort_update(ctx, &recovery.installed, &verified.version).with_context(|| {
                format!("update: install failed ({error}); rollback incomplete")
            })?;
            return Err(error);
        }
        Ok(())
    };
    // Object first: if the binary install then fails, only the object needs undoing.
    if let Some((target, bytes)) = &ebpf {
        install(target, bytes, 0o644)?;
    }
    install(ctx.target, &bin, 0o755)?;
    if let Some((target, bytes)) = signature_install {
        install(&target, &bytes, 0o600).context("update: refresh binary signature")?;
    }
    // Baseline and signature share the same durable recovery transaction as
    // the binary, including installation errors before the first service start.
    if let Some(baseline) = ctx.baseline.filter(|p| p.exists()) {
        let line = crate::paths::binary_baseline_line(&hex::encode(verified.sha256));
        install(baseline, line.as_bytes(), 0o600)
            .context("update: refresh binary integrity baseline")?;
    }
    if let Err(e) = platform.restart_service() {
        tracing::error!(error = %e, "update: restart failed, rolling back");
        return recover_update(ctx, platform, &recovery);
    }

    if wait_for_healthy(ctx.paths, &verified.version, ctx.health_timeout) {
        let outcome = finish_update(
            ctx.paths,
            Outcome::Applied {
                version: verified.version,
            },
        )?;
        clear_absence_evidence(&recovery.installed)?;
        Ok(outcome)
    } else {
        tracing::error!(version = %verified.version, "update: new agent not healthy in time, rolling back");
        recover_update(ctx, platform, &recovery)
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
            completion: None,
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
        crate::paths::binary_baseline_line(&hex::encode(Sha256::digest(bytes)))
    }

    fn old_baseline() -> String {
        baseline_for(b"OLD BINARY")
    }

    fn provision_binary_signature(env: &Env, digest: &[u8], include_signature: bool) -> Vec<u8> {
        let key = SigningKey::from_bytes(&[3; 32]);
        let config = env.baseline.parent().unwrap();
        std::fs::write(config.join("signing.pub"), key.verifying_key().to_bytes()).unwrap();
        let old = key.sign(&Sha256::digest(b"OLD BINARY")).to_bytes().to_vec();
        std::fs::write(config.join("binary.sig"), &old).unwrap();
        if include_signature {
            let offer: UpdateOffer =
                serde_json::from_slice(&std::fs::read(env.paths.offer()).unwrap()).unwrap();
            let mut directive: serde_json::Value = serde_json::from_str(&offer.payload).unwrap();
            let mut release: serde_json::Value =
                serde_json::from_str(directive["release"]["payload"].as_str().unwrap()).unwrap();
            release["binary_signature"] =
                serde_json::json!(STANDARD.encode(key.sign(digest).to_bytes()));
            let payload = release.to_string();
            directive["release"]["signature"] =
                serde_json::json!(STANDARD.encode(env.release.sign(payload.as_bytes()).to_bytes()));
            directive["release"]["payload"] = serde_json::json!(payload);
            let payload = directive.to_string();
            let signed = serde_json::json!({"signature": STANDARD.encode(env.command.sign(payload.as_bytes()).to_bytes()), "payload": payload});
            std::fs::write(env.paths.offer(), signed.to_string()).unwrap();
        }
        old
    }

    #[test]
    fn binary_signature_is_rotated_before_restart() {
        let env = setup(b"NEW BINARY", None);
        let old = provision_binary_signature(&env, &Sha256::digest(b"NEW BINARY"), true);
        struct VerifyAtRestart<'a>(&'a Env);
        impl Platform for VerifyAtRestart<'_> {
            fn restart_service(&self) -> Result<()> {
                let bytes = std::fs::read(self.0.baseline.with_file_name("binary.sig"))?;
                let signature = ed25519_dalek::Signature::from_slice(&bytes)?;
                SigningKey::from_bytes(&[3; 32])
                    .verifying_key()
                    .verify_strict(&Sha256::digest(std::fs::read(&self.0.target)?), &signature)?;
                std::fs::write(self.0.paths.healthy_marker(), "0.5.0")?;
                Ok(())
            }
        }
        assert!(matches!(
            run(&env, &VerifyAtRestart(&env), 0).unwrap(),
            Outcome::Applied { .. }
        ));
        assert_ne!(
            std::fs::read(env.baseline.with_file_name("binary.sig")).unwrap(),
            old
        );
    }

    #[test]
    fn rollback_stops_the_failed_version_before_restoring_files() {
        // Windows cannot delete a running service image, so the stop has to
        // happen while the *new* binary is still at the install path.
        let env = setup(b"NEW BINARY", None);
        struct Order<'a> {
            env: &'a Env,
            seen_at_stop: std::cell::RefCell<Option<Vec<u8>>>,
        }
        impl Platform for Order<'_> {
            fn restart_service(&self) -> Result<()> {
                Ok(())
            }
            fn stop_service(&self) -> Result<()> {
                *self.seen_at_stop.borrow_mut() = Some(std::fs::read(&self.env.target)?);
                Ok(())
            }
        }
        let p = Order {
            env: &env,
            seen_at_stop: Default::default(),
        };
        assert!(matches!(
            run(&env, &p, 0).unwrap(),
            Outcome::RolledBack { .. }
        ));
        assert_eq!(p.seen_at_stop.borrow().as_deref(), Some(&b"NEW BINARY"[..]));
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
    }

    #[test]
    fn failed_stop_preserves_all_recovery_files_without_restoring() {
        for restart_fails in [false, true] {
            let env = setup(b"NEW BINARY", None);
            struct CannotStop(bool);
            impl Platform for CannotStop {
                fn restart_service(&self) -> Result<()> {
                    if self.0 {
                        bail!("restart failed");
                    }
                    Ok(())
                }
                fn stop_service(&self) -> Result<()> {
                    bail!("stop timed out")
                }
            }
            let result = run(&env, &CannotStop(restart_fails), 0);
            assert!(
                result.is_err(),
                "a failed stop must prevent rollback success"
            );
            assert_eq!(std::fs::read(&env.target).unwrap(), b"NEW BINARY");
            assert_eq!(
                std::fs::read(prev_path(&env.target)).unwrap(),
                b"OLD BINARY"
            );
            assert!(env.paths.offer().exists());
            assert!(env.paths.artifact().exists());
            assert!(UpdateState::load(&env.paths).blocked_version.is_none());
        }
    }

    #[test]
    fn retry_after_failed_stop_restores_the_original_backup() {
        let env = setup(b"NEW BINARY", None);
        struct CannotStop;
        impl Platform for CannotStop {
            fn restart_service(&self) -> Result<()> {
                Ok(())
            }
            fn stop_service(&self) -> Result<()> {
                bail!("still running")
            }
        }
        assert!(run(&env, &CannotStop, 0).is_err());
        assert!(matches!(
            run_with_baseline_and_version(
                &env,
                &platform(&env, None, false),
                0,
                Some(&env.baseline),
                "0.5.0"
            )
            .unwrap(),
            Outcome::RolledBack { .. }
        ));
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
    }

    #[test]
    fn recovery_cannot_remove_original_files_by_forging_an_absent_plan() {
        let env = setup(b"NEW BINARY", None);
        std::fs::write(prev_path(&env.baseline), old_baseline()).unwrap();
        Recovery {
            version: "0.5.0".into(),
            previous_version: "0.4.4".into(),
            signed_directive_sha256: String::new(),
            installed: vec![Installed {
                target: env.baseline.clone(),
                prev: None,
                original_sha256: None,
                authorized_new_sha256: None,
                absence_evidence: None,
            }],
        }
        .save(&env.paths)
        .unwrap();
        assert!(run(&env, &platform(&env, None, false), 0).is_err());
        assert_eq!(
            std::fs::read_to_string(&env.baseline).unwrap(),
            old_baseline()
        );
        assert!(env.paths.recovery().exists());
    }

    #[test]
    fn recovery_rejects_forged_absence_without_protected_backup() {
        for case in 0..4 {
            let env = if case == 2 {
                setup_full(
                    b"NEW BINARY",
                    None,
                    Some(Ebpf {
                        signed: b"NEW EBPF",
                        staged: b"NEW EBPF",
                        old_exists: true,
                    }),
                )
            } else {
                setup(b"NEW BINARY", None)
            };
            let target = match case {
                0 => env.baseline.clone(),
                1 => {
                    provision_binary_signature(&env, &Sha256::digest(b"NEW BINARY"), true);
                    env.baseline.with_file_name("binary.sig")
                }
                2 => env.ebpf_target.clone(),
                _ => {
                    std::fs::create_dir_all(env.ebpf_target.parent().unwrap()).unwrap();
                    std::fs::write(&env.ebpf_target, b"UNRELATED ORIGINAL EBPF").unwrap();
                    env.ebpf_target.clone()
                }
            };
            let original = std::fs::read(&target).unwrap();
            assert!(!prev_path(&target).exists());
            Recovery {
                version: "0.5.0".into(),
                previous_version: "0.4.4".into(),
                signed_directive_sha256: String::new(),
                installed: vec![Installed {
                    target: target.clone(),
                    prev: None,
                    original_sha256: None,
                    authorized_new_sha256: None,
                    absence_evidence: None,
                }],
            }
            .save(&env.paths)
            .unwrap();
            let platform = platform(&env, None, false);
            assert!(
                run(&env, &platform, 0).is_err(),
                "forged absence must be rejected for case {case}"
            );
            assert_eq!(std::fs::read(&target).unwrap(), original);
            assert_eq!(platform.restarts.get(), 0, "reject before service actions");
            assert!(env.paths.recovery().exists());
        }
    }

    #[test]
    fn recovery_rechecks_absent_plan_content_after_service_stop() {
        let env = setup_full(
            b"NEW BINARY",
            None,
            Some(Ebpf {
                signed: b"NEW EBPF",
                staged: b"NEW EBPF",
                old_exists: false,
            }),
        );
        struct CannotStop;
        impl Platform for CannotStop {
            fn restart_service(&self) -> Result<()> {
                Ok(())
            }
            fn stop_service(&self) -> Result<()> {
                bail!("still running")
            }
        }
        assert!(run(&env, &CannotStop, 0).is_err());
        struct ReplaceAfterValidation<'a>(&'a Env);
        impl Platform for ReplaceAfterValidation<'_> {
            fn restart_service(&self) -> Result<()> {
                Ok(())
            }
            fn stop_service(&self) -> Result<()> {
                std::fs::write(&self.0.ebpf_target, b"REPLACED ORIGINAL EBPF")?;
                Ok(())
            }
        }
        assert!(run(&env, &ReplaceAfterValidation(&env), 0).is_err());
        assert_eq!(
            std::fs::read(&env.ebpf_target).unwrap(),
            b"REPLACED ORIGINAL EBPF"
        );
        assert!(env.paths.recovery().exists());
    }

    #[test]
    fn recovery_rejects_forged_absence_when_original_equals_signed_companion() {
        let env = setup_full(
            b"NEW BINARY",
            None,
            Some(Ebpf {
                signed: b"OLD EBPF",
                staged: b"OLD EBPF",
                old_exists: true,
            }),
        );
        Recovery {
            version: "0.5.0".into(),
            previous_version: "0.4.4".into(),
            signed_directive_sha256: String::new(),
            installed: vec![Installed {
                target: env.ebpf_target.clone(),
                prev: None,
                original_sha256: None,
                authorized_new_sha256: None,
                absence_evidence: None,
            }],
        }
        .save(&env.paths)
        .unwrap();
        assert!(run(&env, &platform(&env, None, false), 0).is_err());
        assert_eq!(std::fs::read(&env.ebpf_target).unwrap(), b"OLD EBPF");
        assert!(env.paths.recovery().exists());
    }

    #[test]
    fn rollback_removes_a_new_signature_only_when_original_was_absent() {
        let env = setup(b"NEW BINARY", None);
        provision_binary_signature(&env, &Sha256::digest(b"NEW BINARY"), true);
        let signature = env.baseline.with_file_name("binary.sig");
        std::fs::remove_file(&signature).unwrap();
        assert!(matches!(
            run(&env, &platform(&env, None, false), 0).unwrap(),
            Outcome::RolledBack { .. }
        ));
        assert!(!signature.exists());
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
    }

    #[test]
    fn protected_absence_evidence_survives_failed_stop_until_successful_retry() {
        let env = setup_full(
            b"NEW BINARY",
            None,
            Some(Ebpf {
                signed: b"NEW EBPF",
                staged: b"NEW EBPF",
                old_exists: false,
            }),
        );
        struct CannotStop;
        impl Platform for CannotStop {
            fn restart_service(&self) -> Result<()> {
                Ok(())
            }
            fn stop_service(&self) -> Result<()> {
                bail!("still running")
            }
        }
        let offer: UpdateOffer =
            serde_json::from_slice(&std::fs::read(env.paths.offer()).unwrap()).unwrap();
        let evidence = ProtectedAbsence::new(
            &env.target,
            &env.ebpf_target,
            &hex::encode(Sha256::digest(offer.payload.as_bytes())),
            &hex::encode(Sha256::digest(b"NEW EBPF")),
        )
        .unwrap();
        assert!(run(&env, &CannotStop, 0).is_err());
        evidence.verify().unwrap();
        assert!(matches!(
            run(&env, &platform(&env, None, false), 0).unwrap(),
            Outcome::RolledBack { .. }
        ));
        assert!(!env.ebpf_target.exists());
        assert!(
            !evidence.path.exists(),
            "evidence removed only after recovery completes"
        );
    }

    #[test]
    fn recovery_requires_protected_evidence_for_the_exact_signed_directive() {
        for missing in [true, false] {
            let env = setup_full(
                b"NEW BINARY",
                None,
                Some(Ebpf {
                    signed: b"NEW EBPF",
                    staged: b"NEW EBPF",
                    old_exists: false,
                }),
            );
            struct CannotStop;
            impl Platform for CannotStop {
                fn restart_service(&self) -> Result<()> {
                    Ok(())
                }
                fn stop_service(&self) -> Result<()> {
                    bail!("still running")
                }
            }
            assert!(run(&env, &CannotStop, 0).is_err());
            let stale = ProtectedAbsence::new(
                &env.target,
                &env.ebpf_target,
                "another signed directive",
                &hex::encode(Sha256::digest(b"NEW EBPF")),
            )
            .unwrap();
            if missing {
                std::fs::remove_file(&stale.path).unwrap();
            } else {
                stale.create().unwrap();
            }
            let platform = platform(&env, None, false);
            assert!(run(&env, &platform, 0).is_err());
            assert_eq!(std::fs::read(&env.ebpf_target).unwrap(), b"NEW EBPF");
            assert_eq!(platform.restarts.get(), 0);
            assert!(env.paths.recovery().exists());
        }
    }

    #[test]
    fn recovery_before_swap_keeps_original_instead_of_stale_backup() {
        let env = setup(b"NEW BINARY", None);
        std::fs::write(prev_path(&env.target), b"OLDER STALE BACKUP").unwrap();
        Recovery {
            version: "0.5.0".to_string(),
            previous_version: "0.4.4".to_string(),
            signed_directive_sha256: String::new(),
            installed: vec![Installed {
                target: env.target.clone(),
                prev: Some(prev_path(&env.target)),
                original_sha256: Some(hex::encode(Sha256::digest(b"OLD BINARY"))),
                authorized_new_sha256: None,
                absence_evidence: None,
            }],
        }
        .save(&env.paths)
        .unwrap();
        assert!(matches!(
            run(&env, &platform(&env, None, false), 0).unwrap(),
            Outcome::RolledBack { .. }
        ));
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
    }

    #[test]
    fn tampered_backup_cannot_be_restored_as_the_original() {
        let env = setup(b"NEW BINARY", None);
        struct CannotStop;
        impl Platform for CannotStop {
            fn restart_service(&self) -> Result<()> {
                Ok(())
            }
            fn stop_service(&self) -> Result<()> {
                bail!("still running")
            }
        }
        assert!(run(&env, &CannotStop, 0).is_err());
        std::fs::write(prev_path(&env.target), b"TAMPERED BACKUP").unwrap();
        assert!(run(&env, &platform(&env, None, false), 0).is_err());
        assert_eq!(std::fs::read(&env.target).unwrap(), b"NEW BINARY");
        assert!(env.paths.recovery().exists());
        assert!(env.paths.offer().exists());
        assert!(UpdateState::load(&env.paths).blocked_version.is_none());
    }

    #[test]
    fn partial_install_failure_retains_recovery_and_retries_original_backup() {
        let env = setup(b"NEW BINARY", None);
        std::fs::remove_file(&env.baseline).unwrap();
        std::fs::create_dir(&env.baseline).unwrap();
        let blocked_restore = env.target.with_file_name(".trapd-agent.rollback");
        std::fs::create_dir(&blocked_restore).unwrap();
        assert!(run(&env, &platform(&env, None, false), 0).is_err());
        assert!(
            env.paths.recovery().exists(),
            "partial installation must have a durable recovery journal"
        );
        assert_eq!(
            std::fs::read(prev_path(&env.target)).unwrap(),
            b"OLD BINARY"
        );
        std::fs::remove_dir(blocked_restore).unwrap();
        assert!(matches!(
            run(&env, &platform(&env, None, false), 0).unwrap(),
            Outcome::RolledBack { .. }
        ));
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
    }

    #[test]
    fn failed_recovery_restart_retains_staging_until_retry_succeeds() {
        let env = setup(b"NEW BINARY", None);
        struct CannotRestart(Cell<u32>);
        impl Platform for CannotRestart {
            fn restart_service(&self) -> Result<()> {
                self.0.set(self.0.get() + 1);
                if self.0.get() > 1 {
                    bail!("old service did not restart");
                }
                Ok(())
            }
        }
        assert!(run(&env, &CannotRestart(Cell::new(0)), 0).is_err());
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
        assert!(env.paths.offer().exists());
        assert!(env.paths.artifact().exists());
        assert!(UpdateState::load(&env.paths).blocked_version.is_none());
        assert!(matches!(
            run(&env, &platform(&env, None, false), 0).unwrap(),
            Outcome::RolledBack { .. }
        ));
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
    }

    #[test]
    fn failed_restore_preserves_staging_and_does_not_block_version() {
        let env = setup(b"NEW BINARY", None);
        struct MissingBackup<'a>(&'a Env);
        impl Platform for MissingBackup<'_> {
            fn restart_service(&self) -> Result<()> {
                Ok(())
            }
            fn stop_service(&self) -> Result<()> {
                std::fs::remove_file(prev_path(&self.0.target))?;
                Ok(())
            }
        }
        assert!(run(&env, &MissingBackup(&env), 0).is_err());
        assert!(
            env.paths.offer().exists(),
            "offer remains available for recovery"
        );
        assert!(env.paths.artifact().exists());
        assert!(UpdateState::load(&env.paths).blocked_version.is_none());
    }

    #[test]
    fn binary_signature_is_restored_on_rollback() {
        let env = setup(b"NEW BINARY", None);
        let old = provision_binary_signature(&env, &Sha256::digest(b"NEW BINARY"), true);
        assert!(matches!(
            run(&env, &platform(&env, None, false), 0).unwrap(),
            Outcome::RolledBack { .. }
        ));
        assert_eq!(
            std::fs::read(env.baseline.with_file_name("binary.sig")).unwrap(),
            old
        );
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
    }

    #[test]
    fn missing_or_wrong_binary_signature_aborts_before_swap() {
        for include_signature in [false, true] {
            let env = setup(b"NEW BINARY", None);
            let old = provision_binary_signature(
                &env,
                &Sha256::digest(b"WRONG BINARY"),
                include_signature,
            );
            let p = platform(&env, Some("0.5.0"), false);
            assert!(run(&env, &p, 0).is_err());
            assert_eq!(p.restarts.get(), 0);
            assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
            assert_eq!(
                std::fs::read(env.baseline.with_file_name("binary.sig")).unwrap(),
                old
            );
        }
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
        run_with_baseline_and_version(env, platform, timeout_ms, baseline, "0.4.4")
    }

    fn run_with_baseline_and_version(
        env: &Env,
        platform: &dyn Platform,
        timeout_ms: u64,
        baseline: Option<&Path>,
        current_version: &str,
    ) -> Result<Outcome> {
        let (rk, ck) = (env.release.verifying_key(), env.command.verifying_key());
        let ctx = ApplyContext {
            verify: VerifyContext {
                release_key: &rk,
                command_key: &ck,
                agent_id: "agent-1",
                current_version,
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
    fn successful_update_cleanup_failure_is_reported_and_can_resume_on_new_version() {
        let env = setup(b"NEW BINARY", None);
        struct LockedArtifact<'a>(&'a Env);
        impl Platform for LockedArtifact<'_> {
            fn restart_service(&self) -> Result<()> {
                std::fs::write(self.0.paths.healthy_marker(), "0.5.0")?;
                // A directory reliably simulates a non-removable staging file
                // on both Windows and Unix, including elevated test runners.
                std::fs::remove_file(self.0.paths.artifact())?;
                std::fs::create_dir(self.0.paths.artifact())?;
                Ok(())
            }
        }
        assert!(run(&env, &LockedArtifact(&env), 0).is_err());
        assert!(env.paths.offer().exists(), "retain the retry trigger");
        std::fs::remove_dir(env.paths.artifact()).unwrap();
        let p = platform(&env, None, false);
        assert_eq!(
            run_with_baseline_and_version(&env, &p, 0, Some(&env.baseline), "0.5.0").unwrap(),
            Outcome::Applied {
                version: "0.5.0".into()
            }
        );
        assert_eq!(
            p.restarts.get(),
            0,
            "completion must not reinstall or roll back"
        );
        assert_eq!(std::fs::read(&env.target).unwrap(), b"NEW BINARY");
        assert_eq!(
            std::fs::read(prev_path(&env.target)).unwrap(),
            b"OLD BINARY"
        );
        assert!(!env.paths.offer().exists());
        assert!(!env.paths.recovery().exists());
        assert_eq!(UpdateState::load(&env.paths).last_issued_at, 500);
    }

    #[test]
    fn completed_update_crash_before_journal_removal_does_not_roll_back() {
        let env = setup(b"NEW BINARY", None);
        struct InterruptedCleanup<'a>(&'a Env);
        impl Platform for InterruptedCleanup<'_> {
            fn restart_service(&self) -> Result<()> {
                std::fs::write(self.0.paths.healthy_marker(), "0.5.0")?;
                std::fs::copy(self.0.paths.recovery(), self.0._root.join("saved-recovery"))?;
                std::fs::remove_file(self.0.paths.recovery())?;
                std::fs::create_dir(self.0.paths.recovery())?;
                Ok(())
            }
        }
        assert!(run(&env, &InterruptedCleanup(&env), 0).is_err());
        assert!(UpdateState::load(&env.paths).completion.is_some());
        // Reconstruct the state at a crash immediately after the completion
        // commit: the healthy binary and the original rollback journal remain.
        std::fs::remove_dir(env.paths.recovery()).unwrap();
        std::fs::copy(env._root.join("saved-recovery"), env.paths.recovery()).unwrap();
        let p = platform(&env, None, false);
        assert_eq!(
            run_with_baseline_and_version(&env, &p, 0, Some(&env.baseline), "0.5.0").unwrap(),
            Outcome::Applied {
                version: "0.5.0".into()
            }
        );
        assert_eq!(p.restarts.get(), 0);
        assert_eq!(std::fs::read(&env.target).unwrap(), b"NEW BINARY");
        assert!(!env.paths.offer().exists());
        assert!(!env.paths.recovery().exists());
    }

    #[test]
    fn rollback_cleanup_failure_retries_cleanup_without_reinstalling_failed_release() {
        let env = setup(b"NEW BINARY", None);
        struct LockedArtifact<'a> {
            env: &'a Env,
            restarts: Cell<u32>,
        }
        impl Platform for LockedArtifact<'_> {
            fn restart_service(&self) -> Result<()> {
                self.restarts.set(self.restarts.get() + 1);
                if self.restarts.get() == 1 {
                    std::fs::remove_file(self.env.paths.artifact())?;
                    std::fs::create_dir(self.env.paths.artifact())?;
                }
                Ok(())
            }
        }
        assert!(run(
            &env,
            &LockedArtifact {
                env: &env,
                restarts: Cell::new(0)
            },
            0
        )
        .is_err());
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
        assert_eq!(
            UpdateState::load(&env.paths).blocked_version.as_deref(),
            Some("0.5.0")
        );
        assert!(env.paths.offer().exists());
        std::fs::remove_dir(env.paths.artifact()).unwrap();
        let p = platform(&env, None, false);
        assert_eq!(
            run(&env, &p, 0).unwrap(),
            Outcome::RolledBack {
                attempted: "0.5.0".into()
            }
        );
        assert_eq!(p.restarts.get(), 0);
        assert_eq!(std::fs::read(&env.target).unwrap(), b"OLD BINARY");
        assert!(!env.paths.offer().exists());
        assert_eq!(UpdateState::load(&env.paths).last_issued_at, 500);
    }

    #[test]
    fn completion_cannot_discard_a_different_offer_and_legacy_state_still_loads() {
        let env = setup(b"NEW BINARY", None);
        let offer = std::fs::read(env.paths.offer()).unwrap();
        run(&env, &platform(&env, Some("0.5.0"), false), 0).unwrap();
        let replacement = [offer.as_slice(), b" "].concat();
        std::fs::write(env.paths.offer(), &replacement).unwrap();
        std::fs::write(env.paths.artifact(), b"next artifact").unwrap();
        assert!(resume_completed_staging(&env.paths).unwrap().is_none());
        assert_eq!(std::fs::read(env.paths.offer()).unwrap(), replacement);
        assert_eq!(
            std::fs::read(env.paths.artifact()).unwrap(),
            b"next artifact"
        );
        assert_eq!(UpdateState::load(&env.paths).last_issued_at, 500);
        std::fs::write(
            env.paths.state(),
            br#"{"last_issued_at":500,"blocked_version":null}"#,
        )
        .unwrap();
        assert!(UpdateState::load(&env.paths).completion.is_none());
        assert_eq!(UpdateState::load(&env.paths).last_issued_at, 500);
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
            completion: None,
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
