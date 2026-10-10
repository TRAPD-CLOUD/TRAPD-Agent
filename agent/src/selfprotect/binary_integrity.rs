//! Binary self-integrity verification.
//!
//! On first run the SHA256 hash of the running executable is written to the
//! baseline (`binary.sha256`).  On every subsequent start the hash is
//! re-computed and compared against it.  A mismatch aborts startup.
//!
//! Trust model (what may refresh a stale baseline):
//!   * the MSI / deb installer (removes the baseline inside its transaction),
//!   * signed self-update (`update::apply` rewrites binary + `binary.sig` +
//!     baseline together after verifying the release signature),
//!   * a binary whose digest carries a valid Ed25519 signature (`binary.sig`)
//!     under the pinned release key: the baseline is then refreshed atomically,
//!   * an operator who deliberately deletes the baseline (see the error text).
//!
//! Nothing else does.  An unsigned binary with a stale baseline is refused,
//! and is never trusted just because it is "newer" or claims a version.
//!
//! Verification key resolution (`resolve_signing_key`):
//!   1. `release_signing.pub` in the release key dir (Linux
//!      `/etc/trapd-release`, read-only for the agent; Windows `config\`),
//!   2. legacy `config/signing.pub`, only if (1) is absent.  The release key
//!      always wins so an agent-writable legacy file can never override the
//!      pinned anchor.
//!
//! If no key exists, or the key exists but there is no `binary.sig`, signature
//! verification is skipped (warning) and only the hash baseline protects the
//! binary.  A key + `binary.sig` that do not verify is always fatal.
//!
//! Restart-loop guard: an integrity violation is not transient, so retrying
//! quickly can never help.  Each consecutive failure for the same binary hash
//! is counted in the state dir and the process holds for an exponentially
//! growing delay (30 s .. 15 min) before exiting, so the service manager does
//! not spin.  A later fixed baseline is still picked up automatically.
//!
//! Layout:
//!   config/binary.sha256 - "sha256:<hex>" baseline (written on first run)
//!   config/binary.sig    - 64-byte raw Ed25519 signature over the raw digest

use std::io::Read as IoRead;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::paths;
use crate::paths::binary_baseline_line as baseline_line;

/// Location of the baseline. Also used by the update helper, which must rewrite
/// it whenever it swaps the binary (see `update::apply`).
pub(crate) fn hash_store_path() -> PathBuf {
    paths::config_dir().join("binary.sha256")
}

fn sig_path() -> PathBuf {
    paths::config_dir().join("binary.sig")
}

fn guard_path() -> PathBuf {
    paths::state_dir().join("integrity_guard")
}

/// Pinned verification key for `binary.sig`; see the module docs.
pub(crate) fn resolve_signing_key(release_dir: &Path, config_dir: &Path) -> Option<PathBuf> {
    let release = release_dir.join("release_signing.pub");
    if release.exists() {
        return Some(release);
    }
    let legacy = config_dir.join("signing.pub");
    if legacy.exists() {
        warn!(
            path = %legacy.display(),
            "using legacy signing.pub; provision release_signing.pub instead"
        );
        return Some(legacy);
    }
    None
}

pub(crate) fn load_signing_key(path: &Path) -> Result<ed25519_dalek::VerifyingKey> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("Cannot read Ed25519 public key from {}", path.display()))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "{} must be exactly 32 raw bytes (Ed25519 verifying key)",
            path.display()
        )
    })?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr).with_context(|| {
        format!(
            "{} contains an invalid Ed25519 verifying key",
            path.display()
        )
    })
}

/// Typed so callers can tell a (non-transient) integrity violation apart from
/// an I/O error and hold off before exiting.
#[derive(Debug)]
pub struct IntegrityViolation {
    message: String,
    pub hold: Duration,
}

impl std::fmt::Display for IntegrityViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for IntegrityViolation {}

/// How long the caller should wait before exiting after `err`, if it is an
/// integrity violation. Callers sleep (stop-aware where possible) then exit.
pub fn hold_duration(err: &anyhow::Error) -> Option<Duration> {
    err.downcast_ref::<IntegrityViolation>().map(|v| v.hold)
}

/// 30 s, 60 s, 120 s ... capped at 15 min.
fn backoff(consecutive_failures: u32) -> Duration {
    let exp = consecutive_failures.saturating_sub(1).min(5);
    Duration::from_secs((30u64 << exp).min(15 * 60))
}

fn read_guard(path: &Path) -> Option<(String, u32)> {
    let text = std::fs::read_to_string(path).ok()?;
    let (hash, count) = text.trim().rsplit_once(' ')?;
    Some((hash.to_string(), count.parse().ok()?))
}

/// Count this failure (per distinct binary hash). Best-effort: a guard that
/// cannot be written degrades to the minimum delay, never to a skipped check.
fn record_failure(path: &Path, hash_str: &str) -> u32 {
    let count = match read_guard(path) {
        Some((h, n)) if h == hash_str => n.saturating_add(1),
        _ => 1,
    };
    if let Err(e) = paths::write_atomic(path, format!("{hash_str} {count}").as_bytes(), 0o600) {
        warn!(error = %e, "could not persist integrity failure counter");
    }
    count
}

fn clear_guard(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[derive(Debug, PartialEq, Eq)]
enum SignatureStatus {
    /// `binary.sig` verified under the pinned key.
    Verified,
    /// No key or no signature: only the baseline protects the binary.
    NotChecked,
}

/// Run all binary integrity checks.  Call this once at agent startup,
/// before any network connections or sensitive operations.
///
/// Hard failures (the agent refuses to start):
///   * the stored baseline does not match the running binary and the binary
///     is not covered by a valid signature, OR
///   * an Ed25519 signature is present but does not verify.
///
/// Soft failures (warn and continue) cover the *absence* of a writable baseline
/// location, e.g. a non-root test run where the config directory is read-only.
pub fn check() -> Result<()> {
    let exe = exe_path()?;
    let (hash_hex, hash_bytes) = sha256_of_file(&exe)?;
    let hash_str = baseline_line(&hash_hex);

    info!(binary = %exe.display(), hash = %hash_str, "Binary integrity check started");

    let key = resolve_signing_key(&crate::update::release_key_dir(), paths::config_dir());
    run_check(
        &exe,
        &hash_str,
        &hash_bytes,
        key.as_deref(),
        &sig_path(),
        &hash_store_path(),
        &guard_path(),
    )
}

fn run_check(
    exe: &Path,
    hash_str: &str,
    hash_bytes: &[u8],
    key: Option<&Path>,
    sig: &Path,
    baseline: &Path,
    guard: &Path,
) -> Result<()> {
    // A failed signature must never leave a new trusted baseline behind.
    let status = match verify_ed25519_signature(hash_bytes, key, sig) {
        Ok(status) => status,
        Err(e) => return Err(violation(guard, hash_str, format!("{e:#}"))),
    };
    match check_baseline(exe, baseline, hash_str, status == SignatureStatus::Verified) {
        Ok(()) => {
            clear_guard(guard);
            Ok(())
        }
        Err(e) => Err(violation(guard, hash_str, format!("{e:#}"))),
    }
}

fn violation(guard: &Path, hash_str: &str, message: String) -> anyhow::Error {
    let hold = backoff(record_failure(guard, hash_str));
    anyhow::Error::new(IntegrityViolation { message, hold })
}

fn check_baseline(exe: &Path, hash_file: &Path, hash_str: &str, signed: bool) -> Result<()> {
    if hash_file.exists() {
        let stored = std::fs::read_to_string(hash_file).with_context(|| {
            format!(
                "Cannot read binary hash baseline from {}",
                hash_file.display()
            )
        })?;
        let stored = stored.trim();

        if stored != hash_str {
            if signed {
                // The binary is covered by a valid signature from the pinned
                // key, so it is authentic regardless of the stale baseline.
                write_baseline(hash_file, hash_str)?;
                warn!(
                    previous = %stored,
                    current = %hash_str,
                    "Binary replaced out of band but its signature verifies - \
                     integrity baseline refreshed"
                );
                return Ok(());
            }
            bail!(
                "BINARY INTEGRITY VIOLATION: {} does not match the recorded baseline\n  \
                 baseline: {stored}\n  \
                 current:  {hash_str}\n  \
                 The binary was replaced outside an installer or signed update and carries \
                 no valid signature, so it is NOT trusted. Remediation, in order of preference:\n  \
                 1. Install the release MSI/deb, or let signed self-update replace it.\n  \
                 2. Place the release's binary.sig next to the baseline (the signature must \
                 verify under release_signing.pub).\n  \
                 3. If you replaced it deliberately and the current SHA-256 above matches the \
                 published release hash: stop the service, delete {}, start the service.\n  \
                 Otherwise treat the binary as tampered with. The agent retries with growing \
                 delays (max 15 min) and does not restart-loop.",
                exe.display(),
                hash_file.display()
            );
        }
        info!("Binary SHA256 ok (matches stored baseline)");
    } else {
        // First run: create the baseline directory + file.  Best-effort: if the
        // config directory is not writable (non-root test run) we warn rather
        // than abort, so the agent still comes up.
        match write_baseline(hash_file, hash_str) {
            Ok(()) => {
                info!(path = %hash_file.display(), "Binary hash baseline written (first run)");
            }
            Err(e) => warn!(
                path = %hash_file.display(),
                error = %e,
                "Could not write binary hash baseline - self-integrity not yet enforced \
                 (config dir not writable?). Agent continues."
            ),
        }
    }

    Ok(())
}

fn write_baseline(hash_file: &Path, hash_str: &str) -> Result<()> {
    // Shared atomic writer (temp sibling, then rename) at mode 0600: a crash
    // mid-write can never leave a half-written baseline that would trigger a
    // false violation on the next start.
    paths::write_atomic(hash_file, hash_str.as_bytes(), 0o600)
        .with_context(|| format!("write binary hash baseline to {}", hash_file.display()))
}

fn verify_ed25519_signature(
    hash_bytes: &[u8],
    key: Option<&Path>,
    sig_path: &Path,
) -> Result<SignatureStatus> {
    use ed25519_dalek::Signature;

    let Some(key_path) = key else {
        warn!(
            "No Ed25519 verification key (release_signing.pub) found - \
             binary signature verification skipped; only the hash baseline applies."
        );
        return Ok(SignatureStatus::NotChecked);
    };
    if !sig_path.exists() {
        warn!(
            "Verification key present but no signature at {} - \
             signature verification skipped.",
            sig_path.display()
        );
        return Ok(SignatureStatus::NotChecked);
    }

    let verifying_key = load_signing_key(key_path)?;
    let sig_bytes = std::fs::read(sig_path)
        .with_context(|| format!("Cannot read Ed25519 signature from {}", sig_path.display()))?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        anyhow::anyhow!("binary.sig must be exactly 64 raw bytes (Ed25519 signature)")
    })?;
    let signature = Signature::from_bytes(&sig_arr);

    // The signature covers the 32-byte raw SHA256 digest of the binary.
    verifying_key
        .verify_strict(hash_bytes, &signature)
        .context(
        "Ed25519 signature verification FAILED - binary may have been replaced or tampered with",
    )?;

    info!("Ed25519 signature ok");
    Ok(SignatureStatus::Verified)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn exe_path() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link("/proc/self/exe")
            .context("Cannot resolve /proc/self/exe - are we running on Linux?")
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::current_exe().context("Cannot resolve the running executable's path")
    }
}

/// Returns `(hex_string, raw_32_bytes)`.
fn sha256_of_file(path: &Path) -> Result<(String, Vec<u8>)> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("Cannot open {} for integrity hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = file
            .read(&mut buf)
            .context("I/O error while hashing binary")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok((hex::encode(digest.as_slice()), digest.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    struct Fx {
        root: PathBuf,
    }
    impl Fx {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("trapd-integrity-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(root.join("config")).unwrap();
            std::fs::create_dir_all(root.join("release")).unwrap();
            Fx { root }
        }
        fn baseline(&self) -> PathBuf {
            self.root.join("config/binary.sha256")
        }
        fn sig(&self) -> PathBuf {
            self.root.join("config/binary.sig")
        }
        fn guard(&self) -> PathBuf {
            self.root.join("state_guard")
        }
        fn key_file(&self) -> PathBuf {
            self.root.join("release/release_signing.pub")
        }
        fn run(&self, bytes: &[u8], key: Option<&Path>) -> Result<()> {
            let digest = Sha256::digest(bytes);
            run_check(
                &self.root.join("agent.exe"),
                &baseline_line(&hex::encode(digest)),
                &digest,
                key,
                &self.sig(),
                &self.baseline(),
                &self.guard(),
            )
        }
    }
    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn line(bytes: &[u8]) -> String {
        baseline_line(&hex::encode(Sha256::digest(bytes)))
    }

    #[test]
    fn a_self_reported_version_change_cannot_authorize_different_bytes() {
        let fx = Fx::new();
        std::fs::write(fx.baseline(), line(b"trusted v0.6.9")).unwrap();
        std::fs::write(fx.root.join("config/binary.version"), "0.6.9").unwrap();
        let err = fx
            .run(b"replacement declaring version 99.0.0", None)
            .unwrap_err();
        assert!(err.to_string().contains("BINARY INTEGRITY VIOLATION"));
        assert_eq!(
            std::fs::read_to_string(fx.baseline()).unwrap(),
            line(b"trusted v0.6.9")
        );
    }

    #[test]
    fn installer_reset_records_new_baseline_then_rejects_later_changes() {
        let fx = Fx::new();
        fx.run(b"installed bytes", None).unwrap();
        assert_eq!(
            std::fs::read_to_string(fx.baseline()).unwrap(),
            line(b"installed bytes")
        );
        fx.run(b"installed bytes", None).unwrap();
        assert!(fx.run(b"other bytes", None).is_err());
        assert_eq!(
            std::fs::read_to_string(fx.baseline()).unwrap(),
            line(b"installed bytes")
        );
    }

    #[test]
    fn validly_signed_manual_copy_refreshes_the_baseline_atomically() {
        let fx = Fx::new();
        let signer = SigningKey::from_bytes(&[9; 32]);
        std::fs::write(fx.key_file(), signer.verifying_key().to_bytes()).unwrap();
        std::fs::write(fx.baseline(), line(b"old")).unwrap();
        std::fs::write(
            fx.sig(),
            signer.sign(&Sha256::digest(b"new release")).to_bytes(),
        )
        .unwrap();
        fx.run(b"new release", Some(&fx.key_file())).unwrap();
        assert_eq!(
            std::fs::read_to_string(fx.baseline()).unwrap(),
            line(b"new release")
        );
        assert!(!fx.guard().exists());
    }

    #[test]
    fn tampered_binary_is_rejected_even_with_a_signature_for_other_bytes() {
        let fx = Fx::new();
        let signer = SigningKey::from_bytes(&[9; 32]);
        std::fs::write(fx.key_file(), signer.verifying_key().to_bytes()).unwrap();
        std::fs::write(fx.baseline(), line(b"old")).unwrap();
        std::fs::write(
            fx.sig(),
            signer.sign(&Sha256::digest(b"genuine")).to_bytes(),
        )
        .unwrap();
        let err = fx.run(b"tampered", Some(&fx.key_file())).unwrap_err();
        assert!(format!("{err:#}").contains("signature verification FAILED"));
        assert!(hold_duration(&err).is_some());
        assert_eq!(
            std::fs::read_to_string(fx.baseline()).unwrap(),
            line(b"old")
        );
    }

    #[test]
    fn signature_from_an_untrusted_key_does_not_refresh_the_baseline() {
        let fx = Fx::new();
        let pinned = SigningKey::from_bytes(&[9; 32]);
        let attacker = SigningKey::from_bytes(&[4; 32]);
        std::fs::write(fx.key_file(), pinned.verifying_key().to_bytes()).unwrap();
        std::fs::write(fx.baseline(), line(b"old")).unwrap();
        std::fs::write(fx.sig(), attacker.sign(&Sha256::digest(b"evil")).to_bytes()).unwrap();
        assert!(fx.run(b"evil", Some(&fx.key_file())).is_err());
        assert_eq!(
            std::fs::read_to_string(fx.baseline()).unwrap(),
            line(b"old")
        );
    }

    #[test]
    fn unsigned_stale_baseline_error_names_the_remediation() {
        let fx = Fx::new();
        std::fs::write(fx.baseline(), line(b"old")).unwrap();
        let err = fx.run(b"manual copy", None).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("binary.sig"));
        assert!(text.contains("release_signing.pub"));
        assert!(text.contains(&format!("delete {}", fx.baseline().display())));
        assert!(hold_duration(&err).is_some());
    }

    #[test]
    fn key_resolution_prefers_release_key_and_falls_back_to_legacy() {
        let fx = Fx::new();
        let (release, config) = (fx.root.join("release"), fx.root.join("config"));
        assert_eq!(resolve_signing_key(&release, &config), None);
        std::fs::write(config.join("signing.pub"), [1u8; 32]).unwrap();
        assert_eq!(
            resolve_signing_key(&release, &config),
            Some(config.join("signing.pub"))
        );
        std::fs::write(release.join("release_signing.pub"), [2u8; 32]).unwrap();
        assert_eq!(
            resolve_signing_key(&release, &config),
            Some(release.join("release_signing.pub"))
        );
    }

    #[test]
    fn absent_key_or_signature_skips_verification() {
        let fx = Fx::new();
        let signer = SigningKey::from_bytes(&[9; 32]);
        std::fs::write(fx.key_file(), signer.verifying_key().to_bytes()).unwrap();
        // key but no binary.sig
        fx.run(b"bytes", Some(&fx.key_file())).unwrap();
        // no key at all
        fx.run(b"bytes", None).unwrap();
    }

    #[test]
    fn restart_guard_backs_off_per_hash_and_resets_on_success() {
        let fx = Fx::new();
        std::fs::write(fx.baseline(), line(b"old")).unwrap();
        let hold = |bytes: &[u8]| hold_duration(&fx.run(bytes, None).unwrap_err()).unwrap();
        assert_eq!(hold(b"bad"), Duration::from_secs(30));
        assert_eq!(hold(b"bad"), Duration::from_secs(60));
        assert_eq!(hold(b"bad"), Duration::from_secs(120));
        // A different binary restarts the sequence.
        assert_eq!(hold(b"other"), Duration::from_secs(30));
        for _ in 0..20 {
            assert!(hold(b"other") <= Duration::from_secs(15 * 60));
        }
        assert_eq!(backoff(1_000_000), Duration::from_secs(15 * 60));
        fx.run(b"old", None).unwrap();
        assert!(!fx.guard().exists());
    }
}
