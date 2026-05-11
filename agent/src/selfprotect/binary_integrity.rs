//! Binary self-integrity verification.
//!
//! On first run the SHA256 hash of `/proc/self/exe` is written to
//! `HASH_STORE_PATH`.  On every subsequent start the hash is re-computed and
//! compared against the stored baseline.  Any mismatch causes the agent to
//! abort with a critical error.
//!
//! If a 32-byte Ed25519 public key exists at `PUBKEY_PATH` **and** a 64-byte
//! raw signature exists at `SIG_PATH`, the signature over the binary's SHA256
//! digest is verified with `ed25519-dalek` before the agent continues.
//!
//! Directory layout under `/etc/trapd/`:
//!   binary.sha256   — "sha256:<hex>" baseline (written on first run)
//!   signing.pub     — 32-byte raw Ed25519 verifying key (optional)
//!   binary.sig      — 64-byte raw Ed25519 signature  (optional)

use std::io::Read as IoRead;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

const HASH_STORE_PATH: &str = "/etc/trapd/binary.sha256";
const PUBKEY_PATH:     &str = "/etc/trapd/signing.pub";
const SIG_PATH:        &str = "/etc/trapd/binary.sig";

/// Run all binary integrity checks.  Call this once at agent startup,
/// before any network connections or sensitive operations.
pub fn check() -> Result<()> {
    let exe = exe_path()?;
    let (hash_hex, hash_bytes) = sha256_of_file(&exe)?;
    let hash_str = format!("sha256:{hash_hex}");

    info!(binary = %exe.display(), hash = %hash_str, "Binary integrity check started");

    let hash_file = Path::new(HASH_STORE_PATH);

    if hash_file.exists() {
        let stored = std::fs::read_to_string(hash_file)
            .context("Cannot read binary hash baseline from /etc/trapd/binary.sha256")?;
        let stored = stored.trim();

        if stored != hash_str {
            bail!(
                "BINARY INTEGRITY VIOLATION: hash mismatch for {}\n  \
                 baseline: {stored}\n  \
                 current:  {hash_str}\n  \
                 The agent binary may have been tampered with.",
                exe.display()
            );
        }
        info!("Binary SHA256 ✓  (matches stored baseline)");
    } else {
        // First run: create the baseline directory + file.
        if let Some(parent) = hash_file.parent() {
            std::fs::create_dir_all(parent)
                .context("Cannot create /etc/trapd/ for binary hash storage")?;
        }
        std::fs::write(hash_file, &hash_str)
            .context("Cannot write binary hash baseline to /etc/trapd/binary.sha256")?;
        info!(path = HASH_STORE_PATH, "Binary hash baseline written (first run)");
    }

    verify_ed25519_signature(&hash_bytes)
}

fn verify_ed25519_signature(hash_bytes: &[u8]) -> Result<()> {
    use ed25519_dalek::{Signature, VerifyingKey};

    let pubkey_path = Path::new(PUBKEY_PATH);
    let sig_path    = Path::new(SIG_PATH);

    match (pubkey_path.exists(), sig_path.exists()) {
        (false, _) => {
            warn!(
                "Ed25519 public key not found at {PUBKEY_PATH} — \
                 signature verification skipped. \
                 Place a 32-byte raw Ed25519 verifying key there to enable."
            );
            return Ok(());
        }
        (true, false) => {
            warn!(
                "Ed25519 public key present but no signature found at {SIG_PATH} — \
                 signature verification skipped."
            );
            return Ok(());
        }
        _ => {}
    }

    let pubkey_bytes = std::fs::read(pubkey_path)
        .context("Cannot read Ed25519 public key from /etc/trapd/signing.pub")?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing.pub must be exactly 32 raw bytes (Ed25519 verifying key)"))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .context("signing.pub contains an invalid Ed25519 verifying key")?;

    let sig_bytes = std::fs::read(sig_path)
        .context("Cannot read Ed25519 signature from /etc/trapd/binary.sig")?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("binary.sig must be exactly 64 raw bytes (Ed25519 signature)"))?;
    let signature = Signature::from_bytes(&sig_arr);

    // The signature covers the 32-byte raw SHA256 digest of the binary.
    verifying_key
        .verify_strict(hash_bytes, &signature)
        .context(
            "Ed25519 signature verification FAILED — binary may have been replaced or tampered with"
        )?;

    info!("Ed25519 signature ✓");
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn exe_path() -> Result<PathBuf> {
    std::fs::read_link("/proc/self/exe")
        .context("Cannot resolve /proc/self/exe — are we running on Linux?")
}

/// Returns `(hex_string, raw_32_bytes)`.
fn sha256_of_file(path: &Path) -> Result<(String, Vec<u8>)> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("Cannot open {} for integrity hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = file.read(&mut buf).context("I/O error while hashing binary")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok((hex::encode(digest.as_slice()), digest.to_vec()))
}
