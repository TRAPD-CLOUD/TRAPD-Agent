//! Software P-256 identity.
//!
//! Linux (and any non-Windows target): the key is the raw 32-byte P-256 scalar
//! in `identity.key` in the state directory, mode 0600, written atomically.
//! Windows has no file key: the CNG providers live in `windows_cng`.

#[cfg(not(windows))]
use anyhow::Result;

#[cfg(not(windows))]
use super::IdentityKey;

#[cfg(not(windows))]
mod file {
    use std::path::{Path, PathBuf};

    use anyhow::{anyhow, Context, Result};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use zeroize::Zeroizing;

    use crate::identity::{IdentityKey, Protection};

    /// File name inside the state directory.
    pub const KEY_FILE: &str = "identity.key";

    pub fn default_path() -> PathBuf {
        crate::paths::state_dir().join(KEY_FILE)
    }

    /// P-256 key held in memory (zeroized on drop by `SigningKey`).
    pub struct SoftwareKey {
        key: SigningKey,
    }

    impl SoftwareKey {
        pub fn load_at(path: &Path) -> Result<Option<Self>> {
            let der = match crate::paths::bounded_regular_bytes(path, 4096) {
                Ok(d) => Zeroizing::new(d),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
            };
            let key = SigningKey::from_slice(&der)
                .map_err(|e| anyhow!("{} is not a valid P-256 key: {e}", path.display()))?;
            Ok(Some(Self { key }))
        }

        pub fn load_or_create_at(path: &Path) -> Result<Self> {
            if let Some(k) = Self::load_at(path)? {
                return Ok(k);
            }
            let key = generate()?;
            let raw = Zeroizing::new(key.to_bytes());
            crate::paths::write_atomic(path, raw.as_slice(), 0o600)
                .with_context(|| format!("persist {}", path.display()))?;
            Ok(Self { key })
        }
    }

    /// Fresh key from the OS CSPRNG (rejection-sampled into the curve order).
    fn generate() -> Result<SigningKey> {
        for _ in 0..8 {
            let mut buf = Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut buf[..]).map_err(|e| anyhow!("OS entropy unavailable: {e}"))?;
            if let Ok(k) = SigningKey::from_slice(&buf[..]) {
                return Ok(k);
            }
        }
        Err(anyhow!("could not generate a valid P-256 scalar"))
    }

    impl IdentityKey for SoftwareKey {
        fn public_key_spki_der(&self) -> Vec<u8> {
            let point = self.key.verifying_key().to_sec1_point(false);
            let x: [u8; 32] = point
                .x()
                .expect("uncompressed")
                .as_slice()
                .try_into()
                .expect("32 bytes");
            let y: [u8; 32] = point
                .y()
                .expect("uncompressed")
                .as_slice()
                .try_into()
                .expect("32 bytes");
            crate::identity::spki_from_xy(&x, &y)
        }

        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
            let sig: Signature = self.key.sign(msg);
            Ok(sig.to_der().as_bytes().to_vec())
        }

        fn protection(&self) -> Protection {
            Protection::Software
        }
    }
}

#[cfg(not(windows))]
pub use file::SoftwareKey;

#[cfg(not(windows))]
pub fn load_or_create() -> Result<Box<dyn IdentityKey>> {
    Ok(Box::new(SoftwareKey::load_or_create_at(
        &file::default_path(),
    )?))
}

#[cfg(not(windows))]
pub fn load_existing() -> Result<Option<Box<dyn IdentityKey>>> {
    Ok(SoftwareKey::load_at(&file::default_path())?.map(|k| Box::new(k) as Box<dyn IdentityKey>))
}

#[cfg(all(test, not(windows)))]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    pub fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("trapd-ident-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn key_file_is_0600_and_reloads_to_same_public_key() {
        let dir = scratch("reload");
        let path = dir.join("identity.key");
        let a = SoftwareKey::load_or_create_at(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let b = SoftwareKey::load_or_create_at(&path).unwrap();
        assert_eq!(a.public_key_spki_der(), b.public_key_spki_der());
        assert_eq!(a.protection(), crate::identity::Protection::Software);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_at_missing_is_none_and_garbage_is_an_error() {
        let dir = scratch("missing");
        let path = dir.join("identity.key");
        assert!(SoftwareKey::load_at(&path).unwrap().is_none());
        std::fs::write(&path, b"not a key").unwrap();
        assert!(SoftwareKey::load_at(&path).is_err());
        // A corrupt file must not be silently replaced by a new identity.
        assert!(SoftwareKey::load_or_create_at(&path).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
