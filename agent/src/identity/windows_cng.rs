//! Windows CNG (NCrypt) backed identity key.
//!
//! Machine-scope, non-exportable ECDSA P-256 key named [`KEY_NAME`]. The
//! private key never leaves the key storage provider, so a copy of
//! `credentials.json` / the state directory does not carry the identity.
//!
//! Two providers: [`Provider::Platform`] (`MS_PLATFORM_CRYPTO_PROVIDER`, the
//! TPM; `Protection::Tpm`) and [`Provider::Software`] (`MS_KEY_STORAGE_PROVIDER`).
//! Which one is used is decided by [`super::select`]; the provider that created
//! the key is recorded in `identity.provider` in the state directory.
//!
//! Key ACL: machine keys are stored under
//! `%ProgramData%\Microsoft\Crypto\{Keys,PCPKSP}` and are accessible to
//! SYSTEM and the local Administrators only (CNG default for machine keys; we
//! set no custom security descriptor). TPM keys additionally cannot be
//! exported at all (the private part exists only inside the TPM). The key is
//! created with no UI and no authorization value, so the service can use it
//! unattended; anyone who can run code as SYSTEM/admin on the host can ask the
//! TPM to sign, which is why the backend also cross-checks behaviour (L6).

use std::sync::Mutex;

use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::{
    NTE_BAD_KEYSET, NTE_DEVICE_NOT_READY, NTE_NOT_SUPPORTED, NTE_NO_KEY, NTE_PROVIDER_DLL_FAIL,
    NTE_PROV_DLL_NOT_FOUND,
};
use windows_sys::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash, BCRYPT_ECCKEY_BLOB,
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
    MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ALLOW_SIGNING_FLAG,
    NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY,
    NCRYPT_MACHINE_KEY_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
};

use super::select::{der_from_p1363, Backend, ProviderError};
use super::{spki_from_xy, IdentityKey, Protection};

/// Persisted key name inside the provider.
const KEY_NAME: &str = "TRAPD-Agent-Identity";

/// Key storage provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    /// `MS_KEY_STORAGE_PROVIDER` (software).
    Software,
    /// `MS_PLATFORM_CRYPTO_PROVIDER` (TPM).
    Platform,
}

impl Provider {
    fn name(self) -> PCWSTR {
        match self {
            Provider::Software => MS_KEY_STORAGE_PROVIDER,
            Provider::Platform => MS_PLATFORM_CRYPTO_PROVIDER,
        }
    }

    fn protection(self) -> Protection {
        match self {
            Provider::Software => Protection::Software,
            Provider::Platform => Protection::Tpm,
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Map an HRESULT to a [`ProviderError`]. With `provider_stage` set, the codes
/// that mean "this provider cannot be used on this machine" (TPM absent,
/// disabled, not ready, provider DLL missing, TBS/PCP errors) become
/// `Unavailable`; everything else is `Failed`.
fn classify(what: &str, hr: i32, provider_stage: bool) -> Result<(), ProviderError> {
    if hr >= 0 {
        return Ok(());
    }
    if provider_stage && is_provider_unavailable(hr) {
        return Err(ProviderError::Unavailable(format!(
            "{what}: HRESULT 0x{:08X}",
            hr as u32
        )));
    }
    Err(ProviderError::Failed(anyhow!(
        "{what} failed: HRESULT 0x{:08X}",
        hr as u32
    )))
}

fn is_provider_unavailable(hr: i32) -> bool {
    let u = hr as u32;
    hr == NTE_DEVICE_NOT_READY
        || hr == NTE_NOT_SUPPORTED
        || hr == NTE_PROV_DLL_NOT_FOUND
        || hr == NTE_PROVIDER_DLL_FAIL
        // TBS (0x8028xxxx) and TPM Platform Crypto Provider (0x8029xxxx) errors,
        // e.g. TBS_E_TPM_NOT_FOUND, TPM_E_PCP_DEVICE_NOT_READY.
        || (0x8028_0000..=0x8029_FFFF).contains(&u)
}

fn check(what: &str, hr: i32) -> Result<()> {
    if hr < 0 {
        bail!("{what} failed: HRESULT 0x{:08X}", hr as u32);
    }
    Ok(())
}

struct Handles {
    prov: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
}

impl Drop for Handles {
    fn drop(&mut self) {
        // SAFETY: both handles were returned by NCrypt and are freed exactly once.
        unsafe {
            if self.key != 0 {
                NCryptFreeObject(self.key);
            }
            if self.prov != 0 {
                NCryptFreeObject(self.prov);
            }
        }
    }
}

pub struct CngKey {
    handles: Mutex<Handles>,
    spki: Vec<u8>,
    provider: Provider,
}

impl CngKey {
    /// Open the persisted key `key_name`; when absent and `create` is set,
    /// generate it. `Ok(None)` only when the key is absent and `create` is
    /// false. `ProviderError::Unavailable` means the provider itself cannot be
    /// used on this machine (no/disabled TPM).
    pub fn open_named(
        provider: Provider,
        key_name: &str,
        create: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut prov: NCRYPT_PROV_HANDLE = 0;
        // SAFETY: out-pointer is valid; provider name is a static wide string.
        let hr = unsafe { NCryptOpenStorageProvider(&mut prov, provider.name(), 0) };
        classify("NCryptOpenStorageProvider", hr, true)?;
        let mut handles = Handles { prov, key: 0 };
        let name = wide(key_name);
        let flags = NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG;

        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: valid provider handle, NUL-terminated name, valid out-pointer.
        let hr = unsafe { NCryptOpenKey(handles.prov, &mut key, name.as_ptr(), 0, flags) };
        if hr == NTE_BAD_KEYSET || hr == NTE_NO_KEY {
            if !create {
                return Ok(None);
            }
            key = Self::create_key(provider, handles.prov, &name, flags)?;
        } else {
            classify("NCryptOpenKey", hr, false)?;
        }
        handles.key = key;
        let spki = Self::export_spki(key).map_err(ProviderError::Failed)?;
        Ok(Some(Self {
            handles: Mutex::new(handles),
            spki,
            provider,
        }))
    }

    fn create_key(
        provider: Provider,
        prov: NCRYPT_PROV_HANDLE,
        name: &[u16],
        flags: u32,
    ) -> Result<NCRYPT_KEY_HANDLE, ProviderError> {
        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: valid provider handle, static algorithm id, NUL-terminated name.
        let hr = unsafe {
            NCryptCreatePersistedKey(
                prov,
                &mut key,
                BCRYPT_ECDSA_P256_ALGORITHM,
                name.as_ptr(),
                0,
                flags,
            )
        };
        classify("NCryptCreatePersistedKey", hr, true)?;
        let result = (|| -> Result<(), ProviderError> {
            // Export policy 0 = the private key can never be exported. TPM
            // keys are non-exportable by construction; the platform provider
            // may reject the property, which is harmless there.
            let policy: u32 = 0;
            // SAFETY: key is a live handle; the buffer is a valid 4-byte DWORD.
            let hr = unsafe {
                NCryptSetProperty(
                    key,
                    NCRYPT_EXPORT_POLICY_PROPERTY,
                    &policy as *const u32 as *const u8,
                    4,
                    NCRYPT_SILENT_FLAG,
                )
            };
            if !(provider == Provider::Platform && hr == NTE_NOT_SUPPORTED) {
                classify("NCryptSetProperty(export policy)", hr, false)?;
            }
            let usage: u32 = NCRYPT_ALLOW_SIGNING_FLAG;
            // SAFETY: as above.
            let hr = unsafe {
                NCryptSetProperty(
                    key,
                    NCRYPT_KEY_USAGE_PROPERTY,
                    &usage as *const u32 as *const u8,
                    4,
                    NCRYPT_SILENT_FLAG,
                )
            };
            classify("NCryptSetProperty(key usage)", hr, false)?;
            // SAFETY: key is a live, not yet finalized handle.
            let hr = unsafe { NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG) };
            classify("NCryptFinalizeKey", hr, true)
        })();
        if let Err(e) = result {
            // SAFETY: free the half-built handle (not persisted until finalized).
            unsafe { NCryptFreeObject(key) };
            return Err(e);
        }
        Ok(key)
    }

    /// Public key as SPKI DER, built from the exported `ECCPUBLICBLOB`.
    fn export_spki(key: NCRYPT_KEY_HANDLE) -> Result<Vec<u8>> {
        let mut len: u32 = 0;
        // SAFETY: size query (null output buffer) on a live handle.
        check("NCryptExportKey(size)", unsafe {
            NCryptExportKey(
                key,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
                &mut len,
                0,
            )
        })?;
        let mut blob = vec![0u8; len as usize];
        // SAFETY: `blob` is `len` bytes long.
        check("NCryptExportKey", unsafe {
            NCryptExportKey(
                key,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                std::ptr::null(),
                blob.as_mut_ptr(),
                len,
                &mut len,
                0,
            )
        })?;
        let hdr = std::mem::size_of::<BCRYPT_ECCKEY_BLOB>();
        if blob.len() < hdr + 64 {
            bail!("unexpected public key blob length {}", blob.len());
        }
        let magic = u32::from_le_bytes(blob[0..4].try_into().unwrap());
        let cb_key = u32::from_le_bytes(blob[4..8].try_into().unwrap());
        if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || cb_key != 32 {
            bail!("identity key is not an ECDSA P-256 key (magic 0x{magic:08X}, cbKey {cb_key})");
        }
        let x: [u8; 32] = blob[hdr..hdr + 32].try_into().unwrap();
        let y: [u8; 32] = blob[hdr + 32..hdr + 64].try_into().unwrap();
        Ok(spki_from_xy(&x, &y))
    }
}

impl IdentityKey for CngKey {
    fn public_key_spki_der(&self) -> Vec<u8> {
        self.spki.clone()
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let digest = Sha256::digest(msg);
        let guard = self
            .handles
            .lock()
            .map_err(|_| anyhow!("identity key handle poisoned"))?;
        let mut sig = [0u8; 64];
        let mut written: u32 = 0;
        // SAFETY: live key handle; digest is 32 bytes; `sig` is 64 bytes. ECDSA
        // takes no padding info and returns the IEEE P1363 (r || s) form.
        check("NCryptSignHash", unsafe {
            NCryptSignHash(
                guard.key,
                std::ptr::null(),
                digest.as_ptr(),
                digest.len() as u32,
                sig.as_mut_ptr(),
                sig.len() as u32,
                &mut written,
                NCRYPT_SILENT_FLAG,
            )
        })?;
        if written != 64 {
            bail!("unexpected ECDSA signature length {written}");
        }
        der_from_p1363(&sig)
    }

    fn protection(&self) -> Protection {
        self.provider.protection()
    }
}

/// [`Backend`] over one CNG provider and key name.
pub struct CngBackend {
    pub provider: Provider,
    pub key_name: &'static str,
}

impl Backend for CngBackend {
    type Key = CngKey;
    fn open(&self, create: bool) -> Result<Option<CngKey>, ProviderError> {
        CngKey::open_named(self.provider, self.key_name, create)
    }
}

/// Default backends for the production key name.
pub fn backends() -> (CngBackend, CngBackend) {
    (
        CngBackend {
            provider: Provider::Platform,
            key_name: KEY_NAME,
        },
        CngBackend {
            provider: Provider::Software,
            key_name: KEY_NAME,
        },
    )
}

/// Record file naming the provider that holds the key.
const RECORD_FILE: &str = "identity.provider";

fn record_path() -> std::path::PathBuf {
    crate::paths::state_dir().join(RECORD_FILE)
}

fn read_record() -> Result<Option<Protection>> {
    match std::fs::read_to_string(record_path()) {
        Ok(raw) => super::select::parse_record(&raw).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!("read {}: {e}", record_path().display())),
    }
}

fn write_record(p: Protection) -> Result<()> {
    crate::paths::write_atomic(&record_path(), p.as_str().as_bytes(), 0o600)
}

fn finish(sel: super::select::Selected<CngKey>) -> Result<Box<dyn IdentityKey>> {
    if sel.record_needed {
        // The record only hardens against provider confusion; the key itself
        // is already persisted, so a failed write must not fail the agent.
        if let Err(e) = write_record(sel.protection) {
            tracing::warn!(error = %e, "identity: could not write the provider record");
        }
    }
    Ok(Box::new(sel.key))
}

pub fn load_or_create() -> Result<Box<dyn IdentityKey>> {
    let (tpm, sw) = backends();
    finish(super::select::select_or_create(read_record()?, &tpm, &sw)?)
}

pub fn load_existing() -> Result<Option<Box<dyn IdentityKey>>> {
    let (tpm, sw) = backends();
    match super::select::select_existing(read_record()?, &tpm, &sw)? {
        Some(sel) => finish(sel).map(Some),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    /// Needs a real TPM (or the software KSP); run with
    /// `cargo test -- --ignored identity::windows_cng` as Administrator.
    /// Creates a throwaway machine key, signs, verifies, deletes it.
    fn roundtrip(provider: Provider) {
        let name = format!("TRAPD-Agent-Identity-test-{}", std::process::id());
        let key = CngKey::open_named(provider, &name, true)
            .unwrap_or_else(|e| panic!("create failed: {e}"))
            .unwrap();
        assert_eq!(
            key.protection(),
            if provider == Provider::Platform {
                Protection::Tpm
            } else {
                Protection::Software
            }
        );
        let spki = key.public_key_spki_der();
        let vk = VerifyingKey::from_sec1_bytes(&spki[26..]).unwrap();
        let msg = b"trapd-agent-session-v1\nagent\nnonce";
        let sig = Signature::from_der(&key.sign(msg).unwrap()).unwrap();
        vk.verify(msg, &sig).unwrap();
        assert!(vk.verify(b"other", &sig).is_err());
        // Reopening yields the same public key.
        let again = CngKey::open_named(provider, &name, false).unwrap().unwrap();
        assert_eq!(again.public_key_spki_der(), spki);
        drop(again);
        delete_key(provider, &name);
        assert!(CngKey::open_named(provider, &name, false)
            .unwrap()
            .is_none());
    }

    fn delete_key(provider: Provider, name: &str) {
        use windows_sys::Win32::Security::Cryptography::NCryptDeleteKey;
        let mut prov: NCRYPT_PROV_HANDLE = 0;
        let flags = NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG;
        let w = wide(name);
        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: standard open/delete sequence; NCryptDeleteKey frees the key handle.
        unsafe {
            assert!(NCryptOpenStorageProvider(&mut prov, provider.name(), 0) >= 0);
            assert!(NCryptOpenKey(prov, &mut key, w.as_ptr(), 0, flags) >= 0);
            assert!(NCryptDeleteKey(key, NCRYPT_SILENT_FLAG) >= 0);
            NCryptFreeObject(prov);
        }
    }

    #[test]
    #[ignore = "needs Windows + Administrator"]
    fn software_provider_roundtrip() {
        roundtrip(Provider::Software);
    }

    #[test]
    #[ignore = "needs Windows + Administrator + a TPM"]
    fn platform_provider_roundtrip() {
        roundtrip(Provider::Platform);
    }
}
