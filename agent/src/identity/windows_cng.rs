//! Windows CNG (NCrypt) backed identity key.
//!
//! Machine-scope, non-exportable (export policy 0) ECDSA P-256 key named
//! [`KEY_NAME`]. The private key never leaves the key storage provider, so a
//! copy of `credentials.json` / the state directory does not carry the
//! identity.
//!
//! WP2 adds a second [`Provider`] (`MS_PLATFORM_CRYPTO_PROVIDER`, TPM) that is
//! tried before the software one; the key name and flow stay identical.

use std::sync::Mutex;

use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::NTE_BAD_KEYSET;
use windows_sys::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash, BCRYPT_ECCKEY_BLOB,
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
    MS_KEY_STORAGE_PROVIDER, NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_EXPORT_POLICY_PROPERTY,
    NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_PROV_HANDLE,
    NCRYPT_SILENT_FLAG,
};

use super::{spki_from_xy, IdentityKey, Protection};

/// Persisted key name inside the provider.
const KEY_NAME: &str = "TRAPD-Agent-Identity";

/// Key storage provider. WP2: add `Platform` (`MS_PLATFORM_CRYPTO_PROVIDER`).
#[derive(Clone, Copy)]
pub enum Provider {
    Software,
}

impl Provider {
    fn name(self) -> PCWSTR {
        match self {
            Provider::Software => MS_KEY_STORAGE_PROVIDER,
        }
    }

    fn protection(self) -> Protection {
        match self {
            Provider::Software => Protection::Software,
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
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
    /// Open the persisted key; when absent and `create` is set, generate it.
    /// `Ok(None)` only when the key is absent and `create` is false.
    pub fn open_or_create(provider: Provider, create: bool) -> Result<Option<Self>> {
        let mut prov: NCRYPT_PROV_HANDLE = 0;
        // SAFETY: out-pointer is valid; provider name is a static wide string.
        check("NCryptOpenStorageProvider", unsafe {
            NCryptOpenStorageProvider(&mut prov, provider.name(), 0)
        })?;
        let mut handles = Handles { prov, key: 0 };
        let name = wide(KEY_NAME);
        let flags = NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG;

        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: valid provider handle, NUL-terminated name, valid out-pointer.
        let hr = unsafe { NCryptOpenKey(handles.prov, &mut key, name.as_ptr(), 0, flags) };
        if hr == NTE_BAD_KEYSET || hr == windows_sys::Win32::Foundation::NTE_NO_KEY {
            if !create {
                return Ok(None);
            }
            key = Self::create_key(handles.prov, &name, flags)?;
        } else {
            check("NCryptOpenKey", hr)?;
        }
        handles.key = key;
        let spki = Self::export_spki(key)?;
        Ok(Some(Self {
            handles: Mutex::new(handles),
            spki,
            provider,
        }))
    }

    fn create_key(prov: NCRYPT_PROV_HANDLE, name: &[u16], flags: u32) -> Result<NCRYPT_KEY_HANDLE> {
        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: valid provider handle, static algorithm id, NUL-terminated name.
        check("NCryptCreatePersistedKey", unsafe {
            NCryptCreatePersistedKey(
                prov,
                &mut key,
                BCRYPT_ECDSA_P256_ALGORITHM,
                name.as_ptr(),
                0,
                flags,
            )
        })?;
        let result = (|| -> Result<()> {
            // Export policy 0 = the private key can never be exported.
            let policy: u32 = 0;
            // SAFETY: key is a live handle; the buffer is a valid 4-byte DWORD.
            check("NCryptSetProperty(export policy)", unsafe {
                NCryptSetProperty(
                    key,
                    NCRYPT_EXPORT_POLICY_PROPERTY,
                    &policy as *const u32 as *const u8,
                    4,
                    NCRYPT_SILENT_FLAG,
                )
            })?;
            let usage: u32 = NCRYPT_ALLOW_SIGNING_FLAG;
            // SAFETY: as above.
            check("NCryptSetProperty(key usage)", unsafe {
                NCryptSetProperty(
                    key,
                    NCRYPT_KEY_USAGE_PROPERTY,
                    &usage as *const u32 as *const u8,
                    4,
                    NCRYPT_SILENT_FLAG,
                )
            })?;
            // SAFETY: key is a live, not yet finalized handle.
            check("NCryptFinalizeKey", unsafe {
                NCryptFinalizeKey(key, NCRYPT_SILENT_FLAG)
            })
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
        let sig = p256::ecdsa::Signature::from_slice(&sig)
            .map_err(|e| anyhow!("malformed CNG signature: {e}"))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }

    fn protection(&self) -> Protection {
        self.provider.protection()
    }
}
