//! Hardware-bound agent identity (Phase 09, L1).
//!
//! The agent proves who it is with an ECDSA P-256 key pair instead of the
//! long-lived bearer secret issued at enrollment. The private key never leaves
//! the provider: [`IdentityKey::sign`] is the only operation exposed.
//!
//! Provider selection happens in [`load_or_create`]:
//!
//! 1. (WP2, not implemented yet) TPM-backed key — `Protection::Tpm`.
//! 2. Software key — `Protection::Software`:
//!    * Linux: key file `identity.key` in the state directory (0600,
//!      written atomically, zeroized in memory).
//!    * Windows: CNG key in the Microsoft Software Key Storage Provider,
//!      machine scope, export policy 0 (non-exportable).
//!
//! There is deliberately **no silent downgrade**: once the backend has bound a
//! public key, a missing/changed key is a loud failure that needs re-enrollment
//! (see [`session`]).

use anyhow::Result;
use serde::{Deserialize, Serialize};

pub mod session;
mod software;
#[cfg(windows)]
mod windows_cng;

pub use session::SessionTokens;

/// How the private key is protected. Serialized as `"tpm"` / `"software"` on
/// the wire (`identity/bind` body).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protection {
    Tpm,
    Software,
}

impl Protection {
    pub fn as_str(self) -> &'static str {
        match self {
            Protection::Tpm => "tpm",
            Protection::Software => "software",
        }
    }
}

/// An asymmetric agent identity. Implementations must never expose the private
/// key material.
pub trait IdentityKey: Send + Sync {
    /// P-256 SubjectPublicKeyInfo, DER encoded.
    fn public_key_spki_der(&self) -> Vec<u8>;
    /// ECDSA P-256 over SHA-256 of `msg`; the signature is ASN.1 DER.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;
    fn protection(&self) -> Protection;
}

/// Load the existing identity key, or create one on first use.
///
/// Only call this when the agent is allowed to mint a new identity (fresh
/// enrollment, or a legacy agent that still holds its `agent_secret`). A
/// already-bound agent must use [`load_existing`] so a lost key is not silently
/// replaced.
pub fn load_or_create() -> Result<Box<dyn IdentityKey>> {
    // WP2 HOOK: try the TPM provider first (Windows CNG
    // `MS_PLATFORM_CRYPTO_PROVIDER`, machine key, non-exportable):
    //
    //     if let Some(key) = tpm::try_load_or_create()? { return Ok(key); }
    //
    // It must return `Ok(None)` only when no TPM is present. A TPM that is
    // present but failing is an error, never a fall-through to software.
    software::load_or_create()
}

/// Load the identity key if one exists; `Ok(None)` when there is none.
///
/// Mirrors [`load_or_create`]'s provider order (WP2 adds the TPM provider
/// first) but never creates a key.
pub fn load_existing() -> Result<Option<Box<dyn IdentityKey>>> {
    // WP2 HOOK: try the TPM provider's existing key first.
    software::load_existing()
}

/// Message the agent signs to open a session:
/// `"trapd-agent-session-v1\n" + agent_id + "\n" + nonce_b64`.
pub fn session_message(agent_id: &str, nonce_b64: &str) -> Vec<u8> {
    format!("trapd-agent-session-v1\n{agent_id}\n{nonce_b64}").into_bytes()
}

/// DER prefix of a P-256 SubjectPublicKeyInfo up to the uncompressed point
/// (`0x04 || X || Y`, 65 bytes).
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// SPKI DER from the affine coordinates (32 bytes each, big endian).
fn spki_from_xy(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(91);
    out.extend_from_slice(&P256_SPKI_PREFIX);
    out.push(0x04);
    out.extend_from_slice(x);
    out.extend_from_slice(y);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    #[cfg(not(windows))]
    use p256::ecdsa::{signature::Verifier, Signature};

    /// Strict SPKI check: exact DER prefix, then the SEC1 point.
    pub(crate) fn vk_from_spki(spki: &[u8]) -> VerifyingKey {
        assert_eq!(spki.len(), 91);
        assert_eq!(&spki[..26], &P256_SPKI_PREFIX);
        VerifyingKey::from_sec1_bytes(&spki[26..]).unwrap()
    }

    #[test]
    fn protection_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Protection::Tpm).unwrap(), "\"tpm\"");
        assert_eq!(
            serde_json::to_string(&Protection::Software).unwrap(),
            "\"software\""
        );
    }

    #[test]
    fn session_message_format_is_exact() {
        assert_eq!(
            session_message("agent-1", "bm9uY2U="),
            b"trapd-agent-session-v1\nagent-1\nbm9uY2U=".to_vec()
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn spki_and_signature_verify_with_p256() {
        let dir = software::tests::scratch("verify");
        let key = software::SoftwareKey::load_or_create_at(&dir.join("identity.key")).unwrap();
        let vk = vk_from_spki(&key.public_key_spki_der());
        let msg = session_message("a", "n");
        let sig = Signature::from_der(&key.sign(&msg).unwrap()).unwrap();
        vk.verify(&msg, &sig).unwrap();
        assert!(vk.verify(b"other", &sig).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
