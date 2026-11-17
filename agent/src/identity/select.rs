//! Provider selection for the identity key (platform independent, so the state
//! machine is unit-testable on Linux; only the Windows CNG glue uses it).
//!
//! Rules (anti-downgrade):
//!
//! * A **recorded** provider (`identity.provider` in the state directory,
//!   written when the key was created) is honoured exclusively. A key is never
//!   opened from, or created in, any other provider, and an unavailable
//!   recorded provider is an error, not a fall-through.
//! * Without a record (agents created before the record existed) the TPM is
//!   probed first, then the software provider, read-only.
//! * Only when no key exists anywhere and creation is allowed: try the TPM,
//!   and use the software provider only if the TPM is *unavailable*
//!   (absent/disabled/not ready). Any other TPM failure is an error.

use anyhow::{anyhow, bail, Result};

use super::Protection;

/// Why a provider could not hand out a key.
#[derive(Debug)]
pub enum ProviderError {
    /// The provider cannot be used on this machine at all (no/disabled TPM,
    /// provider DLL missing, device not ready). Allows the first-creation
    /// fall-back to software.
    Unavailable(String),
    /// Anything else. Never triggers a fall-back.
    Failed(anyhow::Error),
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderError::Unavailable(m) => write!(f, "provider unavailable: {m}"),
            ProviderError::Failed(e) => write!(f, "{e:#}"),
        }
    }
}

/// One key storage provider.
pub trait Backend {
    type Key;
    /// Open the named key; with `create`, generate it when absent.
    /// `Ok(None)` only when absent and `create` is false.
    fn open(&self, create: bool) -> Result<Option<Self::Key>, ProviderError>;
}

/// Result of a selection: the key and which provider holds it.
pub struct Selected<K> {
    pub protection: Protection,
    pub key: K,
    /// True when the caller must write the provider record.
    pub record_needed: bool,
}

fn backend_for<'a, K>(
    p: Protection,
    tpm: &'a dyn Backend<Key = K>,
    sw: &'a dyn Backend<Key = K>,
) -> &'a dyn Backend<Key = K> {
    match p {
        Protection::Tpm => tpm,
        Protection::Software => sw,
    }
}

fn hard(p: Protection, e: ProviderError) -> anyhow::Error {
    anyhow!("identity provider {} failed: {e}", p.as_str())
}

/// Load an existing key, never creating one. `Ok(None)` when none exists.
pub fn select_existing<K>(
    recorded: Option<Protection>,
    tpm: &dyn Backend<Key = K>,
    sw: &dyn Backend<Key = K>,
) -> Result<Option<Selected<K>>> {
    if let Some(p) = recorded {
        return match backend_for(p, tpm, sw).open(false) {
            Ok(Some(key)) => Ok(Some(Selected {
                protection: p,
                key,
                record_needed: false,
            })),
            // The record says the key lives here; if it does not, that is a
            // lost key, never a reason to look elsewhere.
            Ok(None) => Ok(None),
            Err(e) => Err(hard(p, e)),
        };
    }
    match tpm.open(false) {
        Ok(Some(key)) => {
            return Ok(Some(Selected {
                protection: Protection::Tpm,
                key,
                record_needed: true,
            }))
        }
        Ok(None) | Err(ProviderError::Unavailable(_)) => {}
        Err(e) => return Err(hard(Protection::Tpm, e)),
    }
    match sw.open(false) {
        Ok(Some(key)) => Ok(Some(Selected {
            protection: Protection::Software,
            key,
            record_needed: true,
        })),
        Ok(None) => Ok(None),
        Err(e) => Err(hard(Protection::Software, e)),
    }
}

/// Load the key, or create it on first use (TPM first, software only if the
/// TPM is unavailable).
pub fn select_or_create<K>(
    recorded: Option<Protection>,
    tpm: &dyn Backend<Key = K>,
    sw: &dyn Backend<Key = K>,
) -> Result<Selected<K>> {
    if let Some(p) = recorded {
        // Same provider only; create there if the key is gone.
        return match backend_for(p, tpm, sw).open(true) {
            Ok(Some(key)) => Ok(Selected {
                protection: p,
                key,
                record_needed: false,
            }),
            Ok(None) => bail!("identity provider {} returned no key", p.as_str()),
            Err(e) => Err(hard(p, e)),
        };
    }
    if let Some(sel) = select_existing(None, tpm, sw)? {
        return Ok(sel);
    }
    match tpm.open(true) {
        Ok(Some(key)) => {
            return Ok(Selected {
                protection: Protection::Tpm,
                key,
                record_needed: true,
            })
        }
        Ok(None) => bail!("identity provider tpm returned no key"),
        Err(ProviderError::Unavailable(_)) => {}
        Err(e) => return Err(hard(Protection::Tpm, e)),
    }
    match sw.open(true) {
        Ok(Some(key)) => Ok(Selected {
            protection: Protection::Software,
            key,
            record_needed: true,
        }),
        Ok(None) => bail!("identity provider software returned no key"),
        Err(e) => Err(hard(Protection::Software, e)),
    }
}

/// Parse the provider record (`tpm` / `software`, surrounding whitespace ok).
/// An unreadable value is an error: guessing could open the wrong provider.
pub fn parse_record(raw: &str) -> Result<Protection> {
    match raw.trim() {
        "tpm" => Ok(Protection::Tpm),
        "software" => Ok(Protection::Software),
        other => bail!("identity.provider has an unknown value {other:?}"),
    }
}

/// Convert a CNG/IEEE-P1363 ECDSA P-256 signature (`r || s`, 64 bytes) to DER.
pub fn der_from_p1363(rs: &[u8]) -> Result<Vec<u8>> {
    if rs.len() != 64 {
        bail!("unexpected ECDSA signature length {}", rs.len());
    }
    let sig = p256::ecdsa::Signature::from_slice(rs)
        .map_err(|e| anyhow!("malformed CNG signature: {e}"))?;
    Ok(sig.to_der().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Clone, Copy)]
    enum Mode {
        Absent,
        Present,
        Unavailable,
        Broken,
    }

    struct Fake {
        mode: Mode,
        tag: &'static str,
        opens: RefCell<Vec<bool>>,
    }

    fn fake(mode: Mode, tag: &'static str) -> Fake {
        Fake {
            mode,
            tag,
            opens: RefCell::new(vec![]),
        }
    }

    impl Backend for Fake {
        type Key = &'static str;
        fn open(&self, create: bool) -> Result<Option<&'static str>, ProviderError> {
            self.opens.borrow_mut().push(create);
            match self.mode {
                Mode::Present => Ok(Some(self.tag)),
                Mode::Absent if create => Ok(Some(self.tag)),
                Mode::Absent => Ok(None),
                Mode::Unavailable => Err(ProviderError::Unavailable("no tpm".into())),
                Mode::Broken => Err(ProviderError::Failed(anyhow!("boom"))),
            }
        }
    }

    #[test]
    fn first_creation_prefers_tpm() {
        let (t, s) = (fake(Mode::Absent, "tpm"), fake(Mode::Absent, "sw"));
        let sel = select_or_create(None, &t, &s).unwrap();
        assert_eq!(
            (sel.protection, sel.key, sel.record_needed),
            (Protection::Tpm, "tpm", true)
        );
        // The software provider is only probed read-only, never created in.
        assert_eq!(*s.opens.borrow(), vec![false]);
    }

    #[test]
    fn unavailable_tpm_falls_back_to_software_on_first_creation() {
        let (t, s) = (fake(Mode::Unavailable, "tpm"), fake(Mode::Absent, "sw"));
        let sel = select_or_create(None, &t, &s).unwrap();
        assert_eq!((sel.protection, sel.key), (Protection::Software, "sw"));
        assert!(sel.record_needed);
    }

    #[test]
    fn failing_tpm_is_an_error_not_a_fallback() {
        let (t, s) = (fake(Mode::Broken, "tpm"), fake(Mode::Absent, "sw"));
        assert!(select_or_create(None, &t, &s).is_err());
        assert!(select_existing(None, &t, &s).is_err());
        assert!(!s.opens.borrow().contains(&true));
    }

    #[test]
    fn existing_tpm_key_wins_without_record() {
        let (t, s) = (fake(Mode::Present, "tpm"), fake(Mode::Present, "sw"));
        let sel = select_existing(None, &t, &s).unwrap().unwrap();
        assert_eq!(sel.protection, Protection::Tpm);
        assert!(sel.record_needed);
    }

    #[test]
    fn legacy_software_key_is_found_without_record() {
        let (t, s) = (fake(Mode::Unavailable, "tpm"), fake(Mode::Present, "sw"));
        let sel = select_existing(None, &t, &s).unwrap().unwrap();
        assert_eq!((sel.protection, sel.key), (Protection::Software, "sw"));
    }

    #[test]
    fn no_key_anywhere_is_none_and_never_creates() {
        let (t, s) = (fake(Mode::Absent, "tpm"), fake(Mode::Absent, "sw"));
        assert!(select_existing(None, &t, &s).unwrap().is_none());
        assert!(!t.opens.borrow().contains(&true) && !s.opens.borrow().contains(&true));
    }

    #[test]
    fn recorded_provider_is_honoured_exclusively() {
        // Record says software; a TPM key exists too and must be ignored.
        let (t, s) = (fake(Mode::Present, "tpm"), fake(Mode::Present, "sw"));
        let sel = select_existing(Some(Protection::Software), &t, &s)
            .unwrap()
            .unwrap();
        assert_eq!(sel.key, "sw");
        assert!(t.opens.borrow().is_empty());
        // Record says tpm; software key must be ignored.
        let (t, s) = (fake(Mode::Present, "tpm"), fake(Mode::Present, "sw"));
        let sel = select_or_create(Some(Protection::Tpm), &t, &s).unwrap();
        assert_eq!(sel.key, "tpm");
        assert!(s.opens.borrow().is_empty());
    }

    #[test]
    fn recorded_tpm_missing_key_is_not_replaced_from_software() {
        let (t, s) = (fake(Mode::Absent, "tpm"), fake(Mode::Present, "sw"));
        assert!(select_existing(Some(Protection::Tpm), &t, &s)
            .unwrap()
            .is_none());
        assert!(s.opens.borrow().is_empty());
    }

    #[test]
    fn recorded_tpm_unavailable_is_an_error_not_a_downgrade() {
        let (t, s) = (fake(Mode::Unavailable, "tpm"), fake(Mode::Present, "sw"));
        assert!(select_existing(Some(Protection::Tpm), &t, &s).is_err());
        assert!(select_or_create(Some(Protection::Tpm), &t, &s).is_err());
        assert!(s.opens.borrow().is_empty());
    }

    #[test]
    fn record_parsing() {
        assert_eq!(parse_record("tpm\n").unwrap(), Protection::Tpm);
        assert_eq!(parse_record(" software ").unwrap(), Protection::Software);
        assert!(parse_record("").is_err());
        assert!(parse_record("TPM2").is_err());
    }

    fn der_int(v: &[u8]) -> Vec<u8> {
        // Minimal positive DER INTEGER.
        let mut v = v.to_vec();
        while v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0 {
            v.remove(0);
        }
        if v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        let mut o = vec![0x02, v.len() as u8];
        o.extend(v);
        o
    }

    fn expected_der(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
        let (ri, si) = (der_int(r), der_int(s));
        let mut o = vec![0x30, (ri.len() + si.len()) as u8];
        o.extend(ri);
        o.extend(si);
        o
    }

    #[test]
    fn der_handles_leading_zeros_and_high_bit() {
        // r: many leading zeros; s: high bit set (needs a 0x00 pad).
        let mut r = [0u8; 32];
        r[31] = 0x05;
        let mut s = [0x11u8; 32];
        s[0] = 0xF0;
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(&r);
        rs[32..].copy_from_slice(&s);
        assert_eq!(der_from_p1363(&rs).unwrap(), expected_der(&r, &s));

        // r high bit set, s with a leading zero byte.
        let mut r = [0x80u8; 32];
        r[1] = 0x01;
        let mut s = [0x22u8; 32];
        s[0] = 0x00;
        rs[..32].copy_from_slice(&r);
        rs[32..].copy_from_slice(&s);
        assert_eq!(der_from_p1363(&rs).unwrap(), expected_der(&r, &s));
    }

    #[test]
    fn der_rejects_bad_length_and_zero_components() {
        assert!(der_from_p1363(&[1u8; 63]).is_err());
        assert!(der_from_p1363(&[1u8; 65]).is_err());
        assert!(der_from_p1363(&[0u8; 64]).is_err());
    }

    #[test]
    fn der_roundtrips_real_signatures() {
        use p256::ecdsa::{
            signature::{Signer, Verifier},
            Signature, SigningKey,
        };
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        for i in 0..64u8 {
            let msg = [i; 16];
            let sig: Signature = sk.sign(&msg);
            let der = der_from_p1363(sig.to_bytes().as_slice()).unwrap();
            sk.verifying_key()
                .verify(&msg, &Signature::from_der(&der).unwrap())
                .unwrap();
        }
    }
}
