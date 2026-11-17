//! SPKI pinning of the backend TLS chain.
//!
//! [`PinningVerifier`] wraps rustls' default webpki verifier: the chain must
//! first verify normally against the configured trust anchors (pinned
//! `ca.crt`, or the system roots when explicitly opted in), and only then are
//! the SPKI hashes of the presented certificates compared with the pin set.
//! A pin never replaces normal validation.
//!
//! Modes (see [`decide`]):
//! * no pins configured: **report-only**. The observed SPKI hashes are
//!   recorded so an operator can copy them into the pin list.
//! * pins configured: at least one presented certificate (leaf or an
//!   intermediate the server sends) must match a pin, else the handshake is
//!   refused and a mismatch is queued for `selfprotect.tls_pin_mismatch`.
//! * a tenant inspection CA pin is accepted like a backend pin, so a corporate
//!   TLS-inspection proxy keeps working once the tenant approved its CA.
//!
//! Only certificates the server *sends* can match. The trust anchor itself is
//! normally not sent, so pin the leaf or the issuing intermediate.
//!
//! A refused handshake means the backend is unreachable, so the mismatch event
//! goes through the normal pipeline into the persistent spool and is delivered
//! once a connection with a matching chain succeeds.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

pub type Pin = [u8; 32];

const MAX_OBSERVED: usize = 64;
const MAX_MISMATCHES: usize = 16;
/// A mismatch already handed out is handed out again after this long.
const REREPORT_AFTER: Duration = Duration::from_secs(3600);

// --- SPKI extraction ------------------------------------------------------

/// `(tag, value, rest)` of the DER element at the start of `b`.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let l0 = *b.get(1)?;
    let (len, hdr) = if l0 < 0x80 {
        (usize::from(l0), 2)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*b.get(2 + i)?);
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    Some((tag, b.get(hdr..end)?, b.get(end..)?))
}

/// The complete DER `SubjectPublicKeyInfo` of an X.509 certificate.
pub fn spki_der(cert: &[u8]) -> Option<&[u8]> {
    let (t, cert_body, _) = tlv(cert)?;
    if t != 0x30 {
        return None;
    }
    let (t, tbs, _) = tlv(cert_body)?;
    if t != 0x30 {
        return None;
    }
    let mut cur = tbs;
    // Optional explicit version [0].
    if cur.first() == Some(&0xa0) {
        cur = tlv(cur)?.2;
    }
    // serial, signature algorithm, issuer, validity, subject
    for _ in 0..5 {
        cur = tlv(cur)?.2;
    }
    let (t, _, rest) = tlv(cur)?;
    if t != 0x30 {
        return None;
    }
    Some(&cur[..cur.len() - rest.len()])
}

/// SHA-256 of the certificate's SPKI (the HPKP / `pin-sha256` value).
pub fn spki_pin(cert: &[u8]) -> Option<Pin> {
    Some(Sha256::digest(spki_der(cert)?).into())
}

pub fn encode_pin(p: &Pin) -> String {
    B64.encode(p)
}

/// One pin: standard base64 of 32 bytes, optionally prefixed `sha256/`.
pub fn parse_pin(s: &str) -> Result<Pin, String> {
    let raw = s.trim().strip_prefix("sha256/").unwrap_or(s.trim());
    let bytes = B64
        .decode(raw)
        .map_err(|_| format!("pin {raw:?} is not base64"))?;
    bytes
        .try_into()
        .map_err(|_| format!("pin {raw:?} is not a 32-byte SHA-256"))
}

pub fn parse_pins(list: &[String]) -> Result<HashSet<Pin>, String> {
    list.iter().map(|s| parse_pin(s)).collect()
}

// --- policy ---------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PinPolicy {
    pub pins: HashSet<Pin>,
    pub inspection: HashSet<Pin>,
    /// Pins were configured but could not be parsed: enforce with what is
    /// valid (possibly nothing) instead of falling back to report-only.
    pub enforce: bool,
}

impl PinPolicy {
    pub fn from_lists(pins: &[String], inspection: &[String]) -> (Self, Option<String>) {
        let mut err = None;
        let mut parse = |l: &[String]| {
            let mut ok = HashSet::new();
            for s in l {
                match parse_pin(s) {
                    Ok(p) => {
                        ok.insert(p);
                    }
                    Err(e) => err = Some(e),
                }
            }
            ok
        };
        let pins_ok = parse(pins);
        let insp_ok = parse(inspection);
        let configured = !pins.is_empty() || !inspection.is_empty();
        (
            Self {
                pins: pins_ok,
                inspection: insp_ok,
                enforce: configured,
            },
            err,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinDecision {
    /// No pins configured: record, never refuse.
    ReportOnly,
    Match,
    /// Matched the tenant inspection CA pin.
    InspectionMatch,
    Mismatch,
}

pub fn decide(policy: &PinPolicy, chain: &[Pin]) -> PinDecision {
    if !policy.enforce {
        return PinDecision::ReportOnly;
    }
    if chain.iter().any(|p| policy.pins.contains(p)) {
        PinDecision::Match
    } else if chain.iter().any(|p| policy.inspection.contains(p)) {
        PinDecision::InspectionMatch
    } else {
        PinDecision::Mismatch
    }
}

// --- shared state ----------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinMismatch {
    pub host: String,
    /// SPKI pins of the chain the server presented (leaf first).
    pub observed: Vec<String>,
    pub count: u64,
}

struct MismatchSlot {
    rec: PinMismatch,
    last_taken: Option<Instant>,
}

/// Pin policy plus what the verifier saw. Shared between the verifier (TLS
/// threads) and the network guard collector.
#[derive(Default)]
pub struct PinState {
    policy: RwLock<PinPolicy>,
    observed: Mutex<BTreeSet<String>>,
    mismatches: Mutex<HashMap<(String, Vec<String>), MismatchSlot>>,
}

impl PinState {
    pub fn with_policy(policy: PinPolicy) -> Arc<Self> {
        Arc::new(Self {
            policy: RwLock::new(policy),
            ..Default::default()
        })
    }

    /// Replace the policy (signed-config hook).
    pub fn set_policy(&self, policy: PinPolicy) {
        if let Ok(mut p) = self.policy.write() {
            *p = policy;
        }
    }

    pub fn policy(&self) -> PinPolicy {
        self.policy.read().map(|p| p.clone()).unwrap_or_default()
    }

    fn record_observed(&self, chain: &[Pin]) {
        if let Ok(mut o) = self.observed.lock() {
            for p in chain {
                if o.len() < MAX_OBSERVED {
                    o.insert(encode_pin(p));
                }
            }
        }
    }

    fn record_mismatch(&self, host: &str, chain: &[Pin]) {
        let observed: Vec<String> = chain.iter().map(encode_pin).collect();
        if let Ok(mut m) = self.mismatches.lock() {
            let key = (host.to_string(), observed.clone());
            if let Some(slot) = m.get_mut(&key) {
                slot.rec.count += 1;
            } else if m.len() < MAX_MISMATCHES {
                m.insert(
                    key,
                    MismatchSlot {
                        rec: PinMismatch {
                            host: host.to_string(),
                            observed,
                            count: 1,
                        },
                        last_taken: None,
                    },
                );
            }
        }
    }

    /// Observed pins (report-only mode) not yet returned before.
    pub fn observed_pins(&self) -> Vec<String> {
        self.observed
            .lock()
            .map(|o| o.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Mismatches that are new or due for a repeat report.
    pub fn take_mismatches(&self) -> Vec<PinMismatch> {
        let now = Instant::now();
        let Ok(mut m) = self.mismatches.lock() else {
            return vec![];
        };
        let mut out = Vec::new();
        for slot in m.values_mut() {
            if slot
                .last_taken
                .is_none_or(|t| now.duration_since(t) >= REREPORT_AFTER)
            {
                slot.last_taken = Some(now);
                out.push(slot.rec.clone());
            }
        }
        out
    }
}

/// Process-wide state, initialised from [`super::settings::Settings`] on first
/// use. An unparseable pin configuration is logged and enforced (fail closed).
pub fn global() -> &'static Arc<PinState> {
    static STATE: OnceLock<Arc<PinState>> = OnceLock::new();
    STATE.get_or_init(|| {
        let settings = match super::settings::Settings::load() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "network guard settings unreadable; pins not loaded");
                Default::default()
            }
        };
        let (policy, err) =
            PinPolicy::from_lists(&settings.spki_pins, &settings.inspection_ca_pins);
        if let Some(e) = err {
            tracing::error!(error = %e, "invalid TLS pin in configuration; enforcing the valid pins only");
        }
        if policy.enforce {
            tracing::info!(
                pins = policy.pins.len(),
                inspection = policy.inspection.len(),
                "TLS: backend SPKI pinning enforced"
            );
        } else {
            tracing::info!("TLS: no SPKI pins configured, running in report-only mode");
        }
        PinState::with_policy(policy)
    })
}

// --- verifier -------------------------------------------------------------

#[derive(Debug)]
pub struct PinningVerifier {
    inner: Arc<WebPkiServerVerifier>,
    state: Arc<PinState>,
}

impl PinningVerifier {
    pub fn new(roots: RootCertStore, state: Arc<PinState>) -> anyhow::Result<Arc<Self>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|e| anyhow::anyhow!("TLS: cannot build certificate verifier: {e}"))?;
        Ok(Arc::new(Self { inner, state }))
    }
}

impl std::fmt::Debug for PinState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinState")
    }
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, TlsError> {
        // Normal path validation first; a pin never substitutes for it.
        let ok = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let chain: Vec<Pin> = std::iter::once(end_entity)
            .chain(intermediates)
            .filter_map(|c| spki_pin(c.as_ref()))
            .collect();
        let policy = self.state.policy();
        match decide(&policy, &chain) {
            PinDecision::ReportOnly => {
                self.state.record_observed(&chain);
                Ok(ok)
            }
            PinDecision::Match => Ok(ok),
            PinDecision::InspectionMatch => {
                tracing::debug!("TLS: chain accepted through the tenant inspection CA pin");
                Ok(ok)
            }
            PinDecision::Mismatch => {
                self.state.record_mismatch(&server_name.to_str(), &chain);
                Err(TlsError::General(
                    "backend certificate chain does not match any configured SPKI pin".into(),
                ))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;

    const CA: &str = include_str!("../../../tests/fixtures/tls/ca.pem");
    const LEAF: &str = include_str!("../../../tests/fixtures/tls/leaf.pem");
    const OTHER: &str = include_str!("../../../tests/fixtures/tls/other.pem");
    // `openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`
    const LEAF_PIN: &str = "80DnfYEFSfic/R4K/U8B7OAJ9dZwj/hvQu4YmIIF0/c=";
    const CA_PIN: &str = "tIQn31OoLmnaS0vIiY6tNIGq8Da+KtFNbK1NGmLN5D8=";
    const OTHER_PIN: &str = "RgIEHp8ygo95bEkxO3IrSBWdm8cGy1/QoyyqFCtJ6wo=";

    fn der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
    }

    fn verifier(state: Arc<PinState>) -> Arc<PinningVerifier> {
        let mut roots = RootCertStore::empty();
        roots.add(der(CA)).unwrap();
        PinningVerifier::new(roots, state).unwrap()
    }

    fn verify(v: &PinningVerifier, leaf: &str, host: &str) -> Result<(), TlsError> {
        v.verify_server_cert(
            &der(leaf),
            &[],
            &ServerName::try_from(host.to_string()).unwrap(),
            &[],
            UnixTime::now(),
        )
        .map(|_| ())
    }

    #[test]
    fn spki_hash_matches_openssl() {
        assert_eq!(encode_pin(&spki_pin(der(LEAF).as_ref()).unwrap()), LEAF_PIN);
        assert_eq!(encode_pin(&spki_pin(der(CA).as_ref()).unwrap()), CA_PIN);
        assert_eq!(
            encode_pin(&spki_pin(der(OTHER).as_ref()).unwrap()),
            OTHER_PIN
        );
    }

    #[test]
    fn spki_extraction_rejects_garbage_without_panicking() {
        assert!(spki_der(&[]).is_none());
        assert!(spki_der(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
        let good = der(LEAF);
        for n in [1, 5, 40, good.len() - 1] {
            assert!(spki_der(&good[..n]).is_none(), "truncated at {n}");
        }
    }

    #[test]
    fn pin_parsing() {
        assert!(parse_pin(LEAF_PIN).is_ok());
        assert_eq!(
            parse_pin(&format!("sha256/{LEAF_PIN}")),
            parse_pin(LEAF_PIN)
        );
        assert!(parse_pin("not base64 !!").is_err());
        assert!(parse_pin("AAAA").is_err(), "wrong length");
    }

    #[test]
    fn decision_table() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let report = PinPolicy::default();
        assert_eq!(decide(&report, &[a]), PinDecision::ReportOnly);
        let enforcing = PinPolicy {
            pins: [a].into(),
            inspection: [b].into(),
            enforce: true,
        };
        assert_eq!(decide(&enforcing, &[[9; 32], a]), PinDecision::Match);
        assert_eq!(decide(&enforcing, &[b]), PinDecision::InspectionMatch);
        assert_eq!(decide(&enforcing, &[[9; 32]]), PinDecision::Mismatch);
        assert_eq!(decide(&enforcing, &[]), PinDecision::Mismatch);
    }

    #[test]
    fn invalid_pin_config_still_enforces() {
        let (p, err) = PinPolicy::from_lists(&["garbage".into()], &[]);
        assert!(err.is_some());
        assert!(p.enforce && p.pins.is_empty());
        assert_eq!(decide(&p, &[[1; 32]]), PinDecision::Mismatch);
    }

    #[test]
    fn report_only_accepts_and_records_observed_pins() {
        let state = PinState::with_policy(PinPolicy::default());
        let v = verifier(Arc::clone(&state));
        verify(&v, LEAF, "backend.test").unwrap();
        assert_eq!(state.observed_pins(), [LEAF_PIN]);
        assert!(state.take_mismatches().is_empty());
    }

    #[test]
    fn matching_leaf_or_intermediate_pin_is_accepted() {
        let (policy, _) = PinPolicy::from_lists(&[LEAF_PIN.into()], &[]);
        let v = verifier(PinState::with_policy(policy));
        verify(&v, LEAF, "backend.test").unwrap();
    }

    #[test]
    fn pin_mismatch_refuses_and_is_reported_once() {
        let (policy, _) = PinPolicy::from_lists(&[CA_PIN.into()], &[]);
        let state = PinState::with_policy(policy);
        let v = verifier(Arc::clone(&state));
        // Chain is valid but carries no pinned key (the CA is not sent).
        assert!(verify(&v, LEAF, "backend.test").is_err());
        assert!(verify(&v, LEAF, "backend.test").is_err());
        let m = state.take_mismatches();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].host, "backend.test");
        assert_eq!(m[0].observed, [LEAF_PIN]);
        assert_eq!(m[0].count, 2);
        assert!(state.take_mismatches().is_empty(), "not repeated at once");
    }

    #[test]
    fn inspection_ca_pin_is_accepted() {
        let (policy, _) = PinPolicy::from_lists(&[CA_PIN.into()], &[LEAF_PIN.into()]);
        let v = verifier(PinState::with_policy(policy));
        verify(&v, LEAF, "backend.test").unwrap();
    }

    #[test]
    fn rogue_chain_fails_normal_validation_and_is_not_a_pin_event() {
        // A rogue CA is rejected by the default verifier before pins matter,
        // even when its key is in the pin list.
        let (policy, _) = PinPolicy::from_lists(&[OTHER_PIN.into()], &[]);
        let state = PinState::with_policy(policy);
        let v = verifier(Arc::clone(&state));
        assert!(verify(&v, OTHER, "backend.test").is_err());
        assert!(state.take_mismatches().is_empty());
    }

    #[test]
    fn wrong_host_fails_normal_validation() {
        let v = verifier(PinState::with_policy(PinPolicy::default()));
        assert!(verify(&v, LEAF, "evil.test").is_err());
    }

    #[test]
    fn set_policy_takes_effect_for_new_handshakes() {
        let state = PinState::with_policy(PinPolicy::default());
        let v = verifier(Arc::clone(&state));
        verify(&v, LEAF, "backend.test").unwrap();
        state.set_policy(PinPolicy::from_lists(&[CA_PIN.into()], &[]).0);
        assert!(verify(&v, LEAF, "backend.test").is_err());
    }
}
