//! Verification of signed agent updates. Pure logic, no I/O.
//!
//! An update offer carries two independently signed statements:
//!
//! 1. **Release statement** — "this artifact is an authentic TRAPD release"
//!    (version, platform, URL, SHA-256, size). Signed in CI with the *release*
//!    key. A compromised backend cannot forge it.
//! 2. **Update directive** — "agent X should install this release now". Signed
//!    by the backend with the *command* key. It carries the recipient and a
//!    monotonically increasing `issued_at` (replay / rollback protection) and
//!    gives the backend rollout control and a kill switch. A compromised
//!    GitHub account cannot forge it.
//!
//! Both are [`SignedBlob`]s: the signature covers the exact bytes of the
//! `payload` string, which is parsed only *after* verification. Unlike the
//! config channel there is no canonical re-serialisation to keep byte-exact
//! across languages.

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt;

/// Upper bound for an update artifact (the Windows MSI is the largest asset).
pub const MAX_ARTIFACT_BYTES: u64 = 200 * 1024 * 1024;

/// Artifacts may only be fetched from this repository's release downloads.
/// Part of the trust decision, so a compile-time constant rather than config.
pub const ALLOWED_URL_PREFIX: &str =
    "https://github.com/trapd-cloud/trapd-agent/releases/download/";

#[derive(Debug, Clone, Deserialize)]
pub struct SignedBlob {
    pub payload: String,
    pub signature: String,
}

/// Signed by the release key (CI).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseStatement {
    version: String,
    os: String,
    arch: String,
    url: String,
    sha256: String,
    size: u64,
    /// Base64 Ed25519 signature over the raw binary SHA-256 digest, verified
    /// against the host's pinned release key (`release_signing.pub`) by the apply helper.
    #[serde(default)]
    binary_signature: Option<String>,
    /// Linux only: the kernel-side eBPF object shipped with this version. Its
    /// map layout is coupled to the userspace binary, so both are covered by the
    /// one release signature and installed (and rolled back) together.
    #[serde(default)]
    ebpf: Option<ArtifactSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactSpec {
    url: String,
    sha256: String,
    size: u64,
}

/// Signed by the backend with the command key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateDirective {
    agent_id: String,
    /// Unix seconds. Must be strictly greater than the last accepted value.
    issued_at: i64,
    /// The release statement exactly as signed in CI.
    release: SignedBlobOwned,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedBlobOwned {
    payload: String,
    signature: String,
}

/// Wire format of `GET /api/v1/agents/{id}/update` when an update is offered.
pub type UpdateOffer = SignedBlob;

/// A downloadable artifact whose URL, size and digest passed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArtifact {
    pub url: String,
    pub sha256: [u8; 32],
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUpdate {
    pub version: String,
    pub url: String,
    pub sha256: [u8; 32],
    pub size: u64,
    pub binary_signature: Option<[u8; 64]>,
    /// Companion eBPF object (Linux), installed together with the binary.
    pub ebpf: Option<VerifiedArtifact>,
    pub issued_at: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    BadSignature(&'static str),
    Malformed(&'static str),
    WrongRecipient,
    Replay,
    PlatformMismatch,
    NotNewer,
    UrlNotAllowed,
    TooLarge,
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reject::BadSignature(w) => write!(f, "invalid signature ({w})"),
            Reject::Malformed(w) => write!(f, "malformed update ({w})"),
            Reject::WrongRecipient => f.write_str("update addressed to a different agent"),
            Reject::Replay => f.write_str("issued_at not newer than last accepted update"),
            Reject::PlatformMismatch => f.write_str("release is for a different os/arch"),
            Reject::NotNewer => f.write_str("release is not newer than the running version"),
            Reject::UrlNotAllowed => f.write_str("artifact url is not an allowed release url"),
            Reject::TooLarge => f.write_str("artifact exceeds the size limit"),
        }
    }
}

pub struct VerifyContext<'a> {
    pub release_key: &'a VerifyingKey,
    pub command_key: &'a VerifyingKey,
    pub agent_id: &'a str,
    pub current_version: &'a str,
    pub os: &'a str,
    pub arch: &'a str,
    /// Highest `issued_at` accepted so far (persisted by the caller).
    pub last_issued_at: i64,
}

fn verify_blob(
    key: &VerifyingKey,
    payload: &str,
    signature_b64: &str,
    which: &'static str,
) -> Result<(), Reject> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|_| Reject::BadSignature(which))?;
    let arr: [u8; 64] = bytes.try_into().map_err(|_| Reject::BadSignature(which))?;
    key.verify_strict(payload.as_bytes(), &Signature::from_bytes(&arr))
        .map_err(|_| Reject::BadSignature(which))
}

/// Strict `MAJOR.MINOR.PATCH`. Pre-release / build suffixes are rejected so a
/// pre-release can never compare as "newer" by accident.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Verify an offer end to end. Order matters: both signatures are checked
/// before any payload field is trusted.
pub fn verify_offer(
    offer: &UpdateOffer,
    ctx: &VerifyContext<'_>,
) -> Result<VerifiedUpdate, Reject> {
    verify_blob(
        ctx.command_key,
        &offer.payload,
        &offer.signature,
        "directive",
    )?;
    let directive: UpdateDirective =
        serde_json::from_str(&offer.payload).map_err(|_| Reject::Malformed("directive"))?;

    if directive.agent_id != ctx.agent_id {
        return Err(Reject::WrongRecipient);
    }
    if directive.issued_at <= ctx.last_issued_at {
        return Err(Reject::Replay);
    }

    verify_blob(
        ctx.release_key,
        &directive.release.payload,
        &directive.release.signature,
        "release",
    )?;
    let release: ReleaseStatement = serde_json::from_str(&directive.release.payload)
        .map_err(|_| Reject::Malformed("release"))?;

    if release.os != ctx.os || release.arch != ctx.arch {
        return Err(Reject::PlatformMismatch);
    }

    let new = parse_version(&release.version).ok_or(Reject::Malformed("version"))?;
    let current = parse_version(ctx.current_version).ok_or(Reject::Malformed("current version"))?;
    if new <= current {
        return Err(Reject::NotNewer);
    }

    let main = validate_artifact(&release.url, &release.sha256, release.size)?;
    let binary_signature = release
        .binary_signature
        .map(|s| {
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or(Reject::Malformed("binary_signature"))
        })
        .transpose()?;
    let ebpf = match release.ebpf {
        None => None,
        Some(_) if release.os != "linux" => return Err(Reject::Malformed("ebpf")),
        Some(e) => Some(validate_artifact(&e.url, &e.sha256, e.size)?),
    };

    Ok(VerifiedUpdate {
        version: release.version,
        url: main.url,
        sha256: main.sha256,
        size: main.size,
        binary_signature,
        ebpf,
        issued_at: directive.issued_at,
    })
}

fn validate_artifact(url: &str, sha256: &str, size: u64) -> Result<VerifiedArtifact, Reject> {
    // The prefix ends in '/', so "…/download/../x" style tricks are the only
    // way to leave it; reject any dot-segment or userinfo/query smuggling.
    if !url.starts_with(ALLOWED_URL_PREFIX)
        || url.contains("..")
        || url.contains(['?', '#', '@', '\\'])
    {
        return Err(Reject::UrlNotAllowed);
    }
    if size == 0 || size > MAX_ARTIFACT_BYTES {
        return Err(Reject::TooLarge);
    }
    let sha256: [u8; 32] = hex::decode(sha256)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(Reject::Malformed("sha256"))?;
    Ok(VerifiedArtifact {
        url: url.to_string(),
        sha256,
        size,
    })
}

/// Constant-shape helper for the downloader: SHA-256 of the received bytes
/// must equal the signed digest.
pub fn sha256_matches(actual: Sha256, expected: &[u8; 32]) -> bool {
    actual.finalize().as_slice() == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sign(k: &SigningKey, payload: &str) -> String {
        STANDARD.encode(k.sign(payload.as_bytes()).to_bytes())
    }

    struct Fixture {
        release: SigningKey,
        command: SigningKey,
    }

    fn fx() -> Fixture {
        Fixture {
            release: key(1),
            command: key(2),
        }
    }

    fn release_payload(version: &str, url: &str, size: u64) -> String {
        serde_json::json!({
            "version": version, "os": "linux", "arch": "x86_64",
            "url": url, "sha256": "00".repeat(32), "size": size,
        })
        .to_string()
    }

    const GOOD_URL: &str =
        "https://github.com/trapd-cloud/trapd-agent/releases/download/v0.5.0/trapd-agent-linux-x86_64";

    fn offer_with(
        f: &Fixture,
        agent: &str,
        issued_at: i64,
        rel_payload: &str,
        rel_signer: &SigningKey,
    ) -> UpdateOffer {
        let rel_sig = sign(rel_signer, rel_payload);
        let payload = serde_json::json!({
            "agent_id": agent, "issued_at": issued_at,
            "release": { "payload": rel_payload, "signature": rel_sig },
        })
        .to_string();
        let signature = sign(&f.command, &payload);
        UpdateOffer { payload, signature }
    }

    fn ctx<'a>(f: &'a Fixture, rk: &'a VerifyingKey, ck: &'a VerifyingKey) -> VerifyContext<'a> {
        let _ = f;
        VerifyContext {
            release_key: rk,
            command_key: ck,
            agent_id: "agent-1",
            current_version: "0.4.4",
            os: "linux",
            arch: "x86_64",
            last_issued_at: 100,
        }
    }

    fn run(f: &Fixture, offer: &UpdateOffer) -> Result<VerifiedUpdate, Reject> {
        let (rk, ck) = (f.release.verifying_key(), f.command.verifying_key());
        verify_offer(offer, &ctx(f, &rk, &ck))
    }

    #[test]
    fn accepts_valid_offer() {
        let f = fx();
        let rel = release_payload("0.5.0", GOOD_URL, 1024);
        let v = run(&f, &offer_with(&f, "agent-1", 101, &rel, &f.release)).unwrap();
        assert_eq!(v.version, "0.5.0");
        assert_eq!(v.issued_at, 101);
        assert_eq!(v.size, 1024);
    }

    #[test]
    fn rejects_release_signed_by_command_key() {
        // A compromised backend must not be able to mint releases.
        let f = fx();
        let rel = release_payload("0.5.0", GOOD_URL, 1024);
        let o = offer_with(&f, "agent-1", 101, &rel, &f.command);
        assert_eq!(run(&f, &o), Err(Reject::BadSignature("release")));
    }

    #[test]
    fn rejects_directive_signed_by_release_key() {
        // A compromised release pipeline must not be able to push to agents.
        let f = fx();
        let rel = release_payload("0.5.0", GOOD_URL, 1024);
        let mut o = offer_with(&f, "agent-1", 101, &rel, &f.release);
        o.signature = sign(&f.release, &o.payload);
        assert_eq!(run(&f, &o), Err(Reject::BadSignature("directive")));
    }

    #[test]
    fn rejects_tampered_payload() {
        let f = fx();
        let rel = release_payload("0.5.0", GOOD_URL, 1024);
        let mut o = offer_with(&f, "agent-1", 101, &rel, &f.release);
        o.payload = o.payload.replace("0.5.0", "9.9.9");
        assert_eq!(run(&f, &o), Err(Reject::BadSignature("directive")));
    }

    #[test]
    fn rejects_other_recipient() {
        let f = fx();
        let rel = release_payload("0.5.0", GOOD_URL, 1024);
        let o = offer_with(&f, "agent-2", 101, &rel, &f.release);
        assert_eq!(run(&f, &o), Err(Reject::WrongRecipient));
    }

    #[test]
    fn rejects_replay_and_equal_issued_at() {
        let f = fx();
        let rel = release_payload("0.5.0", GOOD_URL, 1024);
        for t in [100, 99] {
            let o = offer_with(&f, "agent-1", t, &rel, &f.release);
            assert_eq!(run(&f, &o), Err(Reject::Replay));
        }
    }

    #[test]
    fn rejects_downgrade_and_same_version() {
        let f = fx();
        for v in ["0.4.4", "0.4.3", "0.3.9"] {
            let rel = release_payload(v, GOOD_URL, 1024);
            let o = offer_with(&f, "agent-1", 101, &rel, &f.release);
            assert_eq!(run(&f, &o), Err(Reject::NotNewer), "{v}");
        }
    }

    #[test]
    fn version_compare_is_numeric_not_lexicographic() {
        let f = fx();
        let rel = release_payload("0.10.0", GOOD_URL, 1024);
        assert!(run(&f, &offer_with(&f, "agent-1", 101, &rel, &f.release)).is_ok());
    }

    #[test]
    fn rejects_prerelease_versions() {
        let f = fx();
        let rel = release_payload("0.5.0-beta.1", GOOD_URL, 1024);
        let o = offer_with(&f, "agent-1", 101, &rel, &f.release);
        assert_eq!(run(&f, &o), Err(Reject::Malformed("version")));
    }

    #[test]
    fn rejects_other_platform() {
        let f = fx();
        let rel = release_payload("0.5.0", GOOD_URL, 1024).replace("linux", "windows");
        let o = offer_with(&f, "agent-1", 101, &rel, &f.release);
        assert_eq!(run(&f, &o), Err(Reject::PlatformMismatch));
    }

    #[test]
    fn rejects_urls_outside_the_release_repo() {
        let f = fx();
        for url in [
            "http://github.com/trapd-cloud/trapd-agent/releases/download/v0.5.0/a",
            "https://evil.example/trapd-cloud/trapd-agent/releases/download/v0.5.0/a",
            "https://github.com/other/repo/releases/download/v0.5.0/a",
            "https://github.com/trapd-cloud/trapd-agent/releases/download/../../../x/a",
            "https://github.com/trapd-cloud/trapd-agent/releases/download/v0.5.0/a?x=1",
            "https://github.com/trapd-cloud/trapd-agent/releases/download/@evil.example/a",
        ] {
            let rel = release_payload("0.5.0", url, 1024);
            let o = offer_with(&f, "agent-1", 101, &rel, &f.release);
            assert_eq!(run(&f, &o), Err(Reject::UrlNotAllowed), "{url}");
        }
    }

    #[test]
    fn rejects_zero_and_oversized_artifacts() {
        let f = fx();
        for size in [0, MAX_ARTIFACT_BYTES + 1] {
            let rel = release_payload("0.5.0", GOOD_URL, size);
            let o = offer_with(&f, "agent-1", 101, &rel, &f.release);
            assert_eq!(run(&f, &o), Err(Reject::TooLarge));
        }
    }

    #[test]
    fn rejects_unknown_fields_in_signed_payloads() {
        let f = fx();
        let rel = release_payload("0.5.0", GOOD_URL, 1024).replace('}', ",\"extra\":1}");
        let o = offer_with(&f, "agent-1", 101, &rel, &f.release);
        assert_eq!(run(&f, &o), Err(Reject::Malformed("release")));
    }

    fn release_with_ebpf(os: &str, ebpf_url: &str) -> String {
        serde_json::json!({
            "version": "0.5.0", "os": os, "arch": "x86_64",
            "url": GOOD_URL, "sha256": "00".repeat(32), "size": 1024,
            "ebpf": { "url": ebpf_url, "sha256": "11".repeat(32), "size": 2048 },
        })
        .to_string()
    }

    const EBPF_URL: &str =
        "https://github.com/trapd-cloud/trapd-agent/releases/download/v0.5.0/trapd-agent-exec";

    #[test]
    fn accepts_a_signed_ebpf_companion() {
        let f = fx();
        let rel = release_with_ebpf("linux", EBPF_URL);
        let v = run(&f, &offer_with(&f, "agent-1", 101, &rel, &f.release)).unwrap();
        let e = v.ebpf.expect("companion present");
        assert_eq!(e.size, 2048);
        assert_eq!(e.url, EBPF_URL);
    }

    #[test]
    fn ebpf_companion_gets_the_same_url_and_size_rules() {
        let f = fx();
        let rel = release_with_ebpf("linux", "https://evil.example/trapd-agent-exec");
        let o = offer_with(&f, "agent-1", 101, &rel, &f.release);
        assert_eq!(run(&f, &o), Err(Reject::UrlNotAllowed));
    }

    #[test]
    fn ebpf_companion_is_linux_only() {
        let f = fx();
        let rel = release_with_ebpf("windows", EBPF_URL);
        let o = offer_with(&f, "agent-1", 101, &rel, &f.release);
        // Platform check precedes it for a mismatching host; use a windows ctx.
        let (rk, ck) = (f.release.verifying_key(), f.command.verifying_key());
        let mut c = ctx(&f, &rk, &ck);
        c.os = "windows";
        assert_eq!(verify_offer(&o, &c), Err(Reject::Malformed("ebpf")));
    }

    #[test]
    fn a_release_without_ebpf_has_none() {
        let f = fx();
        let rel = release_payload("0.5.0", GOOD_URL, 1024);
        let v = run(&f, &offer_with(&f, "agent-1", 101, &rel, &f.release)).unwrap();
        assert!(v.ebpf.is_none());
    }

    #[test]
    fn rejects_bad_sha256() {
        let f = fx();
        let rel = release_payload("0.5.0", GOOD_URL, 1024).replace(&"00".repeat(32), "zz");
        let o = offer_with(&f, "agent-1", 101, &rel, &f.release);
        assert_eq!(run(&f, &o), Err(Reject::Malformed("sha256")));
    }

    /// Offer produced by the *backend's* TypeScript signer
    /// (`frontend/scripts/test-agent-update.ts`, seeds 0x01 release / 0x02
    /// command). Proves the two implementations agree on the wire format.
    #[test]
    fn verifies_offer_signed_by_the_backend_implementation() {
        let offer: UpdateOffer = serde_json::from_str(include_str!(
            "../../tests/fixtures/update-offer-vector.json"
        ))
        .unwrap();
        let f = fx();
        let (rk, ck) = (f.release.verifying_key(), f.command.verifying_key());
        let v = verify_offer(&offer, &ctx(&f, &rk, &ck)).expect("backend offer must verify");
        assert_eq!(v.version, "0.5.0");
        assert_eq!(v.issued_at, 1_700_000_000);
    }
}
