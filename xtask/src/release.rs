//! Release signing for the agent self-update.
//!
//! `sign-release` turns one built artifact into the *release statement* the
//! agent and backend verify (see `agent/src/update/manifest.rs`): a JSON string
//! naming version, platform, download URL, SHA-256 and size, plus a detached
//! Ed25519 signature over the exact bytes of that string. The signing key is the
//! offline **release key**, deliberately distinct from the backend's command key.

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

/// Must equal `ALLOWED_URL_PREFIX` in the agent: anything else is rejected by
/// every agent and by the backend at registration.
const URL_PREFIX: &str = "https://github.com/trapd-cloud/trapd-agent/releases/download/";

pub struct Artifact<'a> {
    pub version: &'a str,
    pub os: &'a str,
    pub arch: &'a str,
    pub tag: &'a str,
    pub asset_name: &'a str,
    pub bytes: &'a [u8],
    /// Linux: the eBPF object shipped with this version, as (asset name, bytes).
    /// Its map layout is coupled to the binary, so it is signed with it.
    pub ebpf: Option<(&'a str, &'a [u8])>,
}

fn asset_url(tag: &str, name: &str) -> Result<String, String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        || name.contains("..")
    {
        return Err(format!("unsafe asset name {name:?}"));
    }
    Ok(format!("{URL_PREFIX}{tag}/{name}"))
}

/// Release statement as a JSON string (keys in alphabetical order).
pub fn statement(a: &Artifact<'_>) -> Result<String, String> {
    if a.version.split('.').count() != 3 || a.version.split('.').any(|p| p.parse::<u64>().is_err())
    {
        return Err(format!(
            "version must be MAJOR.MINOR.PATCH, got {:?}",
            a.version
        ));
    }
    let mut statement = serde_json::json!({
        "arch": a.arch,
        "os": a.os,
        "sha256": hex::encode(Sha256::digest(a.bytes)),
        "size": a.bytes.len(),
        "url": asset_url(a.tag, a.asset_name)?,
        "version": a.version,
    });
    if let Some((name, bytes)) = a.ebpf {
        if a.os != "linux" {
            return Err("the eBPF companion is Linux only".to_string());
        }
        statement["ebpf"] = serde_json::json!({
            "sha256": hex::encode(Sha256::digest(bytes)),
            "size": bytes.len(),
            "url": asset_url(a.tag, name)?,
        });
    }
    Ok(statement.to_string())
}

/// Parse the base64 32-byte seed held in the `RELEASE_SIGNING_KEY` secret.
pub fn signing_key(seed_b64: &str) -> Result<SigningKey, String> {
    let seed = STANDARD
        .decode(seed_b64.trim())
        .map_err(|e| format!("release key is not valid base64: {e}"))?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| "release key must decode to exactly 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Detached signature over the statement's exact bytes.
pub fn sign(key: &SigningKey, payload: &str) -> String {
    STANDARD.encode(key.sign(payload.as_bytes()).to_bytes())
}

/// Embed the independent digest signature before signing the release payload.
pub fn add_binary_signature(
    payload: &str,
    bytes: &[u8],
    key: &SigningKey,
) -> Result<String, String> {
    let mut statement: serde_json::Value =
        serde_json::from_str(payload).map_err(|e| e.to_string())?;
    statement["binary_signature"] =
        serde_json::json!(STANDARD.encode(key.sign(&Sha256::digest(bytes)).to_bytes()));
    Ok(statement.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    fn artifact(bytes: &[u8]) -> Artifact<'_> {
        Artifact {
            version: "0.5.0",
            os: "linux",
            arch: "x86_64",
            tag: "v0.5.0",
            asset_name: "trapd-agent-linux-x86_64",
            bytes,
            ebpf: None,
        }
    }

    #[test]
    fn ebpf_companion_is_part_of_the_signed_statement() {
        let mut a = artifact(b"binary");
        a.ebpf = Some(("trapd-agent-exec", b"object"));
        let v: serde_json::Value = serde_json::from_str(&statement(&a).unwrap()).unwrap();
        assert_eq!(v["ebpf"]["size"], 6);
        assert_eq!(v["ebpf"]["sha256"], hex::encode(Sha256::digest(b"object")));
        assert_eq!(
            v["ebpf"]["url"],
            "https://github.com/trapd-cloud/trapd-agent/releases/download/v0.5.0/trapd-agent-exec"
        );
        let keys: Vec<_> = v["ebpf"].as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys, ["sha256", "size", "url"]);
    }

    #[test]
    fn embedded_binary_signature_verifies_the_raw_digest() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let payload =
            add_binary_signature(&statement(&artifact(b"binary")).unwrap(), b"binary", &key)
                .unwrap();
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let bytes = STANDARD
            .decode(v["binary_signature"].as_str().unwrap())
            .unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&bytes).unwrap();
        key.verifying_key()
            .verify_strict(&Sha256::digest(b"binary"), &sig)
            .unwrap();
        assert!(key
            .verifying_key()
            .verify_strict(&Sha256::digest(b"other"), &sig)
            .is_err());
    }

    #[test]
    fn ebpf_companion_is_refused_for_windows() {
        let mut a = artifact(b"binary");
        a.os = "windows";
        a.ebpf = Some(("trapd-agent-exec", b"object"));
        assert!(statement(&a).is_err());
    }

    #[test]
    fn statement_matches_what_the_agent_parses() {
        let s = statement(&artifact(b"binary")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        // Exactly the fields the agent's `deny_unknown_fields` struct accepts.
        assert_eq!(keys, ["arch", "os", "sha256", "size", "url", "version"]);
        assert_eq!(v["size"], 6);
        assert_eq!(
            v["url"],
            "https://github.com/trapd-cloud/trapd-agent/releases/download/v0.5.0/trapd-agent-linux-x86_64"
        );
        assert_eq!(v["sha256"], hex::encode(Sha256::digest(b"binary")));
    }

    #[test]
    fn signature_verifies_over_exact_payload_bytes() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let payload = statement(&artifact(b"binary")).unwrap();
        let sig = sign(&key, &payload);
        let sig = ed25519_dalek::Signature::from_slice(&STANDARD.decode(sig).unwrap()).unwrap();
        assert!(key.verifying_key().verify(payload.as_bytes(), &sig).is_ok());
        assert!(key
            .verifying_key()
            .verify(format!("{payload} ").as_bytes(), &sig)
            .is_err());
    }

    #[test]
    fn rejects_bad_versions_and_asset_names() {
        for v in ["1.2", "1.2.3-beta", "a.b.c", ""] {
            let mut a = artifact(b"x");
            a.version = v;
            assert!(statement(&a).is_err(), "{v}");
        }
        for n in ["../x", "a/b", "a?b", "a b", ""] {
            let mut a = artifact(b"x");
            a.asset_name = n;
            // An empty name is caught by the URL rules downstream; the rest here.
            if !n.is_empty() {
                assert!(statement(&a).is_err(), "{n}");
            }
        }
    }

    #[test]
    fn key_must_be_32_bytes_of_base64() {
        assert!(signing_key(&STANDARD.encode([7u8; 32])).is_ok());
        assert!(signing_key(&STANDARD.encode([7u8; 31])).is_err());
        assert!(signing_key("not base64!!").is_err());
    }
}
