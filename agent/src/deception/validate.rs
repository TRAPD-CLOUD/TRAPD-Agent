//! Bait-content validation and anti-fingerprinting guards (issue #32, point 3).
//!
//! The backend's LLM produces the *content* of a honeytoken; the agent places
//! it. A malformed token — an "AWS key" that is not shaped like one, a JWT with
//! two segments, a kubeconfig missing `clusters:` — is worse than no token at
//! all: it is the tell that reveals the trap to an attentive adversary. So
//! before the agent commits a token to disk it validates that the content
//! actually *looks like* the artefact it claims to be, and rejects the
//! deployment otherwise.
//!
//! Two layers run on every deploy:
//!
//!   1. [`validate_bait`] — a per-kind structural check (does this content match
//!      the real format?). Unknown kinds pass structurally (the backend may add
//!      families faster than the agent learns them) but still face layer 2.
//!   2. [`reject_shared_watermark`] — a universal guard that fails if the content
//!      carries a tell-tale TRAPD-internal marker. A shared, greppable watermark
//!      across all tokens would let an attacker enumerate and avoid every bait at
//!      once, so such strings must never reach disk.
//!
//! The functions are pure and exhaustively unit-tested; `deploy` calls
//! [`validate_bait`] and refuses placement on error, leaving the target
//! untouched.

use std::fmt;

/// Why a piece of bait content was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaitError {
    pub kind: String,
    pub reason: String,
}

impl fmt::Display for BaitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid '{}' honeytoken content: {}", self.kind, self.reason)
    }
}

impl std::error::Error for BaitError {}

/// Internal markers that must never appear in bait content. A real attacker who
/// finds any of these knows instantly the file is a trap — and, worse, can grep
/// the whole host (and every other host) for the same string to map and avoid
/// every token. Matching is case-insensitive. The list is deliberately limited
/// to unambiguous TRAPD/deception tells, not generic words a genuine secret
/// might contain.
const FORBIDDEN_MARKERS: &[&str] = &[
    "trapd",
    "honeytoken",
    "honeypot",
    "canarytoken",
    "this is a decoy",
    "do not use this credential",
];

/// Validate bait `content` for the declared token `kind`, then apply the
/// universal anti-fingerprinting guard. Returns `Ok(())` when the content is
/// safe to place.
pub fn validate_bait(kind: &str, content: &[u8]) -> Result<(), BaitError> {
    // Empty content is never a believable artefact.
    if content.is_empty() {
        return Err(err(kind, "content is empty"));
    }

    // Binary archetypes are validated by magic bytes before any UTF-8 view.
    match kind {
        "office_doc" => return finish(kind, content, validate_office(content)),
        "pdf_doc" => return finish(kind, content, validate_pdf(content)),
        "passwords_kdbx" => return finish(kind, content, validate_kdbx(content)),
        _ => {}
    }

    // Text archetypes. A token that is not valid UTF-8 but claims to be a text
    // credential file is itself a tell.
    let text = match std::str::from_utf8(content) {
        Ok(t) => t,
        Err(_) => {
            // Unknown kinds may legitimately be binary; only reject non-UTF-8 for
            // kinds we expect to be text.
            if is_text_kind(kind) {
                return Err(err(kind, "expected UTF-8 text content"));
            }
            // Still apply the watermark guard on the raw bytes' lossy view.
            return reject_shared_watermark(kind, &String::from_utf8_lossy(content));
        }
    };

    let structural = match kind {
        "aws_credentials" => validate_aws(text),
        "jwt" | "jwt_token" => validate_jwt(text),
        "kube_config" => validate_kubeconfig(text),
        "pgpass" => validate_pgpass(text),
        "my_cnf" => validate_my_cnf(text),
        "ssh_private_key" => validate_ssh_key(text),
        "docker_config" => validate_docker_config(text),
        "webroot_env" => validate_env(text),
        "git_credentials" => validate_git_credentials(text),
        "shadow_backup" => validate_shadow(text),
        "browser_logins" => validate_browser_logins(text),
        // Free-form families (root_backup_keys, shell_history, …) and any kind
        // the agent does not yet know: accept structurally, still guard below.
        _ => Ok(()),
    };
    structural?;
    reject_shared_watermark(kind, text)
}

/// Universal guard: fail if `text` carries a TRAPD/deception tell.
pub fn reject_shared_watermark(kind: &str, text: &str) -> Result<(), BaitError> {
    let lower = text.to_ascii_lowercase();
    for marker in FORBIDDEN_MARKERS {
        if lower.contains(marker) {
            return Err(err(
                kind,
                &format!("content carries a forbidden shared marker ('{marker}')"),
            ));
        }
    }
    Ok(())
}

// ── Per-kind validators ───────────────────────────────────────────────────────

/// AWS credentials file: an INI profile with a key id shaped like
/// `(AKIA|ASIA|AGPA|AIDA|AROA)` + 16 upper-alnum and a 40-char secret. Notably
/// this rejects the documentation placeholder `AKIAIOSFODNN7EXAMPLE`, whose
/// `EXAMPLE` suffix is itself a fingerprint.
fn validate_aws(c: &str) -> Result<(), BaitError> {
    let kind = "aws_credentials";
    require(c.contains("aws_access_key_id"), kind, "missing aws_access_key_id")?;
    require(c.contains("aws_secret_access_key"), kind, "missing aws_secret_access_key")?;
    require(
        has_access_key_id(c),
        kind,
        "no AWS access key id of the form AKIA/ASIA/… + 16 upper-alnum chars",
    )?;
    require(
        line_value(c, "aws_secret_access_key").is_some_and(is_aws_secret),
        kind,
        "aws_secret_access_key is not a 40-char secret",
    )?;
    if c.to_ascii_uppercase().contains("EXAMPLE") {
        return Err(err(kind, "contains the 'EXAMPLE' placeholder (documentation tell)"));
    }
    Ok(())
}

/// JWT: three non-empty base64url segments, the header decoding to a JSON object
/// that declares an `alg`.
fn validate_jwt(c: &str) -> Result<(), BaitError> {
    let kind = "jwt";
    let token = c
        .split(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'' || ch == '=')
        .find(|t| t.matches('.').count() == 2 && t.len() > 20)
        .ok_or_else(|| err(kind, "no dotted three-segment token found"))?;
    let mut parts = token.split('.');
    let header_b64 = parts.next().unwrap_or("");
    let payload_b64 = parts.next().unwrap_or("");
    let sig_b64 = parts.next().unwrap_or("");
    require(
        !header_b64.is_empty() && !payload_b64.is_empty() && !sig_b64.is_empty(),
        kind,
        "a JWT segment is empty",
    )?;
    let header = b64url_decode(header_b64).ok_or_else(|| err(kind, "header is not base64url"))?;
    let json: serde_json::Value =
        serde_json::from_slice(&header).map_err(|_| err(kind, "header is not JSON"))?;
    require(json.get("alg").is_some(), kind, "JWT header has no 'alg'")?;
    Ok(())
}

/// kubeconfig: the four keys every real config carries.
fn validate_kubeconfig(c: &str) -> Result<(), BaitError> {
    let kind = "kube_config";
    for needle in ["apiVersion", "clusters", "contexts", "users"] {
        require(c.contains(needle), kind, &format!("missing '{needle}:' section"))?;
    }
    require(
        c.contains("kind: Config") || c.contains("kind:Config"),
        kind,
        "missing 'kind: Config'",
    )?;
    Ok(())
}

/// `.pgpass`: at least one `host:port:db:user:password` line (5 colon fields).
fn validate_pgpass(c: &str) -> Result<(), BaitError> {
    let kind = "pgpass";
    let ok = c.lines().filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty()).any(|l| {
        // Fields may contain '\:' escapes; count unescaped colons.
        unescaped_colon_fields(l) == 5
    });
    require(ok, kind, "no host:port:db:user:password line")
}

/// `.my.cnf`: a `[client]` section with user + password.
fn validate_my_cnf(c: &str) -> Result<(), BaitError> {
    let kind = "my_cnf";
    let lower = c.to_ascii_lowercase();
    require(lower.contains("[client]"), kind, "missing [client] section")?;
    require(lower.contains("password"), kind, "no password key")?;
    require(lower.contains("user"), kind, "no user key")
}

/// SSH private key: a PEM envelope.
fn validate_ssh_key(c: &str) -> Result<(), BaitError> {
    let kind = "ssh_private_key";
    require(c.contains("-----BEGIN") && c.contains("PRIVATE KEY-----"), kind, "no PEM BEGIN PRIVATE KEY header")?;
    require(c.contains("-----END"), kind, "no PEM END footer")
}

/// `~/.docker/config.json`: JSON with an `auths` object.
fn validate_docker_config(c: &str) -> Result<(), BaitError> {
    let kind = "docker_config";
    let v: serde_json::Value = serde_json::from_str(c).map_err(|_| err(kind, "not valid JSON"))?;
    require(v.get("auths").map(|a| a.is_object()).unwrap_or(false), kind, "no 'auths' object")
}

/// Webroot `.env`: at least one secret-bearing `KEY=value` assignment.
fn validate_env(c: &str) -> Result<(), BaitError> {
    let kind = "webroot_env";
    let secrety = ["PASSWORD", "SECRET", "KEY", "TOKEN", "DSN", "DATABASE_URL", "PASSWD"];
    let ok = c.lines().filter_map(|l| l.split_once('=')).any(|(k, v)| {
        let ku = k.trim().to_ascii_uppercase();
        !v.trim().is_empty() && secrety.iter().any(|s| ku.contains(s))
    });
    require(ok, kind, "no secret-bearing KEY=value assignment")
}

/// `.git-credentials`: at least one `scheme://user:pass@host` line.
fn validate_git_credentials(c: &str) -> Result<(), BaitError> {
    let kind = "git_credentials";
    let ok = c.lines().filter(|l| !l.trim().is_empty()).any(|l| {
        let l = l.trim();
        if let Some((scheme, rest)) = l.split_once("://") {
            !scheme.is_empty()
                && rest.contains('@')
                && rest.split('@').next().is_some_and(|userinfo| userinfo.contains(':'))
        } else {
            false
        }
    });
    require(ok, kind, "no scheme://user:password@host line")
}

/// A `shadow`-style file: at least one line with 9 colon-separated fields whose
/// second field is a hash (`$id$…`), lock (`!`/`*`), or empty.
fn validate_shadow(c: &str) -> Result<(), BaitError> {
    let kind = "shadow_backup";
    let ok = c.lines().filter(|l| !l.trim().is_empty()).any(|l| {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() != 9 {
            return false;
        }
        let pw = f[1];
        pw.starts_with('$') || pw == "!" || pw == "*" || pw == "!!" || pw.is_empty()
    });
    require(ok, kind, "no user:hash:…(9 fields) shadow line")
}

/// Browser login store (Firefox `logins.json` / Chrome export): JSON carrying a
/// recognisable logins array.
fn validate_browser_logins(c: &str) -> Result<(), BaitError> {
    let kind = "browser_logins";
    let v: serde_json::Value = serde_json::from_str(c).map_err(|_| err(kind, "not valid JSON"))?;
    let has_logins = v.get("logins").map(|l| l.is_array()).unwrap_or(false)
        || v.as_array().map(|a| !a.is_empty()).unwrap_or(false);
    require(has_logins, kind, "no 'logins' array")
}

/// Office Open XML (docx/xlsx/pptx) is a ZIP — magic `PK\x03\x04`.
fn validate_office(c: &[u8]) -> Result<(), BaitError> {
    require(c.starts_with(b"PK\x03\x04"), "office_doc", "not a ZIP/OOXML container (PK header)")
}

/// PDF magic `%PDF-`.
fn validate_pdf(c: &[u8]) -> Result<(), BaitError> {
    require(c.starts_with(b"%PDF-"), "pdf_doc", "not a PDF (%PDF- header)")
}

/// KeePass KDBX magic (`0x9AA2D903`).
fn validate_kdbx(c: &[u8]) -> Result<(), BaitError> {
    require(c.len() >= 4 && c[0] == 0x03 && c[1] == 0xD9 && c[2] == 0xA2 && c[3] == 0x9A,
        "passwords_kdbx", "not a KDBX container (magic mismatch)")
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn is_text_kind(kind: &str) -> bool {
    matches!(
        kind,
        "aws_credentials" | "jwt" | "jwt_token" | "kube_config" | "pgpass" | "my_cnf"
            | "ssh_private_key" | "docker_config" | "webroot_env" | "git_credentials"
            | "shadow_backup" | "browser_logins" | "root_backup_keys" | "shell_history"
    )
}

fn finish(kind: &str, content: &[u8], structural: Result<(), BaitError>) -> Result<(), BaitError> {
    structural?;
    reject_shared_watermark(kind, &String::from_utf8_lossy(content))
}

fn require(cond: bool, kind: &str, reason: &str) -> Result<(), BaitError> {
    if cond { Ok(()) } else { Err(err(kind, reason)) }
}

fn err(kind: &str, reason: &str) -> BaitError {
    BaitError { kind: kind.to_string(), reason: reason.to_string() }
}

/// Value to the right of `key=` or `key =` on the first matching line.
fn line_value<'a>(c: &'a str, key: &str) -> Option<&'a str> {
    c.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == key).then(|| v.trim())
    })
}

/// True if `c` contains an AWS access-key-id-shaped token.
fn has_access_key_id(c: &str) -> bool {
    const PREFIXES: &[&str] = &["AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA", "ABIA"];
    let bytes = c.as_bytes();
    for prefix in PREFIXES {
        let pl = prefix.len();
        let mut i = 0;
        while let Some(pos) = c[i..].find(prefix) {
            let start = i + pos;
            // boundary before
            let before_ok = start == 0 || !is_key_char(bytes[start - 1]);
            let end = start + pl + 16;
            if before_ok && end <= bytes.len() {
                let body = &bytes[start + pl..end];
                let body_ok = body.iter().all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit());
                let after_ok = end == bytes.len() || !is_key_char(bytes[end]);
                if body_ok && after_ok {
                    return true;
                }
            }
            i = start + pl;
        }
    }
    false
}

fn is_key_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// AWS secret access keys are 40 chars of base64 alphabet (`A-Za-z0-9/+`).
fn is_aws_secret(v: &str) -> bool {
    v.len() == 40 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'+')
}

/// Count colon-separated fields, honouring `\:` escapes (as in `.pgpass`).
fn unescaped_colon_fields(line: &str) -> usize {
    let bytes = line.as_bytes();
    let mut fields = 1;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2; // skip the escaped char
            continue;
        }
        if bytes[i] == b':' {
            fields += 1;
        }
        i += 1;
    }
    fields
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()
        .or_else(|| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_accepts_realistic_and_rejects_malformed() {
        let good = "[default]\naws_access_key_id = AKIA2E0AABCDEFGHIJKL\n\
                    aws_secret_access_key = wJalrXUtnFEMIabcdefGHIjklMNOpqrsTUVwxyz1\n";
        assert!(validate_bait("aws_credentials", good.as_bytes()).is_ok());

        // Truncated key id.
        assert!(validate_bait("aws_credentials", b"[default]\naws_access_key_id=AKIA...\naws_secret_access_key=x\n").is_err());
        // The documentation placeholder must be rejected (it is a fingerprint).
        let example = "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\n\
                       aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
        assert!(validate_bait("aws_credentials", example.as_bytes()).is_err());
    }

    #[test]
    fn jwt_requires_three_decodable_segments() {
        // header {"alg":"HS256","typ":"JWT"} . payload . sig
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlZGF0YQ";
        assert!(validate_bait("jwt", format!("token={jwt}\n").as_bytes()).is_ok());
        assert!(validate_bait("jwt", b"only.two").is_err());
    }

    #[test]
    fn kubeconfig_needs_all_sections() {
        let kc = "apiVersion: v1\nkind: Config\nclusters:\n- cluster: {}\ncontexts: []\nusers: []\n";
        assert!(validate_bait("kube_config", kc.as_bytes()).is_ok());
        assert!(validate_bait("kube_config", b"apiVersion: v1\nclusters: []\n").is_err());
    }

    #[test]
    fn pgpass_and_git_credentials_shape() {
        assert!(validate_bait("pgpass", b"db.internal:5432:appdb:appuser:s3cr3tpw\n").is_ok());
        assert!(validate_bait("pgpass", b"justonefield\n").is_err());
        assert!(validate_bait("git_credentials", b"https://deploy:ghp_abc123@git.internal\n").is_ok());
        assert!(validate_bait("git_credentials", b"https://git.internal\n").is_err());
    }

    #[test]
    fn ssh_and_shadow_and_env() {
        assert!(validate_bait("ssh_private_key", b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n").is_ok());
        assert!(validate_bait("shadow_backup", b"root:$6$abc$def:19000:0:99999:7:::\n").is_ok());
        assert!(validate_bait("webroot_env", b"DB_PASSWORD=hunter2\nAPP_ENV=prod\n").is_ok());
        assert!(validate_bait("webroot_env", b"APP_ENV=prod\n").is_err());
    }

    #[test]
    fn binary_kinds_checked_by_magic() {
        assert!(validate_bait("office_doc", b"PK\x03\x04rest-of-zip").is_ok());
        assert!(validate_bait("office_doc", b"not a zip").is_err());
        assert!(validate_bait("pdf_doc", b"%PDF-1.7\n...").is_ok());
    }

    #[test]
    fn forbidden_watermark_is_rejected_for_every_kind() {
        // Even structurally-valid content is refused if it carries a tell.
        let c = "[default]\naws_access_key_id=AKIA2E0AABCDEFGHIJKL\n\
                 aws_secret_access_key=wJalrXUtnFEMIabcdefGHIjklMNOpqrsTUVwxyz1\n# trapd honeytoken\n";
        let e = validate_bait("aws_credentials", c.as_bytes()).unwrap_err();
        assert!(e.reason.contains("forbidden shared marker"), "got: {}", e.reason);
        // Free-form kind also guarded.
        assert!(validate_bait("root_backup_keys", b"this is a HONEYTOKEN").is_err());
    }

    #[test]
    fn empty_content_rejected() {
        assert!(validate_bait("aws_credentials", b"").is_err());
        assert!(validate_bait("unknown_kind", b"").is_err());
    }

    #[test]
    fn unknown_kind_passes_structurally_but_is_guarded() {
        assert!(validate_bait("some_future_kind", b"arbitrary plausible content").is_ok());
    }
}
