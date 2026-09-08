//! Best-effort secret redaction on log *payloads* before they leave the host.
//!
//! Falcon-class collectors ship the raw line. We do not: a postgres statement
//! or nginx query-string routinely contains credentials, and the backend (and
//! every SIEM it fans out to) should not become a second credential store.
//! Redaction is conservative — over-redacting a token is cheap; leaking an
//! AWS key is not.

use std::sync::OnceLock;

use regex::Regex;

fn aws_key() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b").expect("aws_key"))
}

fn bearer() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(bearer|token)\s+[A-Za-z0-9._\-+=/]{12,}").expect("bearer")
    })
}

fn assignment() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(password|passwd|secret|api[_-]?key|private[_-]?key)\s*[:=]\s*([^\s,;]+)"#,
        )
        .expect("assignment")
    })
}

fn pem() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")
            .expect("pem")
    })
}

fn jwt() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
            .expect("jwt")
    })
}

/// Redact known secret shapes in `s`. The original length is not preserved;
/// callers that care about truncation already measured before this step.
pub fn redact(s: &str) -> String {
    let mut out = pem().replace_all(s, "[REDACTED_PRIVATE_KEY]").into_owned();
    out = aws_key()
        .replace_all(&out, "[REDACTED_AWS_KEY]")
        .into_owned();
    out = jwt().replace_all(&out, "[REDACTED_JWT]").into_owned();
    out = bearer()
        .replace_all(&out, "$1 [REDACTED_TOKEN]")
        .into_owned();
    out = assignment().replace_all(&out, "$1=[REDACTED]").into_owned();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_aws_access_key() {
        let s = redact("key=AKIAIOSFODNN7EXAMPLE leftover");
        assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(s.contains("[REDACTED_AWS_KEY]"));
        assert!(s.contains("leftover"));
    }

    #[test]
    fn redacts_password_assignment() {
        let s = redact("user=alice password=hunter2 host=db");
        assert!(!s.contains("hunter2"));
        assert!(s.contains("password=[REDACTED]"));
        assert!(s.contains("user=alice"));
    }

    #[test]
    fn redacts_jwt() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.abcde_fghij";
        let s = redact(&format!("Authorization: {token}"));
        assert!(!s.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(s.contains("[REDACTED_JWT]"));
    }

    #[test]
    fn leaves_benign_text_alone() {
        let src = "GET /health HTTP/1.1\" 200 12";
        assert_eq!(redact(src), src);
    }
}
