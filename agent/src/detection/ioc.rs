//! Indicator-of-Compromise (IOC) matching.
//!
//! A lightweight, dependency-free IOC store loaded from a JSON file in the
//! config directory (`<config>/iocs.json`).  The backend (or a threat-intel
//! feed sync job) is expected to keep that file up to date; the agent reloads
//! it on a timer.  Matching is O(1) hash-set lookups so it stays cheap even
//! with large feeds.
//!
//! Supported indicator types:
//!   * `hashes`  — SHA256 of process executables / files (with or without the
//!     `sha256:` prefix; matching is prefix-insensitive)
//!   * `ips`     — exact destination IP addresses
//!   * `domains` — exact domains *and* parent-domain suffixes (a hit on
//!     `evil.example.com` also fires for `c2.evil.example.com`)

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
struct RawIocFile {
    #[serde(default)]
    hashes: Vec<String>,
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    domains: Vec<String>,
}

/// An immutable, queryable set of indicators.
#[derive(Debug, Default, Clone)]
pub struct IocSet {
    hashes: HashSet<String>,
    ips: HashSet<String>,
    domains: HashSet<String>,
}

impl IocSet {
    /// Parse an IOC set from JSON bytes.  Hashes are normalised to lower-case
    /// hex without the `sha256:` prefix; domains/ips are lower-cased + trimmed.
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let raw: RawIocFile = serde_json::from_slice(bytes)?;
        Ok(Self {
            hashes: raw.hashes.iter().map(|h| normalize_hash(h)).collect(),
            ips: raw
                .ips
                .iter()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            domains: raw
                .domains
                .iter()
                .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }

    /// Load from a file path, returning an empty set if the file is absent.
    pub fn load(path: &Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => Self::from_json(&bytes).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty() && self.ips.is_empty() && self.domains.is_empty()
    }

    pub fn len(&self) -> usize {
        self.hashes.len() + self.ips.len() + self.domains.len()
    }

    /// Returns the matched (normalised) hash if `hash` is a known-bad indicator.
    pub fn match_hash(&self, hash: &str) -> bool {
        self.hashes.contains(&normalize_hash(hash))
    }

    /// Returns true if `ip` is a known-bad destination.
    pub fn match_ip(&self, ip: &str) -> bool {
        self.ips.contains(&ip.trim().to_ascii_lowercase())
    }

    /// Returns the matched parent indicator if `domain` is, or is a subdomain
    /// of, a known-bad domain.
    pub fn match_domain(&self, domain: &str) -> Option<String> {
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if d.is_empty() {
            return None;
        }
        // Check the full name and each parent suffix: a.b.c → a.b.c, b.c, c
        let mut hay = d.as_str();
        loop {
            if self.domains.contains(hay) {
                return Some(hay.to_string());
            }
            match hay.find('.') {
                Some(idx) => hay = &hay[idx + 1..],
                None => return None,
            }
        }
    }
}

/// Strip a leading `sha256:` (any case) and lower-case the hex.
fn normalize_hash(h: &str) -> String {
    let h = h.trim();
    let h = h
        .strip_prefix("sha256:")
        .or_else(|| h.strip_prefix("SHA256:"))
        .unwrap_or(h);
    h.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> IocSet {
        let json = br#"{
            "hashes": ["sha256:ABCD1234", "deadbeef"],
            "ips": ["203.0.113.5", "198.51.100.9"],
            "domains": ["evil.example.com", "bad.test"]
        }"#;
        IocSet::from_json(json).unwrap()
    }

    #[test]
    fn matches_hash_prefix_insensitive() {
        let s = sample();
        assert!(s.match_hash("abcd1234"));
        assert!(s.match_hash("sha256:abcd1234"));
        assert!(s.match_hash("SHA256:ABCD1234"));
        assert!(s.match_hash("deadbeef"));
        assert!(!s.match_hash("cafebabe"));
    }

    #[test]
    fn matches_ip_exact() {
        let s = sample();
        assert!(s.match_ip("203.0.113.5"));
        assert!(!s.match_ip("203.0.113.6"));
    }

    #[test]
    fn matches_domain_and_subdomains() {
        let s = sample();
        assert_eq!(
            s.match_domain("evil.example.com").as_deref(),
            Some("evil.example.com")
        );
        assert_eq!(
            s.match_domain("c2.evil.example.com").as_deref(),
            Some("evil.example.com")
        );
        assert_eq!(
            s.match_domain("EVIL.EXAMPLE.COM").as_deref(),
            Some("evil.example.com")
        );
        assert!(s.match_domain("example.com").is_none());
        assert!(s.match_domain("good.test").is_none());
    }

    #[test]
    fn empty_on_garbage() {
        assert!(IocSet::from_json(b"not json").is_err());
        assert!(IocSet::default().is_empty());
    }

    #[test]
    fn counts_indicators() {
        assert_eq!(sample().len(), 6);
    }
}
