//! Operator settings of the network guard.
//!
//! Sources, lowest to highest precedence: `<config>/network_guard.json`
//! (optional, root-writable config directory), then environment variables
//! (the agent's env file is loaded into the process environment at start).
//!
//! | JSON key / env var                                  | Meaning |
//! |-----------------------------------------------------|---------|
//! | `enabled` / `TRAPD_NETWORK_GUARD=0`                 | switch the whole guard off |
//! | `spki_pins` / `TRAPD_BACKEND_SPKI_PINS`             | base64 SHA-256 SPKI pins of the backend chain |
//! | `inspection_ca_pins` / `TRAPD_TLS_INSPECTION_CA_PINS` | pins of a tenant-approved TLS-inspection CA |
//! | `allow` / `TRAPD_NETWORK_GUARD_ALLOW`               | filter/rule names, providers, proxy servers, hosts-file IPs to ignore |
//! | `probe_url` / `TRAPD_NETWORK_PROBE_URL`             | neutral URL for the selective-unreachability check (default: none) |
//!
//! The signed agent config also carries `backend_spki_pins` and
//! `tls_inspection_ca_pins` (see [`super::signed_pins`]). Signed backend pins
//! replace `spki_pins` from here; signed inspection CA pins are merged with
//! `inspection_ca_pins`. These local sources can therefore only add to what
//! was signed, never remove it.

use std::path::Path;

use serde::Deserialize;

const MAX_FILE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub spki_pins: Vec<String>,
    pub inspection_ca_pins: Vec<String>,
    pub allow: Vec<String>,
    pub probe_url: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            spki_pins: vec![],
            inspection_ca_pins: vec![],
            allow: vec![],
            probe_url: None,
        }
    }
}

fn split_list(raw: &str) -> Vec<String> {
    raw.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

impl Settings {
    /// Merge an optional JSON document with environment overrides. A document
    /// that does not parse is an error: silently ignoring a pin file would
    /// downgrade enforcement to report-only.
    pub fn from_sources(
        file_json: Option<&str>,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, String> {
        let mut s = match file_json {
            Some(j) => serde_json::from_str::<Settings>(j)
                .map_err(|e| format!("network_guard.json: {e}"))?,
            None => Settings::default(),
        };
        let get = |k: &str| env(k).filter(|v| !v.trim().is_empty());
        if let Some(v) = get("TRAPD_NETWORK_GUARD") {
            s.enabled = !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            );
        }
        if let Some(v) = get("TRAPD_BACKEND_SPKI_PINS") {
            s.spki_pins = split_list(&v);
        }
        if let Some(v) = get("TRAPD_TLS_INSPECTION_CA_PINS") {
            s.inspection_ca_pins = split_list(&v);
        }
        if let Some(v) = get("TRAPD_NETWORK_GUARD_ALLOW") {
            s.allow = v
                .split([',', ';'])
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect();
        }
        if let Some(v) = get("TRAPD_NETWORK_PROBE_URL") {
            s.probe_url = Some(v.trim().to_string());
        }
        Ok(s)
    }

    /// Load from the config directory and the process environment.
    pub fn load() -> Result<Self, String> {
        let path = crate::paths::config_dir().join("network_guard.json");
        Self::from_sources(read_capped(&path).as_deref(), |k| std::env::var(k).ok())
    }

    pub fn allows(&self, key: &str) -> bool {
        let key = key.trim().to_lowercase();
        self.allow.iter().any(|a| a.trim().to_lowercase() == key)
    }
}

fn read_capped(path: &Path) -> Option<String> {
    if std::fs::metadata(path).ok()?.len() > MAX_FILE_BYTES {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn defaults_are_enabled_pinless_and_probeless() {
        let s = Settings::from_sources(None, no_env).unwrap();
        assert!(s.enabled);
        assert!(s.spki_pins.is_empty());
        assert!(s.probe_url.is_none(), "probe must be opt-in (privacy)");
    }

    #[test]
    fn env_overrides_file() {
        let file = r#"{"spki_pins":["AAAA"],"allow":["x"],"probe_url":"https://a.example"}"#;
        let env = |k: &str| match k {
            "TRAPD_BACKEND_SPKI_PINS" => Some("B1, B2 B3".to_string()),
            "TRAPD_NETWORK_GUARD" => Some("off".to_string()),
            _ => None,
        };
        let s = Settings::from_sources(Some(file), env).unwrap();
        assert_eq!(s.spki_pins, ["B1", "B2", "B3"]);
        assert_eq!(s.allow, ["x"]);
        assert!(!s.enabled);
        assert_eq!(s.probe_url.as_deref(), Some("https://a.example"));
    }

    #[test]
    fn malformed_file_is_an_error_not_a_silent_downgrade() {
        assert!(Settings::from_sources(Some("{not json"), no_env).is_err());
        assert!(Settings::from_sources(Some(r#"{"spki_pin":["x"]}"#), no_env).is_err());
    }

    #[test]
    fn allow_is_case_insensitive_exact() {
        let s = Settings {
            allow: vec!["Corp Proxy:3128".into()],
            ..Default::default()
        };
        assert!(s.allows("corp proxy:3128"));
        assert!(!s.allows("corp proxy"));
    }
}
