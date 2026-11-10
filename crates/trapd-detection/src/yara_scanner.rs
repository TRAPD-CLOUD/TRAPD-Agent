//! Optional YARA-based file and process-memory scanning.
//!
//! Compiled only with `--features yara` (which pulls in the `yara-rust`
//! binding and a vendored libyara).  At start the scanner compiles every
//! `*.yar` rule file found in the rules directory (`<config>/rules`); newly
//! created files reported by the filesystem collector's inotify watch
//! (`CREATE` only) are scanned against the compiled rule set, and so are the
//! suspicious memory regions the memory scanner finds (anonymous executable,
//! memfd-backed and deleted-image mappings), via [`YaraScanner::scan_bytes`].
//! A match yields a detection carrying the matched rule name and the
//! `severity` taken from the rule's YARA metadata (defaulting to `high`).
//!
//! If the rules directory is missing or contains no usable rules, the scanner
//! is a silent no-op — never an error — so an agent without rules behaves
//! exactly as before.

use std::path::Path;

use tracing::{info, warn};

use trapd_schema::{DetectionData, Severity};

/// Default directory scanned for `*.yar` rule files.
const RULES_DIR: &str = "/etc/trapd/rules";

/// Per-scan timeout passed to libyara, in seconds.
const SCAN_TIMEOUT_SECS: i32 = 10;

/// Holds the compiled YARA rule set, if any rules were loaded.
pub struct YaraScanner {
    rules: Option<yara_rust::Rules>,
}

impl YaraScanner {
    /// Compile all `*.yar` files under [`RULES_DIR`].
    pub fn load() -> Self {
        Self::load_from(Path::new(RULES_DIR))
    }

    /// Compile all `*.yar` files under `dir`.  Returns an inert scanner (no
    /// rules) when the directory is absent or no rules compile — by design
    /// this never fails.
    pub fn load_from(dir: &Path) -> Self {
        let shown = dir.display();
        if !dir.is_dir() {
            info!("YaraScanner: {shown} absent — YARA scanning disabled");
            return Self { rules: None };
        }

        let mut compiler = match yara_rust::Compiler::new() {
            Ok(c) => c,
            Err(e) => {
                warn!("YaraScanner: compiler init failed: {e}");
                return Self { rules: None };
            }
        };

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                warn!("YaraScanner: cannot read {shown}: {e}");
                return Self { rules: None };
            }
        };

        let mut added = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("yar") {
                continue;
            }
            // `add_rules_file` consumes the compiler and discards it on error, so
            // validate each file in an isolated probe compiler first — that way a
            // single malformed rule file is skipped instead of wiping out every
            // rule already accumulated.
            let valid = match yara_rust::Compiler::new() {
                Ok(probe) => probe.add_rules_file(&path).is_ok(),
                Err(_) => false,
            };
            if !valid {
                warn!("YaraScanner: skipping invalid rule file {}", path.display());
                continue;
            }
            match compiler.add_rules_file(&path) {
                Ok(c) => {
                    compiler = c;
                    added += 1;
                }
                Err(e) => {
                    warn!("YaraScanner: failed to load {}: {e}", path.display());
                    return Self { rules: None };
                }
            }
        }

        if added == 0 {
            info!("YaraScanner: no *.yar rules in {shown} — YARA scanning disabled");
            return Self { rules: None };
        }

        match compiler.compile_rules() {
            Ok(rules) => {
                info!("YaraScanner: {added} rule file(s) compiled from {shown}");
                Self { rules: Some(rules) }
            }
            Err(e) => {
                warn!("YaraScanner: rule compilation failed: {e}");
                Self { rules: None }
            }
        }
    }

    /// Compile rules from source text (tests and embedded rule sets).
    pub fn from_source(source: &str) -> Option<Self> {
        let rules = yara_rust::Compiler::new()
            .ok()?
            .add_rules_str(source)
            .ok()?
            .compile_rules()
            .ok()?;
        Some(Self { rules: Some(rules) })
    }

    /// Scan a buffer — a region read from a process's memory. Returns the
    /// first matching rule's identifier and severity.
    pub fn scan_bytes(&self, data: &[u8]) -> Option<(String, Severity)> {
        let rules = self.rules.as_ref()?;
        let matches = match rules.scan_mem(data, SCAN_TIMEOUT_SECS) {
            Ok(m) => m,
            Err(e) => {
                warn!("YaraScanner: memory scan failed: {e}");
                return None;
            }
        };
        let m = matches.first()?;
        Some((m.identifier.to_string(), rule_severity(m)))
    }

    /// `true` when rules are loaded and scanning is active.
    #[allow(dead_code)]
    pub fn is_active(&self) -> bool {
        self.rules.is_some()
    }

    /// Scan a single file.  Returns `(severity, detection)` for the first
    /// matching rule, or `None` if no rules are loaded or nothing matched.
    pub fn scan_file(&self, path: &str) -> Option<(Severity, DetectionData)> {
        let rules = self.rules.as_ref()?;
        let matches = match rules.scan_file(path, SCAN_TIMEOUT_SECS) {
            Ok(m) => m,
            Err(e) => {
                warn!("YaraScanner: scan of {path} failed: {e}");
                return None;
            }
        };
        let m = matches.first()?;
        let severity = rule_severity(m);
        let detection = DetectionData {
            rule_id: format!("yara.{}", m.identifier),
            title: format!("YARA rule '{}' matched", m.identifier),
            category: "yara".into(),
            mitre_tactic: None,
            mitre_technique: None,
            confidence: confidence_for(&severity),
            subject: path.to_string(),
            detail: format!("File {path} matched YARA rule {}", m.identifier),
            evidence: serde_json::json!({
                "matched_rule": m.identifier,
                "file_path": path,
                "severity": severity_str(&severity),
            }),
            ..Default::default()
        };
        Some((severity, detection))
    }
}

/// Read a `severity = "critical|high|medium|low"` metadata field from a matched
/// rule, defaulting to `High` when absent or unrecognised.
fn rule_severity(m: &yara_rust::Rule) -> Severity {
    for meta in &m.metadatas {
        if meta.identifier == "severity" {
            if let yara_rust::MetadataValue::String(s) = &meta.value {
                return match s.to_ascii_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    "info" => Severity::Info,
                    _ => Severity::High,
                };
            }
        }
    }
    Severity::High
}

fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

pub fn confidence_for(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 95,
        Severity::High => 80,
        Severity::Medium => 55,
        Severity::Low => 30,
        Severity::Info => 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = r#"
rule test_shellcode_marker {
    meta:
        severity = "critical"
    strings:
        $m = "TRAPD-YARA-TEST-MARKER"
    condition:
        $m
}
"#;

    #[test]
    fn scan_bytes_matches_and_carries_rule_severity() {
        let s = YaraScanner::from_source(RULE).unwrap();
        assert!(s.is_active());
        let mut buf = vec![0x90u8; 8192];
        buf[4000..4022].copy_from_slice(b"TRAPD-YARA-TEST-MARKER");
        assert_eq!(
            s.scan_bytes(&buf),
            Some(("test_shellcode_marker".to_string(), Severity::Critical))
        );
        assert_eq!(s.scan_bytes(&[0x90u8; 8192]), None);
    }

    #[test]
    fn invalid_source_and_missing_dir_are_inert() {
        assert!(YaraScanner::from_source("rule broken {").is_none());
        let s = YaraScanner::load_from(Path::new("/nonexistent/trapd/rules"));
        assert!(!s.is_active());
        assert_eq!(s.scan_bytes(b"TRAPD-YARA-TEST-MARKER"), None);
    }
}
