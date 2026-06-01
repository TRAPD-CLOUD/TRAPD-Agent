//! Optional YARA-based file scanning.
//!
//! Compiled only with `--features yara` (which pulls in the `yara-rust`
//! binding and, transitively, the libyara C library).  At start the scanner
//! compiles every `*.yar` rule file found in [`RULES_DIR`]; newly-created files
//! reported by the filesystem collector's inotify watch (`CREATE` only) are
//! scanned against the compiled rule set.  A match yields a detection carrying
//! the matched rule name, the file path and the `severity` taken from the
//! rule's YARA metadata (defaulting to `high`).
//!
//! If the rules directory is missing or contains no usable rules, the scanner
//! is a silent no-op — never an error — so an agent without rules behaves
//! exactly as before.

use std::path::Path;

use tracing::{info, warn};

use crate::schema::{DetectionData, Severity};

/// Directory scanned for `*.yar` rule files.
const RULES_DIR: &str = "/etc/trapd/rules";

/// Per-scan timeout passed to libyara, in seconds.
const SCAN_TIMEOUT_SECS: i32 = 10;

/// Holds the compiled YARA rule set, if any rules were loaded.
pub struct YaraScanner {
    rules: Option<yara_rust::Rules>,
}

impl YaraScanner {
    /// Compile all `*.yar` files under [`RULES_DIR`].  Returns an inert scanner
    /// (no rules) when the directory is absent or no rules compile — by design
    /// this never fails.
    pub fn load() -> Self {
        let dir = Path::new(RULES_DIR);
        if !dir.is_dir() {
            info!("YaraScanner: {RULES_DIR} absent — YARA scanning disabled");
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
                warn!("YaraScanner: cannot read {RULES_DIR}: {e}");
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
            info!("YaraScanner: no *.yar rules in {RULES_DIR} — YARA scanning disabled");
            return Self { rules: None };
        }

        match compiler.compile_rules() {
            Ok(rules) => {
                info!("YaraScanner: {added} rule file(s) compiled from {RULES_DIR}");
                Self { rules: Some(rules) }
            }
            Err(e) => {
                warn!("YaraScanner: rule compilation failed: {e}");
                Self { rules: None }
            }
        }
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

fn confidence_for(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 95,
        Severity::High => 80,
        Severity::Medium => 55,
        Severity::Low => 30,
        Severity::Info => 10,
    }
}
