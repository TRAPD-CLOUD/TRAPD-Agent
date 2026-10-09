//! Severity policy — a pure, deterministic function from (catalog entry,
//! confidence, context) to the severity a finding is reported with.
//!
//! The backend runs the identical policy (plus the asset-criticality modifier,
//! which only it knows) and is authoritative; the agent's result drives local
//! auto-response and offline output. Both sides test against the same vectors
//! (`tests/fixtures/severity-vectors.json`), so they cannot drift silently.
//!
//! Policy:
//! 1. confidence < 50 demotes the finding to a `signal`.
//! 2. Modifiers, each one step: `+web_lineage`, `+root` (rules with
//!    `root_bump`), `+container` (rules with `container_bump`), `+in_chain`,
//!    `-pkg_mgr_lineage`, `-config_mgmt_lineage`, `-suppression_downgrade`;
//!    the sum is clamped to ±2.
//! 3. Asset criticality (backend only): `high` +1, `low` -1.
//! 4. severity = clamp(base + steps, Info, max); an alert never drops below Low.
//! 5. A signal is capped at Low — it never alerts on its own.

use trapd_schema::{DetectionMode, Severity};

use super::catalog::RuleMeta;

pub const FLAG_ROOT: &str = "root";
pub const FLAG_WEB_LINEAGE: &str = "web_lineage";
pub const FLAG_PKG_MGR_LINEAGE: &str = "pkg_mgr_lineage";
pub const FLAG_CONFIG_MGMT_LINEAGE: &str = "config_mgmt_lineage";
pub const FLAG_CONTAINER: &str = "container";
pub const FLAG_IN_CHAIN: &str = "in_chain";
pub const FLAG_SSH_SESSION: &str = "ssh_session";
pub const FLAG_SUPPRESSION_DOWNGRADE: &str = "suppression_downgrade";

/// Everything the policy reasons over.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PolicyInput {
    pub base: Severity,
    pub max: Severity,
    pub mode: DetectionMode,
    pub confidence: u8,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub root_bump: bool,
    #[serde(default)]
    pub container_bump: bool,
    /// `high` / `low` / anything else (neutral). Backend only.
    #[serde(default)]
    pub asset_criticality: Option<String>,
}

impl PolicyInput {
    pub fn from_meta(meta: &RuleMeta, base: Severity, confidence: u8, flags: Vec<String>) -> Self {
        Self {
            base,
            max: meta.max,
            mode: meta.mode,
            confidence,
            flags,
            root_bump: meta.root_bump,
            container_bump: meta.container_bump,
            asset_criticality: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct PolicyOutcome {
    pub severity: Severity,
    pub mode: DetectionMode,
    #[serde(default)]
    pub reasons: Vec<String>,
}

fn rank(s: Severity) -> i8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn from_rank(r: i8) -> Severity {
    match r {
        i8::MIN..=0 => Severity::Info,
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        _ => Severity::Critical,
    }
}

fn label(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Apply the policy.
pub fn evaluate(input: &PolicyInput) -> PolicyOutcome {
    let has = |f: &str| input.flags.iter().any(|x| x == f);
    let mut reasons = vec![format!("base:{}", label(input.base))];

    let mut mode = input.mode;
    if mode == DetectionMode::Alert && input.confidence < 50 {
        mode = DetectionMode::Signal;
        reasons.push("signal:low_confidence".into());
    }

    let mut steps: i8 = 0;
    let mut step = |delta: i8, why: &str| {
        steps += delta;
        reasons.push(format!("{}{}", if delta > 0 { "+" } else { "-" }, why));
    };
    if has(FLAG_WEB_LINEAGE) {
        step(1, FLAG_WEB_LINEAGE);
    }
    if input.root_bump && has(FLAG_ROOT) {
        step(1, FLAG_ROOT);
    }
    if input.container_bump && has(FLAG_CONTAINER) {
        step(1, FLAG_CONTAINER);
    }
    if has(FLAG_IN_CHAIN) {
        step(1, FLAG_IN_CHAIN);
    }
    if has(FLAG_PKG_MGR_LINEAGE) {
        step(-1, FLAG_PKG_MGR_LINEAGE);
    }
    if has(FLAG_CONFIG_MGMT_LINEAGE) {
        step(-1, FLAG_CONFIG_MGMT_LINEAGE);
    }
    if has(FLAG_SUPPRESSION_DOWNGRADE) {
        step(-1, FLAG_SUPPRESSION_DOWNGRADE);
    }
    let mut steps = steps.clamp(-2, 2);

    match input.asset_criticality.as_deref() {
        Some("high") => {
            steps += 1;
            reasons.push("+asset_high".into());
        }
        Some("low") => {
            steps -= 1;
            reasons.push("-asset_low".into());
        }
        _ => {}
    }

    let mut sev = rank(input.base) + steps;
    if sev > rank(input.max) {
        sev = rank(input.max);
        reasons.push(format!("cap:{}", label(input.max)));
    }
    if mode == DetectionMode::Alert {
        sev = sev.max(rank(Severity::Low));
    } else {
        sev = sev.min(rank(Severity::Low));
    }
    PolicyOutcome {
        severity: from_rank(sev),
        mode,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vector {
        name: String,
        input: PolicyInput,
        expect: Expect,
    }

    #[derive(serde::Deserialize)]
    struct Expect {
        severity: Severity,
        mode: DetectionMode,
    }

    /// Shared with the backend (`backend/fixtures/detection/severity-vectors.json`):
    /// both implementations must produce the same severity and mode.
    #[test]
    fn shared_vectors() {
        let raw = include_str!("../tests/fixtures/severity-vectors.json");
        let vectors: Vec<Vector> = serde_json::from_str(raw).unwrap();
        assert!(vectors.len() >= 20);
        for v in vectors {
            let out = evaluate(&v.input);
            assert_eq!(out.severity, v.expect.severity, "vector {}", v.name);
            assert_eq!(out.mode, v.expect.mode, "vector {}", v.name);
        }
    }

    #[test]
    fn reasons_explain_the_decision() {
        let out = evaluate(&PolicyInput {
            base: Severity::High,
            max: Severity::Critical,
            mode: DetectionMode::Alert,
            confidence: 90,
            flags: vec![FLAG_WEB_LINEAGE.into()],
            root_bump: false,
            container_bump: false,
            asset_criticality: None,
        });
        assert_eq!(out.severity, Severity::Critical);
        assert_eq!(out.reasons, vec!["base:high", "+web_lineage"]);
    }
}
