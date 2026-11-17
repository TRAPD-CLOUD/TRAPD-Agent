//! Findings of the network guard, their stable fingerprints and the events
//! built from them. Pure, so the event shape is unit tested.

use std::collections::HashSet;

use trapd_schema::{AgentEvent, DetectionData, EventAction, EventClass, EventData, Severity};

use super::matching::{FilterInfo, Reason};
use super::tls_pin::PinMismatch;

pub const RULE_SILENCED: &str = "selfprotect.network_silenced";
pub const RULE_REDIRECTED: &str = "selfprotect.backend_redirected";
pub const RULE_PIN_MISMATCH: &str = "selfprotect.tls_pin_mismatch";
pub const RULE_UNREACHABLE: &str = "selfprotect.backend_unreachable_selective";

const MAX_TEXT: usize = 200;

fn clip(s: &str) -> String {
    s.chars().take(MAX_TEXT).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A block filter / rule that targets the agent or the backend.
    Silenced {
        filter: FilterInfo,
        reason: Reason,
    },
    /// Something that sends backend traffic elsewhere.
    Redirected {
        /// `hosts`, `proxy_env`, `proxy_winhttp`, `proxy_wininet`, `nrpt`.
        vector: &'static str,
        /// What was found (hosts line, proxy server, NRPT namespace).
        subject: String,
        detail: String,
        /// Extra strings an operator may allowlist this finding by.
        allow_keys: Vec<String>,
        /// Hosts entries and NRPT rules are changes someone made on purpose;
        /// a proxy is common in enterprises, so it ranks lower.
        severity: Severity,
    },
    PinMismatch(PinMismatch),
    UnreachableSelective {
        backend: String,
        probe: String,
    },
}

impl Finding {
    /// Stable identity: the same finding is reported once until it clears.
    pub fn fingerprint(&self) -> String {
        match self {
            Finding::Silenced { filter, reason } => format!(
                "silenced|{}|{}|{}|{}|{}",
                filter.source,
                filter.provider,
                filter.layer,
                filter.name,
                reason.as_str()
            ),
            Finding::Redirected {
                vector, subject, ..
            } => format!("redirected|{vector}|{subject}"),
            Finding::PinMismatch(m) => format!("pin|{}|{}", m.host, m.observed.join(",")),
            Finding::UnreachableSelective { backend, .. } => format!("selective|{backend}"),
        }
    }

    /// Strings an operator can put in the `allow` list to silence this finding.
    pub fn allow_keys(&self) -> Vec<String> {
        match self {
            Finding::Silenced { filter, .. } => {
                vec![filter.name.clone(), filter.provider.clone()]
            }
            Finding::Redirected { allow_keys, .. } => allow_keys.clone(),
            // Pin and reachability findings are never allowlisted: pins are
            // already an explicit operator decision.
            Finding::PinMismatch(_) | Finding::UnreachableSelective { .. } => vec![],
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Finding::Silenced { .. } | Finding::PinMismatch(_) => Severity::High,
            Finding::Redirected { severity, .. } => *severity,
            Finding::UnreachableSelective { .. } => Severity::Medium,
        }
    }

    pub fn detection(&self) -> DetectionData {
        match self {
            Finding::Silenced { filter, reason } => DetectionData {
                rule_id: RULE_SILENCED.into(),
                title: "Network filter blocks the TRAPD agent or its backend".into(),
                category: "defense_evasion".into(),
                mitre_tactic: Some("TA0005 Defense Evasion".into()),
                mitre_technique: Some("T1562.004".into()),
                confidence: 85,
                subject: clip(&filter.name),
                detail: format!(
                    "A {} block rule matches {}; agent traffic to the backend may be dropped",
                    filter.source,
                    match reason {
                        Reason::AppId => "the agent executable",
                        Reason::BackendAddress => "the backend address",
                        Reason::Uid => "the agent user id",
                        Reason::Cgroup => "the agent cgroup",
                    }
                ),
                evidence: serde_json::json!({
                    "source": filter.source,
                    "filter_name": clip(&filter.name),
                    "provider": clip(&filter.provider),
                    "layer": clip(&filter.layer),
                    "reason": reason.as_str(),
                }),
                ..Default::default()
            },
            Finding::Redirected {
                vector,
                subject,
                detail,
                ..
            } => DetectionData {
                rule_id: RULE_REDIRECTED.into(),
                title: "Backend traffic is redirected on this host".into(),
                category: "defense_evasion".into(),
                mitre_tactic: Some("TA0006 Credential Access".into()),
                mitre_technique: Some("T1557".into()),
                confidence: 70,
                subject: clip(subject),
                detail: clip(detail),
                evidence: serde_json::json!({
                    "vector": vector,
                    "subject": clip(subject),
                }),
                ..Default::default()
            },
            Finding::PinMismatch(m) => DetectionData {
                rule_id: RULE_PIN_MISMATCH.into(),
                title: "Backend TLS certificate chain does not match the configured pins".into(),
                category: "defense_evasion".into(),
                mitre_tactic: Some("TA0006 Credential Access".into()),
                mitre_technique: Some("T1557".into()),
                confidence: 90,
                subject: clip(&m.host),
                detail: "The agent refused the connection: the chain verified against the \
                         trust anchors but carries none of the pinned keys (TLS interception \
                         or an unannounced certificate rotation)"
                    .into(),
                evidence: serde_json::json!({
                    "host": clip(&m.host),
                    "observed_spki_sha256": m.observed,
                    "refused_handshakes": m.count,
                }),
                ..Default::default()
            },
            Finding::UnreachableSelective { backend, probe } => DetectionData {
                rule_id: RULE_UNREACHABLE.into(),
                title: "Backend unreachable while the internet is reachable".into(),
                category: "defense_evasion".into(),
                mitre_tactic: Some("TA0005 Defense Evasion".into()),
                mitre_technique: Some("T1562.004".into()),
                confidence: 60,
                subject: clip(backend),
                detail: "The backend did not answer for several minutes while the configured \
                         neutral probe did, which points at targeted blocking"
                    .into(),
                evidence: serde_json::json!({ "backend": clip(backend), "probe_host": clip(probe) }),
                ..Default::default()
            },
        }
    }

    pub fn to_event(&self, agent_id: &str, hostname: &str) -> AgentEvent {
        AgentEvent::new(
            agent_id.to_string(),
            hostname.to_string(),
            EventClass::Detection,
            EventAction::Detected,
            self.severity(),
            EventData::Detection(Box::new(self.detection())),
        )
    }
}

/// Reports each fingerprint once until it disappears from the scan, so a
/// persistent filter is one finding, and a removed-then-re-added one is two.
#[derive(Default)]
pub struct Reported(HashSet<String>);

impl Reported {
    pub fn fresh(&mut self, current: Vec<Finding>) -> Vec<Finding> {
        let now: HashSet<String> = current.iter().map(Finding::fingerprint).collect();
        self.0.retain(|k| now.contains(k));
        current
            .into_iter()
            .filter(|f| self.0.insert(f.fingerprint()))
            .collect()
    }
}

/// Backend counts as selectively unreachable after this many consecutive scans
/// in which it failed while the probe answered.
pub const SELECTIVE_AFTER: u32 = 3;

#[derive(Default)]
pub struct SelectiveTracker {
    streak: u32,
}

impl SelectiveTracker {
    /// `true` while the selective-unreachability condition holds (and has held
    /// for [`SELECTIVE_AFTER`] scans). Both-down is a plain outage, not
    /// selective, and resets the streak.
    pub fn observe(&mut self, backend_ok: bool, probe_ok: bool) -> bool {
        if backend_ok || !probe_ok {
            self.streak = 0;
        } else {
            self.streak = self.streak.saturating_add(1);
        }
        self.streak >= SELECTIVE_AFTER
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selfprotect::network_guard::matching::Verdict;

    fn silenced(name: &str) -> Finding {
        Finding::Silenced {
            filter: FilterInfo {
                source: "wfp",
                name: name.into(),
                provider: "Microsoft Windows Firewall".into(),
                layer: "ALE Auth Connect v4".into(),
                verdict: Verdict::Block,
                disabled: false,
                app_ids: vec![],
                remote: vec![],
                uid_ranges: vec![],
                cgroup_paths: vec![],
                cgroup_ids: vec![],
            },
            reason: Reason::AppId,
        }
    }

    #[test]
    fn silenced_event_is_high_and_carries_name_provider_layer() {
        let ev = silenced("Block trapd").to_event("a1", "host");
        assert_eq!(ev.severity, Severity::High);
        let EventData::Detection(d) = ev.data else {
            panic!("not a detection")
        };
        assert_eq!(d.rule_id, "selfprotect.network_silenced");
        assert_eq!(d.evidence["filter_name"], "Block trapd");
        assert_eq!(d.evidence["provider"], "Microsoft Windows Firewall");
        assert_eq!(d.evidence["layer"], "ALE Auth Connect v4");
        assert_eq!(d.evidence["reason"], "app_id");
    }

    #[test]
    fn foreign_text_is_clipped() {
        let long = "x".repeat(5000);
        let d = silenced(&long).detection();
        assert_eq!(d.subject.len(), 200);
        assert_eq!(d.evidence["filter_name"].as_str().unwrap().len(), 200);
    }

    #[test]
    fn reported_dedupes_and_rearms_after_clear() {
        let mut r = Reported::default();
        assert_eq!(r.fresh(vec![silenced("a"), silenced("b")]).len(), 2);
        assert_eq!(r.fresh(vec![silenced("a"), silenced("b")]).len(), 0);
        assert_eq!(r.fresh(vec![silenced("b"), silenced("c")]).len(), 1);
        assert_eq!(r.fresh(vec![]).len(), 0);
        assert_eq!(r.fresh(vec![silenced("a")]).len(), 1, "re-added filter");
    }

    #[test]
    fn selective_needs_a_streak_and_a_live_probe() {
        let mut t = SelectiveTracker::default();
        assert!(!t.observe(false, true));
        assert!(!t.observe(false, true));
        assert!(t.observe(false, true));
        assert!(!t.observe(true, true), "backend recovered");
        assert!(!t.observe(false, true));
        assert!(!t.observe(false, false), "full outage is not selective");
        assert!(!t.observe(false, true));
    }

    #[test]
    fn redirect_severity_and_allow_keys_pass_through() {
        let f = Finding::Redirected {
            vector: "proxy_env",
            subject: "http://proxy:3128".into(),
            detail: "d".into(),
            allow_keys: vec!["http://proxy:3128".into()],
            severity: Severity::Medium,
        };
        assert_eq!(f.severity(), Severity::Medium);
        assert_eq!(f.allow_keys(), ["http://proxy:3128"]);
        assert_eq!(f.detection().rule_id, RULE_REDIRECTED);
    }

    #[test]
    fn pin_mismatch_event() {
        let f = Finding::PinMismatch(PinMismatch {
            host: "api.trapd.eu".into(),
            observed: vec!["AAA=".into()],
            count: 3,
        });
        let d = f.detection();
        assert_eq!(d.rule_id, RULE_PIN_MISMATCH);
        assert_eq!(d.evidence["refused_handshakes"], 3);
        assert!(f.allow_keys().is_empty());
    }
}
