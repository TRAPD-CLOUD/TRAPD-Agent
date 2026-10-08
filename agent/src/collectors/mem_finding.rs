//! The result of classifying a process's memory, shared by the Linux
//! (`/proc/<pid>/maps`) and Windows (`VirtualQueryEx`) memory scanners so both
//! platforms raise the same detections with the same fields.

use crate::schema::{DetectionData, Severity};

/// A classified memory finding (rule + scoring), independent of any I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemFinding {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub technique: &'static str,
    pub confidence: u8,
    pub severity: Severity,
    /// Human description of the offending region.
    pub region: String,
}

/// Turn a finding into the detection event the engine and the response layer
/// consume. The offending pid is carried in `evidence`, so automated response
/// can act on it.
pub fn finding_to_detection(pid: i32, name: &str, f: &MemFinding) -> DetectionData {
    DetectionData {
        rule_id: f.rule_id.to_string(),
        title: f.title.to_string(),
        category: "memory".into(),
        mitre_tactic: Some("TA0005 Defense Evasion".into()),
        mitre_technique: Some(f.technique.to_string()),
        confidence: f.confidence,
        subject: format!("pid {pid} ({name})"),
        detail: format!("PID {pid} ({name}): {}", f.region),
        evidence: serde_json::json!({ "pid": pid, "comm": name, "region": f.region }),
        ..Default::default()
    }
}
