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

/// Windows finding identity includes the kernel-assigned process generation.
/// Low-confidence allocator context is grouped within that generation; injected
/// images and running threads are specific to their region.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemFindingKey {
    pub pid: i32,
    pub process_start_time: u64,
    rule_id: &'static str,
    region: MemFindingRegionKey,
}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum MemFindingRegionKey {
    Context { writable: bool },
    Region(u64),
}

#[cfg(any(windows, test))]
impl MemFindingKey {
    pub fn new(
        pid: i32,
        process_start_time: u64,
        finding: &MemFinding,
        base: u64,
        writable: bool,
    ) -> Self {
        let region = if finding.rule_id == "memory.anon_exec" && finding.confidence < 50 {
            MemFindingRegionKey::Context { writable }
        } else {
            MemFindingRegionKey::Region(base)
        };
        Self {
            pid,
            process_start_time,
            rule_id: finding.rule_id,
            region,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_dedup_retains_distinct_process_generations() {
        let finding = MemFinding {
            rule_id: "memory.anon_exec",
            title: "",
            technique: "T1055",
            confidence: 48,
            severity: Severity::High,
            region: String::new(),
        };
        let old = MemFindingKey::new(7, 100, &finding, 0x1000, true);
        let current = MemFindingKey::new(7, 200, &finding, 0x1000, true);
        assert_ne!(old, current);
        assert_eq!(current, MemFindingKey::new(7, 200, &finding, 0x9000, true));
        let pe = MemFinding {
            rule_id: "memory.injected_pe",
            ..finding
        };
        assert_ne!(
            MemFindingKey::new(7, 200, &pe, 0x1000, true),
            MemFindingKey::new(7, 200, &pe, 0x9000, true)
        );
        let live = std::collections::HashSet::from([(7, 200)]);
        let mut seen = std::collections::HashSet::from([old, current.clone()]);
        seen.retain(|key| live.contains(&(key.pid, key.process_start_time)));
        assert_eq!(seen, std::collections::HashSet::from([current]));
    }
}
