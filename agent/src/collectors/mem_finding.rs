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

/// Stable fold key for anonymous executable memory: one per (image identity,
/// mapping kind), independent of pid and address, so the backend folds repeats
/// of the same binary into one signal. Shared by the Linux and Windows
/// scanners so both platforms fold identically. The image hash wins over the path (a
/// replaced binary is a different identity); `comm` is the last resort.
pub fn anon_exec_dedup_key(
    image: Option<&str>,
    sha256: Option<&str>,
    comm: &str,
    writable: bool,
) -> String {
    let identity = match (sha256, image) {
        (Some(h), _) => format!("sha256:{}", h.trim_start_matches("sha256:")),
        (None, Some(p)) => format!("path:{p}"),
        (None, None) => format!("comm:{comm}"),
    };
    let kind = if writable { "rwx" } else { "rx" };
    let mut key = format!("memory.anon_exec:{identity}:{kind}");
    // Bound the key (paths and comm are attacker-influenced): keep the kind.
    if key.len() > 256 {
        let mut cut = 240;
        while !key.is_char_boundary(cut) {
            cut -= 1;
        }
        key.truncate(cut);
        key.push_str(&format!("…:{kind}"));
    }
    key
}

/// Backend fold key for a Windows finding. Only low-confidence allocator
/// context (`memory.anon_exec` below the alert threshold) folds per image:
/// JITs, hooking engines and Atomic-style test harnesses leave it in many
/// processes, and without a key every pid became its own signal. Injected PE
/// images and running threads stay one signal per region.
#[cfg(any(windows, test))]
pub fn windows_context_dedup_key(
    finding: &MemFinding,
    writable: bool,
    image: Option<&str>,
    sha256: Option<&str>,
    name: &str,
) -> Option<String> {
    if finding.rule_id != "memory.anon_exec" || finding.confidence >= 50 {
        return None;
    }
    // Windows paths are case-insensitive; the same binary must fold.
    let image = image.map(str::to_lowercase);
    Some(anon_exec_dedup_key(
        image.as_deref(),
        sha256,
        name,
        writable,
    ))
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

    #[test]
    fn windows_context_findings_fold_per_image_and_alerts_do_not() {
        let ctx = MemFinding {
            rule_id: "memory.anon_exec",
            title: "Executable private memory",
            technique: "T1055",
            confidence: 40,
            severity: Severity::Low,
            region: "0x1000-0x2000 r-x <private>".into(),
        };
        let a = windows_context_dedup_key(
            &ctx,
            false,
            Some(r"C:\Windows\System32\RUNDLL32.EXE"),
            None,
            "rundll32.exe",
        );
        let b = windows_context_dedup_key(
            &ctx,
            false,
            Some(r"c:\windows\system32\rundll32.exe"),
            None,
            "rundll32.exe",
        );
        assert_eq!(a, b);
        assert_eq!(
            a.as_deref(),
            Some(r"memory.anon_exec:path:c:\windows\system32\rundll32.exe:rx")
        );
        assert_ne!(
            a,
            windows_context_dedup_key(
                &ctx,
                true,
                Some(r"C:\Windows\System32\rundll32.exe"),
                None,
                "rundll32.exe"
            )
        );
        assert_eq!(
            windows_context_dedup_key(&ctx, false, Some(r"C:\x.exe"), Some("sha256:ab"), "x.exe")
                .as_deref(),
            Some("memory.anon_exec:sha256:ab:rx")
        );
        let thread = MemFinding {
            confidence: 94,
            severity: Severity::High,
            ..ctx.clone()
        };
        assert_eq!(
            windows_context_dedup_key(&thread, true, Some("C:\\x.exe"), None, "x.exe"),
            None
        );
        let pe = MemFinding {
            rule_id: "memory.injected_pe",
            confidence: 88,
            ..ctx
        };
        assert_eq!(
            windows_context_dedup_key(&pe, true, Some("C:\\x.exe"), None, "x.exe"),
            None
        );
    }
}
