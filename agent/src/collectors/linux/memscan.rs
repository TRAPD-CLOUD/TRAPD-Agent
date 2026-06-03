//! Process-memory scanner — periodic `/proc/<pid>/maps` + `environ` analysis.
//!
//! The eBPF syscall tracer already flags *mmap-time* RWX/anon-exec allocations,
//! but a process can be born malicious (injected before the agent started) or
//! mutate its mappings between the agent's view. This collector closes that gap
//! with a cheap, periodic sweep of every process's memory map, raising a
//! first-class [`crate::schema::DetectionData`] for the classic fileless /
//! code-injection footprints:
//!
//!   * **anonymous executable memory** (`anon + x`, worse if `rwx`) — shellcode,
//!     unbacked JIT, reflective loaders (MITRE T1055 / T1620);
//!   * **memfd-backed execution** (`/memfd:… (deleted)` mapped executable) —
//!     fileless payloads (T1620);
//!   * **deleted-binary execution** (`… (deleted)` exec mapping) — a process
//!     running an image unlinked from disk (T1036 / T1620);
//!   * **`LD_PRELOAD` injection** observed at runtime via `/proc/<pid>/environ`
//!     pointing outside the standard library paths (T1574.006).
//!
//! It only reads `maps` and `environ` (never `/proc/<pid>/mem`), so it is cheap
//! and safe to run on the whole process table; the heavyweight memory *dump*
//! lives behind a signed RTR command. Findings carry the offending pid in
//! `evidence`, so the automated-response engine can act on them.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration};
use tracing::info;

use crate::config::AgentConfig;
use crate::schema::{AgentEvent, DetectionData, EventAction, EventClass, EventData, Severity};

use super::super::Collector;

/// One line of `/proc/<pid>/maps`, parsed into the fields we classify on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapRegion {
    pub start: u64,
    pub end: u64,
    /// Raw permission string, e.g. `r-xp`, `rwxp`.
    pub perms: String,
    /// Pathname column: empty for anonymous, `[heap]`/`[stack]`/`[vdso]` for
    /// special regions, a path (optionally suffixed ` (deleted)`) otherwise.
    pub path: String,
}

impl MapRegion {
    fn is_exec(&self) -> bool {
        self.perms.contains('x')
    }
    fn is_write(&self) -> bool {
        self.perms.contains('w')
    }
    /// Anonymous: no backing path and not one of the kernel pseudo-regions.
    fn is_anon(&self) -> bool {
        self.path.is_empty()
    }
    fn is_deleted(&self) -> bool {
        self.path.ends_with(" (deleted)")
    }
    fn is_memfd(&self) -> bool {
        self.path.starts_with("/memfd:")
    }
}

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

/// Parse `/proc/<pid>/maps` content into regions. Malformed lines are skipped.
pub fn parse_maps(content: &str) -> Vec<MapRegion> {
    content.lines().filter_map(parse_maps_line).collect()
}

/// Parse a single maps line: `start-end perms offset dev inode  pathname`.
pub fn parse_maps_line(line: &str) -> Option<MapRegion> {
    let mut cols = line.split_whitespace();
    let range = cols.next()?;
    let perms = cols.next()?;
    let (start_hex, end_hex) = range.split_once('-')?;
    let start = u64::from_str_radix(start_hex, 16).ok()?;
    let end = u64::from_str_radix(end_hex, 16).ok()?;
    // Skip offset, dev, inode; the remainder (may contain spaces) is the path.
    let _offset = cols.next()?;
    let _dev = cols.next()?;
    let _inode = cols.next()?;
    let path = cols.collect::<Vec<_>>().join(" ");
    Some(MapRegion {
        start,
        end,
        perms: perms.to_string(),
        path,
    })
}

/// Classify one region. Returns `None` for benign regions and the kernel
/// pseudo-mappings (`[vdso]`, `[vsyscall]`, `[vvar]`) which are legitimately
/// executable.
pub fn classify_region(r: &MapRegion) -> Option<MemFinding> {
    if !r.is_exec() {
        return None;
    }

    if r.is_memfd() {
        return Some(MemFinding {
            rule_id: "memory.memfd_exec",
            title: "Execution from anonymous memfd image",
            technique: "T1620",
            confidence: 90,
            severity: Severity::Critical,
            region: format!("{:#x}-{:#x} {} {}", r.start, r.end, r.perms, r.path),
        });
    }

    if r.is_anon() {
        // Anonymous executable memory. RWX is the strongest single-region
        // injection signal; plain anon r-x is still abnormal for most code.
        let (confidence, severity) = if r.is_write() {
            (88, Severity::High)
        } else {
            (78, Severity::High)
        };
        return Some(MemFinding {
            rule_id: "memory.anon_exec",
            title: if r.is_write() {
                "Writable+executable anonymous memory (RWX)"
            } else {
                "Executable anonymous memory"
            },
            technique: "T1055",
            confidence,
            severity,
            region: format!("{:#x}-{:#x} {} <anonymous>", r.start, r.end, r.perms),
        });
    }

    if r.is_deleted() {
        // A running image unlinked from disk. Common-ish after a package
        // upgrade for long-lived daemons, so kept at medium severity to avoid
        // auto-response false positives — but still surfaced.
        return Some(MemFinding {
            rule_id: "memory.deleted_exec",
            title: "Execution from a deleted on-disk image",
            technique: "T1620",
            confidence: 60,
            severity: Severity::Medium,
            region: format!("{:#x}-{:#x} {} {}", r.start, r.end, r.perms, r.path),
        });
    }

    None
}

/// Standard library roots a legitimate `LD_PRELOAD` is expected to live under.
const TRUSTED_LIB_PREFIXES: &[&str] = &[
    "/lib/",
    "/lib64/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/local/lib/",
];

/// Extract `LD_PRELOAD` from raw `/proc/<pid>/environ` (NUL-separated).
pub fn ld_preload_from_environ(environ: &[u8]) -> Option<String> {
    environ
        .split(|b| *b == 0)
        .filter_map(|kv| std::str::from_utf8(kv).ok())
        .find_map(|kv| kv.strip_prefix("LD_PRELOAD="))
        .map(str::to_string)
        .filter(|v| !v.is_empty())
}

/// An `LD_PRELOAD` value is suspicious when any of its entries resolves outside
/// the trusted system library roots (e.g. `/tmp`, `/dev/shm`, a home dir).
pub fn is_suspicious_preload(value: &str) -> bool {
    value
        .split([' ', ':'])
        .filter(|s| !s.is_empty())
        .any(|lib| lib.starts_with('/') && !TRUSTED_LIB_PREFIXES.iter().any(|p| lib.starts_with(p)))
}

fn finding_to_detection(pid: i32, comm: &str, f: &MemFinding) -> DetectionData {
    DetectionData {
        rule_id: f.rule_id.to_string(),
        title: f.title.to_string(),
        category: "memory".into(),
        mitre_tactic: Some("TA0005 Defense Evasion".into()),
        mitre_technique: Some(f.technique.to_string()),
        confidence: f.confidence,
        subject: format!("pid {pid} ({comm})"),
        detail: format!("PID {pid} ({comm}): {}", f.region),
        evidence: serde_json::json!({ "pid": pid, "comm": comm, "region": f.region }),
    }
}

// ── Collector ────────────────────────────────────────────────────────────────

pub struct MemScanCollector {
    cfg: Arc<RwLock<AgentConfig>>,
    /// Already-reported `pid:rule:region` keys, so a standing condition is
    /// emitted once rather than every interval. Pruned as PIDs disappear.
    seen: HashSet<String>,
}

impl MemScanCollector {
    pub fn new(cfg: Arc<RwLock<AgentConfig>>) -> Self {
        Self {
            cfg,
            seen: HashSet::new(),
        }
    }
}

#[async_trait]
impl Collector for MemScanCollector {
    fn name(&self) -> &'static str {
        "memscan"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let (enabled, interval_secs) = {
            let c = self.cfg.read().expect("config lock");
            (c.memory_scan_enabled, c.memory_scan_interval_secs)
        };
        if !enabled {
            info!("memscan: disabled by config");
            return Ok(());
        }

        let own_pid = std::process::id() as i32;
        let mut ticker = interval(Duration::from_secs(interval_secs.max(30)));
        loop {
            ticker.tick().await;

            // Re-check the toggle so a hot config reload can switch us off.
            if !self
                .cfg
                .read()
                .map(|c| c.memory_scan_enabled)
                .unwrap_or(false)
            {
                continue;
            }

            let mut live: HashSet<i32> = HashSet::new();
            for pid in live_pids() {
                if pid == own_pid {
                    continue;
                }
                live.insert(pid);
                for (severity, det) in self.scan_pid(pid) {
                    let event = AgentEvent::new(
                        agent_id.clone(),
                        hostname.clone(),
                        EventClass::Detection,
                        EventAction::Detected,
                        severity,
                        EventData::Detection(det),
                    );
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
            }
            // Forget findings for processes that have since exited.
            self.seen.retain(|k| {
                k.split_once(':')
                    .and_then(|(p, _)| p.parse::<i32>().ok())
                    .map(|p| live.contains(&p))
                    .unwrap_or(false)
            });
        }
    }
}

impl MemScanCollector {
    /// Scan one pid's maps + environ, returning *new* detections (deduped).
    fn scan_pid(&mut self, pid: i32) -> Vec<(Severity, DetectionData)> {
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let mut out = Vec::new();

        if let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) {
            for region in parse_maps(&maps) {
                if let Some(f) = classify_region(&region) {
                    let key = format!("{pid}:{}:{:#x}", f.rule_id, region.start);
                    if self.seen.insert(key) {
                        out.push((f.severity, finding_to_detection(pid, &comm, &f)));
                    }
                }
            }
        }

        if let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ")) {
            if let Some(val) = ld_preload_from_environ(&environ) {
                if is_suspicious_preload(&val) {
                    let key = format!("{pid}:ld_preload:{val}");
                    if self.seen.insert(key) {
                        out.push((Severity::High, DetectionData {
                            rule_id: "injection.ld_preload_runtime".into(),
                            title: "LD_PRELOAD injection from a non-standard path".into(),
                            category: "memory".into(),
                            mitre_tactic: Some("TA0005 Defense Evasion".into()),
                            mitre_technique: Some("T1574.006".into()),
                            confidence: 80,
                            subject: format!("pid {pid} ({comm})"),
                            detail: format!("PID {pid} ({comm}) runs with LD_PRELOAD={val}"),
                            evidence: serde_json::json!({ "pid": pid, "comm": comm, "ld_preload": val }),
                        }));
                    }
                }
            }
        }

        out
    }
}

/// Enumerate numeric `/proc/<pid>` entries.
fn live_pids() -> Vec<i32> {
    let mut pids = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/proc") {
        for entry in rd.flatten() {
            if let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<i32>().ok())
            {
                pids.push(pid);
            }
        }
    }
    pids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_normal_maps_line() {
        let r =
            parse_maps_line("55a1b2c00000-55a1b2c21000 r-xp 00001000 08:01 1311056 /usr/bin/bash")
                .unwrap();
        assert_eq!(r.start, 0x55a1b2c00000);
        assert_eq!(r.end, 0x55a1b2c21000);
        assert_eq!(r.perms, "r-xp");
        assert_eq!(r.path, "/usr/bin/bash");
        assert!(
            classify_region(&r).is_none(),
            "a file-backed r-x text segment is benign"
        );
    }

    #[test]
    fn flags_rwx_anonymous_memory() {
        let r = parse_maps_line("7f0000000000-7f0000001000 rwxp 00000000 00:00 0 ").unwrap();
        assert!(r.is_anon());
        let f = classify_region(&r).unwrap();
        assert_eq!(f.rule_id, "memory.anon_exec");
        assert_eq!(f.severity, Severity::High);
        assert!(f.confidence >= 85);
    }

    #[test]
    fn flags_anon_exec_without_write_too() {
        let r = parse_maps_line("7f0000000000-7f0000001000 r-xp 00000000 00:00 0 ").unwrap();
        let f = classify_region(&r).unwrap();
        assert_eq!(f.rule_id, "memory.anon_exec");
    }

    #[test]
    fn flags_memfd_execution() {
        let r = parse_maps_line(
            "7f0000000000-7f0000005000 r-xp 00000000 00:00 1234 /memfd:payload (deleted)",
        )
        .unwrap();
        let f = classify_region(&r).unwrap();
        assert_eq!(f.rule_id, "memory.memfd_exec");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn flags_deleted_binary_execution_at_medium() {
        let r =
            parse_maps_line("55a000000000-55a000021000 r-xp 00000000 08:01 99 /tmp/x (deleted)")
                .unwrap();
        let f = classify_region(&r).unwrap();
        assert_eq!(f.rule_id, "memory.deleted_exec");
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn ignores_kernel_pseudo_regions_and_non_exec() {
        let vdso =
            parse_maps_line("7fffabc00000-7fffabc01000 r-xp 00000000 00:00 0 [vdso]").unwrap();
        assert!(
            classify_region(&vdso).is_none(),
            "[vdso] is legitimately executable"
        );
        let heap =
            parse_maps_line("55a000000000-55a000021000 rw-p 00000000 00:00 0 [heap]").unwrap();
        assert!(classify_region(&heap).is_none(), "non-exec heap is fine");
    }

    #[test]
    fn extracts_and_scores_ld_preload() {
        let environ = b"PATH=/usr/bin\0LD_PRELOAD=/tmp/evil.so\0HOME=/root\0";
        let v = ld_preload_from_environ(environ).unwrap();
        assert_eq!(v, "/tmp/evil.so");
        assert!(is_suspicious_preload(&v));

        // A legit preload under a system lib path is not flagged.
        assert!(!is_suspicious_preload(
            "/usr/lib/x86_64-linux-gnu/libfoo.so"
        ));
        // Missing var → None.
        assert!(ld_preload_from_environ(b"PATH=/usr/bin\0").is_none());
    }

    #[test]
    fn parse_maps_skips_garbage_lines() {
        let content = "not-a-line\n7f0000000000-7f0000001000 rwxp 0 00:00 0 \n";
        let regions = parse_maps(content);
        assert_eq!(regions.len(), 1);
    }
}
