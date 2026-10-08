//! Automated response to *local detections* — the policy that turns the agent's
//! detection stream into active EDR action (kill / quarantine / isolate).
//!
//! The agent already raises high-signal local detections (IOC hash hits, reverse
//! shells, IOA attack-chains, ransomware indicators, `setuid(0)` privilege
//! escalation, credential-store access). Until now only honeytoken hits and
//! IoC-policy `ProcessExec` rules were *acted on*; every other detection was
//! emitted and shipped but never enforced. This module closes that gap.
//!
//! It is split into a **pure decision layer** (this file) and the
//! side-effecting executor (on the prevention [`super::engine::Engine`]). The
//! risky part — "should we really kill this process?" — is a pure function with
//! no I/O, so it is exhaustively unit-tested without touching a single PID.
//!
//! Safety posture: auto-response is **opt-in** (`auto_response_enabled`,
//! default off) and gated on severity *and* confidence thresholds plus an
//! allowlist, so a single false positive cannot silently kill a legitimate
//! process. Actions degrade gracefully when no concrete target is known.

use crate::schema::Severity;

/// What the engine should do about a detection, escalating in blast radius.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoAction {
    /// Take no active action (the detection is already emitted upstream).
    None,
    /// Emit a prevention alert only — no process / file / network action.
    Alert,
    /// SIGKILL the offending process.
    Kill,
    /// Kill the process **and** quarantine the offending file.
    Quarantine,
    /// Kill + quarantine + full host network isolation.
    Isolate,
}

impl AutoAction {
    /// Parse the configured action. Unknown values fall back to the safe
    /// `Alert` (never silently escalate to a destructive action on a typo).
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => AutoAction::None,
            "alert" => AutoAction::Alert,
            "kill" => AutoAction::Kill,
            "quarantine" => AutoAction::Quarantine,
            "isolate" | "isolate_network" => AutoAction::Isolate,
            _ => AutoAction::Alert,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AutoAction::None => "none",
            AutoAction::Alert => "alert",
            AutoAction::Kill => "kill",
            AutoAction::Quarantine => "quarantine",
            AutoAction::Isolate => "isolate",
        }
    }
}

/// Total order on severity for threshold comparisons.
fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Parse a configured minimum severity. Unknown values fall back to the
/// conservative `Critical` (act only on the strongest signals).
pub fn parse_severity(s: &str) -> Severity {
    match s.trim().to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        _ => Severity::Critical,
    }
}

/// The concrete things a response can act on, resolved from a detection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Targets {
    /// PID of the offending process, when known and safe to act on (> 1).
    pub pid: Option<i32>,
    /// Generation observed with the PID; never resolve this at action time.
    pub process_start_time: Option<u64>,
    /// Absolute path of the offending file, when known (for quarantine).
    pub file_path: Option<String>,
}

/// Paths a response must never quarantine: the OS itself. Moving
/// `/usr/bin/bash` aside because a reverse shell ran *in* it would take the
/// host down with the attacker.
const NEVER_QUARANTINE: &[&str] = &[
    "/usr/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/lib32/",
    "/lib64/",
    "/libx32/",
    "/etc/",
    "/boot/",
    "/opt/trapd",
    "/var/lib/dpkg/",
    "/var/lib/rpm/",
    "/snap/",
];

/// Windows OS and agent locations, matched on the part after the drive letter
/// so a relocated or secondary drive is protected the same way, case-insensitively.
const NEVER_QUARANTINE_WINDOWS: &[&str] = &[
    "windows\\",
    "program files\\trapd",
    "programdata\\trapd\\",
    "programdata\\microsoft\\",
    "program files\\windowsapps\\",
    "program files\\common files\\microsoft shared\\",
];

/// `X:\` or `X:/` — an absolute, local-drive Windows path. UNC and device paths
/// (`\\server\share`, `\\?\`) are deliberately not accepted: a response must
/// not move files on a remote share or through a device namespace.
fn is_windows_drive_path(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

/// Normalize ordinary local Windows paths without consulting the filesystem.
/// Reject aliases (ADS, DOS devices, trailing dots/spaces) whose interpretation
/// would differ from the directory names checked by this decision layer.
fn normalized_windows_path(p: &str) -> Option<String> {
    if !is_windows_drive_path(p) || p.contains('\0') {
        return None;
    }
    let normalized = p.replace('/', "\\").to_ascii_lowercase();
    let mut parts = Vec::new();
    for part in normalized[3..].split('\\') {
        match part {
            "" | "." => continue,
            ".." => {
                parts.pop()?;
            }
            _ => {
                if part.contains(':') || part.ends_with(['.', ' ']) {
                    return None;
                }
                let stem = part.split('.').next()?;
                if matches!(stem, "con" | "prn" | "aux" | "nul")
                    || (stem.len() == 4
                        && (stem.starts_with("com") || stem.starts_with("lpt"))
                        && matches!(stem.as_bytes()[3], b'1'..=b'9'))
                {
                    return None;
                }
                parts.push(part);
            }
        }
    }
    Some(format!("{}\\{}", &normalized[..2], parts.join("\\")))
}

fn within_windows_directory(path: &str, directory: &str) -> bool {
    let directory = directory.trim_end_matches('\\');
    path == directory
        || path
            .strip_prefix(directory)
            .is_some_and(|rest| rest.starts_with('\\'))
}

/// Whether `p` is inside the OS (or the agent itself) on Windows. `system_root`
/// is the host's `%SystemRoot%`, protected even when it is not `X:\Windows`.
fn is_windows_protected(p: &str, system_root: Option<&str>) -> bool {
    let Some(norm) = normalized_windows_path(p) else {
        return false;
    };
    if let Some(root) = system_root.and_then(normalized_windows_path) {
        if within_windows_directory(&norm, &root) {
            return true;
        }
    }
    let rest = &norm[3..];
    NEVER_QUARANTINE_WINDOWS.iter().any(|d| {
        let base = d.trim_end_matches('\\');
        rest == base || rest.starts_with(d)
    })
}

/// Pure candidate screening; the executor resolves filesystem aliases again
/// immediately before an automatic quarantine.
fn safe_quarantine_candidate(p: &str) -> bool {
    if is_windows_drive_path(p) {
        normalized_windows_path(p).is_some()
            && !is_windows_protected(p, std::env::var("SystemRoot").ok().as_deref())
    } else {
        !cfg!(windows)
            && p.starts_with('/')
            && !p.starts_with("//")
            && !p.contains('\0')
            && !NEVER_QUARANTINE.iter().any(|d| p.starts_with(d))
    }
}

/// Resolve a local automatic-quarantine target on Windows and check the final
/// path, catching junctions, symlinks and short-name aliases into protected
/// directories. A canonical UNC/device result is never a local response target.
pub fn validated_quarantine_path(p: &str) -> Option<String> {
    if !safe_quarantine_candidate(p) {
        return None;
    }
    #[cfg(windows)]
    {
        let resolved = std::fs::canonicalize(p).ok()?;
        let resolved = resolved
            .to_str()?
            .strip_prefix(r"\\?\")
            .unwrap_or(resolved.to_str()?);
        if !safe_quarantine_candidate(resolved) {
            return None;
        }
        // Drive-letter paths can still name mapped remote shares.
        let drive: Vec<u16> = resolved[..3].encode_utf16().chain(Some(0)).collect();
        // SAFETY: a NUL-terminated local drive root is provided.
        use windows_sys::Win32::System::WindowsProgramming::{
            DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOVABLE,
        };
        if !matches!(
            unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(drive.as_ptr()) },
            DRIVE_FIXED | DRIVE_RAMDISK | DRIVE_REMOVABLE
        ) {
            return None;
        }
        let normalized = normalized_windows_path(resolved)?;
        let protected_dirs = [
            std::path::PathBuf::from(std::env::var("SystemRoot").ok()?),
            crate::paths::state_dir().to_path_buf(),
            crate::paths::config_dir().to_path_buf(),
            crate::paths::log_dir().to_path_buf(),
            std::env::current_exe().ok()?.parent()?.to_path_buf(),
        ];
        for directory in protected_dirs {
            let directory = std::fs::canonicalize(&directory).unwrap_or(directory);
            let directory = directory.to_str()?;
            let directory = directory.strip_prefix(r"\\?\").unwrap_or(directory);
            let directory = normalized_windows_path(directory)?;
            if within_windows_directory(&normalized, &directory) {
                return None;
            }
        }
        Some(resolved.to_string())
    }
    #[cfg(not(windows))]
    {
        Some(p.to_string())
    }
}

/// Resolve the response targets from a detection's rule, `subject` and `evidence`.
///
/// The acting PID is, in priority order: an explicit `evidence.pid`, an
/// `accessor_pid`, or the head of the IOA-injected `process_lineage` (which the
/// detection engine attaches to every process-correlated finding). PID 0/1 are
/// never targets.
///
/// The file to quarantine must be named *as a dropped artifact*:
/// `evidence.dropped_file`, or the subject of an IOC hash / temp-exec finding.
/// A rule's `subject` is usually the acting executable (`/usr/bin/bash`), and
/// `evidence.path` the file it touched (`/etc/shadow`) — neither is malware —
/// so they are never quarantine targets, and no path under the OS
/// directories ever is.
///
/// `rule_id` decides whether the subject itself is the dropped payload.
pub fn targets_for_rule(rule_id: &str, subject: &str, evidence: &serde_json::Value) -> Targets {
    let explicit_pid = evidence.get("pid").or_else(|| evidence.get("accessor_pid"));
    let lineage_head = evidence
        .get("process_lineage")
        .and_then(|l| l.as_array())
        .and_then(|a| a.first());
    let (pid, process_start_time) = if let Some(pid) = explicit_pid {
        (
            pid.as_i64(),
            match evidence.get("process_start_time") {
                Some(start) => start.as_u64(),
                None => lineage_head
                    .filter(|head| {
                        pid.as_i64().is_some()
                            && head.get("pid").and_then(|v| v.as_i64()) == pid.as_i64()
                    })
                    .and_then(|head| head.get("process_start_time"))
                    .and_then(|start| start.as_u64()),
            },
        )
    } else {
        (
            lineage_head
                .and_then(|h| h.get("pid"))
                .and_then(|v| v.as_i64()),
            lineage_head
                .and_then(|h| h.get("process_start_time"))
                .and_then(|v| v.as_u64()),
        )
    };
    let pid = pid
        .and_then(|p| i32::try_from(p).ok())
        .filter(|p| *p > if cfg!(windows) { 4 } else { 1 });
    let process_start_time = process_start_time.filter(|start| *start > 0);

    // Rules whose subject *is* the malicious file.
    const SUBJECT_IS_PAYLOAD: &[&str] = &[
        "ioc.process_hash",
        "defense.tmp_exec_chmod",
        "defense.kmod_from_tmp",
        "impact.cryptominer",
    ];
    let file_path = evidence
        .get("dropped_file")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            (SUBJECT_IS_PAYLOAD.contains(&rule_id) || rule_id.starts_with("yara."))
                .then(|| subject.to_string())
        })
        .filter(|p| safe_quarantine_candidate(p));

    Targets {
        pid,
        process_start_time,
        file_path,
    }
}

/// The outcome of the pure decision: which action to take and why (audited).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: AutoAction,
    pub reason: String,
}

impl Decision {
    fn skip(reason: impl Into<String>) -> Self {
        Decision {
            action: AutoAction::None,
            reason: reason.into(),
        }
    }
}

/// Decide what to do about a detection — a pure function (no I/O).
///
/// Returns [`AutoAction::None`] unless auto-response is enabled, the event meets
/// the severity *and* confidence thresholds, and the rule is not allowlisted.
/// The configured action is then **clamped** to what the known targets allow:
/// `Kill`/`Quarantine` without a target PID degrade to `Alert`, and
/// `Quarantine` without a file path degrades to `Kill`.
#[allow(clippy::too_many_arguments)]
pub fn decide(
    enabled: bool,
    configured: AutoAction,
    min_severity: Severity,
    min_confidence: u8,
    allowlist: &[String],
    event_severity: Severity,
    rule_id: &str,
    category: &str,
    confidence: u8,
    targets: &Targets,
) -> Decision {
    if !enabled {
        return Decision::skip("auto-response disabled");
    }
    if configured == AutoAction::None {
        return Decision::skip("configured action is none");
    }
    if severity_rank(event_severity) < severity_rank(min_severity) {
        return Decision::skip(format!(
            "severity {:?} below threshold {:?}",
            event_severity, min_severity
        ));
    }
    if confidence < min_confidence {
        return Decision::skip(format!(
            "confidence {} below threshold {}",
            confidence, min_confidence
        ));
    }
    if allowlist
        .iter()
        .any(|a| a.eq_ignore_ascii_case(rule_id) || a.eq_ignore_ascii_case(category))
    {
        return Decision::skip("rule allowlisted");
    }

    let has_pid = targets.pid.is_some() && targets.process_start_time.is_some();
    let has_path = targets.file_path.is_some();

    // Clamp the configured action to what the available targets support.
    let action = match configured {
        AutoAction::None | AutoAction::Alert => AutoAction::Alert,
        // Network isolation needs no per-process target; keep it regardless.
        AutoAction::Isolate => AutoAction::Isolate,
        AutoAction::Quarantine => {
            if has_path {
                AutoAction::Quarantine
            } else if has_pid {
                AutoAction::Kill
            } else {
                AutoAction::Alert
            }
        }
        AutoAction::Kill => {
            if has_pid {
                AutoAction::Kill
            } else {
                AutoAction::Alert
            }
        }
    };

    let reason = if action != configured {
        format!("{} (clamped from {})", action.as_str(), configured.as_str())
    } else {
        format!("{} per policy", action.as_str())
    };
    Decision { action, reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn t(pid: Option<i32>, path: Option<&str>) -> Targets {
        Targets {
            pid,
            process_start_time: pid.map(|_| 100),
            file_path: path.map(String::from),
        }
    }

    #[test]
    fn windows_traversal_into_os_directory_is_protected() {
        for p in [
            r"C:\Users\Public\..\..\Windows\System32\notepad.exe",
            r"C:\Users\Public\..\..\ProgramData\TRAPD\payload.exe",
            r"C:/Users/Public/../../Windows/System32/notepad.exe",
        ] {
            assert!(is_windows_protected(p, Some(r"C:\Windows")), "{p}");
            assert!(targets_for_rule("ioc.process_hash", p, &json!({}))
                .file_path
                .is_none());
        }
    }

    #[cfg(windows)]
    #[test]
    fn resolved_quarantine_target_rejects_a_symlink_into_windows() {
        let directory =
            std::env::temp_dir().join(format!("trapd-auto-path-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let malicious = directory.join("payload.exe");
        std::fs::write(&malicious, b"payload").unwrap();
        assert!(validated_quarantine_path(malicious.to_str().unwrap()).is_some());
        let alias = directory.join("alias.exe");
        let system = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap())
            .join("System32\\notepad.exe");
        std::os::windows::fs::symlink_file(system, &alias)
            .expect("native Windows tests require elevation");
        assert!(validated_quarantine_path(alias.to_str().unwrap()).is_none());
        std::fs::remove_file(&alias).unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn remote_or_ambiguous_quarantine_paths_are_rejected() {
        for p in [
            "//server/share/payload.exe",
            r"\\server\share\payload.exe",
            r"\\?\C:\Users\Public\payload.exe",
            r"C:\Users\Public\payload.exe:stream",
            r"C:\Users\Public\payload.exe.\child",
            r"C:\Users\Public\NUL.exe",
        ] {
            assert!(
                targets_for_rule("ioc.process_hash", p, &json!({}))
                    .file_path
                    .is_none(),
                "{p}"
            );
        }
    }

    #[test]
    fn unknown_process_generation_does_not_allow_automatic_kill() {
        let targets = Targets {
            pid: Some(99),
            ..Default::default()
        };
        let decision = decide(
            true,
            AutoAction::Kill,
            Severity::High,
            80,
            &[],
            Severity::Critical,
            "memory.inject",
            "memory",
            95,
            &targets,
        );
        assert_eq!(decision.action, AutoAction::Alert);
    }

    #[test]
    fn observed_generation_stays_paired_with_its_pid() {
        let explicit = targets_for_rule(
            "memory.inject",
            "",
            &json!({
                "pid": 99, "process_start_time": 123,
                "process_lineage": [{ "pid": 88, "process_start_time": 456 }]
            }),
        );
        assert_eq!(
            (explicit.pid, explicit.process_start_time),
            (Some(99), Some(123))
        );
        let unknown = targets_for_rule(
            "memory.inject",
            "",
            &json!({
                "pid": 99, "process_lineage": [{ "pid": 88, "process_start_time": 456 }]
            }),
        );
        assert_eq!((unknown.pid, unknown.process_start_time), (Some(99), None));
        let lineage = targets_for_rule(
            "ioa.chain",
            "",
            &json!({
                "process_lineage": [{ "pid": 88, "process_start_time": 456 }]
            }),
        );
        assert_eq!(
            (lineage.pid, lineage.process_start_time),
            (Some(88), Some(456))
        );
    }

    #[test]
    fn matching_lineage_identity_allows_configured_automatic_kill() {
        for field in ["pid", "accessor_pid"] {
            let targets = targets_for_rule(
                "privesc.setuid_root",
                "bash",
                &json!({field: 99, "process_lineage": [{"pid": 99, "process_start_time": 456}]}),
            );
            assert_eq!(
                (targets.pid, targets.process_start_time),
                (Some(99), Some(456))
            );
            let decision = decide(
                true,
                AutoAction::Kill,
                Severity::High,
                80,
                &[],
                Severity::Critical,
                "privesc.setuid_root",
                "privilege_escalation",
                95,
                &targets,
            );
            assert_eq!(decision.action, AutoAction::Kill);
        }
    }

    #[test]
    fn explicit_generation_wins_over_matching_lineage() {
        let targets = targets_for_rule(
            "memory.inject",
            "",
            &json!({"pid": 99, "process_start_time": 123,
                "process_lineage": [{"pid": 99, "process_start_time": 456}]}),
        );
        assert_eq!(
            (targets.pid, targets.process_start_time),
            (Some(99), Some(123))
        );
    }

    #[test]
    fn invalid_explicit_generation_cannot_be_replaced_by_lineage() {
        for start in [json!(0), json!(-1), json!(null), json!("123")] {
            let targets = targets_for_rule(
                "memory.inject",
                "",
                &json!({
                    "pid": 99, "process_start_time": start,
                    "process_lineage": [{"pid": 99, "process_start_time": 456}]
                }),
            );
            assert_eq!(targets.process_start_time, None);
        }
    }

    #[test]
    fn oversized_pid_cannot_wrap_into_a_valid_target() {
        let targets = targets_for_rule(
            "memory.inject",
            "",
            &json!({
                "pid": 4_294_967_395_i64, "process_start_time": 123,
            }),
        );
        assert_eq!(targets.pid, None);
    }

    #[test]
    fn parse_action_is_safe_on_garbage() {
        assert_eq!(AutoAction::parse("kill"), AutoAction::Kill);
        assert_eq!(AutoAction::parse("ISOLATE"), AutoAction::Isolate);
        assert_eq!(AutoAction::parse("quarantine"), AutoAction::Quarantine);
        assert_eq!(AutoAction::parse("none"), AutoAction::None);
        assert_eq!(AutoAction::parse("wat"), AutoAction::Alert);
    }

    #[test]
    fn disabled_never_acts() {
        let d = decide(
            false,
            AutoAction::Kill,
            Severity::Critical,
            90,
            &[],
            Severity::Critical,
            "ioc.process_hash",
            "ioc",
            95,
            &t(Some(42), None),
        );
        assert_eq!(d.action, AutoAction::None);
    }

    #[test]
    fn below_severity_threshold_skips() {
        let d = decide(
            true,
            AutoAction::Kill,
            Severity::Critical,
            90,
            &[],
            Severity::High,
            "x",
            "y",
            99,
            &t(Some(42), None),
        );
        assert_eq!(d.action, AutoAction::None);
    }

    #[test]
    fn below_confidence_threshold_skips() {
        let d = decide(
            true,
            AutoAction::Kill,
            Severity::High,
            90,
            &[],
            Severity::Critical,
            "x",
            "y",
            80,
            &t(Some(42), None),
        );
        assert_eq!(d.action, AutoAction::None);
    }

    #[test]
    fn allowlist_by_rule_id_or_category_skips() {
        let by_rule = decide(
            true,
            AutoAction::Kill,
            Severity::High,
            0,
            &["lolbin.shell".into()],
            Severity::Critical,
            "lolbin.shell",
            "lolbin",
            99,
            &t(Some(42), None),
        );
        assert_eq!(by_rule.action, AutoAction::None);

        let by_cat = decide(
            true,
            AutoAction::Kill,
            Severity::High,
            0,
            &["IOC".into()],
            Severity::Critical,
            "ioc.process_hash",
            "ioc",
            99,
            &t(Some(42), None),
        );
        assert_eq!(by_cat.action, AutoAction::None);
    }

    #[test]
    fn kill_requires_pid_else_alerts() {
        let with_pid = decide(
            true,
            AutoAction::Kill,
            Severity::Critical,
            90,
            &[],
            Severity::Critical,
            "x",
            "y",
            95,
            &t(Some(42), None),
        );
        assert_eq!(with_pid.action, AutoAction::Kill);

        let no_pid = decide(
            true,
            AutoAction::Kill,
            Severity::Critical,
            90,
            &[],
            Severity::Critical,
            "x",
            "y",
            95,
            &t(None, None),
        );
        assert_eq!(no_pid.action, AutoAction::Alert);
    }

    #[test]
    fn quarantine_without_path_degrades_to_kill() {
        let d = decide(
            true,
            AutoAction::Quarantine,
            Severity::Critical,
            90,
            &[],
            Severity::Critical,
            "ransomware.high_entropy",
            "ransomware",
            95,
            &t(Some(42), None),
        );
        assert_eq!(d.action, AutoAction::Kill);
    }

    #[test]
    fn quarantine_with_path_stays_quarantine() {
        let d = decide(
            true,
            AutoAction::Quarantine,
            Severity::Critical,
            90,
            &[],
            Severity::Critical,
            "ransomware.high_entropy",
            "ransomware",
            95,
            &t(Some(42), Some("/tmp/evil")),
        );
        assert_eq!(d.action, AutoAction::Quarantine);
    }

    #[test]
    fn isolate_keeps_even_without_target() {
        let d = decide(
            true,
            AutoAction::Isolate,
            Severity::Critical,
            90,
            &[],
            Severity::Critical,
            "ioc.network_ip",
            "ioc",
            95,
            &t(None, None),
        );
        assert_eq!(d.action, AutoAction::Isolate);
    }

    #[test]
    fn targets_prefers_explicit_pid_then_lineage() {
        let ev = json!({ "pid": 4242, "process_lineage": [{ "pid": 9 }] });
        assert_eq!(targets_for_rule("x", "/usr/bin/curl", &ev).pid, Some(4242));

        let ev2 = json!({ "process_lineage": [{ "pid": 777, "comm": "bash" }] });
        let tg = targets_for_rule("x", "bash", &ev2);
        assert_eq!(tg.pid, Some(777));
        assert_eq!(tg.file_path, None);
    }

    #[test]
    fn targets_never_takes_pid_0_or_1() {
        let ev = json!({ "pid": 1 });
        assert_eq!(targets_for_rule("x", "init", &ev).pid, None);
    }

    #[test]
    fn never_quarantines_the_acting_binary_or_touched_files() {
        // A reverse shell runs *in* bash: bash is not the malware.
        let revshell = targets_for_rule(
            "revshell.dev_tcp_redirect",
            "/usr/bin/bash",
            &json!({ "pid": 77 }),
        );
        assert_eq!(revshell.file_path, None);
        assert_eq!(revshell.pid, Some(77));
        // The file a credential rule touched is the victim, not the payload.
        let shadow = targets_for_rule(
            "creds.sensitive_file_access",
            "/etc/shadow",
            &json!({ "path": "/etc/shadow" }),
        );
        assert_eq!(shadow.file_path, None);
        // Even an explicitly dropped file under the OS directories is refused.
        let os = targets_for_rule("x", "x", &json!({ "dropped_file": "/usr/bin/ls" }));
        assert_eq!(os.file_path, None);
    }

    #[test]
    fn payload_rules_and_dropped_files_are_targets() {
        let payload = if cfg!(windows) {
            r"C:\Users\Public\payload.exe"
        } else {
            "/tmp/payload"
        };
        let dropped_path = if cfg!(windows) {
            r"C:\Users\bob\AppData\Local\Temp\payload.exe"
        } else {
            "/home/u/.cache/x"
        };
        let ioc = targets_for_rule("ioc.process_hash", payload, &json!({}));
        assert_eq!(ioc.file_path.as_deref(), Some(payload));
        let dropped = targets_for_rule("x", "curl", &json!({ "dropped_file": dropped_path }));
        assert_eq!(dropped.file_path.as_deref(), Some(dropped_path));
        let none = targets_for_rule("x", "curl", &json!({}));
        assert_eq!(none.file_path, None);
    }

    #[test]
    fn windows_drive_paths_are_quarantine_targets_but_the_os_is_not() {
        let ev = json!({ "dropped_file": "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe" });
        let t = targets_for_rule("x", "x", &ev);
        assert_eq!(
            t.file_path.as_deref(),
            Some("C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe")
        );
        // Windows paths are only meaningful (and only matched case-insensitively
        // against the OS tree) on drive-letter form.
        assert!(is_windows_protected("C:\\Windows\\System32\\cmd.exe", None));
        assert!(is_windows_protected("d:/WINDOWS/system32/cmd.exe", None));
        assert!(is_windows_protected(
            "C:\\Program Files\\TRAPD\\trapd-agent.exe",
            None
        ));
        assert!(is_windows_protected(
            "C:\\ProgramData\\TRAPD\\state\\credentials.json",
            None
        ));
        assert!(is_windows_protected("E:\\WINNT\\x.exe", Some("E:\\WINNT")));
        assert!(!is_windows_protected(
            "C:\\Users\\bob\\Windows\\x.exe",
            None
        ));
        assert!(!is_windows_protected("C:\\Windows.old\\x.exe", None));
    }

    #[test]
    fn unc_and_device_paths_are_never_quarantine_targets() {
        for p in [
            "\\\\server\\share\\x.exe",
            "\\\\?\\C:\\x.exe",
            "relative\\x.exe",
            "C:x.exe",
        ] {
            let ev = json!({ "dropped_file": p });
            assert!(targets_for_rule("x", "x", &ev).file_path.is_none(), "{p}");
        }
    }
}
