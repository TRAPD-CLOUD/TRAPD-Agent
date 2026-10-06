//! Grading of a Windows decoy access from a 4663 object-access audit event.
//!
//! An SACL on each decoy plus the "Audit File System" subcategory makes Windows
//! log Security event 4663 whenever a process reads one — with the process
//! image, PID, the subject account and the access mask. That is the attribution
//! the `ReadDirectoryChangesW` / last-access fallback never had.
//!
//! The grading is the false-positive gate, and it is the whole point: a decoy
//! placed to fit a user will occasionally be brushed by that user or by a
//! backup/indexer, and treating every touch as critical would be exactly the
//! noise this project exists to remove. So:
//!
//!   * a metadata-only access (attributes/listing, no `ReadData`) → signal;
//!   * `ReadData` by a **verified** sweeper (AV, backup) → info/signal;
//!   * `ReadData` by the decoy's **owner in an interactive session** → high,
//!     flagged "possibly the legitimate user", raised when it comes from a
//!     remote session or outside the user's learned active hours;
//!   * `ReadData` by any other process or account → critical.
//!
//! Pure over its inputs, so every rule above is unit-tested.

use serde::Serialize;

use crate::schema::{HoneytokenAccessData, ProcessLineage};

/// Windows access-mask bits (winnt.h) relevant to a file read.
pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_READ_EA: u32 = 0x0008;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_EXECUTE: u32 = 0x0020;
pub const DELETE: u32 = 0x0001_0000;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004;

/// A decoy the agent planted, with what it needs to grade an access.
#[derive(Debug, Clone)]
pub struct DecoyInfo {
    pub token_id: String,
    pub path: String,
    pub kind: String,
    /// SID of the user the decoy belongs to (its placement owner).
    pub owner_sid: String,
}

/// The accessor as the 4663 event reports it.
#[derive(Debug, Clone, Default)]
pub struct Accessor {
    pub process_name: String,
    pub pid: i32,
    pub subject_user: String,
    pub subject_sid: String,
    pub access_mask: u32,
    /// Logon type of the subject's session, when it can be correlated
    /// (2 interactive, 10 RemoteInteractive/RDP, 3 network, 5 service, …).
    pub logon_type: Option<u32>,
    /// Whether the signature of `process_name` was verified (Authenticode).
    pub signed_trusted: bool,
}

/// Verified-sweeper image names (lowercase). A name match alone is never
/// enough — the caller sets `signed_trusted` only after a signature check, and
/// both are required before a content read is downgraded.
pub const WINDOWS_SWEEPERS: &[&str] = &[
    "msmpeng.exe", // Microsoft Defender
    "mpcmdrun.exe",
    "windefend",
    "searchindexer.exe", // Windows Search
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "veeam.endpoint.service.exe",
    "veeamagent.exe",
    "veeam.backup.manager.exe",
    "acronis",
    "cbengine.exe", // Windows Server Backup
    "wbengine.exe",
    "sense.exe", // Defender for Endpoint
    "mssense.exe",
    "ccmexec.exe", // SCCM inventory
    "antimalwareserviceexecutable.exe",
];

fn basename(name: &str) -> String {
    name.rsplit(['\\', '/'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase()
}

fn is_sweeper(a: &Accessor) -> bool {
    let b = basename(&a.process_name);
    a.signed_trusted && WINDOWS_SWEEPERS.iter().any(|s| b == *s || b.starts_with(s))
}

/// Grade of a decoy access, most benign first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Grade {
    /// Metadata only, or a verified sweeper: evidence, not an alert.
    Signal,
    /// The owner in an interactive session read it: likely legitimate.
    OwnerInteractive,
    /// A foreign process/account read the content: intrusion.
    Foreign,
}

/// Why the grade landed where it did (human-readable, no local paths).
#[derive(Debug, Clone)]
pub struct Verdict {
    pub grade: Grade,
    pub confidence: u8,
    pub access_kind: &'static str,
    pub reasons: Vec<String>,
}

fn classify_access(mask: u32) -> (&'static str, bool) {
    // Returns (access_kind, is_content_read).
    if mask & (FILE_WRITE_DATA | FILE_APPEND_DATA) != 0 {
        ("modify", false)
    } else if mask & DELETE != 0 {
        ("unlink", false)
    } else if mask & (FILE_READ_DATA | FILE_EXECUTE) != 0 {
        ("open", true)
    } else if mask & (FILE_READ_ATTRIBUTES | FILE_READ_EA) != 0 {
        ("stat", false)
    } else {
        ("open", true) // unknown bits: treat conservatively as a read
    }
}

/// Grade one access. `active_hour` is the caller's "is the current hour unusual
/// for this user" verdict from activity learning (`Some(true)` = unusual),
/// `None` when unknown.
pub fn grade(decoy: &DecoyInfo, a: &Accessor, unusual_hour: Option<bool>) -> Verdict {
    let (access_kind, content_read) = classify_access(a.access_mask);
    let mut reasons = Vec::new();

    // Writes, renames and deletes are tamper, always a strong signal
    // regardless of who: nobody edits a decoy by accident.
    if !content_read && matches!(access_kind, "modify" | "unlink") {
        return Verdict {
            grade: Grade::Foreign,
            confidence: 90,
            access_kind,
            reasons: vec![format!("{access_kind} of a decoy")],
        };
    }
    if !content_read {
        reasons.push("metadata access only (listing or attributes)".into());
        return Verdict {
            grade: Grade::Signal,
            confidence: 40,
            access_kind,
            reasons,
        };
    }

    if is_sweeper(a) {
        reasons.push(format!(
            "verified sweeper {} read the content",
            basename(&a.process_name)
        ));
        return Verdict {
            grade: Grade::Signal,
            confidence: 30,
            access_kind,
            reasons,
        };
    }

    let owner = !a.subject_sid.is_empty() && a.subject_sid.eq_ignore_ascii_case(&decoy.owner_sid);
    let interactive = matches!(a.logon_type, Some(2) | Some(10) | Some(11) | None);
    if owner && interactive {
        let mut confidence = 70;
        reasons.push(
            "read by the decoy's owner in an interactive session (possibly legitimate)".into(),
        );
        if a.logon_type == Some(10) {
            confidence = 85;
            reasons.push("owner session is remote (RDP)".into());
        }
        if unusual_hour == Some(true) {
            confidence = confidence.max(85);
            reasons.push("access outside the user's usual active hours".into());
        }
        return Verdict {
            grade: Grade::OwnerInteractive,
            confidence,
            access_kind,
            reasons,
        };
    }

    // Foreign process or account, or a non-interactive logon reading content.
    if owner {
        reasons.push("decoy owner's account but a non-interactive logon read the content".into());
    } else if a.subject_sid.is_empty() {
        reasons.push("content read; accessor account not resolved".into());
    } else {
        reasons.push(format!(
            "content read by a different account ({})",
            a.subject_user
        ));
    }
    Verdict {
        grade: Grade::Foreign,
        confidence: 100,
        access_kind,
        reasons,
    }
}

/// Build the honeytoken detection payload for an access the grader did not
/// drop. The engine's gate and severity policy then decide alert vs. signal
/// (an `OwnerInteractive`/`Signal` grade rides as a non-alerting signal; a
/// `Foreign` grade alerts). Returns `None` when the access is pure metadata by
/// a verified sweeper (nothing worth recording).
pub fn to_access_data(decoy: &DecoyInfo, a: &Accessor, verdict: &Verdict) -> HoneytokenAccessData {
    let (tactic, technique) = match verdict.access_kind {
        "modify" | "unlink" => ("TA0040 Impact", "T1565.001"),
        _ => ("TA0006 Credential Access", "T1552.001"),
    };
    HoneytokenAccessData {
        token_id: decoy.token_id.clone(),
        path: decoy.path.clone(),
        kind: decoy.kind.clone(),
        access_kind: verdict.access_kind.to_string(),
        open_flags: a.access_mask as u64,
        confidence: verdict.confidence,
        mitre_tactic: tactic.to_string(),
        mitre_technique: technique.to_string(),
        accessor: ProcessLineage {
            pid: a.pid,
            uid: 0,
            gid: 0,
            username: a.subject_user.clone(),
            comm: basename(&a.process_name),
            exe: (!a.process_name.is_empty()).then(|| a.process_name.clone()),
            cmdline: None,
            ancestors: Vec::new(),
        },
        session: None,
        allowlisted_accessor: is_sweeper(a),
        scheduled_sweep: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoy() -> DecoyInfo {
        DecoyInfo {
            token_id: "winfs:abc".into(),
            path: "C:\\Users\\anna\\Documents\\IT\\Zugangsdaten.txt".into(),
            kind: "password_note".into(),
            owner_sid: "S-1-5-21-1-2-3-1001".into(),
        }
    }
    fn accessor(proc: &str, sid: &str, mask: u32) -> Accessor {
        Accessor {
            process_name: proc.into(),
            pid: 4242,
            subject_user: "CORP\\x".into(),
            subject_sid: sid.into(),
            access_mask: mask,
            logon_type: Some(2),
            signed_trusted: false,
        }
    }

    #[test]
    fn foreign_content_read_is_critical() {
        let v = grade(
            &decoy(),
            &accessor(
                "C:\\Tools\\mimikatz.exe",
                "S-1-5-21-9-9-9-500",
                FILE_READ_DATA,
            ),
            None,
        );
        assert_eq!(v.grade, Grade::Foreign);
        assert_eq!(v.confidence, 100);
        assert_eq!(v.access_kind, "open");
    }

    #[test]
    fn owner_interactive_read_is_high_not_critical() {
        let v = grade(
            &decoy(),
            &accessor(
                "C:\\Windows\\System32\\notepad.exe",
                "S-1-5-21-1-2-3-1001",
                FILE_READ_DATA,
            ),
            None,
        );
        assert_eq!(v.grade, Grade::OwnerInteractive);
        assert_eq!(v.confidence, 70);
    }

    #[test]
    fn owner_read_over_rdp_or_off_hours_scores_higher() {
        let mut a = accessor("notepad.exe", "S-1-5-21-1-2-3-1001", FILE_READ_DATA);
        a.logon_type = Some(10);
        assert_eq!(grade(&decoy(), &a, None).confidence, 85);
        a.logon_type = Some(2);
        assert_eq!(grade(&decoy(), &a, Some(true)).confidence, 85);
    }

    #[test]
    fn metadata_access_is_a_signal() {
        let v = grade(
            &decoy(),
            &accessor("explorer.exe", "S-1-5-21-1-2-3-1001", FILE_READ_ATTRIBUTES),
            None,
        );
        assert_eq!(v.grade, Grade::Signal);
        assert_eq!(v.access_kind, "stat");
    }

    #[test]
    fn verified_sweeper_content_read_is_a_signal_name_alone_is_not() {
        let mut a = accessor(
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe",
            "S-1-5-18",
            FILE_READ_DATA,
        );
        a.signed_trusted = true;
        assert_eq!(grade(&decoy(), &a, None).grade, Grade::Signal);
        // Same name, unsigned → not trusted → graded as a foreign read.
        a.signed_trusted = false;
        assert_eq!(grade(&decoy(), &a, None).grade, Grade::Foreign);
    }

    #[test]
    fn tamper_is_always_strong() {
        assert_eq!(
            grade(
                &decoy(),
                &accessor("x.exe", "S-1-5-21-1-2-3-1001", FILE_WRITE_DATA),
                None
            )
            .access_kind,
            "modify"
        );
        let del = grade(
            &decoy(),
            &accessor("x.exe", "S-1-5-21-1-2-3-1001", DELETE),
            None,
        );
        assert_eq!(del.grade, Grade::Foreign);
        assert_eq!(del.access_kind, "unlink");
    }

    #[test]
    fn owner_account_non_interactive_is_foreign() {
        let mut a = accessor("svc.exe", "S-1-5-21-1-2-3-1001", FILE_READ_DATA);
        a.logon_type = Some(3); // network logon
        assert_eq!(grade(&decoy(), &a, None).grade, Grade::Foreign);
    }

    #[test]
    fn payload_carries_process_and_mask() {
        let a = accessor("C:\\Tools\\x.exe", "S-1-5-21-9-9-9-500", FILE_READ_DATA);
        let v = grade(&decoy(), &a, None);
        let d = to_access_data(&decoy(), &a, &v);
        assert_eq!(d.accessor.comm, "x.exe");
        assert_eq!(d.accessor.exe.as_deref(), Some("C:\\Tools\\x.exe"));
        assert_eq!(d.open_flags, FILE_READ_DATA as u64);
        assert_eq!(d.confidence, 100);
        assert!(!d.allowlisted_accessor);
    }
}

// ── 4663 field parsing + shared decoy registry ──────────────────────────────

use std::collections::HashMap;
use std::sync::Mutex;

/// Build an [`Accessor`] from a 4663 event's `Data` fields and a logon-type
/// looked up from the subject's logon id (4624 correlation; `None` if unknown).
pub fn accessor_from_4663(
    field: impl Fn(&str) -> String,
    logon_type: Option<u32>,
    signed_trusted: bool,
) -> Accessor {
    let mask = field("AccessMask");
    let mask = mask.trim().trim_start_matches("0x");
    Accessor {
        process_name: field("ProcessName"),
        pid: i64::from_str_radix(field("ProcessId").trim().trim_start_matches("0x"), 16)
            .ok()
            .or_else(|| field("ProcessId").trim().parse().ok())
            .unwrap_or(0) as i32,
        subject_user: {
            let d = field("SubjectDomainName");
            let u = field("SubjectUserName");
            if d.is_empty() {
                u
            } else {
                format!("{d}\\{u}")
            }
        },
        subject_sid: field("SubjectUserSid"),
        access_mask: u32::from_str_radix(mask, 16).unwrap_or(0),
        logon_type,
        signed_trusted,
    }
}

#[derive(Default)]
struct Registry {
    by_path: HashMap<String, DecoyInfo>,
}

fn registry() -> &'static Mutex<Registry> {
    static R: std::sync::OnceLock<Mutex<Registry>> = std::sync::OnceLock::new();
    R.get_or_init(|| Mutex::new(Registry::default()))
}

/// Register (or refresh) a planted decoy so the 4663 path can attribute reads.
/// Paths are compared case-insensitively (Windows file system).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn register_decoy(info: DecoyInfo) {
    if let Ok(mut r) = registry().lock() {
        r.by_path.insert(info.path.to_ascii_lowercase(), info);
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn forget_decoy(path: &str) {
    if let Ok(mut r) = registry().lock() {
        r.by_path.remove(&path.to_ascii_lowercase());
    }
}

/// The decoy at `path`, if one is registered there.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn lookup_decoy(path: &str) -> Option<DecoyInfo> {
    registry()
        .lock()
        .ok()
        .and_then(|r| r.by_path.get(&path.to_ascii_lowercase()).cloned())
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn parses_4663_fields_and_hex_mask() {
        let f = |k: &str| match k {
            "ProcessName" => "C:\\Tools\\x.exe".to_string(),
            "ProcessId" => "0x10a4".to_string(),
            "SubjectUserName" => "anna".to_string(),
            "SubjectDomainName" => "CORP".to_string(),
            "SubjectUserSid" => "S-1-5-21-1-2-3-1001".to_string(),
            "AccessMask" => "0x1".to_string(),
            _ => String::new(),
        };
        let a = accessor_from_4663(f, Some(2), false);
        assert_eq!(a.pid, 0x10a4);
        assert_eq!(a.subject_user, "CORP\\anna");
        assert_eq!(a.access_mask, FILE_READ_DATA);
    }

    #[test]
    fn registry_round_trip_is_case_insensitive() {
        register_decoy(DecoyInfo {
            token_id: "t".into(),
            path: "C:\\Users\\Anna\\Documents\\IT\\Zugang.txt".into(),
            kind: "password_note".into(),
            owner_sid: "S-1-5-21-1-2-3-1001".into(),
        });
        assert!(lookup_decoy("c:\\users\\anna\\documents\\it\\zugang.txt").is_some());
        forget_decoy("C:\\Users\\Anna\\Documents\\IT\\Zugang.txt");
        assert!(lookup_decoy("c:\\users\\anna\\documents\\it\\zugang.txt").is_none());
    }
}
