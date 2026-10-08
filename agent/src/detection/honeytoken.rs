//! Honeytoken-access detection: turn a raw kernel "token N was opened" signal
//! into a full, high-confidence intrusion event — or suppress it as a known
//! legitimate sweep.
//!
//! Step 2's userspace half. The kernel (see `trapd-agent-ebpf/src/file_open.rs`)
//! does the cheap path-gate and hands us `(pid, uid, gid, comm, token_id,
//! flags)`. Here we:
//!
//!   1. **harden against false positives** (2c) — drop accesses from the agent
//!      itself (camouflage/integrity reads) and *metadata* sweeps by verified
//!      sweepers (mlocate/updatedb, indexers, AV scanners, backup tools).
//!      Content reads and tamper by those tools are never dropped — an
//!      attacker can run `restic backup ~/.ssh` too. Only a provably scheduled
//!      run (no terminal, launched by PID 1 or a job scheduler, judged by
//!      executable path, not comm) is downgraded to info and flagged
//!      `scheduled_sweep`; any other run keeps its full score;
//!   2. **enrich with full process lineage** (2b) — walk `/proc` to attach the
//!      accessor's exe/cmdline and its parent chain up toward PID 1, so the
//!      backend can reconstruct *how* the process that touched the bait came to
//!      exist (the "flight recorder" idea);
//!   3. emit a `HoneytokenAccess` event scored by [`AccessKind`]: a content
//!      read/exec (open/openat2/exec/hardlink/unlink) is an unambiguous
//!      intrusion at **confidence 100/90**, while bare metadata recon
//!      (stat/statx/readlink) is a strong-but-softer lead at **confidence 75**,
//!      so the backend/ML can weight a "someone combed the directory" signal
//!      below a "someone read the secret" one.
//!
//! Pure parsing helpers are unit-tested; the `/proc` walkers are thin wrappers
//! over them.

use std::collections::HashSet;

use uuid::Uuid;

use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, HoneytokenAccessData, ProcessAncestor,
    ProcessLineage, SessionContext, Severity,
};

/// How far up the parent chain we walk. Deep enough to capture
/// `sshd → bash → cat`, bounded so a cycle or bad data cannot loop forever.
const MAX_LINEAGE_DEPTH: usize = 12;

/// Comms that legitimately stat/scan large swathes of the filesystem. Most
/// indexers only `stat()` directory entries (they never open file contents) so
/// they would not even trip the open-based gate — but we allowlist them
/// explicitly anyway, plus AV scanners and backup tools that *do* read content.
///
/// Names are resolved to trusted executable identities when the allowlist is
/// built. An accessor's mutable comm is never sufficient for suppression.
const DEFAULT_ALLOWLIST: &[&str] = &[
    // locate/updatedb family (comm is truncated to 15 chars by the kernel)
    "updatedb",
    "updatedb.mlocat",
    "updatedb.mlocate",
    "updatedb.plocat",
    "updatedb.plocate",
    "mlocate",
    "plocate",
    "locate",
    "mandb",
    // desktop/file indexers
    "tracker-miner-f",
    "tracker-miner-fs",
    "tracker-extract",
    "baloo_file",
    // AV / rootkit scanners
    "clamscan",
    "clamd",
    "freshclam",
    "rkhunter",
    "chkrootkit",
    // backup tooling
    "restic",
    "borg",
    "duplicity",
    "bacula-fd",
];

/// Accessor allowlist: the default set plus any operator-configured comms.
#[derive(Debug, Clone)]
pub struct Allowlist {
    executables: HashSet<(u64, u64)>,
    /// The agent's own PID — its camouflage/integrity reads of its own tokens
    /// must never alarm (self-exclusion, 2c).
    agent_pid: u32,
}

impl Allowlist {
    pub fn new(agent_pid: u32, extra: &[String]) -> Self {
        let mut executables = HashSet::new();
        for name in DEFAULT_ALLOWLIST
            .iter()
            .copied()
            .chain(extra.iter().map(|s| s.trim()))
        {
            if name.is_empty() {
                continue;
            }
            let paths: Vec<std::path::PathBuf> = if std::path::Path::new(name).is_absolute() {
                vec![name.into()]
            } else {
                [
                    "/usr/bin",
                    "/usr/sbin",
                    "/bin",
                    "/sbin",
                    "/usr/local/bin",
                    "/usr/local/sbin",
                ]
                .iter()
                .map(|dir| std::path::Path::new(dir).join(name))
                .collect()
            };
            for path in paths {
                if let Some(id) = trusted_executable(&path) {
                    executables.insert(id);
                }
            }
        }
        Self {
            executables,
            agent_pid,
        }
    }

    /// Who the accessor is, as far as suppression is concerned. The verdict is
    /// based on the agent PID and the accessor's executable *identity*, never
    /// on its mutable comm.
    pub fn classify(&self, pid: i32) -> AccessorClass {
        if pid as u32 == self.agent_pid {
            return AccessorClass::Agent; // the agent reading its own bait
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let known = std::fs::metadata(format!("/proc/{pid}/exe"))
                .ok()
                .is_some_and(|meta| self.executables.contains(&(meta.dev(), meta.ino())));
            if known {
                return AccessorClass::Allowlisted;
            }
        }
        AccessorClass::Other
    }

    /// True when an access from `pid` comes from the agent or a verified sweeper.
    #[cfg(test)]
    pub fn is_allowed(&self, pid: i32, _comm: &str) -> bool {
        self.classify(pid) != AccessorClass::Other
    }
}

/// Suppression verdict for an accessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessorClass {
    /// The agent itself (camouflage / integrity reads): always dropped.
    Agent,
    /// A verified sweeper executable (indexer, AV, backup tool).
    Allowlisted,
    /// Anything else.
    Other,
}

/// Whether the in-kernel honeytoken sensor is actually watching: its access
/// consumer runs *and* tokens are armed (detection enabled in config). Health
/// reports carry this so the console never calls a host protected whose decoy
/// sits on disk unwatched (e.g. the eBPF program failed to load).
static KERNEL_CONSUMER_RUNNING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static KERNEL_ARMING_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_kernel_consumer_running(running: bool) {
    KERNEL_CONSUMER_RUNNING.store(running, std::sync::atomic::Ordering::Relaxed);
}

pub fn set_kernel_arming_enabled(enabled: bool) {
    KERNEL_ARMING_ENABLED.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// `kernel` while the sensor watches the tokens, `none` otherwise. Reported in
/// `prevention.honeytoken_health` as `details.detection`.
pub fn kernel_detection_mode() -> &'static str {
    use std::sync::atomic::Ordering::Relaxed;
    if KERNEL_CONSUMER_RUNNING.load(Relaxed) && KERNEL_ARMING_ENABLED.load(Relaxed) {
        "kernel"
    } else {
        "none"
    }
}

/// Confidence of a content read by an allowlisted tool outside an interactive
/// session: kept as evidence, scored far below a real intrusion signal.
const SCHEDULED_SWEEPER_CONFIDENCE: u8 = 20;

/// Wrappers a scheduler commonly puts between itself and the job.
const JOB_WRAPPERS: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "run-parts",
    "nice",
    "ionice",
    "flock",
    "timeout",
    "env",
    "chronic",
];

/// Executables that start scheduled jobs.
const SCHEDULERS: &[&str] = &[
    "/usr/sbin/cron",
    "/usr/sbin/crond",
    "/usr/sbin/anacron",
    "/usr/sbin/atd",
    "/usr/lib/systemd/systemd",
    "/lib/systemd/systemd",
    "/sbin/init",
];

/// Did a scheduler start this process? Walks up past job wrappers (judged by
/// executable basename) to the first real ancestor, which must be PID 1 or a
/// scheduler executable. Executable paths come from `/proc/<pid>/exe` and
/// cannot be renamed like `comm`; an unknown lineage is not scheduled.
fn launched_by_scheduler(ancestors: &[ProcessAncestor]) -> bool {
    for ancestor in ancestors {
        let Some(exe) = ancestor.exe.as_deref() else {
            return false;
        };
        let exe = exe.trim_end_matches(" (deleted)");
        if SCHEDULERS.contains(&exe) {
            return true;
        }
        let base = exe.rsplit('/').next().unwrap_or(exe);
        if !JOB_WRAPPERS.contains(&base) {
            return false;
        }
    }
    false
}

/// Authenticate both the executable and its canonical parent chain. Root
/// ownership alone is insufficient when an unprivileged writer can replace a
/// directory entry. Capture inode identity rather than trusting its basename.
fn trusted_executable(path: &std::path::Path) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let canonical = path.canonicalize().ok()?;
        for component in canonical.ancestors() {
            let meta = std::fs::symlink_metadata(component).ok()?;
            if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return None;
            }
        }
        let meta = std::fs::metadata(canonical).ok()?;
        if !meta.is_file() || meta.mode() & 0o111 == 0 {
            return None;
        }
        Some((meta.dev(), meta.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// The raw kernel-reported access, before enrichment.
pub struct AccessHit<'a> {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
    pub comm: &'a str,
    pub open_flags: u64,
    pub token_id: &'a str,
    pub path: &'a str,
    pub kind: &'a str,
    /// Which syscall family tripped the kernel gate (open vs exec vs recon vs
    /// tamper). Drives the event's severity, confidence and MITRE mapping.
    pub access_kind: AccessKind,
}

/// How a honeytoken was touched, mirroring the kernel `ACCESS_*` constants in
/// `trapd-agent-ebpf/src/file_open.rs`. Content access/execution is a full
/// intrusion (confidence 100); metadata recon and tamper are strong-but-softer
/// leads scored below that so the backend/ML can weight them accordingly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    /// openat(2) — content read/write.
    Openat,
    /// open(2), the legacy no-dirfd variant — content read/write.
    Open,
    /// openat2(2) — content read/write.
    Openat2,
    /// execve/execveat — the bait was executed.
    Exec,
    /// newfstatat — metadata recon (`stat`/`ls -l`).
    Stat,
    /// statx — metadata recon.
    Statx,
    /// readlinkat — metadata recon.
    Readlink,
    /// linkat — a hardlink was created to the token (evasion attempt).
    Link,
    /// unlinkat — the token was deleted (tamper).
    Unlink,
    /// renameat2 — the token was renamed away (tamper).
    Rename,
    /// mmap — the token's contents were read through a memory mapping.
    Mmap,
    /// getdents64 — a token's parent directory was listed (directory recon).
    Getdents,
    /// A successful open with write/truncate intent.
    Modify,
    /// Unrecognised kind from a newer/older kernel build — treated as full access.
    Unknown,
}

impl AccessKind {
    /// Metadata-only access: the token's contents were not read or changed.
    /// Sweepers do this to every file they pass, so it is the only kind an
    /// allowlisted tool may make silently.
    pub fn is_metadata_only(self) -> bool {
        matches!(
            self,
            Self::Stat | Self::Statx | Self::Readlink | Self::Getdents
        )
    }

    /// Decode the kernel-reported discriminator.
    pub fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Openat,
            1 => Self::Open,
            2 => Self::Openat2,
            3 => Self::Exec,
            4 => Self::Stat,
            5 => Self::Statx,
            6 => Self::Readlink,
            7 => Self::Link,
            8 => Self::Unlink,
            9 => Self::Rename,
            10 => Self::Mmap,
            11 => Self::Getdents,
            _ => Self::Unknown,
        }
    }

    /// Scoring for this access: `(label, severity, confidence, mitre_tactic,
    /// mitre_technique)`. The label is a stable string the backend can route on.
    pub fn describe(self) -> (&'static str, Severity, u8, &'static str, &'static str) {
        match self {
            // ── Content access / execution — unambiguous intrusion ───────────
            Self::Openat => (
                "open",
                Severity::Critical,
                100,
                "TA0006 Credential Access",
                "T1552.001",
            ),
            Self::Open => (
                "open_legacy",
                Severity::Critical,
                100,
                "TA0006 Credential Access",
                "T1552.001",
            ),
            Self::Openat2 => (
                "openat2",
                Severity::Critical,
                100,
                "TA0006 Credential Access",
                "T1552.001",
            ),
            Self::Unknown => (
                "unknown",
                Severity::Critical,
                100,
                "TA0006 Credential Access",
                "T1552.001",
            ),
            Self::Mmap => (
                "mmap",
                Severity::Critical,
                100,
                "TA0006 Credential Access",
                "T1552.001",
            ),
            Self::Exec => (
                "exec",
                Severity::Critical,
                100,
                "TA0002 Execution",
                "T1204.002",
            ),
            // ── Evasion / tamper — deliberate, high-confidence ───────────────
            Self::Link => (
                "hardlink",
                Severity::Critical,
                90,
                "TA0005 Defense Evasion",
                "T1564.001",
            ),
            Self::Unlink => (
                "unlink",
                Severity::Critical,
                90,
                "TA0040 Impact",
                "T1070.004",
            ),
            Self::Modify => (
                "modify",
                Severity::Critical,
                95,
                "TA0040 Impact",
                "T1565.001",
            ),
            Self::Rename => ("rename", Severity::High, 85, "TA0040 Impact", "T1070.004"),
            // ── Metadata recon — strong lead, scored below content access ────
            Self::Stat => ("stat", Severity::High, 75, "TA0007 Discovery", "T1083"),
            Self::Statx => ("statx", Severity::High, 75, "TA0007 Discovery", "T1083"),
            Self::Readlink => ("readlink", Severity::High, 75, "TA0007 Discovery", "T1083"),
            // Directory listing is inherently noisier (a user's own `ls` trips
            // it), so it is scored as a soft lead — telemetry for the backend/ML
            // rather than a high-severity alert.
            Self::Getdents => (
                "getdents",
                Severity::Medium,
                50,
                "TA0007 Discovery",
                "T1083",
            ),
        }
    }
}

/// Derive the stable `u64` the eBPF map uses to identify a token, from its UUID.
/// The first 8 bytes of a v4 UUID are random, so collisions across the handful
/// of tokens on a host are astronomically unlikely.
pub fn token_id_u64(id: &Uuid) -> u64 {
    let b = id.as_bytes();
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Build the enriched detection event, or `None` when the access is the agent's
/// own or a verified sweeper's metadata pass.
///
/// `proc` abstracts `/proc` so lineage enrichment is unit-testable; production
/// passes [`RealProc`].
pub fn build_access_event(
    agent_id: &str,
    hostname: &str,
    hit: &AccessHit<'_>,
    allowlist: &Allowlist,
    proc: &dyn ProcInfo,
) -> Option<AgentEvent> {
    let normalized = normalized_hit(hit);
    let hit = &normalized;
    let class = allowlist.classify(hit.pid);
    match class {
        AccessorClass::Agent => return None,
        AccessorClass::Allowlisted if hit.access_kind.is_metadata_only() => return None,
        _ => {}
    }
    build_event(
        agent_id,
        hostname,
        hit,
        class == AccessorClass::Allowlisted,
        proc,
    )
}

fn normalized_hit<'a>(hit: &AccessHit<'a>) -> AccessHit<'a> {
    let kind = if matches!(
        hit.access_kind,
        AccessKind::Openat | AccessKind::Open | AccessKind::Openat2 | AccessKind::Mmap
    ) {
        if hit.open_flags & 0x20_0000 != 0 {
            AccessKind::Stat
        } else if hit.open_flags & (3 | 0x200) != 0 {
            AccessKind::Modify
        } else {
            hit.access_kind
        }
    } else {
        hit.access_kind
    };
    AccessHit {
        access_kind: kind,
        ..*hit
    }
}

fn build_event(
    agent_id: &str,
    hostname: &str,
    hit: &AccessHit<'_>,
    allowlisted: bool,
    proc: &dyn ProcInfo,
) -> Option<AgentEvent> {
    let normalized = normalized_hit(hit);
    let hit = &normalized;
    let accessor = ProcessLineage {
        pid: hit.pid,
        uid: hit.uid,
        gid: hit.gid,
        username: proc.username(hit.uid),
        comm: hit.comm.to_string(),
        exe: proc.exe(hit.pid),
        cmdline: proc.cmdline(hit.pid),
        ancestors: build_ancestry(hit.pid, proc),
    };

    let (label, severity, confidence, tactic, technique) = hit.access_kind.describe();

    let mut data = HoneytokenAccessData {
        sensor: Some(crate::schema::HoneytokenSensor::LinuxEbpf),
        assessment: None,
        assessment_reasons: Vec::new(),
        mode: None,
        token_id: hit.token_id.to_string(),
        path: hit.path.to_string(),
        kind: hit.kind.to_string(),
        access_kind: label.to_string(),
        open_flags: hit.open_flags,
        confidence,
        mitre_tactic: tactic.to_string(),
        mitre_technique: technique.to_string(),
        accessor,
        // Session/forensic context (issue #32, point 5): who/where the accessor
        // ran. The remote IP is correlated later by the engine's flight recorder.
        session: proc.session(hit.pid),
        allowlisted_accessor: allowlisted,
        scheduled_sweep: false,
    };

    // A backup/AV tool reading the bait on its schedule is expected. The same
    // tool started any other way (terminal, `ssh host cmd`, a reverse shell)
    // is how an attacker would exfiltrate with it, so it keeps its full score.
    let non_interactive = data
        .session
        .as_ref()
        .is_some_and(|s| s.tty.is_none() && s.remote_addr.is_none());
    data.scheduled_sweep = allowlisted
        && matches!(
            hit.access_kind,
            AccessKind::Openat | AccessKind::Open | AccessKind::Openat2 | AccessKind::Mmap
        )
        && non_interactive
        && launched_by_scheduler(&data.accessor.ancestors);
    data.assessment = Some(if data.scheduled_sweep {
        crate::schema::HoneytokenAssessment::ScheduledSweep
    } else if hit.access_kind.is_metadata_only() {
        crate::schema::HoneytokenAssessment::Metadata
    } else {
        crate::schema::HoneytokenAssessment::ContentAccess
    });
    let severity = if data.scheduled_sweep {
        data.confidence = SCHEDULED_SWEEPER_CONFIDENCE;
        Severity::Info
    } else {
        severity
    };

    Some(AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Detection,
        EventAction::HoneytokenAccess,
        severity,
        EventData::HoneytokenAccess(Box::new(data)),
    ))
}

/// Walk the parent chain from `pid` up towards PID 1.
fn build_ancestry(pid: i32, proc: &dyn ProcInfo) -> Vec<ProcessAncestor> {
    let mut out = Vec::new();
    let mut current = pid;
    for _ in 0..MAX_LINEAGE_DEPTH {
        let Some(ppid) = proc.ppid(current) else {
            break;
        };
        if ppid <= 0 || ppid == current {
            break;
        }
        out.push(ProcessAncestor {
            pid: ppid,
            comm: proc.comm(ppid).unwrap_or_else(|| "?".to_string()),
            exe: proc.exe(ppid),
            cmdline: proc.cmdline(ppid),
        });
        if ppid == 1 {
            break;
        }
        current = ppid;
    }
    out
}

// ── /proc abstraction ─────────────────────────────────────────────────────────

/// Process-info source. Abstracted so the lineage walk is testable without a
/// live `/proc`.
pub trait ProcInfo {
    fn ppid(&self, pid: i32) -> Option<i32>;
    fn comm(&self, pid: i32) -> Option<String>;
    fn exe(&self, pid: i32) -> Option<String>;
    fn cmdline(&self, pid: i32) -> Option<String>;
    fn username(&self, uid: u32) -> String;
    /// Session / execution context of the accessor (issue #32, point 5).
    /// Best-effort; `None` when nothing could be resolved.
    fn session(&self, pid: i32) -> Option<SessionContext>;
}

/// Reads the live `/proc` and `/etc/passwd`.
pub struct RealProc;

impl ProcInfo for RealProc {
    fn ppid(&self, pid: i32) -> Option<i32> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        parse_stat_ppid(&stat)
    }
    fn comm(&self, pid: i32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim_end().to_string())
            .filter(|s| !s.is_empty())
    }
    fn exe(&self, pid: i32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
    fn cmdline(&self, pid: i32) -> Option<String> {
        let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        if raw.is_empty() {
            return None;
        }
        // argv is NUL-separated; render as a space-joined command line.
        let s: String = raw
            .split(|&b| b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p))
            .collect::<Vec<_>>()
            .join(" ");
        (!s.is_empty()).then_some(s)
    }
    fn username(&self, uid: u32) -> String {
        username_for_uid(uid)
    }
    fn session(&self, pid: i32) -> Option<SessionContext> {
        crate::forensics::capture_session_opt(pid)
    }
}

/// Extract the parent PID (field 4) from a `/proc/<pid>/stat` line. The comm
/// field (field 2) is wrapped in parens and may itself contain spaces and
/// parens, so we split *after the last* `)` — the canonical robust parse.
pub fn parse_stat_ppid(stat: &str) -> Option<i32> {
    let rparen = stat.rfind(')')?;
    let rest = stat.get(rparen + 1..)?;
    let mut fields = rest.split_whitespace();
    let _state = fields.next()?; // field 3
    fields.next()?.parse::<i32>().ok() // field 4: ppid
}

fn username_for_uid(uid: u32) -> String {
    std::fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .find_map(|line| {
            let mut f = line.splitn(7, ':');
            let name = f.next()?;
            let _ = f.next();
            let u = f.next()?.parse::<u32>().ok()?;
            (u == uid).then(|| name.to_string())
        })
        .unwrap_or_else(|| format!("uid:{uid}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn pid_one_without_verified_scheduler_image_is_not_a_schedule() {
        assert!(!launched_by_scheduler(&[ProcessAncestor {
            pid: 1,
            comm: "systemd".into(),
            exe: Some("/tmp/systemd".into()),
            cmdline: None
        }]));
    }

    #[test]
    fn parses_ppid_with_simple_comm() {
        let stat = "4242 (cat) R 4099 4242 4099 34816 4242 4194304 ...";
        assert_eq!(parse_stat_ppid(stat), Some(4099));
    }

    #[test]
    fn parses_ppid_with_nasty_comm() {
        // comm containing spaces and parens must not break the parse.
        let stat = "10 (weird )( name) S 7 10 7 0 -1 ...";
        assert_eq!(parse_stat_ppid(stat), Some(7));
    }

    #[test]
    fn allowlist_excludes_agent_and_indexers() {
        let al = Allowlist::new(999, &["custombackup".to_string()]);
        assert!(al.is_allowed(999, "anything"), "agent pid is self-excluded");
        assert!(
            !al.is_allowed(5, "trapd-agent"),
            "spoofed agent comm must not exclude"
        );
        assert!(
            !al.is_allowed(5, "updatedb"),
            "unverified indexer must not exclude"
        );
        assert!(
            !al.is_allowed(5, "custombackup"),
            "unverified configured extra must not exclude"
        );
        assert!(
            !al.is_allowed(5, "cat"),
            "an interactive read is NOT excluded"
        );
        assert!(!al.is_allowed(5, "python3"), "a script is NOT excluded");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_executable_identity_still_suppresses_scanner() {
        use std::os::unix::fs::MetadataExt;
        let pid = std::process::id();
        let meta = std::fs::metadata(format!("/proc/{pid}/exe")).unwrap();
        let mut al = Allowlist::new(pid + 1, &[]);
        // Pin the installed scanner identity as the constructor does. The
        // currently running test executable stands in for that scanner.
        al.executables.insert((meta.dev(), meta.ino()));
        assert!(al.is_allowed(pid as i32, "scanner"));
        al.executables.clear();
        assert!(!al.is_allowed(pid as i32, "scanner"));
    }

    #[test]
    fn token_id_u64_is_stable() {
        let id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        // first 8 bytes little-endian
        assert_eq!(token_id_u64(&id), 0x7766_5544_3322_1100);
    }

    /// In-memory `/proc` for lineage tests.
    struct FakeProc {
        ppid: HashMap<i32, i32>,
        comm: HashMap<i32, String>,
        exe: HashMap<i32, String>,
        tty: Option<String>,
        session_resolved: bool,
    }
    impl ProcInfo for FakeProc {
        fn ppid(&self, pid: i32) -> Option<i32> {
            self.ppid.get(&pid).copied()
        }
        fn comm(&self, pid: i32) -> Option<String> {
            self.comm.get(&pid).cloned()
        }
        fn exe(&self, pid: i32) -> Option<String> {
            self.exe.get(&pid).cloned()
        }
        fn cmdline(&self, _pid: i32) -> Option<String> {
            None
        }
        fn username(&self, _uid: u32) -> String {
            "tester".into()
        }
        fn session(&self, _pid: i32) -> Option<SessionContext> {
            // Keep lineage tests independent of the host's /proc.
            (self.session_resolved || self.tty.is_some()).then(|| SessionContext {
                tty: self.tty.clone(),
                ..SessionContext::default()
            })
        }
    }

    fn fake() -> FakeProc {
        // 100 (cat) <- 50 (bash) <- 10 (sshd) <- 1 (init)
        let mut ppid = HashMap::new();
        ppid.insert(100, 50);
        ppid.insert(50, 10);
        ppid.insert(10, 1);
        let mut comm = HashMap::new();
        comm.insert(50, "bash".to_string());
        comm.insert(10, "sshd".to_string());
        comm.insert(1, "systemd".to_string());
        FakeProc {
            ppid,
            comm,
            exe: HashMap::new(),
            tty: None,
            session_resolved: false,
        }
    }

    #[test]
    fn builds_full_ancestry_chain() {
        let chain = build_ancestry(100, &fake());
        let pids: Vec<i32> = chain.iter().map(|a| a.pid).collect();
        assert_eq!(pids, vec![50, 10, 1]);
        assert_eq!(chain[0].comm, "bash");
        assert_eq!(chain[2].comm, "systemd");
    }

    #[test]
    fn allowlisted_access_yields_no_event() {
        let al = Allowlist::new(999, &[]);
        let hit = AccessHit {
            pid: 999, // the agent itself
            uid: 0,
            gid: 0,
            comm: "trapd-agent",
            open_flags: 0,
            token_id: "tok",
            path: "/root/.aws/credentials",
            kind: "aws_credentials",
            access_kind: AccessKind::Openat,
        };
        assert!(build_access_event("a", "h", &hit, &al, &RealProc).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn open_path_is_metadata_and_write_flags_are_tamper() {
        for kind in [
            AccessKind::Openat,
            AccessKind::Open,
            AccessKind::Openat2,
            AccessKind::Mmap,
        ] {
            let mut hit = sweeper_hit(100, kind);
            hit.open_flags = 0x20_0000; // O_PATH: never a readable descriptor.
            let ev = build_event("a", "h", &hit, false, &fake()).unwrap();
            let EventData::HoneytokenAccess(d) = ev.data else {
                panic!("payload")
            };
            assert_eq!(d.access_kind, "stat");
            for flags in [1, 2, 0x200, 1 | 0x200] {
                hit.open_flags = flags;
                let ev = build_event(
                    "a",
                    "h",
                    &hit,
                    true,
                    &lineage(100, &[(1, "systemd", "/usr/lib/systemd/systemd")]),
                )
                .unwrap();
                let EventData::HoneytokenAccess(d) = ev.data else {
                    panic!("payload")
                };
                assert_eq!(d.access_kind, "modify");
                assert!(!d.scheduled_sweep);
                assert!(d.confidence >= 90);
            }
        }
    }

    #[test]
    fn intruder_access_yields_critical_event() {
        let al = Allowlist::new(999, &[]);
        let hit = AccessHit {
            pid: 100,
            uid: 1000,
            gid: 1000,
            comm: "cat",
            open_flags: 0, // read-only — must still fire
            token_id: "tok-123",
            path: "/home/alice/.aws/credentials",
            kind: "aws_credentials",
            access_kind: AccessKind::Openat,
        };
        let ev = build_access_event("a", "h", &hit, &al, &fake()).expect("event");
        assert!(matches!(ev.severity, Severity::Critical));
        assert!(matches!(ev.action, EventAction::HoneytokenAccess));
        match ev.data {
            EventData::HoneytokenAccess(d) => {
                assert_eq!(d.confidence, 100);
                assert_eq!(d.access_kind, "open");
                assert_eq!(d.token_id, "tok-123");
                assert_eq!(d.accessor.comm, "cat");
                // ancestry resolved from the fake /proc
                assert_eq!(
                    d.accessor.ancestors.first().map(|a| a.comm.as_str()),
                    Some("bash")
                );
            }
            _ => panic!("wrong payload"),
        }
    }

    #[test]
    fn access_kind_decodes_from_kernel_discriminator() {
        assert_eq!(AccessKind::from_u32(0), AccessKind::Openat);
        assert_eq!(AccessKind::from_u32(2), AccessKind::Openat2);
        assert_eq!(AccessKind::from_u32(3), AccessKind::Exec);
        assert_eq!(AccessKind::from_u32(6), AccessKind::Readlink);
        assert_eq!(AccessKind::from_u32(9), AccessKind::Rename);
        assert_eq!(AccessKind::from_u32(10), AccessKind::Mmap);
        assert_eq!(AccessKind::from_u32(11), AccessKind::Getdents);
        // Out-of-range values fail safe to a full-access interpretation.
        assert_eq!(AccessKind::from_u32(42), AccessKind::Unknown);
    }

    #[test]
    fn mmap_is_full_read_getdents_is_soft_recon() {
        let al = Allowlist::new(999, &[]);
        let mk = |k| AccessHit {
            pid: 100,
            uid: 1000,
            gid: 1000,
            comm: "x",
            open_flags: 0,
            token_id: "t",
            path: "/home/a/.aws/credentials",
            kind: "aws_credentials",
            access_kind: k,
        };
        // mmap of a token reads its contents — same weight as an open.
        let mm = build_access_event("a", "h", &mk(AccessKind::Mmap), &al, &fake()).unwrap();
        assert!(matches!(mm.severity, Severity::Critical));
        match mm.data {
            EventData::HoneytokenAccess(d) => {
                assert_eq!(d.access_kind, "mmap");
                assert_eq!(d.confidence, 100);
            }
            _ => panic!("wrong payload"),
        }
        // getdents (directory listing) is a soft, noisy lead.
        let gd = build_access_event("a", "h", &mk(AccessKind::Getdents), &al, &fake()).unwrap();
        assert!(matches!(gd.severity, Severity::Medium));
        match gd.data {
            EventData::HoneytokenAccess(d) => {
                assert_eq!(d.access_kind, "getdents");
                assert_eq!(d.confidence, 50);
            }
            _ => panic!("wrong payload"),
        }
    }

    #[test]
    fn recon_access_is_high_confidence_not_critical() {
        let al = Allowlist::new(999, &[]);
        let hit = AccessHit {
            pid: 100,
            uid: 1000,
            gid: 1000,
            comm: "find",
            open_flags: 0,
            token_id: "tok-9",
            path: "/home/alice/.ssh/id_rsa",
            kind: "ssh_private_key",
            access_kind: AccessKind::Stat, // bare metadata recon
        };
        let ev = build_access_event("a", "h", &hit, &al, &fake()).expect("event");
        assert!(
            matches!(ev.severity, Severity::High),
            "recon is High, not Critical"
        );
        match ev.data {
            EventData::HoneytokenAccess(d) => {
                assert_eq!(d.confidence, 75, "recon scores below content access");
                assert_eq!(d.access_kind, "stat");
                assert_eq!(d.mitre_technique, "T1083");
            }
            _ => panic!("wrong payload"),
        }
    }

    #[test]
    fn exec_and_tamper_are_distinct_kinds() {
        let al = Allowlist::new(999, &[]);
        for (kind, want_label, want_conf) in [
            (AccessKind::Exec, "exec", 100u8),
            (AccessKind::Link, "hardlink", 90),
            (AccessKind::Unlink, "unlink", 90),
            (AccessKind::Rename, "rename", 85),
        ] {
            let hit = AccessHit {
                pid: 100,
                uid: 1000,
                gid: 1000,
                comm: "sh",
                open_flags: 0,
                token_id: "t",
                path: "/home/alice/.aws/credentials",
                kind: "aws_credentials",
                access_kind: kind,
            };
            let ev = build_access_event("a", "h", &hit, &al, &fake()).expect("event");
            match ev.data {
                EventData::HoneytokenAccess(d) => {
                    assert_eq!(d.access_kind, want_label);
                    assert_eq!(d.confidence, want_conf);
                }
                _ => panic!("wrong payload"),
            }
        }
    }

    /// An allowlist that verifies the running test executable as a sweeper,
    /// standing in for an installed backup tool.
    #[cfg(target_os = "linux")]
    fn sweeper_allowlist() -> (Allowlist, i32) {
        use std::os::unix::fs::MetadataExt;
        let pid = std::process::id();
        let meta = std::fs::metadata(format!("/proc/{pid}/exe")).unwrap();
        let mut al = Allowlist::new(pid + 1, &[]);
        al.executables.insert((meta.dev(), meta.ino()));
        (al, pid as i32)
    }

    #[cfg(target_os = "linux")]
    fn sweeper_hit(pid: i32, access_kind: AccessKind) -> AccessHit<'static> {
        AccessHit {
            pid,
            uid: 0,
            gid: 0,
            comm: "restic",
            open_flags: 0,
            token_id: "tok-bk",
            path: "/home/alice/.ssh/id_ed25519",
            kind: "ssh_private_key",
            access_kind,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sweeper_metadata_pass_is_suppressed() {
        let (al, pid) = sweeper_allowlist();
        for kind in [
            AccessKind::Stat,
            AccessKind::Statx,
            AccessKind::Readlink,
            AccessKind::Getdents,
        ] {
            assert!(
                build_access_event("a", "h", &sweeper_hit(pid, kind), &al, &fake()).is_none(),
                "{kind:?}"
            );
        }
    }

    /// A `/proc` where `pid` was started through `chain` (nearest parent
    /// first): `(pid, comm, exe)` per ancestor.
    fn lineage(pid: i32, chain: &[(i32, &str, &str)]) -> FakeProc {
        let mut proc = fake();
        proc.session_resolved = true;
        let mut child = pid;
        for (ancestor, comm, exe) in chain {
            proc.ppid.insert(child, *ancestor);
            proc.comm.insert(*ancestor, comm.to_string());
            proc.exe.insert(*ancestor, exe.to_string());
            child = *ancestor;
        }
        proc
    }

    #[cfg(target_os = "linux")]
    fn verdict(proc: &FakeProc, pid: i32, al: &Allowlist) -> (Severity, HoneytokenAccessData) {
        let ev = build_access_event("a", "h", &sweeper_hit(pid, AccessKind::Openat), al, proc)
            .expect("a content read is never suppressed");
        match ev.data {
            EventData::HoneytokenAccess(d) => (ev.severity, *d),
            _ => panic!("wrong payload"),
        }
    }

    /// Regression: the allowlist used to drop *every* access by a sweeper, so
    /// `restic backup ~/.ssh` exfiltrated a decoy without a trace.
    #[cfg(target_os = "linux")]
    #[test]
    fn scheduled_sweeper_content_read_is_reported_as_info() {
        let (al, pid) = sweeper_allowlist();
        for proc in [
            // cron → sh -c → restic
            lineage(
                pid,
                &[
                    (70, "sh", "/usr/bin/dash"),
                    (60, "cron", "/usr/sbin/cron"),
                    (1, "systemd", "/usr/lib/systemd/systemd"),
                ],
            ),
            // systemd timer → restic
            lineage(pid, &[(1, "systemd", "/usr/lib/systemd/systemd")]),
            // systemd --user → nice → borg
            lineage(
                pid,
                &[
                    (90, "nice", "/usr/bin/nice"),
                    (80, "systemd", "/usr/lib/systemd/systemd"),
                ],
            ),
        ] {
            let (severity, d) = verdict(&proc, pid, &al);
            assert!(matches!(severity, Severity::Info));
            assert!(d.allowlisted_accessor && d.scheduled_sweep);
            assert_eq!(d.confidence, SCHEDULED_SWEEPER_CONFIDENCE);
            assert_eq!(d.access_kind, "open");
        }
    }

    /// The same verified tool started by anything but a scheduler is how an
    /// attacker would exfiltrate with it: full score, never `scheduled_sweep`.
    #[cfg(target_os = "linux")]
    #[test]
    fn sweeper_started_any_other_way_keeps_full_score() {
        let (al, pid) = sweeper_allowlist();
        let mut with_tty = lineage(pid, &[(60, "cron", "/usr/sbin/cron")]);
        with_tty.tty = Some("pts/3".into());
        for (case, proc) in [
            // `ssh host 'restic backup ~/.ssh'`: no TTY, but sshd lineage.
            (
                "ssh without tty",
                lineage(
                    pid,
                    &[
                        (50, "bash", "/usr/bin/bash"),
                        (10, "sshd", "/usr/sbin/sshd"),
                    ],
                ),
            ),
            // Reverse shell that renamed itself: comm says cron, exe does not.
            (
                "renamed reverse shell",
                lineage(pid, &[(80, "cron", "/usr/bin/python3")]),
            ),
            (
                "web shell",
                lineage(
                    pid,
                    &[
                        (70, "sh", "/usr/bin/dash"),
                        (60, "php-fpm8.2", "/usr/sbin/php-fpm8.2"),
                    ],
                ),
            ),
            ("unknown lineage", fake()),
            ("terminal", with_tty),
        ] {
            let (severity, d) = verdict(&proc, pid, &al);
            assert!(matches!(severity, Severity::Critical), "{case}");
            assert!(d.allowlisted_accessor && !d.scheduled_sweep, "{case}");
            assert_eq!(d.confidence, 100, "{case}");
        }
    }

    #[test]
    fn ordinary_access_is_not_flagged_as_allowlisted() {
        let al = Allowlist::new(999, &[]);
        let hit = AccessHit {
            pid: 100,
            uid: 1000,
            gid: 1000,
            comm: "restic", // a renamed binary gains nothing
            open_flags: 0,
            token_id: "t",
            path: "/home/alice/.ssh/id_ed25519",
            kind: "ssh_private_key",
            access_kind: AccessKind::Openat,
        };
        let ev = build_access_event("a", "h", &hit, &al, &fake()).unwrap();
        assert!(matches!(ev.severity, Severity::Critical));
        match ev.data {
            EventData::HoneytokenAccess(d) => assert!(!d.allowlisted_accessor),
            _ => panic!("wrong payload"),
        }
        // And the flag stays off the wire when false.
        let wire = serde_json::to_value(build_access_event("a", "h", &hit, &al, &fake()).unwrap())
            .unwrap();
        assert!(wire.to_string().find("allowlisted_accessor").is_none());
        assert!(wire.to_string().find("scheduled_sweep").is_none());
    }
}
