//! Honeytoken-access detection: turn a raw kernel "token N was opened" signal
//! into a full, high-confidence intrusion event — or suppress it as a known
//! legitimate sweep.
//!
//! Step 2's userspace half. The kernel (see `trapd-agent-ebpf/src/file_open.rs`)
//! does the cheap path-gate and hands us `(pid, uid, gid, comm, token_id,
//! flags)`. Here we:
//!
//!   1. **harden against false positives** (2c) — drop accesses from the agent
//!      itself (camouflage/integrity reads) and from legitimate filesystem
//!      sweepers (mlocate/updatedb, AV scanners, backup tools). Without this the
//!      detector would cry wolf and destroy operator trust;
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
/// Note: comm matching is spoofable (an attacker can rename their binary). It is
/// a false-positive filter, not a security boundary — the real signal is that
/// *something* read the bait. Operators extend this via config; they cannot use
/// it to weaken detection of an attacker who does not bother to disguise.
const DEFAULT_ALLOWLIST: &[&str] = &[
    // locate/updatedb family (comm is truncated to 15 chars by the kernel)
    "updatedb",
    "updatedb.mlocat",
    "updatedb.plocat",
    "mlocate",
    "plocate",
    "locate",
    "mandb",
    // desktop/file indexers
    "tracker-miner-f",
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
    comms: HashSet<String>,
    /// The agent's own PID — its camouflage/integrity reads of its own tokens
    /// must never alarm (self-exclusion, 2c).
    agent_pid: u32,
}

impl Allowlist {
    pub fn new(agent_pid: u32, extra: &[String]) -> Self {
        let mut comms: HashSet<String> =
            DEFAULT_ALLOWLIST.iter().map(|s| s.to_string()).collect();
        for c in extra {
            let c = c.trim();
            if !c.is_empty() {
                comms.insert(c.to_string());
            }
        }
        Self { comms, agent_pid }
    }

    /// True when an access from `pid`/`comm` should be treated as benign.
    pub fn is_allowed(&self, pid: i32, comm: &str) -> bool {
        if pid as u32 == self.agent_pid {
            return true; // the agent reading its own bait
        }
        comm == "trapd-agent" || self.comms.contains(comm)
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
    /// Unrecognised kind from a newer/older kernel build — treated as full access.
    Unknown,
}

impl AccessKind {
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
            Self::Openat => ("open", Severity::Critical, 100, "TA0006 Credential Access", "T1552.001"),
            Self::Open => ("open_legacy", Severity::Critical, 100, "TA0006 Credential Access", "T1552.001"),
            Self::Openat2 => ("openat2", Severity::Critical, 100, "TA0006 Credential Access", "T1552.001"),
            Self::Unknown => ("unknown", Severity::Critical, 100, "TA0006 Credential Access", "T1552.001"),
            Self::Mmap => ("mmap", Severity::Critical, 100, "TA0006 Credential Access", "T1552.001"),
            Self::Exec => ("exec", Severity::Critical, 100, "TA0002 Execution", "T1204.002"),
            // ── Evasion / tamper — deliberate, high-confidence ───────────────
            Self::Link => ("hardlink", Severity::Critical, 90, "TA0005 Defense Evasion", "T1564.001"),
            Self::Unlink => ("unlink", Severity::Critical, 90, "TA0040 Impact", "T1070.004"),
            Self::Rename => ("rename", Severity::High, 85, "TA0040 Impact", "T1070.004"),
            // ── Metadata recon — strong lead, scored below content access ────
            Self::Stat => ("stat", Severity::High, 75, "TA0007 Discovery", "T1083"),
            Self::Statx => ("statx", Severity::High, 75, "TA0007 Discovery", "T1083"),
            Self::Readlink => ("readlink", Severity::High, 75, "TA0007 Discovery", "T1083"),
            // Directory listing is inherently noisier (a user's own `ls` trips
            // it), so it is scored as a soft lead — telemetry for the backend/ML
            // rather than a high-severity alert.
            Self::Getdents => ("getdents", Severity::Medium, 50, "TA0007 Discovery", "T1083"),
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

/// Build the enriched detection event, or `None` if the access is allowlisted.
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
    if allowlist.is_allowed(hit.pid, hit.comm) {
        return None;
    }

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

    let data = HoneytokenAccessData {
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
        let Some(ppid) = proc.ppid(current) else { break };
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
        assert!(al.is_allowed(5, "trapd-agent"), "agent comm excluded");
        assert!(al.is_allowed(5, "updatedb"), "indexer excluded");
        assert!(al.is_allowed(5, "custombackup"), "configured extra excluded");
        assert!(!al.is_allowed(5, "cat"), "an interactive read is NOT excluded");
        assert!(!al.is_allowed(5, "python3"), "a script is NOT excluded");
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
    }
    impl ProcInfo for FakeProc {
        fn ppid(&self, pid: i32) -> Option<i32> {
            self.ppid.get(&pid).copied()
        }
        fn comm(&self, pid: i32) -> Option<String> {
            self.comm.get(&pid).cloned()
        }
        fn exe(&self, _pid: i32) -> Option<String> {
            None
        }
        fn cmdline(&self, _pid: i32) -> Option<String> {
            None
        }
        fn username(&self, _uid: u32) -> String {
            "tester".into()
        }
        fn session(&self, _pid: i32) -> Option<SessionContext> {
            None // keep lineage tests independent of the host's /proc
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
        FakeProc { ppid, comm }
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
                assert_eq!(d.accessor.ancestors.first().map(|a| a.comm.as_str()), Some("bash"));
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
            pid: 100, uid: 1000, gid: 1000, comm: "x", open_flags: 0,
            token_id: "t", path: "/home/a/.aws/credentials", kind: "aws_credentials",
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
        assert!(matches!(ev.severity, Severity::High), "recon is High, not Critical");
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
}
