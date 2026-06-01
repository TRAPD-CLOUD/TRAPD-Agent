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
//!   3. emit a `HoneytokenAccess` event at **confidence 100** — by construction
//!      no legitimate workflow reads a honeytoken.
//!
//! Pure parsing helpers are unit-tested; the `/proc` walkers are thin wrappers
//! over them.

use std::collections::HashSet;

use uuid::Uuid;

use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, HoneytokenAccessData, ProcessAncestor,
    ProcessLineage, Severity,
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

    let data = HoneytokenAccessData {
        token_id: hit.token_id.to_string(),
        path: hit.path.to_string(),
        kind: hit.kind.to_string(),
        open_flags: hit.open_flags,
        confidence: 100,
        mitre_tactic: "TA0006 Credential Access".to_string(),
        mitre_technique: "T1552.001".to_string(),
        accessor,
    };

    Some(AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Detection,
        EventAction::HoneytokenAccess,
        Severity::Critical,
        EventData::HoneytokenAccess(data),
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
        };
        let ev = build_access_event("a", "h", &hit, &al, &fake()).expect("event");
        assert!(matches!(ev.severity, Severity::Critical));
        assert!(matches!(ev.action, EventAction::HoneytokenAccess));
        match ev.data {
            EventData::HoneytokenAccess(d) => {
                assert_eq!(d.confidence, 100);
                assert_eq!(d.token_id, "tok-123");
                assert_eq!(d.accessor.comm, "cat");
                // ancestry resolved from the fake /proc
                assert_eq!(d.accessor.ancestors.first().map(|a| a.comm.as_str()), Some("bash"));
            }
            _ => panic!("wrong payload"),
        }
    }
}
