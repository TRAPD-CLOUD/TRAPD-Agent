//! Stateful process-tree model — the memory the IOA correlator reasons over.
//!
//! Single-event heuristics are blind to *sequences*: `curl` is fine, `chmod +x`
//! is fine, a shell under `sshd` is fine.  What makes them an attack is the
//! **chain within one process lineage over a short window**
//! (`sshd → bash → curl → chmod +x → exec /tmp/x → outbound`).  To reason about
//! that the engine has to remember *who spawned whom* — that is this tree.
//!
//! It is fed from the process-lifecycle events the collectors already emit
//! (`exec`, `fork`, `create`, `terminate`) and answers two questions the
//! correlator needs:
//!   * **lineage** — the parent chain of a pid, for enriching every detection;
//!   * **relatedness** — do two pids belong to the same session subtree, so a
//!     download in `curl` and an exec in a sibling can be tied to one shell.
//!
//! Design constraints:
//!   * **Bounded** — caps total nodes and GCs tombstones, so a fork-bomb or a
//!     long-lived agent can never grow it without limit.
//!   * **Tombstoned** — a terminated process is kept briefly so the lineage of
//!     its still-living children stays resolvable.
//!   * **I/O-free** — the tree never touches the disk; executable hashes are
//!     computed once at collection time and attached via `set_exe_hash`.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Max live + tombstoned nodes retained.  Bounds memory on busy hosts; eviction
/// prefers exited then oldest.
const MAX_NODES: usize = 32_768;
/// How long a terminated process is kept (as a tombstone) so the lineage of its
/// still-living children can still be resolved.
const TOMBSTONE_TTL: Duration = Duration::from_secs(300);
/// Max ancestry depth walked — guards against pathological / cyclic ppid chains.
const MAX_DEPTH: usize = 32;
/// Depth within which two pids are treated as "same session subtree" by
/// [`ProcessTree::related`].  Bounded so unrelated processes that merely share
/// `init`/`systemd` as a distant ancestor are *not* correlated.
const RELATE_DEPTH: usize = 10;

/// Max ancestors carried as correlation keys on a finding.
const MAX_LINEAGE_KEYS: usize = 8;

/// Session boundaries: a process whose parent is one of these starts a new
/// session root (an SSH login shell, a cron job, a container's init, …).
const SESSION_BOUNDARIES: &[&str] = &[
    "systemd", "init", "sshd", "cron", "crond", "atd", "login", "su", "sudo",
    "containerd-shim", "containerd-shim-runc-v2", "conmon", "runc", "tmux: server",
    "screen", "gdm-session-worker", "lightdm", "sddm", "xrdp-sesman", "kthreadd",
];
/// System services that are never reported as a session root: grouping on
/// them would tie unrelated activity together.
const SYSTEM_ROOTS: &[&str] = &[
    "systemd", "init", "sshd", "cron", "crond", "atd", "dbus-daemon", "kthreadd",
    "containerd", "dockerd", "containerd-shim", "containerd-shim-runc-v2", "conmon",
    "NetworkManager", "polkitd", "snapd", "journald", "systemd-journal", "systemd-logind",
];
/// Web servers / app servers: a shell below one of these is a web shell.
pub const WEB_SERVERS: &[&str] = &[
    "nginx", "apache2", "httpd", "lighttpd", "caddy", "php-fpm", "php-fpm7", "php-fpm8",
    "php-fpm8.1", "php-fpm8.2", "php-fpm8.3", "tomcat", "catalina", "uwsgi", "gunicorn",
    "w3wp",
];
/// Package managers: their children legitimately write to system locations.
const PKG_MANAGERS: &[&str] = &[
    "dpkg", "apt", "apt-get", "aptitude", "unattended-upgr", "unattended-upgrade", "rpm",
    "dnf", "yum", "zypper", "pacman", "snapd", "flatpak", "apk", "packagekitd",
    // Windows installers and servicing.
    "msiexec.exe", "tiworker.exe", "trustedinstaller.exe", "wuauclt.exe", "usoclient.exe",
    "winget.exe", "choco.exe", "setuphost.exe",
];
/// Configuration-management agents.
const CONFIG_MGMT: &[&str] = &[
    "ansible-playboo", "ansible-playbook", "ansible", "puppet", "chef-client", "salt-minion",
    "salt-call", "cloud-init",
    // Windows management agents (ConfigMgr, Intune, Group Policy, DSC).
    "ccmexec.exe", "agentexecutor.exe", "microsoft.management.services.intunewindowsagent.exe",
    "intunemanagementextension.exe", "gpscript.exe", "omsagent.exe",
];

/// What a collector knows about a process's identity at exec time.
#[derive(Debug, Clone, Default)]
pub struct ProcIdentity {
    pub start_ticks: Option<u64>,
    pub container_id: Option<String>,
}

/// Correlation context of one process, resolved from the tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcContext {
    pub pid: i32,
    pub process_key: String,
    pub parent_key: Option<String>,
    /// Ancestors, nearest first, bounded to [`MAX_LINEAGE_KEYS`].
    pub lineage_keys: Vec<String>,
    pub root_key: Option<String>,
    pub uid: u32,
    pub username: String,
    pub comm: String,
    pub exe: String,
    pub exe_hash: Option<String>,
    pub container_id: Option<String>,
    /// Ancestor `comm`s, nearest first (for lineage-based rules).
    pub ancestor_comms: Vec<String>,
    /// Policy flags: `root`, `web_lineage`, `pkg_mgr_lineage`,
    /// `config_mgmt_lineage`, `ssh_session`, `container`.
    pub flags: Vec<&'static str>,
}

/// Two known, different start times for one pid mean the pid was reused.
fn is_reuse(old: Option<u64>, new: Option<u64>) -> bool {
    matches!((old, new), (Some(a), Some(b)) if a != b)
}

/// `boot:pid:start` — the process identity used for correlation.
pub fn process_key(pid: i32, start_ticks: Option<u64>) -> String {
    format!("{}:{pid}:{}", boot_prefix(), start_ticks.unwrap_or(0))
}

fn boot_prefix() -> &'static str {
    static PREFIX: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PREFIX.get_or_init(|| {
        let id = crate::telemetry::identity::boot_id();
        id.split('-').next().unwrap_or(id).to_string()
    })
}

/// The `root` policy flag. Windows has no numeric uid (collectors report 0
/// for every process), so there the equivalent is the SYSTEM account; without
/// this every Windows finding was bumped as if it ran as root.
fn is_privileged(node: &ProcNode) -> bool {
    let windows = node.username.contains('\\') || node.exe.to_ascii_lowercase().ends_with(".exe");
    if windows {
        let u = node.username.to_ascii_lowercase();
        return u == "nt authority\\system" || u == "system";
    }
    node.uid == 0
}

fn comm_in(comm: &str, set: &[&str]) -> bool {
    let base = comm.rsplit(['/', '\\']).next().unwrap_or(comm);
    set.iter().any(|s| {
        // Windows image names are case-insensitive (`CcmExec.exe`).
        if s.ends_with(".exe") {
            return base.eq_ignore_ascii_case(s);
        }
        *s == base || (s.len() >= 6 && base.starts_with(s))
    })
}

/// One process in the tree.  After an `exec` the image fields (`exe`,
/// `cmdline`, `exe_hash`) describe the *current* image; a `fork`ed child
/// inherits its parent's image until it execs.
#[derive(Clone, Debug)]
pub struct ProcNode {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub exe: String,
    pub cmdline: String,
    pub uid: u32,
    pub gid: u32,
    pub username: String,
    /// SHA256 of the executable image, when hashing is enabled and the file is
    /// a regular, size-bounded file.  `None` otherwise (memfd, too large, gone).
    pub exe_hash: Option<String>,
    /// Kernel start time in clock ticks since boot, when the collector knew
    /// it. With the pid it is the process identity that survives PID reuse.
    pub start_ticks: Option<u64>,
    /// Container the process runs in, when known.
    pub container_id: Option<String>,
    /// When this node was first observed.
    pub start: Instant,
    /// Set when a `terminate` is seen; the node becomes a GC-able tombstone.
    pub exited: Option<Instant>,
}

/// The process tree.  Not `Sync` on its own — the engine guards it behind a
/// `Mutex`, matching the other stateful trackers in this crate.
///
/// The tree never touches the disk: executable hashes are computed once at
/// collection time (see `collectors::linux::exehash`) and attached via
/// [`set_exe_hash`](Self::set_exe_hash), so detection stays allocation-light
/// and I/O-free.
pub struct ProcessTree {
    nodes: HashMap<i32, ProcNode>,
}

impl ProcessTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub fn node(&self, pid: i32) -> Option<&ProcNode> {
        self.nodes.get(&pid)
    }

    // ── Ingest ────────────────────────────────────────────────────────────────

    /// Record an `execve`: the pid now runs a (possibly new) image.
    #[allow(clippy::too_many_arguments)]
    pub fn on_exec(
        &mut self,
        pid: i32,
        ppid: i32,
        uid: u32,
        gid: u32,
        username: &str,
        comm: &str,
        exe: &str,
        cmdline: &str,
        identity: ProcIdentity,
        now: Instant,
    ) {
        // A re-exec keeps the process identity; a different start time means
        // the pid was reused by an unrelated process.
        let existing = self.nodes.get(&pid);
        let reused = existing.is_some_and(|n| is_reuse(n.start_ticks, identity.start_ticks));
        let start = existing.filter(|_| !reused).map(|n| n.start).unwrap_or(now);
        let start_ticks = identity
            .start_ticks
            .or_else(|| existing.filter(|_| !reused).and_then(|n| n.start_ticks));
        self.nodes.insert(
            pid,
            ProcNode {
                pid,
                ppid,
                comm: comm.to_string(),
                exe: exe.to_string(),
                cmdline: cmdline.to_string(),
                uid,
                gid,
                username: username.to_string(),
                exe_hash: None,
                start_ticks,
                container_id: identity.container_id,
                start,
                exited: None,
            },
        );
    }

    /// Record a `/proc`-polled process create.  Carries no gid, so it defaults
    /// to 0; an eBPF `exec` for the same pid later fills the richer fields.
    #[allow(clippy::too_many_arguments)]
    pub fn on_create(
        &mut self,
        pid: i32,
        ppid: i32,
        uid: u32,
        username: &str,
        name: &str,
        exe: &str,
        cmdline: &str,
        start_ticks: Option<u64>,
        now: Instant,
    ) {
        // Don't clobber a richer exec-sourced node for the same process — but a
        // different start time is a reused pid, which must replace it.
        if let Some(n) = self.nodes.get(&pid) {
            if !is_reuse(n.start_ticks, start_ticks) {
                return;
            }
        }
        self.nodes.insert(
            pid,
            ProcNode {
                pid,
                ppid,
                comm: name.to_string(),
                exe: exe.to_string(),
                cmdline: cmdline.to_string(),
                uid,
                gid: 0,
                username: username.to_string(),
                exe_hash: None,
                start_ticks,
                container_id: None,
                start: now,
                exited: None,
            },
        );
    }

    /// Attach the executable's SHA256 (computed once at collection time) to a
    /// node.  No-op when the hash is `None` or the pid is unknown.
    pub fn set_exe_hash(&mut self, pid: i32, hash: Option<&str>) {
        if let (Some(h), Some(node)) = (hash, self.nodes.get_mut(&pid)) {
            node.exe_hash = Some(h.to_string());
        }
    }

    /// Record a `fork`: the child inherits the parent's image until it execs.
    pub fn on_fork(
        &mut self,
        parent_pid: i32,
        child_pid: i32,
        parent_comm: &str,
        child_comm: &str,
        now: Instant,
    ) {
        if self.nodes.contains_key(&child_pid) {
            return;
        }
        let inherited = self.nodes.get(&parent_pid).cloned();
        let node = match inherited {
            Some(p) => ProcNode {
                pid: child_pid,
                ppid: parent_pid,
                comm: child_comm.to_string(),
                exe: p.exe,
                cmdline: p.cmdline,
                uid: p.uid,
                gid: p.gid,
                username: p.username,
                exe_hash: p.exe_hash,
                start_ticks: None,
                container_id: p.container_id,
                start: now,
                exited: None,
            },
            None => ProcNode {
                pid: child_pid,
                ppid: parent_pid,
                comm: child_comm.to_string(),
                exe: String::new(),
                cmdline: String::new(),
                uid: 0,
                gid: 0,
                username: String::new(),
                exe_hash: None,
                start_ticks: None,
                container_id: None,
                start: now,
                exited: None,
            },
        };
        // Make sure the parent at least exists so lineage walks don't dead-end.
        self.nodes.entry(parent_pid).or_insert_with(|| ProcNode {
            pid: parent_pid,
            ppid: 0,
            comm: parent_comm.to_string(),
            exe: String::new(),
            cmdline: String::new(),
            uid: 0,
            gid: 0,
            username: String::new(),
            exe_hash: None,
            start_ticks: None,
            container_id: None,
            start: now,
            exited: None,
        });
        self.nodes.insert(child_pid, node);
    }

    /// Mark a process exited.  It becomes a tombstone (kept for lineage) until
    /// [`gc`](Self::gc) reaps it.
    pub fn on_exit(&mut self, pid: i32, now: Instant) {
        if let Some(n) = self.nodes.get_mut(&pid) {
            n.exited = Some(now);
        }
    }

    // ── Queries ─────────────────────────────────────────────────────────────

    /// True if `ancestor` is `descendant` itself or sits on its parent chain.
    pub fn is_ancestor(&self, ancestor: i32, descendant: i32) -> bool {
        if ancestor == descendant {
            return true;
        }
        let mut cur = descendant;
        for _ in 0..MAX_DEPTH {
            let ppid = match self.nodes.get(&cur) {
                Some(n) => n.ppid,
                None => return false,
            };
            if ppid == ancestor {
                return true;
            }
            if ppid <= 1 || ppid == cur {
                return false;
            }
            cur = ppid;
        }
        false
    }

    /// True if two pids belong to the same session subtree: one is an ancestor
    /// of the other, or they share a common ancestor within [`RELATE_DEPTH`]
    /// (their shell / login session) — but *not* if they only meet at
    /// `init`/`systemd`.  This is what lets a download in `curl` and an exec in
    /// a sibling under the same `bash` be tied into one chain.
    pub fn related(&self, a: i32, b: i32) -> bool {
        if a == b || self.is_ancestor(a, b) || self.is_ancestor(b, a) {
            return true;
        }
        let anc_a = self.ancestor_set(a);
        if anc_a.is_empty() {
            return false;
        }
        let mut cur = b;
        for _ in 0..RELATE_DEPTH {
            let ppid = match self.nodes.get(&cur) {
                Some(n) => n.ppid,
                None => return false,
            };
            if ppid <= 1 || ppid == cur {
                return false;
            }
            if anc_a.contains(&ppid) {
                return true;
            }
            cur = ppid;
        }
        false
    }

    /// The set of ancestor pids of `pid` (excluding pid 1 / unknown roots),
    /// bounded to [`RELATE_DEPTH`].
    fn ancestor_set(&self, pid: i32) -> HashSet<i32> {
        let mut out = HashSet::new();
        let mut cur = pid;
        for _ in 0..RELATE_DEPTH {
            let ppid = match self.nodes.get(&cur) {
                Some(n) => n.ppid,
                None => break,
            };
            if ppid <= 1 || ppid == cur {
                break;
            }
            out.insert(ppid);
            cur = ppid;
        }
        out
    }

    /// Lineage of `pid` as a JSON array `[{pid,comm,exe,exe_hash}, …]`, nearest
    /// process first, walking up towards the session root.  `None` if the pid is
    /// unknown — used to enrich every detection with *how the process came to be*.
    pub fn lineage_json(&self, pid: i32) -> Option<serde_json::Value> {
        if !self.nodes.contains_key(&pid) {
            return None;
        }
        let mut out = Vec::new();
        let mut cur = pid;
        for _ in 0..MAX_DEPTH {
            let n = match self.nodes.get(&cur) {
                Some(n) => n,
                None => break,
            };
            let mut entry = serde_json::json!({
                "pid":  n.pid,
                "process_start_time": n.start_ticks,
                "comm": n.comm,
            });
            if !n.exe.is_empty() {
                entry["exe"] = serde_json::Value::String(n.exe.clone());
            }
            if let Some(h) = &n.exe_hash {
                entry["exe_sha256"] = serde_json::Value::String(h.clone());
            }
            out.push(entry);
            if n.ppid <= 1 || n.ppid == cur {
                break;
            }
            cur = n.ppid;
        }
        Some(serde_json::Value::Array(out))
    }

    /// Correlation context for `pid`, or `None` when the pid is unknown.
    pub fn context(&self, pid: i32) -> Option<ProcContext> {
        let node = self.nodes.get(&pid)?;
        let mut ctx = ProcContext {
            pid,
            process_key: process_key(pid, node.start_ticks),
            uid: node.uid,
            username: node.username.clone(),
            comm: node.comm.clone(),
            exe: node.exe.clone(),
            exe_hash: node.exe_hash.clone(),
            container_id: node.container_id.clone(),
            ..Default::default()
        };

        // Walk up, collecting ancestors (nearest first).
        let mut chain: Vec<&ProcNode> = vec![node];
        let mut cur = node;
        for _ in 0..MAX_DEPTH {
            if cur.ppid <= 0 || cur.ppid == cur.pid {
                break;
            }
            match self.nodes.get(&cur.ppid) {
                Some(p) => {
                    chain.push(p);
                    cur = p;
                }
                None => break,
            }
        }
        for anc in chain.iter().skip(1) {
            if ctx.lineage_keys.len() < MAX_LINEAGE_KEYS {
                ctx.lineage_keys.push(process_key(anc.pid, anc.start_ticks));
            }
            ctx.ancestor_comms.push(anc.comm.clone());
        }
        ctx.parent_key = ctx.lineage_keys.first().cloned();

        // Session root: the topmost process whose parent is a session boundary
        // (or unknown / pid 1). Never a system service itself.
        let mut root_idx = chain.len() - 1;
        for i in 0..chain.len() {
            let parent = chain.get(i + 1);
            let boundary = match parent {
                Some(p) => comm_in(&p.comm, SESSION_BOUNDARIES) || p.pid <= 1,
                None => true,
            };
            if boundary {
                root_idx = i;
                break;
            }
        }
        let root = chain[root_idx];
        if !comm_in(&root.comm, SYSTEM_ROOTS) && root.pid > 1 {
            ctx.root_key = Some(process_key(root.pid, root.start_ticks));
        }

        if is_privileged(node) {
            ctx.flags.push(crate::detection::severity::FLAG_ROOT);
        }
        let ancestors = &chain[1..];
        if ancestors.iter().any(|a| comm_in(&a.comm, WEB_SERVERS)) {
            ctx.flags.push(crate::detection::severity::FLAG_WEB_LINEAGE);
        }
        if ancestors.iter().any(|a| comm_in(&a.comm, PKG_MANAGERS)) {
            ctx.flags.push(crate::detection::severity::FLAG_PKG_MGR_LINEAGE);
        }
        if ancestors.iter().any(|a| comm_in(&a.comm, CONFIG_MGMT)) {
            ctx.flags.push(crate::detection::severity::FLAG_CONFIG_MGMT_LINEAGE);
        }
        if ancestors.iter().any(|a| a.comm == "sshd") {
            ctx.flags.push(crate::detection::severity::FLAG_SSH_SESSION);
        }
        if node.container_id.is_some() {
            ctx.flags.push(crate::detection::severity::FLAG_CONTAINER);
        }
        Some(ctx)
    }

    /// The process key of `pid` as currently known (start time may be 0).
    pub fn key_of(&self, pid: i32) -> String {
        process_key(pid, self.nodes.get(&pid).and_then(|n| n.start_ticks))
    }

    // ── Maintenance ───────────────────────────────────────────────────────────

    /// Reap expired tombstones and enforce the node cap.  Called periodically by
    /// the engine; cheap and allocation-light on the common (under-cap) path.
    pub fn gc(&mut self, now: Instant) {
        self.nodes.retain(|_, n| match n.exited {
            Some(t) => now.duration_since(t) < TOMBSTONE_TTL,
            None => true,
        });
        if self.nodes.len() > MAX_NODES {
            let over = self.nodes.len() - MAX_NODES;
            // Evict exited-before-live, then oldest-start-first.
            let mut cand: Vec<(i32, u8, Instant)> = self
                .nodes
                .iter()
                .map(|(p, n)| (*p, u8::from(n.exited.is_none()), n.start))
                .collect();
            cand.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
            for (pid, _, _) in cand.into_iter().take(over) {
                self.nodes.remove(&pid);
            }
        }
    }
}

impl Default for ProcessTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> ProcessTree {
        ProcessTree::new()
    }

    #[test]
    fn windows_root_flag_and_management_lineage() {
        let mut tree = t();
        let now = Instant::now();
        tree.on_create(500, 4, 0, "NT AUTHORITY\\SYSTEM", "CcmExec.exe", "C:\\Windows\\CCM\\CcmExec.exe", "", None, now);
        tree.on_create(600, 500, 0, "NT AUTHORITY\\SYSTEM", "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "", None, now);
        tree.on_create(700, 4, 0, "CORP\\anna", "powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "", None, now);
        let managed = tree.context(600).unwrap();
        assert!(managed.flags.contains(&crate::detection::severity::FLAG_ROOT));
        assert!(managed.flags.contains(&crate::detection::severity::FLAG_CONFIG_MGMT_LINEAGE));
        let user = tree.context(700).unwrap();
        assert!(!user.flags.contains(&crate::detection::severity::FLAG_ROOT), "uid 0 on Windows is not root");
        assert!(!user.flags.contains(&crate::detection::severity::FLAG_CONFIG_MGMT_LINEAGE));
    }

    #[test]
    fn resolves_direct_ancestry() {
        let mut tree = t();
        let now = Instant::now();
        tree.on_exec(100, 1, 0, 0, "root", "sshd", "/usr/sbin/sshd", "sshd", ProcIdentity::default(), now);
        tree.on_exec(200, 100, 0, 0, "root", "bash", "/bin/bash", "bash", ProcIdentity::default(), now);
        tree.on_exec(
            300,
            200,
            0,
            0,
            "root",
            "curl",
            "/usr/bin/curl",
            "curl http://x",
            ProcIdentity::default(), now,
        );
        assert!(
            tree.is_ancestor(100, 300),
            "sshd should be an ancestor of curl"
        );
        assert!(tree.is_ancestor(200, 300));
        assert!(!tree.is_ancestor(300, 200));
    }

    #[test]
    fn siblings_under_one_shell_are_related() {
        let mut tree = t();
        let now = Instant::now();
        tree.on_exec(200, 1, 0, 0, "root", "bash", "/bin/bash", "bash", ProcIdentity::default(), now);
        // two children of the same shell — not ancestors of each other
        tree.on_exec(301, 200, 0, 0, "root", "curl", "/usr/bin/curl", "curl", ProcIdentity::default(), now);
        tree.on_exec(
            302,
            200,
            0,
            0,
            "root",
            "evil",
            "/tmp/evil",
            "/tmp/evil",
            ProcIdentity::default(), now,
        );
        assert!(!tree.is_ancestor(301, 302));
        assert!(
            tree.related(301, 302),
            "siblings under one bash share a session"
        );
    }

    #[test]
    fn unrelated_processes_meeting_at_init_are_not_related() {
        let mut tree = t();
        let now = Instant::now();
        // Two independent daemons whose only common ancestor is init (pid 1).
        tree.on_exec(
            10,
            1,
            0,
            0,
            "root",
            "nginx",
            "/usr/sbin/nginx",
            "nginx",
            ProcIdentity::default(), now,
        );
        tree.on_exec(20, 1, 0, 0, "root", "cron", "/usr/sbin/cron", "cron", ProcIdentity::default(), now);
        assert!(!tree.related(10, 20));
    }

    #[test]
    fn fork_child_inherits_then_exec_replaces() {
        let mut tree = t();
        let now = Instant::now();
        tree.on_exec(200, 1, 1000, 1000, "u", "bash", "/bin/bash", "bash", ProcIdentity::default(), now);
        tree.on_fork(200, 201, "bash", "bash", now);
        assert_eq!(
            tree.node(201).unwrap().exe,
            "/bin/bash",
            "child inherits parent image"
        );
        tree.on_exec(
            201,
            200,
            1000,
            1000,
            "u",
            "curl",
            "/usr/bin/curl",
            "curl",
            ProcIdentity::default(), now,
        );
        assert_eq!(
            tree.node(201).unwrap().exe,
            "/usr/bin/curl",
            "exec replaces image"
        );
    }

    #[test]
    fn tombstones_are_reaped_but_keep_living_children_resolvable() {
        let mut tree = t();
        let now = Instant::now();
        tree.on_exec(200, 1, 0, 0, "root", "bash", "/bin/bash", "bash", ProcIdentity::default(), now);
        tree.on_exec(300, 200, 0, 0, "root", "curl", "/usr/bin/curl", "curl", ProcIdentity::default(), now);
        tree.on_exit(200, now);
        // Parent dead but child alive — lineage still resolvable before GC TTL.
        assert!(tree.is_ancestor(200, 300));
        // After TTL the tombstone is reaped.
        let later = now + TOMBSTONE_TTL + Duration::from_secs(1);
        tree.gc(later);
        assert!(tree.node(200).is_none());
    }

    #[test]
    fn set_exe_hash_surfaces_in_lineage() {
        let mut tree = t();
        let now = Instant::now();
        tree.on_exec(200, 1, 0, 0, "root", "bash", "/bin/bash", "bash", ProcIdentity::default(), now);
        tree.set_exe_hash(200, Some("abc123"));
        // Unknown pid / None are no-ops.
        tree.set_exe_hash(999, Some("nope"));
        tree.set_exe_hash(200, None);
        let lin = tree.lineage_json(200).unwrap();
        assert_eq!(lin.as_array().unwrap()[0]["exe_sha256"], "abc123");
    }

    #[test]
    fn lineage_json_walks_up_the_chain() {
        let mut tree = t();
        let now = Instant::now();
        tree.on_exec(100, 1, 0, 0, "root", "sshd", "/usr/sbin/sshd", "sshd", ProcIdentity::default(), now);
        tree.on_exec(200, 100, 0, 0, "root", "bash", "/bin/bash", "bash", ProcIdentity::default(), now);
        let lin = tree.lineage_json(200).unwrap();
        let arr = lin.as_array().unwrap();
        assert_eq!(arr[0]["pid"], 200);
        assert_eq!(arr[0]["comm"], "bash");
        assert_eq!(arr[1]["pid"], 100);
        assert_eq!(arr[1]["comm"], "sshd");
    }
}
