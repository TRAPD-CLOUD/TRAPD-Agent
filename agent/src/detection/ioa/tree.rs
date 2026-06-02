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
//!   * **Cheap** — exec hashing is cached by path+mtime and size-capped, and is
//!     the only thing here that can touch the disk.

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
/// Executables larger than this are not hashed (cost bound on the hot path).
const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;
/// Cap on the exe-hash cache before it is cleared wholesale.
const HASH_CACHE_CAP: usize = 4_096;

/// One process in the tree.  After an `exec` the image fields (`exe`,
/// `cmdline`, `exe_hash`) describe the *current* image; a `fork`ed child
/// inherits its parent's image until it execs.
#[derive(Clone, Debug)]
pub struct ProcNode {
    pub pid:      i32,
    pub ppid:     i32,
    pub comm:     String,
    pub exe:      String,
    pub cmdline:  String,
    pub uid:      u32,
    pub gid:      u32,
    pub username: String,
    /// SHA256 of the executable image, when hashing is enabled and the file is
    /// a regular, size-bounded file.  `None` otherwise (memfd, too large, gone).
    pub exe_hash: Option<String>,
    /// When this node was first observed.
    pub start:    Instant,
    /// Set when a `terminate` is seen; the node becomes a GC-able tombstone.
    pub exited:   Option<Instant>,
}

/// The process tree.  Not `Sync` on its own — the engine guards it behind a
/// `Mutex`, matching the other stateful trackers in this crate.
pub struct ProcessTree {
    nodes:            HashMap<i32, ProcNode>,
    hash_cache:       HashMap<String, (u64, Option<String>)>,
    hash_executables: bool,
}

impl ProcessTree {
    pub fn new(hash_executables: bool) -> Self {
        Self {
            nodes: HashMap::new(),
            hash_cache: HashMap::new(),
            hash_executables,
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
        now: Instant,
    ) {
        let exe_hash = self.compute_hash(exe);
        let start = self.nodes.get(&pid).map(|n| n.start).unwrap_or(now);
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
                exe_hash,
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
        now: Instant,
    ) {
        // Don't clobber a richer exec-sourced node for the same pid.
        if self.nodes.contains_key(&pid) {
            return;
        }
        let exe_hash = self.compute_hash(exe);
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
                exe_hash,
                start: now,
                exited: None,
            },
        );
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

    // ── Internals ─────────────────────────────────────────────────────────────

    /// SHA256 the executable at `path`, cached by path+mtime and size-capped.
    /// Returns `None` when hashing is disabled, the path is not an absolute
    /// regular file, it is too large, or the read fails.
    fn compute_hash(&mut self, path: &str) -> Option<String> {
        if !self.hash_executables || !path.starts_with('/') {
            return None;
        }
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() || meta.len() > MAX_HASH_BYTES {
            return None;
        }
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Some((cached_mtime, hash)) = self.hash_cache.get(path) {
            if *cached_mtime == mtime {
                return hash.clone();
            }
        }
        let hash = std::fs::read(path).ok().map(|bytes| {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            hex::encode(hasher.finalize())
        });
        if self.hash_cache.len() >= HASH_CACHE_CAP {
            self.hash_cache.clear();
        }
        self.hash_cache.insert(path.to_string(), (mtime, hash.clone()));
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> ProcessTree {
        ProcessTree::new(false)
    }

    #[test]
    fn resolves_direct_ancestry() {
        let mut tree = t();
        let now = Instant::now();
        tree.on_exec(100, 1, 0, 0, "root", "sshd", "/usr/sbin/sshd", "sshd", now);
        tree.on_exec(200, 100, 0, 0, "root", "bash", "/bin/bash", "bash", now);
        tree.on_exec(300, 200, 0, 0, "root", "curl", "/usr/bin/curl", "curl http://x", now);
        assert!(tree.is_ancestor(100, 300), "sshd should be an ancestor of curl");
        assert!(tree.is_ancestor(200, 300));
        assert!(!tree.is_ancestor(300, 200));
    }

    #[test]
    fn siblings_under_one_shell_are_related() {
        let mut tree = t();
        let now = Instant::now();
        tree.on_exec(200, 1, 0, 0, "root", "bash", "/bin/bash", "bash", now);
        // two children of the same shell — not ancestors of each other
        tree.on_exec(301, 200, 0, 0, "root", "curl", "/usr/bin/curl", "curl", now);
        tree.on_exec(302, 200, 0, 0, "root", "evil", "/tmp/evil", "/tmp/evil", now);
        assert!(!tree.is_ancestor(301, 302));
        assert!(tree.related(301, 302), "siblings under one bash share a session");
    }

    #[test]
    fn unrelated_processes_meeting_at_init_are_not_related() {
        let mut tree = t();
        let now = Instant::now();
        // Two independent daemons whose only common ancestor is init (pid 1).
        tree.on_exec(10, 1, 0, 0, "root", "nginx", "/usr/sbin/nginx", "nginx", now);
        tree.on_exec(20, 1, 0, 0, "root", "cron", "/usr/sbin/cron", "cron", now);
        assert!(!tree.related(10, 20));
    }

    #[test]
    fn fork_child_inherits_then_exec_replaces() {
        let mut tree = t();
        let now = Instant::now();
        tree.on_exec(200, 1, 1000, 1000, "u", "bash", "/bin/bash", "bash", now);
        tree.on_fork(200, 201, "bash", "bash", now);
        assert_eq!(tree.node(201).unwrap().exe, "/bin/bash", "child inherits parent image");
        tree.on_exec(201, 200, 1000, 1000, "u", "curl", "/usr/bin/curl", "curl", now);
        assert_eq!(tree.node(201).unwrap().exe, "/usr/bin/curl", "exec replaces image");
    }

    #[test]
    fn tombstones_are_reaped_but_keep_living_children_resolvable() {
        let mut tree = t();
        let now = Instant::now();
        tree.on_exec(200, 1, 0, 0, "root", "bash", "/bin/bash", "bash", now);
        tree.on_exec(300, 200, 0, 0, "root", "curl", "/usr/bin/curl", "curl", now);
        tree.on_exit(200, now);
        // Parent dead but child alive — lineage still resolvable before GC TTL.
        assert!(tree.is_ancestor(200, 300));
        // After TTL the tombstone is reaped.
        let later = now + TOMBSTONE_TTL + Duration::from_secs(1);
        tree.gc(later);
        assert!(tree.node(200).is_none());
    }

    #[test]
    fn lineage_json_walks_up_the_chain() {
        let mut tree = t();
        let now = Instant::now();
        tree.on_exec(100, 1, 0, 0, "root", "sshd", "/usr/sbin/sshd", "sshd", now);
        tree.on_exec(200, 100, 0, 0, "root", "bash", "/bin/bash", "bash", now);
        let lin = tree.lineage_json(200).unwrap();
        let arr = lin.as_array().unwrap();
        assert_eq!(arr[0]["pid"], 200);
        assert_eq!(arr[0]["comm"], "bash");
        assert_eq!(arr[1]["pid"], 100);
        assert_eq!(arr[1]["comm"], "sshd");
    }
}
