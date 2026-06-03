//! Attack-chain state machines — the "indicator of attack" logic.
//!
//! A [`ChainDef`] is an *ordered* sequence of [`Stage`]s.  Each stage is a pure
//! predicate over [`EventFacts`] (a cheap, pre-classified view of one event).
//! The [`Correlator`] tracks, per running attack, how far along its chain we are
//! and only advances when the next stage is seen **in the same session subtree**
//! (see [`super::tree::ProcessTree::related`]) and **within the time window**.
//! When the last stage matches, the whole chain fires as one high-signal
//! finding carrying the full evidence trail.
//!
//! Why state machines and not one big rule: it keeps each chain declarative and
//! independently testable, lets stages happen across *different* processes in
//! one lineage (the download is `curl`, the payload exec is a sibling), and
//! bounds work to a linear scan of a capped active-instance list.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::tree::ProcessTree;

/// How long a partially-matched chain stays open before it expires.
const CHAIN_WINDOW: Duration = Duration::from_secs(300);
/// Cap on concurrently-tracked partial chains (bounds memory under load).
const MAX_ACTIVE: usize = 4_096;
/// Per (chain, anchor) cooldown so a looping attacker doesn't produce an alert
/// storm of the same finding.
const FIRE_COOLDOWN: Duration = Duration::from_secs(60);

/// Cheap, pre-computed classification of a single event.  Derived once per event
/// so every stage predicate is a trivial boolean read — no re-parsing of command
/// lines inside the per-instance loop.
#[derive(Default, Debug, Clone)]
pub struct EventFacts {
    /// The acting pid, when the event has one.  Events without a pid cannot be
    /// correlated into a lineage and are ignored by the correlator.
    pub pid: Option<i32>,
    pub is_shell_exec: bool,
    pub is_downloader_exec: bool,
    /// Exec of a binary living in a world-writable / temp / in-memory location.
    pub is_temp_exec: bool,
    /// A chmod that set any execute bit.
    pub made_executable: bool,
    /// setuid(0) from a non-root uid — privilege gained.
    pub setuid_root: bool,
    /// An exec/create observed running as a non-root uid.
    pub is_nonroot_proc: bool,
    /// Touched a credential store (shadow, SSH key, cloud creds, …).
    pub cred_access: bool,
    /// Outbound connection to a routable destination.
    pub outbound_routable: bool,
    /// Wrote to an autostart / persistence location.
    pub persistence_write: bool,
}

type Predicate = fn(&EventFacts) -> bool;

fn p_shell(f: &EventFacts) -> bool {
    f.is_shell_exec
}
fn p_downloader(f: &EventFacts) -> bool {
    f.is_downloader_exec
}
fn p_temp_exec(f: &EventFacts) -> bool {
    f.is_temp_exec
}
fn p_setuid_root(f: &EventFacts) -> bool {
    f.setuid_root
}
fn p_nonroot(f: &EventFacts) -> bool {
    f.is_nonroot_proc
}
fn p_cred(f: &EventFacts) -> bool {
    f.cred_access
}
fn p_outbound(f: &EventFacts) -> bool {
    f.outbound_routable
}
/// "Did something with the new privileges": run a dropped binary, persist, or
/// grab credentials.
fn p_priv_action(f: &EventFacts) -> bool {
    f.is_temp_exec || f.persistence_write || f.cred_access
}

/// One stage in a chain.
pub struct Stage {
    pub label: &'static str,
    pub matches: Predicate,
}

/// A declarative attack chain.
pub struct ChainDef {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub mitre_tactic: &'static str,
    pub mitre_technique: &'static str,
    /// Confidence assigned when the full chain fires (0–100).
    pub confidence: u8,
    pub stages: &'static [Stage],
}

/// The built-in chain library.  Deliberately few and high-signal: each one is a
/// multi-step pattern that is suspicious *as a sequence* even though every
/// individual step is common in isolation.
pub static CHAINS: &[ChainDef] = &[
    // sshd → bash → curl (download) → chmod +x / exec from /tmp.
    ChainDef {
        id: "ioa.download_and_execute",
        title: "Staged download-and-execute",
        category: "ioa.execution",
        mitre_tactic: "TA0002 Execution",
        mitre_technique: "T1059",
        confidence: 88,
        stages: &[
            Stage {
                label: "interactive shell",
                matches: p_shell,
            },
            Stage {
                label: "network downloader spawned",
                matches: p_downloader,
            },
            Stage {
                label: "executes dropped payload",
                matches: p_temp_exec,
            },
        ],
    },
    // unprivileged process → setuid(0) → acts with the new root privileges.
    ChainDef {
        id: "ioa.privilege_escalation_activity",
        title: "Privilege escalation followed by suspicious activity",
        category: "ioa.privilege_escalation",
        mitre_tactic: "TA0004 Privilege Escalation",
        mitre_technique: "T1548",
        confidence: 82,
        stages: &[
            Stage {
                label: "unprivileged process",
                matches: p_nonroot,
            },
            Stage {
                label: "gains root (setuid 0)",
                matches: p_setuid_root,
            },
            Stage {
                label: "post-escalation action",
                matches: p_priv_action,
            },
        ],
    },
    // reads a credential store → makes an outbound connection (likely exfil).
    ChainDef {
        id: "ioa.credential_access_exfil",
        title: "Credential access followed by outbound network",
        category: "ioa.exfiltration",
        mitre_tactic: "TA0010 Exfiltration",
        mitre_technique: "T1041",
        confidence: 76,
        stages: &[
            Stage {
                label: "credential store access",
                matches: p_cred,
            },
            Stage {
                label: "outbound connection",
                matches: p_outbound,
            },
        ],
    },
];

/// Evidence for one matched stage.
#[derive(Clone, Debug)]
pub struct StageEvidence {
    pub stage: usize,
    pub label: &'static str,
    pub pid: i32,
    pub offset_ms: u128,
}

/// A fully-matched chain, ready to be turned into a detection.
#[derive(Clone, Debug)]
pub struct CompletedChain {
    pub def_idx: usize,
    pub anchor_pid: i32,
    pub final_pid: i32,
    pub duration_ms: u128,
    pub stages: Vec<StageEvidence>,
}

impl CompletedChain {
    pub fn def(&self) -> &'static ChainDef {
        &CHAINS[self.def_idx]
    }
}

/// One in-flight partial match.
struct ChainInstance {
    def_idx: usize,
    anchor_pid: i32,
    /// Index of the *next* stage to match (`[0..stage)` already matched).
    stage: usize,
    started: Instant,
    hits: Vec<StageEvidence>,
}

/// Tracks all partial chains and emits completed ones.
pub struct Correlator {
    active: Vec<ChainInstance>,
    /// (def_idx, anchor_pid) → last fired, for the anti-storm cooldown.
    recently_fired: HashMap<(usize, i32), Instant>,
}

impl Correlator {
    pub fn new() -> Self {
        Self {
            active: Vec::new(),
            recently_fired: HashMap::new(),
        }
    }

    /// Feed one classified event.  Returns any chains that completed on it.
    pub fn observe(
        &mut self,
        facts: &EventFacts,
        tree: &ProcessTree,
        now: Instant,
    ) -> Vec<CompletedChain> {
        // Expire stale partials and cooldown entries first.
        self.active
            .retain(|c| now.duration_since(c.started) < CHAIN_WINDOW);
        self.recently_fired
            .retain(|_, t| now.duration_since(*t) < FIRE_COOLDOWN);

        // Without a pid we cannot tie the event to a lineage.
        let pid = match facts.pid {
            Some(p) => p,
            None => return Vec::new(),
        };

        let mut completed = Vec::new();

        // 1. Advance existing partials whose next stage this event satisfies and
        //    whose anchor shares this pid's session subtree.
        for inst in self.active.iter_mut() {
            let def = &CHAINS[inst.def_idx];
            if inst.stage >= def.stages.len() {
                continue;
            }
            if !tree.related(inst.anchor_pid, pid) {
                continue;
            }
            let stage = inst.stage;
            if (def.stages[stage].matches)(facts) {
                inst.hits.push(StageEvidence {
                    stage,
                    label: def.stages[stage].label,
                    pid,
                    offset_ms: now.duration_since(inst.started).as_millis(),
                });
                inst.stage += 1;
                if inst.stage >= def.stages.len() {
                    let key = (inst.def_idx, inst.anchor_pid);
                    if let std::collections::hash_map::Entry::Vacant(slot) =
                        self.recently_fired.entry(key)
                    {
                        slot.insert(now);
                        completed.push(CompletedChain {
                            def_idx: inst.def_idx,
                            anchor_pid: inst.anchor_pid,
                            final_pid: pid,
                            duration_ms: now.duration_since(inst.started).as_millis(),
                            stages: inst.hits.clone(),
                        });
                    }
                }
            }
        }
        // Drop finished partials.
        self.active
            .retain(|c| c.stage < CHAINS[c.def_idx].stages.len());

        // 2. Open new partials for chains whose first stage this event matches.
        for (idx, def) in CHAINS.iter().enumerate() {
            if !(def.stages[0].matches)(facts) {
                continue;
            }
            // Don't open a duplicate partial for the same chain already anchored
            // here and still waiting on stage 1.
            let dup = self
                .active
                .iter()
                .any(|c| c.def_idx == idx && c.anchor_pid == pid && c.stage == 1);
            if dup {
                continue;
            }
            self.active.push(ChainInstance {
                def_idx: idx,
                anchor_pid: pid,
                stage: 1,
                started: now,
                hits: vec![StageEvidence {
                    stage: 0,
                    label: def.stages[0].label,
                    pid,
                    offset_ms: 0,
                }],
            });
        }

        // 3. Bound the active set (evict oldest first).
        if self.active.len() > MAX_ACTIVE {
            let over = self.active.len() - MAX_ACTIVE;
            self.active.drain(0..over);
        }

        completed
    }
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell() -> EventFacts {
        EventFacts {
            pid: Some(200),
            is_shell_exec: true,
            ..Default::default()
        }
    }

    /// Build a tree where 200 is a bash and 301/302 are its children.
    fn tree() -> ProcessTree {
        let mut t = ProcessTree::new();
        let now = Instant::now();
        t.on_exec(200, 1, 0, 0, "root", "bash", "/bin/bash", "bash", now);
        t.on_exec(301, 200, 0, 0, "root", "curl", "/usr/bin/curl", "curl", now);
        t.on_exec(302, 200, 0, 0, "root", "x", "/tmp/x", "/tmp/x", now);
        t
    }

    #[test]
    fn fires_download_and_execute_across_siblings() {
        let tree = tree();
        let mut c = Correlator::new();
        let t0 = Instant::now();

        // S0: the shell (anchor 200).
        assert!(c.observe(&shell(), &tree, t0).is_empty());
        // S1: curl (pid 301), a child of the shell.
        let dl = EventFacts {
            pid: Some(301),
            is_downloader_exec: true,
            ..Default::default()
        };
        assert!(c
            .observe(&dl, &tree, t0 + Duration::from_secs(1))
            .is_empty());
        // S2: exec of /tmp/x (pid 302), a sibling.
        let ex = EventFacts {
            pid: Some(302),
            is_temp_exec: true,
            ..Default::default()
        };
        let done = c.observe(&ex, &tree, t0 + Duration::from_secs(2));
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].def().id, "ioa.download_and_execute");
        assert_eq!(done[0].stages.len(), 3);
        assert_eq!(done[0].final_pid, 302);
    }

    #[test]
    fn does_not_fire_out_of_order() {
        let tree = tree();
        let mut c = Correlator::new();
        let t0 = Instant::now();
        // Downloader before any shell — no S0 yet, so nothing advances.
        let dl = EventFacts {
            pid: Some(301),
            is_downloader_exec: true,
            ..Default::default()
        };
        assert!(c.observe(&dl, &tree, t0).is_empty());
        let ex = EventFacts {
            pid: Some(302),
            is_temp_exec: true,
            ..Default::default()
        };
        assert!(c.observe(&ex, &tree, t0).is_empty());
    }

    #[test]
    fn expires_after_window() {
        let tree = tree();
        let mut c = Correlator::new();
        let t0 = Instant::now();
        c.observe(&shell(), &tree, t0);
        let dl = EventFacts {
            pid: Some(301),
            is_downloader_exec: true,
            ..Default::default()
        };
        c.observe(&dl, &tree, t0 + Duration::from_secs(1));
        // The payload exec arrives after the window — partial has expired.
        let ex = EventFacts {
            pid: Some(302),
            is_temp_exec: true,
            ..Default::default()
        };
        let done = c.observe(&ex, &tree, t0 + CHAIN_WINDOW + Duration::from_secs(1));
        assert!(
            done.is_empty(),
            "a chain must not complete outside its window"
        );
    }

    #[test]
    fn unrelated_subtree_does_not_advance() {
        // 999 is not in the bash session subtree of 200.
        let mut tree = tree();
        let now = Instant::now();
        tree.on_exec(999, 1, 0, 0, "root", "x", "/tmp/x", "/tmp/x", now);
        let mut c = Correlator::new();
        let t0 = Instant::now();
        c.observe(&shell(), &tree, t0);
        let dl = EventFacts {
            pid: Some(301),
            is_downloader_exec: true,
            ..Default::default()
        };
        c.observe(&dl, &tree, t0 + Duration::from_secs(1));
        // Temp exec by an unrelated process must not complete the shell's chain.
        let ex = EventFacts {
            pid: Some(999),
            is_temp_exec: true,
            ..Default::default()
        };
        assert!(c
            .observe(&ex, &tree, t0 + Duration::from_secs(2))
            .is_empty());
    }

    #[test]
    fn cooldown_suppresses_repeat_storms() {
        let tree = tree();
        let mut c = Correlator::new();
        let t0 = Instant::now();
        let drive = |c: &mut Correlator, base: Instant| {
            c.observe(&shell(), &tree, base);
            let dl = EventFacts {
                pid: Some(301),
                is_downloader_exec: true,
                ..Default::default()
            };
            c.observe(&dl, &tree, base + Duration::from_millis(10));
            let ex = EventFacts {
                pid: Some(302),
                is_temp_exec: true,
                ..Default::default()
            };
            c.observe(&ex, &tree, base + Duration::from_millis(20))
        };
        assert_eq!(drive(&mut c, t0).len(), 1, "first run fires");
        // Re-driving the same (chain, anchor) inside the cooldown is suppressed.
        assert_eq!(
            drive(&mut c, t0 + Duration::from_secs(5)).len(),
            0,
            "repeat within cooldown is suppressed"
        );
    }
}
