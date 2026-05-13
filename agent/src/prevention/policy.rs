//! IoC (Indicator-of-Compromise) policy: data model, matchers and store.
//!
//! Rules can come from two places:
//!
//!   * `/etc/trapd/policy.json` — local boot-time rules (operator-managed)
//!   * Backend `update_policy` commands — pushed at runtime, Ed25519-signed
//!
//! Both sources merge into a single in-memory `PolicyStore` behind an
//! `Arc<RwLock<…>>`.  Matchers are designed to be cheap enough to evaluate on
//! every exec/connect/dns event in the hot path.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// What to do when a rule matches.  `Block` triggers the active response
/// (kill / drop / quarantine); `Alert` only emits an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Block,
    Alert,
}

/// A single IoC rule.  The `type` discriminator is the on-the-wire string.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IocRule {
    /// SHA256 of the executable on disk (lower-case hex, no "sha256:" prefix).
    Sha256       { id: String, value: String, action: RuleAction },
    /// Shell-style glob against the absolute exe path (e.g. `/tmp/**/*.sh`).
    PathGlob     { id: String, value: String, action: RuleAction },
    /// Exact match against the kernel `comm` field (max 15 chars + NUL).
    Comm         { id: String, value: String, action: RuleAction },
    /// Parent comm + child comm pair (e.g. word/excel → bash).
    ParentChild  { id: String, parent: String, child: String, action: RuleAction },
    /// Single IP literal (v4 or v6).
    Ip           { id: String, value: IpAddr, action: RuleAction },
    /// IP network in CIDR form (e.g. `185.220.101.0/24`).
    Cidr         { id: String, value: IpNet, action: RuleAction },
    /// Destination port (TCP/UDP).
    Port         { id: String, value: u16, action: RuleAction },
    /// Fully-qualified domain (case-insensitive, exact match on DNS qname).
    Domain       { id: String, value: String, action: RuleAction },
}

#[allow(dead_code)]
impl IocRule {
    pub fn id(&self) -> &str {
        match self {
            IocRule::Sha256      { id, .. }
            | IocRule::PathGlob  { id, .. }
            | IocRule::Comm      { id, .. }
            | IocRule::ParentChild { id, .. }
            | IocRule::Ip        { id, .. }
            | IocRule::Cidr      { id, .. }
            | IocRule::Port      { id, .. }
            | IocRule::Domain    { id, .. } => id,
        }
    }

    pub fn action(&self) -> RuleAction {
        match self {
            IocRule::Sha256      { action, .. }
            | IocRule::PathGlob  { action, .. }
            | IocRule::Comm      { action, .. }
            | IocRule::ParentChild { action, .. }
            | IocRule::Ip        { action, .. }
            | IocRule::Cidr      { action, .. }
            | IocRule::Port      { action, .. }
            | IocRule::Domain    { action, .. } => *action,
        }
    }
}

/// A matched rule plus a human-readable explanation.
#[derive(Debug, Clone)]
pub struct Match {
    pub rule_id: String,
    pub action:  RuleAction,
    pub reason:  String,
}

/// Snapshot of the in-memory rule index.  Designed for read-mostly access:
/// rebuilt wholesale on policy update, read lock-free on every event.
#[derive(Default, Debug, Clone)]
pub struct PolicyStore {
    sha256:    HashSet<String>,
    comm:      HashSet<String>,
    parent_child: Vec<(String, String, String, RuleAction)>,
    path_globs:   Vec<(String, GlobMatcher, RuleAction)>,
    ips:       Vec<(String, IpAddr, RuleAction)>,
    cidrs:     Vec<(String, IpNet,  RuleAction)>,
    ports:     Vec<(String, u16,    RuleAction)>,
    domains:   HashSet<String>,
    raw:       Vec<IocRule>,
}

impl PolicyStore {
    pub fn from_rules(rules: Vec<IocRule>) -> Result<Self> {
        let mut store = PolicyStore::default();
        for r in &rules {
            store.index(r)?;
        }
        store.raw = rules;
        Ok(store)
    }

    fn index(&mut self, r: &IocRule) -> Result<()> {
        match r {
            IocRule::Sha256 { value, .. } => {
                self.sha256.insert(value.to_ascii_lowercase());
            }
            IocRule::Comm { value, .. } => {
                self.comm.insert(value.clone());
            }
            IocRule::ParentChild { parent, child, id, action } => {
                self.parent_child
                    .push((parent.clone(), child.clone(), id.clone(), *action));
            }
            IocRule::PathGlob { id, value, action } => {
                let g = Glob::new(value)
                    .with_context(|| format!("invalid path glob in rule {id}: {value}"))?
                    .compile_matcher();
                self.path_globs.push((id.clone(), g, *action));
            }
            IocRule::Ip   { id, value, action } => self.ips  .push((id.clone(), *value, *action)),
            IocRule::Cidr { id, value, action } => self.cidrs.push((id.clone(), *value, *action)),
            IocRule::Port { id, value, action } => self.ports.push((id.clone(), *value, *action)),
            IocRule::Domain { value, .. } => {
                self.domains.insert(value.to_ascii_lowercase());
            }
        }
        Ok(())
    }

    pub fn rules(&self) -> &[IocRule] { &self.raw }
    #[allow(dead_code)]
    pub fn comm_set(&self) -> &HashSet<String> { &self.comm }

    /// Match a process exec event.  Returns the highest-severity match
    /// (`Block` wins over `Alert`).
    pub fn match_exec(
        &self,
        exe_path:    &str,
        comm:        &str,
        parent_comm: Option<&str>,
        sha256_hex:  Option<&str>,
    ) -> Option<Match> {
        let mut best: Option<Match> = None;

        if let Some(h) = sha256_hex {
            if self.sha256.contains(&h.to_ascii_lowercase()) {
                best = upgrade(best, Match {
                    rule_id: format!("sha256:{h}"),
                    action:  RuleAction::Block,
                    reason:  format!("SHA256 match: {h}"),
                });
            }
        }

        if self.comm.contains(comm) {
            best = upgrade(best, Match {
                rule_id: format!("comm:{comm}"),
                action:  RuleAction::Block,
                reason:  format!("comm match: {comm}"),
            });
        }

        for (id, glob, action) in &self.path_globs {
            if glob.is_match(exe_path) {
                best = upgrade(best, Match {
                    rule_id: id.clone(),
                    action:  *action,
                    reason:  format!("path glob {} matched {}", glob.glob().glob(), exe_path),
                });
            }
        }

        if let Some(parent) = parent_comm {
            for (p, c, id, action) in &self.parent_child {
                if p == parent && c == comm {
                    best = upgrade(best, Match {
                        rule_id: id.clone(),
                        action:  *action,
                        reason:  format!("parent/child pair {parent}/{comm}"),
                    });
                }
            }
        }

        best
    }

    /// Match a network destination.
    #[allow(dead_code)]
    pub fn match_network(&self, addr: IpAddr, port: u16) -> Option<Match> {
        let mut best: Option<Match> = None;
        for (id, ip, action) in &self.ips {
            if *ip == addr {
                best = upgrade(best, Match {
                    rule_id: id.clone(),
                    action:  *action,
                    reason:  format!("IP match: {addr}"),
                });
            }
        }
        for (id, cidr, action) in &self.cidrs {
            if cidr.contains(&addr) {
                best = upgrade(best, Match {
                    rule_id: id.clone(),
                    action:  *action,
                    reason:  format!("CIDR match: {addr} ∈ {cidr}"),
                });
            }
        }
        for (id, p, action) in &self.ports {
            if *p == port {
                best = upgrade(best, Match {
                    rule_id: id.clone(),
                    action:  *action,
                    reason:  format!("port match: {port}"),
                });
            }
        }
        best
    }

    /// Match a DNS query name (case-insensitive exact match).
    #[allow(dead_code)]
    pub fn match_domain(&self, qname: &str) -> Option<Match> {
        let q = qname.to_ascii_lowercase();
        if self.domains.contains(&q) {
            Some(Match {
                rule_id: format!("domain:{q}"),
                action:  RuleAction::Block,
                reason:  format!("domain match: {q}"),
            })
        } else {
            None
        }
    }
}

/// `Block` outranks `Alert`; otherwise keep the first match.
fn upgrade(current: Option<Match>, new: Match) -> Option<Match> {
    match current {
        None => Some(new),
        Some(c) => {
            if c.action == RuleAction::Block || new.action != RuleAction::Block {
                Some(c)
            } else {
                Some(new)
            }
        }
    }
}

/// Shared, atomically-replaceable policy handle.
#[derive(Clone, Default)]
pub struct PolicyHandle {
    inner: Arc<RwLock<PolicyStore>>,
}

impl PolicyHandle {
    pub fn new(store: PolicyStore) -> Self {
        Self { inner: Arc::new(RwLock::new(store)) }
    }

    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, PolicyStore> {
        self.inner.read().expect("policy lock poisoned")
    }

    pub fn replace(&self, store: PolicyStore) {
        if let Ok(mut g) = self.inner.write() {
            *g = store;
        } else {
            warn!("policy write lock poisoned — policy not updated");
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    #[serde(default)]
    pub rules: Vec<IocRule>,
}

/// Load `/etc/trapd/policy.json` if present.  Missing file is **not** an
/// error: prevention starts with an empty rule set and waits for backend
/// commands.
pub fn load_local_policy(path: &Path) -> Result<PolicyStore> {
    if !path.exists() {
        info!(path = %path.display(), "no local IoC policy file — starting empty");
        return Ok(PolicyStore::default());
    }
    let bytes = std::fs::read(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let file: PolicyFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;
    let n = file.rules.len();
    let store = PolicyStore::from_rules(file.rules)?;
    info!(path = %path.display(), rules = n, "Local IoC policy loaded");
    Ok(store)
}
