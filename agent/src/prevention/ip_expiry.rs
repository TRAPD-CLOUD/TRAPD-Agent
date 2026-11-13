//! Durable Linux IP-block leases. One mutex serializes prepare/effect/commit
//! with expiry; a previous generation can never delete a newer lease.
//!
//! Uncertain installs retain both leases and use the later deadline (an
//! indefinite lease wins). Recovery never retries an unconfirmed installation.
//! Explicit removal is journaled before touching the firewall and is retryable.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_ENTRIES: usize = 2048;
const MAX_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TTL: u64 = 366 * 24 * 60 * 60;
const MAX_EFFECTS_PER_PASS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    generation: Uuid,
    deadline: Option<u64>,
    command_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Installing,
    Active,
    Removing,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    lease: Lease,
    phase: Phase,
    previous: Option<Lease>,
}

impl Entry {
    fn effective_lease(&self) -> Lease {
        let mut lease = self.lease.clone();
        if let Some(previous) = &self.previous {
            lease.deadline = match (previous.deadline, lease.deadline) {
                (Some(old), Some(new)) => Some(old.max(new)),
                _ => None,
            };
        }
        lease
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    entries: BTreeMap<String, Entry>,
}

struct State {
    document: Document,
    healthy: bool,
    restored: BTreeMap<String, Uuid>,
}

pub struct Registry {
    path: PathBuf,
    state: Mutex<State>,
}

pub struct ExpiredBlock {
    pub target: String,
    pub command_id: String,
}

pub struct Reconciled {
    pub removed: Vec<ExpiredBlock>,
    pub active: Vec<String>,
    pub complete: bool,
}

impl Registry {
    pub fn open(path: &Path) -> Result<Self> {
        validate_parent(path)?;
        let document = match read_document(path) {
            Ok(document) => document,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                let document = Document {
                    version: 1,
                    entries: BTreeMap::new(),
                };
                crate::paths::write_atomic(path, &serde_json::to_vec(&document)?, 0o600)?;
                document
            }
            Err(error) => return Err(error),
        };
        Ok(Self {
            path: path.into(),
            state: Mutex::new(State {
                document,
                healthy: true,
                restored: BTreeMap::new(),
            }),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("IP expiry registry poisoned"))?;
        ensure!(state.healthy, "IP expiry registry requires recovery");
        match read_document(&self.path) {
            Ok(document) if document == state.document => Ok(state),
            _ => {
                state.healthy = false;
                Err(anyhow!(
                    "IP expiry registry changed or became unreadable; refusing firewall changes"
                ))
            }
        }
    }

    fn save(&self, state: &mut State, next: Document) -> Result<()> {
        // A failed durable rename/fsync may already have replaced the file.
        // Stop this instance instead of trusting either possible generation.
        let result = (|| {
            validate_parent(&self.path)?;
            ensure!(
                read_document(&self.path)? == state.document,
                "IP expiry registry changed during operation"
            );
            let bytes = serde_json::to_vec(&next)?;
            ensure!(
                bytes.len() as u64 <= MAX_BYTES,
                "IP expiry registry exceeds byte limit"
            );
            crate::paths::write_atomic(&self.path, &bytes, 0o600)
        })();
        if result.is_err() {
            state.healthy = false;
        }
        result?;
        state.document = next;
        Ok(())
    }

    /// Read-only fast path for the engine's existing in-memory firewall dedup.
    /// The engine supplies an IpAddr-derived canonical key. No effect is
    /// skipped for a finite, uncertain, removing or unhealthy lease.
    pub fn has_indefinite_lease(&self, target: &str) -> bool {
        self.state.lock().ok().is_some_and(|state| {
            state.healthy
                && state.document.entries.get(target).is_some_and(|entry| {
                    entry.phase == Phase::Active
                        && entry.lease.deadline.is_none()
                        && state.restored.get(target) == Some(&entry.lease.generation)
                })
        })
    }

    pub fn block(
        &self,
        target: &str,
        ttl: Option<u64>,
        command_id: &str,
        now: u64,
        mut install: impl FnMut(&str) -> Result<String>,
    ) -> Result<String> {
        let target = super::network::canonical_target(target)?;
        ensure!(
            command_id.len() <= 128 && !command_id.chars().any(char::is_control),
            "invalid IP lease command id"
        );
        let deadline = ttl
            .map(|ttl| {
                ensure!(ttl <= MAX_TTL, "IP block TTL exceeds 366 days");
                now.checked_add(ttl)
                    .filter(|value| *value <= i64::MAX as u64)
                    .context("IP block TTL exceeds timestamp range")
            })
            .transpose()?;
        let mut state = self.lock()?;
        ensure!(
            state.document.entries.contains_key(&target)
                || state.document.entries.len() < MAX_ENTRIES,
            "IP expiry registry is full"
        );
        if ttl.is_none()
            && state.document.entries.get(&target).is_some_and(|entry| {
                entry.phase == Phase::Active
                    && entry.lease.deadline.is_none()
                    && state.restored.get(&target) == Some(&entry.lease.generation)
            })
        {
            return Ok("existing durable indefinite IP block".into());
        }
        let previous = state
            .document
            .entries
            .get(&target)
            .map(Entry::effective_lease);
        let lease = Lease {
            generation: Uuid::new_v4(),
            deadline,
            command_id: command_id.into(),
        };
        let mut next = state.document.clone();
        next.entries.insert(
            target.clone(),
            Entry {
                lease: lease.clone(),
                phase: Phase::Installing,
                previous,
            },
        );
        self.save(&mut state, next)?;
        let handle = install(&target)?;
        let mut next = state.document.clone();
        let generation = lease.generation;
        next.entries.insert(
            target.clone(),
            Entry {
                lease,
                phase: Phase::Active,
                previous: None,
            },
        );
        self.save(&mut state, next)?;
        state.restored.insert(target, generation);
        Ok(handle)
    }

    pub fn unblock(&self, target: &str, mut remove: impl FnMut(&str) -> Result<()>) -> Result<()> {
        let target = super::network::canonical_target(target)?;
        let mut state = self.lock()?;
        ensure!(
            state.document.entries.contains_key(&target)
                || state.document.entries.len() < MAX_ENTRIES,
            "IP expiry registry is full"
        );
        let lease = state
            .document
            .entries
            .get(&target)
            .map(Entry::effective_lease)
            .unwrap_or_else(|| Lease {
                generation: Uuid::new_v4(),
                deadline: None,
                command_id: String::new(),
            });
        self.remove_locked(&mut state, &target, lease, &mut remove)
    }

    fn remove_locked(
        &self,
        state: &mut State,
        target: &str,
        lease: Lease,
        remove: &mut impl FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        let mut next = state.document.clone();
        next.entries.insert(
            target.into(),
            Entry {
                lease,
                phase: Phase::Removing,
                previous: None,
            },
        );
        self.save(state, next)?;
        remove(target)?;
        let mut next = state.document.clone();
        next.entries.remove(target);
        self.save(state, next)?;
        state.restored.remove(target);
        Ok(())
    }

    /// Restore confirmed active blocks once at startup. Periodic reconciliation
    /// only removes expired/current generations or retries durable removals.
    pub fn reconcile(
        &self,
        now: u64,
        restore: bool,
        mut install: impl FnMut(&str) -> Result<String>,
        mut remove: impl FnMut(&str) -> Result<()>,
    ) -> Result<Reconciled> {
        let mut state = self.lock()?;
        let entries = state.document.entries.clone();
        let mut result = Reconciled {
            removed: Vec::new(),
            active: Vec::new(),
            complete: true,
        };
        let started = std::time::Instant::now();
        let mut effects = 0;
        for (target, entry) in entries {
            let lease = entry.effective_lease();
            // The mutex spans every filesystem and firewall operation. Compare
            // the generation too so a future queued/snapshot caller stays safe.
            if state
                .document
                .entries
                .get(&target)
                .map(|current| current.lease.generation)
                != Some(entry.lease.generation)
            {
                continue;
            }
            let removing = entry.phase == Phase::Removing
                || lease.deadline.is_some_and(|deadline| now >= deadline);
            let restoring = restore
                && entry.phase == Phase::Active
                && state.restored.get(&target) != Some(&entry.lease.generation);
            // Bound every pass independently of registry capacity. Completed
            // restore generations are remembered in memory so the next pass
            // advances instead of repeatedly reinstalling its first targets.
            if (removing || restoring)
                && (effects >= MAX_EFFECTS_PER_PASS
                    || (effects > 0 && started.elapsed() >= std::time::Duration::from_secs(5)))
            {
                result.complete = false;
                break;
            }
            if removing {
                effects += 1;
                match self.remove_locked(&mut state, &target, lease.clone(), &mut remove) {
                    Ok(()) => result.removed.push(ExpiredBlock {
                        target,
                        command_id: lease.command_id,
                    }),
                    Err(error) => {
                        tracing::warn!(%target, %error, "IP lease removal requires retry or recovery");
                        result.complete = false;
                        break;
                    }
                }
            } else {
                if restoring {
                    effects += 1;
                    if let Err(error) = install(&target) {
                        tracing::warn!(%target, %error, "confirmed IP block restore requires retry");
                        result.complete = false;
                        break;
                    }
                    state
                        .restored
                        .insert(target.clone(), entry.lease.generation);
                }
                result.active.push(target);
            }
        }
        Ok(result)
    }
}

fn validate_parent(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let parent = path.parent().context("IP expiry path has no parent")?;
    let meta = std::fs::symlink_metadata(parent)?;
    ensure!(
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0,
        "IP expiry parent must be a private owned directory"
    );
    Ok(())
}

fn read_document(path: &Path) -> Result<Document> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.len() <= MAX_BYTES
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0,
        "unsafe IP expiry registry file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "IP expiry registry exceeds byte limit"
    );
    let document: Document =
        serde_json::from_slice(&bytes).context("corrupt IP expiry registry")?;
    ensure!(
        document.version == 1 && document.entries.len() <= MAX_ENTRIES,
        "invalid IP expiry registry version/capacity"
    );
    for (target, entry) in &document.entries {
        ensure!(
            super::network::canonical_target(target)? == *target,
            "noncanonical IP expiry target"
        );
        ensure!(
            entry.phase == Phase::Installing || entry.previous.is_none(),
            "invalid previous IP lease"
        );
        for lease in std::iter::once(&entry.lease).chain(entry.previous.iter()) {
            ensure!(
                lease.command_id.len() <= 128
                    && !lease.command_id.chars().any(char::is_control)
                    && lease
                        .deadline
                        .is_none_or(|deadline| deadline <= i64::MAX as u64),
                "invalid IP expiry lease"
            );
        }
    }
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::os::unix::fs::PermissionsExt;

    struct Fixture {
        path: PathBuf,
        rules: RefCell<BTreeSet<String>>,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("trapd-ip-expiry-{}", Uuid::new_v4()));
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                path: dir.join("leases.json"),
                rules: RefCell::new(BTreeSet::new()),
            }
        }
        fn install(&self, target: &str) -> Result<String> {
            self.rules.borrow_mut().insert(target.into());
            Ok(target.into())
        }
        fn remove(&self, target: &str) -> Result<()> {
            self.rules.borrow_mut().remove(target);
            Ok(())
        }
        fn reconcile(&self, registry: &Registry, now: u64, restore: bool) -> Reconciled {
            registry
                .reconcile(
                    now,
                    restore,
                    |target| self.install(target),
                    |target| self.remove(target),
                )
                .unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.path.parent().unwrap());
        }
    }

    #[test]
    fn renewed_lease_survives_the_old_deadline_and_restart() {
        let fixture = Fixture::new();
        let registry = Registry::open(&fixture.path).unwrap();
        registry
            .block("192.0.2.1", Some(5), "old", 100, |target| {
                fixture.install(target)
            })
            .unwrap();
        registry
            .block("192.0.2.1/32", Some(20), "renewed", 102, |target| {
                fixture.install(target)
            })
            .unwrap();
        drop(registry);
        let registry = Registry::open(&fixture.path).unwrap();
        assert!(fixture.reconcile(&registry, 106, true).removed.is_empty());
        assert!(fixture.rules.borrow().contains("192.0.2.1"));
        let expired = fixture.reconcile(&registry, 122, false).removed;
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].command_id, "renewed");
        assert!(fixture.rules.borrow().is_empty());
    }

    #[test]
    fn indefinite_replacement_invalidates_old_expiry_including_ipv6_aliases() {
        let fixture = Fixture::new();
        let registry = Registry::open(&fixture.path).unwrap();
        registry
            .block("2001:db8::1/128", Some(0), "old", 100, |target| {
                fixture.install(target)
            })
            .unwrap();
        registry
            .block("2001:0db8::1", None, "indefinite", 100, |target| {
                fixture.install(target)
            })
            .unwrap();
        drop(registry);
        let registry = Registry::open(&fixture.path).unwrap();
        assert!(fixture
            .reconcile(&registry, 999_999, true)
            .removed
            .is_empty());
        assert_eq!(
            fixture.rules.borrow().iter().cloned().collect::<Vec<_>>(),
            vec!["2001:db8::1"]
        );
    }

    #[test]
    fn restart_restores_confirmed_blocks_but_never_replays_uncertain_installs() {
        let fixture = Fixture::new();
        let registry = Registry::open(&fixture.path).unwrap();
        registry
            .block("192.0.2.1", Some(20), "confirmed", 100, |target| {
                fixture.install(target)
            })
            .unwrap();
        assert!(registry
            .block("192.0.2.2", Some(10), "failed", 100, |_| Err(anyhow!(
                "install failed"
            )))
            .is_err());
        fixture.rules.borrow_mut().clear();
        drop(registry);
        let registry = Registry::open(&fixture.path).unwrap();
        fixture.reconcile(&registry, 105, true);
        assert_eq!(
            fixture.rules.borrow().iter().cloned().collect::<Vec<_>>(),
            vec!["192.0.2.1"]
        );
        fixture.reconcile(&registry, 120, false);
        assert!(fixture.rules.borrow().is_empty());
        assert!(read_document(&fixture.path).unwrap().entries.is_empty());
    }

    #[test]
    fn corrupt_state_and_deadline_overflow_refuse_firewall_effects() {
        let fixture = Fixture::new();
        let registry = Registry::open(&fixture.path).unwrap();
        for (ttl, now) in [(MAX_TTL + 1, 0), (1, u64::MAX)] {
            assert!(registry
                .block("192.0.2.1", Some(ttl), "overflow", now, |target| fixture
                    .install(target))
                .is_err());
        }
        assert!(fixture.rules.borrow().is_empty());
        std::fs::write(&fixture.path, b"{broken").unwrap();
        assert!(registry
            .block("192.0.2.1", Some(1), "corrupt", 100, |target| fixture
                .install(target))
            .is_err());
        assert!(registry
            .reconcile(
                100,
                true,
                |target| fixture.install(target),
                |target| fixture.remove(target)
            )
            .is_err());
        assert!(Registry::open(&fixture.path).is_err());
        assert!(fixture.rules.borrow().is_empty());
    }

    #[test]
    fn failed_post_install_commit_preserves_an_existing_indefinite_rule() {
        let fixture = Fixture::new();
        let registry = Registry::open(&fixture.path).unwrap();
        registry
            .block("192.0.2.1", None, "old-indefinite", 100, |target| {
                fixture.install(target)
            })
            .unwrap();
        let backup = fixture.path.with_extension("backup");
        assert!(registry
            .block("192.0.2.1", Some(0), "new-expiring", 100, |target| {
                fixture.install(target)?;
                std::fs::rename(&fixture.path, &backup)?;
                std::fs::create_dir(&fixture.path)?;
                Ok(target.into())
            })
            .is_err());
        assert!(
            fixture.rules.borrow().contains("192.0.2.1"),
            "failed commit must not roll back by removing the actual block"
        );
        assert!(registry
            .reconcile(
                200,
                false,
                |target| fixture.install(target),
                |target| fixture.remove(target)
            )
            .is_err());
        std::fs::remove_dir(&fixture.path).unwrap();
        std::fs::rename(backup, &fixture.path).unwrap();
        drop(registry);
        let registry = Registry::open(&fixture.path).unwrap();
        assert!(fixture.reconcile(&registry, 200, true).removed.is_empty());
        assert!(fixture.rules.borrow().contains("192.0.2.1"));
    }

    #[test]
    fn failed_removal_is_durable_and_cannot_restore_the_removed_lease() {
        let fixture = Fixture::new();
        let registry = Registry::open(&fixture.path).unwrap();
        registry
            .block("192.0.2.1/24", None, "block", 100, |target| {
                fixture.install(target)
            })
            .unwrap();
        assert!(registry
            .unblock("192.0.2.42/24", |_| Err(anyhow!("unblock failed")))
            .is_err());
        drop(registry);
        let registry = Registry::open(&fixture.path).unwrap();
        fixture.reconcile(&registry, 100, true);
        assert!(fixture.rules.borrow().is_empty());
        assert!(read_document(&fixture.path).unwrap().entries.is_empty());
    }

    #[test]
    fn registry_capacity_is_bounded_before_any_new_firewall_effect() {
        let fixture = Fixture::new();
        let registry = Registry::open(&fixture.path).unwrap();
        let mut document = read_document(&fixture.path).unwrap();
        for index in 0..MAX_ENTRIES {
            document.entries.insert(
                format!("10.0.{}.{}", index / 256, index % 256),
                Entry {
                    lease: Lease {
                        generation: Uuid::new_v4(),
                        deadline: None,
                        command_id: "fixture".into(),
                    },
                    phase: Phase::Active,
                    previous: None,
                },
            );
        }
        crate::paths::write_atomic(
            &fixture.path,
            &serde_json::to_vec(&document).unwrap(),
            0o600,
        )
        .unwrap();
        drop(registry);
        let registry = Registry::open(&fixture.path).unwrap();
        assert!(registry
            .block("192.0.2.1", Some(10), "full", 100, |target| fixture
                .install(target))
            .is_err());
        assert!(fixture.rules.borrow().is_empty());
    }
    #[test]
    fn one_firewall_failure_does_not_hide_completed_expirations_or_restore_progress() {
        let fixture = Fixture::new();
        let registry = Registry::open(&fixture.path).unwrap();
        for ip in ["192.0.2.1", "192.0.2.2"] {
            registry
                .block(ip, Some(1), "expiry", 100, |target| fixture.install(target))
                .unwrap();
        }
        let result = registry
            .reconcile(
                101,
                false,
                |target| fixture.install(target),
                |target| {
                    if target == "192.0.2.2" {
                        return Err(anyhow!("transient firewall failure"));
                    }
                    fixture.remove(target)
                },
            )
            .unwrap();
        assert!(!result.complete);
        assert_eq!(result.removed.len(), 1);
        assert_eq!(result.removed[0].target, "192.0.2.1");
        assert!(fixture.reconcile(&registry, 101, false).complete);
        assert!(fixture.rules.borrow().is_empty());
        registry
            .block("192.0.2.3", None, "restore", 100, |target| {
                fixture.install(target)
            })
            .unwrap();
        fixture.rules.borrow_mut().clear();
        drop(registry);
        let registry = Registry::open(&fixture.path).unwrap();
        let result = registry
            .reconcile(
                102,
                true,
                |_| Err(anyhow!("restore failed")),
                |target| fixture.remove(target),
            )
            .unwrap();
        assert!(!result.complete);
        assert!(fixture.reconcile(&registry, 102, true).complete);
        assert!(fixture.rules.borrow().contains("192.0.2.3"));
    }
    #[test]
    fn expired_lease_is_removed_on_restart_before_any_reinstallation() {
        let fixture = Fixture::new();
        let registry = Registry::open(&fixture.path).unwrap();
        registry
            .block("192.0.2.1", Some(0), "expired", 100, |target| {
                fixture.install(target)
            })
            .unwrap();
        drop(registry);
        let registry = Registry::open(&fixture.path).unwrap();
        let removed = registry
            .reconcile(
                100,
                true,
                |_| panic!("expired blocks must never be restored"),
                |target| fixture.remove(target),
            )
            .unwrap();
        assert_eq!(removed.removed.len(), 1);
        assert!(fixture.rules.borrow().is_empty());
    }

    #[test]
    fn failed_preparation_preserves_the_existing_rule_without_installing_a_replacement() {
        let fixture = Fixture::new();
        let registry = Registry::open(&fixture.path).unwrap();
        registry
            .block("192.0.2.1", None, "existing", 100, |target| {
                fixture.install(target)
            })
            .unwrap();
        std::fs::write(&fixture.path, b"invalid state").unwrap();
        assert!(registry
            .block("192.0.2.1/32", Some(1), "replacement", 100, |_| panic!(
                "failed preparation must precede every firewall effect"
            ))
            .is_err());
        assert!(fixture.rules.borrow().contains("192.0.2.1"));
    }
    #[test]
    fn restore_and_expiry_passes_are_bounded_and_advance_without_repeating_effects() {
        let fixture = Fixture::new();
        let registry = Registry::open(&fixture.path).unwrap();
        for index in 1..=MAX_EFFECTS_PER_PASS + 3 {
            registry
                .block(
                    &format!("192.0.2.{index}"),
                    Some(10),
                    "bounded",
                    100,
                    |target| fixture.install(target),
                )
                .unwrap();
        }
        drop(registry);
        let registry = Registry::open(&fixture.path).unwrap();
        let restored = RefCell::new(Vec::new());
        let first = registry
            .reconcile(
                101,
                true,
                |target| {
                    restored.borrow_mut().push(target.to_string());
                    fixture.install(target)
                },
                |target| fixture.remove(target),
            )
            .unwrap();
        assert!(!first.complete);
        assert_eq!(restored.borrow().len(), MAX_EFFECTS_PER_PASS);
        assert!(!registry.has_indefinite_lease("192.0.2.1"));
        let second = registry
            .reconcile(
                101,
                true,
                |target| {
                    restored.borrow_mut().push(target.to_string());
                    fixture.install(target)
                },
                |target| fixture.remove(target),
            )
            .unwrap();
        assert!(second.complete);
        let calls = restored.borrow();
        assert_eq!(calls.len(), MAX_EFFECTS_PER_PASS + 3);
        assert_eq!(
            calls.iter().collect::<BTreeSet<_>>().len(),
            calls.len(),
            "restored generations must not be replayed in later passes"
        );
        assert!(!fixture.reconcile(&registry, 110, false).complete);
        assert!(fixture.reconcile(&registry, 110, false).complete);
        assert!(fixture.rules.borrow().is_empty());
    }
}
