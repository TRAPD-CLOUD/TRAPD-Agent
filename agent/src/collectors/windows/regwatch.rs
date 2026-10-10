//! Windows registry persistence watcher. Reads the locations listed in
//! [`crate::collectors::registry_watch::SPECS`] every few seconds, diffs against
//! the previous snapshot and emits `class=registry` events for each changed
//! value. The first snapshot is the silent baseline.
//!
//! All pure logic (watch table, diff, storm protection) lives in
//! `collectors/registry_watch.rs`; this file only does the registry reads and
//! the event plumbing.

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tokio::time::{interval, Duration, MissedTickBehavior};
use tracing::{info, warn};

use super::registry::{self, Hive};
use crate::collectors::registry_watch::{
    encode_baseline, load_baseline, plan_events, retain_unavailable, snapshot_with_preferred_users,
    stable_event_id, PendingRegistryPoll, RegRoot, RegistryReader, Snapshot, StormGate, SPECS,
};
use crate::collectors::Collector;
use crate::schema::{AgentEvent, EventClass, EventData, Severity};

const POLL: Duration = Duration::from_secs(10);

struct WinReader;

impl WinReader {
    fn hive(root: RegRoot) -> Hive {
        match root {
            RegRoot::LocalMachine => Hive::LocalMachine,
            RegRoot::Users => Hive::Users,
        }
    }
}

impl RegistryReader for WinReader {
    fn subkeys(&self, root: RegRoot, path: &str) -> Vec<String> {
        registry::subkeys_in(Self::hive(root), path, 0)
    }
    fn values(&self, root: RegRoot, path: &str) -> Vec<(String, String)> {
        registry::values_in(Self::hive(root), path, 0)
    }
    fn checked_subkeys(&self, root: RegRoot, path: &str) -> Result<Vec<String>, u32> {
        registry::subkeys_checked(Self::hive(root), path, 0)
    }
    fn checked_values(&self, root: RegRoot, path: &str) -> Result<Vec<(String, String)>, u32> {
        registry::values_checked(Self::hive(root), path, 0)
    }
}

pub struct RegistryWatchCollector {
    durable_handoff: bool,
}

impl RegistryWatchCollector {
    pub fn new(durable_handoff: bool) -> Self {
        Self { durable_handoff }
    }
}

#[async_trait]
impl Collector for RegistryWatchCollector {
    fn name(&self) -> &'static str {
        "WindowsRegistryWatchCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let baseline_path = crate::paths::state_dir().join("windows_registry_baseline.json");
        let load_path = baseline_path.clone();
        let mut previous: Option<Snapshot> = match tokio::task::spawn_blocking(move || {
            load_baseline(&load_path)
        })
        .await
        {
            Ok(Ok(saved)) => saved,
            Ok(Err(_)) => {
                warn!("registry baseline rejected or unreadable; offline changes cannot be recovered; capturing a new baseline");
                None
            }
            Err(_) => {
                warn!("registry baseline load failed; capturing a new baseline");
                None
            }
        };
        // The persisted baseline: event ids derive from it, so a restart that
        // reloads the same file regenerates the same ids for the same changes.
        let mut last_saved: Option<Vec<u8>> = previous
            .as_ref()
            .and_then(|loaded| encode_baseline(loaded).ok());
        let mut gate = StormGate::default();
        let mut last_omitted_users = 0usize;
        let mut ticker = interval(POLL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut pending: Option<PendingRegistryPoll> = None;
        loop {
            tokio::select! {
                _ = tx.closed() => return Ok(()),
                _ = ticker.tick() => {}
            }
            if pending.is_none() {
                let preferred_users = previous
                    .as_ref()
                    .map(|previous| previous.users.clone())
                    .unwrap_or_default();
                let current = match tokio::task::spawn_blocking(move || {
                    snapshot_with_preferred_users(&WinReader, SPECS, &preferred_users)
                })
                .await
                {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "registry snapshot panicked; skipping poll");
                        continue;
                    }
                };
                if !current.unavailable.contains("HKU")
                    && current.omitted_users != last_omitted_users
                {
                    if current.omitted_users > 0 {
                        warn!(omitted_users = current.omitted_users, "registry loaded-user capacity exceeded; additional user hives are not monitored by snapshots; machine monitoring continues");
                    } else {
                        info!("registry loaded-user count returned within snapshot capacity");
                    }
                    last_omitted_users = current.omitted_users;
                }
                if current.incomplete {
                    warn!("registry snapshot exceeded tracking limit; preserving baseline and skipping poll");
                    continue;
                }
                if !current.unavailable.is_empty() {
                    warn!(
                        unavailable_scopes = current.unavailable.len(),
                        "registry reads incomplete; retaining last known values for unavailable scopes"
                    );
                }
                let next = match previous.as_ref() {
                    Some(prev) => match retain_unavailable(prev, current) {
                        Ok(next) => next,
                        Err(_) => {
                            warn!("registry retained baseline exceeded limits; preserving previous baseline and skipping poll");
                            continue;
                        }
                    },
                    None => {
                        info!("registry watcher initial baseline captured");
                        current
                    }
                };
                let saved = match encode_baseline(&next) {
                    Ok(saved) => saved,
                    Err(_) => {
                        warn!("registry snapshot cannot be persisted within limits; preserving baseline and skipping poll");
                        continue;
                    }
                };
                let mut next_gate = gate.clone();
                let planned = previous
                    .as_ref()
                    .map(|prev| plan_events(prev, &next, &mut next_gate, std::time::Instant::now()))
                    .unwrap_or_default();
                let epoch = last_saved.clone().unwrap_or_default();
                let events = planned
                    .into_iter()
                    .map(|(action, data)| {
                        let event_id = stable_event_id(&epoch, action.clone(), &data);
                        let severity = if data.category == "storm" {
                            Severity::Low
                        } else {
                            Severity::Info
                        };
                        let mut event = AgentEvent::new(
                            agent_id.clone(),
                            hostname.clone(),
                            EventClass::Registry,
                            action,
                            severity,
                            EventData::Registry(data),
                        )
                        .with_source("windows_registry_snapshot");
                        event.event_id = event_id;
                        event
                    })
                    .collect();
                pending = Some(PendingRegistryPoll::new(next, saved, next_gate, events));
            }
            let Some(poll) = pending.as_mut() else {
                continue;
            };
            if poll.handoff(&tx, self.durable_handoff).await.is_err() {
                if tx.is_closed() {
                    return Ok(());
                }
                warn!("registry event not durably journaled; preserving pending poll for retry");
                continue;
            }
            let Some(completed) = pending.take() else {
                continue;
            };
            let (next, saved, next_gate) = completed.into_checkpoint()?;
            // Online, every planned event is fsynced before the baseline moves.
            // Offline retains the existing NDJSON output semantics.
            gate = next_gate;
            if next.evicted_users > 0 {
                warn!(evicted_users = next.evicted_users, "registry baseline capacity discarded inactive user hives; reloaded evicted hives establish a new silent baseline");
            }
            previous = Some(next);
            if last_saved.as_ref() != Some(&saved) {
                let path = baseline_path.clone();
                let bytes = saved.clone();
                match tokio::task::spawn_blocking(move || {
                    crate::paths::write_atomic(&path, &bytes, 0o600)
                })
                .await
                {
                    Ok(Ok(())) => last_saved = Some(saved),
                    _ => {
                        warn!("registry baseline persistence failed; restart coverage is degraded")
                    }
                }
            }
        }
    }
}
