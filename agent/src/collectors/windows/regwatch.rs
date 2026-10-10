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
    encode_baseline, load_baseline, plan_events, retain_unavailable, snapshot, RegRoot,
    RegistryReader, Snapshot, StormGate, SPECS,
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
        let mut last_saved: Option<Vec<u8>> = None;
        let mut gate = StormGate::default();
        let mut ticker = interval(POLL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        'poll: loop {
            tokio::select! {
                _ = tx.closed() => return Ok(()),
                _ = ticker.tick() => {}
            }
            let current = match tokio::task::spawn_blocking(|| snapshot(&WinReader, SPECS)).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "registry snapshot panicked; skipping poll");
                    continue;
                }
            };
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
            for (action, data) in planned {
                let severity = if data.category == "storm" {
                    Severity::Low
                } else {
                    Severity::Info
                };
                let event = AgentEvent::new(
                    agent_id.clone(),
                    hostname.clone(),
                    EventClass::Registry,
                    action,
                    severity,
                    EventData::Registry(data),
                )
                .with_source("windows_registry_snapshot");
                if self.durable_handoff {
                    if crate::pipeline::receipt::send_durable(&tx, event)
                        .await
                        .is_err()
                    {
                        if tx.is_closed() {
                            return Ok(());
                        }
                        warn!("registry event not durably journaled; preserving baseline and retrying changes");
                        continue 'poll;
                    }
                } else if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }
            // Online, every planned event is fsynced before the baseline moves.
            // Offline retains the existing NDJSON output semantics.
            gate = next_gate;
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
