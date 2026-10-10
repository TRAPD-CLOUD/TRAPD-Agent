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
    plan_events, snapshot, RegRoot, RegistryReader, Snapshot, StormGate, SPECS,
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
}

pub struct RegistryWatchCollector;

impl RegistryWatchCollector {
    pub fn new() -> Self {
        Self
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
        let mut previous: Option<Snapshot> = None;
        let mut gate = StormGate::default();
        let mut ticker = interval(POLL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
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
            let Some(prev) = previous.replace(current) else {
                info!("registry watcher baseline captured");
                continue;
            };
            let Some(cur) = previous.as_ref() else {
                continue;
            };
            for (action, data) in plan_events(&prev, cur, &mut gate, std::time::Instant::now()) {
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
                );
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}
