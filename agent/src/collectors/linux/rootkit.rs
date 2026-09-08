//! Periodic rootkit and host-tampering sweeps.
//!
//! Drives the cross-view detectors in [`crate::rootkit`] on a timer. All of the
//! reads are blocking (`/proc` walks, netlink dumps, digest computation) and
//! run on the blocking pool so a sweep never stalls the telemetry pipeline.
//!
//! The sweeps do **not** require eBPF. The kernel view enriches them and adds
//! the "seen loading, never listed" and "bound but invisible" checks, but the
//! `/proc`-versus-netlink and package-digest comparisons stand on their own, so
//! the collector is worth running on hosts where the eBPF programs cannot load.

use std::time::Instant;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc::Sender;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::collectors::Collector;
use crate::rootkit::{
    binaries, hidden_process, hidden_socket,
    kernel_view::kernel_view,
    modules::{self, ModuleHistory, TreeSnapshot},
    Corroborator, Finding, RootkitConfig,
};
use crate::schema::AgentEvent;

pub struct RootkitCollector {
    cfg: RootkitConfig,
    corroborator: Corroborator,
    module_history: ModuleHistory,
    /// `None` until the first sweep: a first look must establish the tree, not
    /// report every module file on the host as newly added.
    module_tree: Option<TreeSnapshot>,
    last_integrity_sweep: Option<Instant>,
}

impl RootkitCollector {
    pub fn new() -> Self {
        let cfg = RootkitConfig::from_env();
        Self {
            corroborator: Corroborator::new(cfg.corroboration),
            cfg,
            module_history: ModuleHistory::default(),
            module_tree: None,
            last_integrity_sweep: None,
        }
    }

    async fn sweep(&mut self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // ── Hidden processes ────────────────────────────────────────────────
        let cfg = self.cfg.clone();
        let sightings = kernel_view().processes();
        let hidden = tokio::task::spawn_blocking(move || {
            let views = hidden_process::gather(&cfg, &sightings);
            hidden_process::analyze(&views, &hidden_process::HostProbe)
        })
        .await
        .unwrap_or_default();
        findings.extend(hidden_process::findings(&hidden));

        // ── Hidden sockets ──────────────────────────────────────────────────
        let binds = kernel_view().binds();
        let socket_findings = tokio::task::spawn_blocking(move || {
            hidden_socket::analyze(&hidden_socket::gather(&binds))
        })
        .await
        .unwrap_or_default();
        findings.extend(socket_findings);

        // ── Kernel modules ──────────────────────────────────────────────────
        let loaded = kernel_view().modules();
        if let Ok((views, tree)) =
            tokio::task::spawn_blocking(move || modules::gather(&loaded)).await
        {
            findings.extend(modules::analyze(&views, &mut self.module_history));
            match &self.module_tree {
                Some(previous) => findings.extend(modules::analyze_tree(previous, &tree)),
                None => debug!(
                    files = tree.len(),
                    "rootkit: module tree baseline established"
                ),
            }
            self.module_tree = Some(tree);
        }

        // ── Critical binary integrity ───────────────────────────────────────
        // Much heavier than the other sweeps (digests plus the package
        // database), so it runs on its own, slower schedule.
        let due = self
            .last_integrity_sweep
            .map(|last| last.elapsed() >= self.cfg.integrity_interval)
            .unwrap_or(true);
        if due {
            self.last_integrity_sweep = Some(Instant::now());
            let state_dir = crate::paths::state_dir().to_path_buf();
            let integrity = tokio::task::spawn_blocking(move || binaries::sweep(&state_dir))
                .await
                .unwrap_or_default();
            findings.extend(integrity);
        }

        findings
    }
}

impl Default for RootkitCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for RootkitCollector {
    fn name(&self) -> &'static str {
        "RootkitCollector"
    }

    async fn run(
        &mut self,
        tx: Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        if !self.cfg.enabled {
            info!("rootkit detection disabled via TRAPD_ROOTKIT");
            return Ok(());
        }

        info!(
            interval_secs = self.cfg.interval.as_secs(),
            integrity_interval_secs = self.cfg.integrity_interval.as_secs(),
            pid_scan_max = self.cfg.pid_scan_max,
            corroboration = self.cfg.corroboration,
            "rootkit cross-view sweeps enabled"
        );

        let mut ticker = interval(self.cfg.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            let started = Instant::now();
            let findings = self.sweep().await;
            let candidates = findings.len();
            let confirmed = self.corroborator.observe(findings);

            debug!(
                candidates,
                confirmed = confirmed.len(),
                elapsed_ms = started.elapsed().as_millis(),
                "rootkit sweep complete"
            );

            for finding in confirmed {
                if tx
                    .send(finding.into_event(&agent_id, &hostname))
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }

            // A sweep taking a large fraction of its own interval competes with
            // the enrichment path for the same blocking pool.
            if started.elapsed() > self.cfg.interval / 2 {
                warn!(
                    elapsed_ms = started.elapsed().as_millis(),
                    interval_secs = self.cfg.interval.as_secs(),
                    "rootkit sweep is slow relative to its interval; consider raising \
                     TRAPD_ROOTKIT_INTERVAL_SECS or lowering TRAPD_ROOTKIT_PID_SCAN_MAX"
                );
            }
        }
    }
}
