use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use inotify::{EventMask, Inotify, WatchMask};
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};

use crate::collectors::Collector;
use crate::schema::{AgentEvent, AgentTamperData, EventAction, EventClass, EventData, Severity};

/// Directories whose contents are made immutable with `chattr +i` at startup.
const IMMUTABLE_FILES: &[&str] = &[
    "/etc/trapd/agent.conf",
    "/etc/trapd/credentials",
    "/etc/trapd/enrollment.json",
];

const WATCH_MASK: WatchMask = WatchMask::CREATE
    .union(WatchMask::DELETE)
    .union(WatchMask::MODIFY)
    .union(WatchMask::MOVED_FROM)
    .union(WatchMask::MOVED_TO)
    .union(WatchMask::ATTRIB);

pub struct AgentProtectCollector {
    /// ~/.trapd directory to monitor.
    home_trapd: PathBuf,
}

impl AgentProtectCollector {
    pub fn new() -> Self {
        let home_trapd = std::env::var("HOME")
            .map(|h| PathBuf::from(h).join(".trapd"))
            .unwrap_or_else(|_| PathBuf::from("/var/lib/trapd"));
        Self { home_trapd }
    }
}

impl Default for AgentProtectCollector {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl Collector for AgentProtectCollector {
    fn name(&self) -> &'static str { "AgentProtectCollector" }

    async fn run(
        &mut self,
        tx:       Sender<AgentEvent>,
        agent_id: String,
        hostname: String,
    ) -> Result<()> {
        let home_trapd = self.home_trapd.clone();
        let (ap_tx, mut ap_rx) = tokio::sync::mpsc::channel::<AgentEvent>(64);

        std::thread::spawn(move || {
            run_protect_sync(ap_tx, agent_id, hostname, home_trapd);
        });

        while let Some(event) = ap_rx.recv().await {
            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }
        Ok(())
    }
}

fn run_protect_sync(
    tx:         tokio::sync::mpsc::Sender<AgentEvent>,
    agent_id:   String,
    hostname:   String,
    home_trapd: PathBuf,
) {
    // Apply chattr +i to critical agent files.
    apply_immutable_flags();

    let mut inotify = match Inotify::init() {
        Ok(i)  => i,
        Err(e) => { warn!("AgentProtectCollector: inotify init failed: {e}"); return; }
    };

    let mut wd_map: HashMap<inotify::WatchDescriptor, String> = HashMap::new();

    // Watch ~/.trapd/ if it exists.
    let home_str = home_trapd.to_string_lossy().into_owned();
    if home_trapd.exists() {
        match inotify.watches().add(&home_trapd, WATCH_MASK) {
            Ok(wd) => { wd_map.insert(wd, home_str.clone()); }
            Err(e) => warn!("AgentProtectCollector: cannot watch {home_str}: {e}"),
        }
        info!("AgentProtectCollector: watching {home_str} for tampering");
    }

    let mut buf = [0u8; 4096];
    loop {
        let events = match inotify.read_events_blocking(&mut buf) {
            Ok(e)  => e,
            Err(e) => { warn!("AgentProtectCollector: inotify read error: {e}"); break; }
        };

        for event in events {
            let dir = match wd_map.get(&event.wd) {
                Some(d) => d.clone(),
                None    => continue,
            };
            let path = match &event.name {
                Some(name) => format!("{dir}/{}", name.to_string_lossy()),
                None       => dir.clone(),
            };
            let mask = event.mask;

            let action_str = if mask.contains(EventMask::DELETE) || mask.contains(EventMask::MOVED_FROM) {
                "delete"
            } else if mask.contains(EventMask::CREATE) || mask.contains(EventMask::MOVED_TO) {
                "create"
            } else if mask.contains(EventMask::ATTRIB) {
                // chattr removal detected
                "modify"
            } else {
                "modify"
            };

            let ev = AgentEvent::new(
                agent_id.clone(), hostname.clone(),
                EventClass::Filesystem, EventAction::AgentTamper, Severity::Critical,
                EventData::AgentTamper(AgentTamperData {
                    path: path.clone(), action: action_str.to_string(),
                }),
            );
            if tx.blocking_send(ev).is_err() { return; }

            // Re-apply immutable flag if an immutable file was tampered with.
            if (mask.contains(EventMask::ATTRIB) || mask.contains(EventMask::MODIFY))
                && IMMUTABLE_FILES.contains(&path.as_str())
            {
                apply_chattr_immutable(&path);
            }
        }
    }
}

/// Attempt to make critical agent config files immutable via `chattr +i`.
/// Requires CAP_LINUX_IMMUTABLE (root). Failures are logged as warnings.
fn apply_immutable_flags() {
    for &file in IMMUTABLE_FILES {
        if std::path::Path::new(file).exists() {
            apply_chattr_immutable(file);
        }
    }
}

fn apply_chattr_immutable(path: &str) {
    match std::process::Command::new("chattr").args(["+i", path]).output() {
        Ok(out) if out.status.success() =>
            info!("AgentProtectCollector: chattr +i applied to {path}"),
        Ok(out) =>
            warn!(
                "AgentProtectCollector: chattr +i failed for {path}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        Err(e) =>
            warn!("AgentProtectCollector: cannot run chattr: {e}"),
    }
}
