use anyhow::Result;
use async_trait::async_trait;
use inotify::{EventMask, Inotify, WatchMask};
use tokio::sync::mpsc::Sender;
use tracing::warn;
use uuid::Uuid;

use crate::collectors::Collector;
use crate::schema::{AgentEvent, EventAction, EventClass, EventData, FileEventData, Severity};

const WATCH_PATHS: &[&str] = &["/etc", "/bin", "/tmp"];

const WATCH_MASK: WatchMask = WatchMask::CREATE
    .union(WatchMask::DELETE)
    .union(WatchMask::MODIFY)
    .union(WatchMask::MOVED_FROM)
    .union(WatchMask::MOVED_TO);

pub struct FilesystemCollector;

impl FilesystemCollector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FilesystemCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Collector for FilesystemCollector {
    fn name(&self) -> &'static str {
        "FilesystemCollector"
    }

    async fn run(
        &mut self,
        tx:       Sender<AgentEvent>,
        agent_id: Uuid,
        hostname: String,
    ) -> Result<()> {
        // Internal channel: blocking inotify thread → async event consumer
        let (fs_tx, mut fs_rx) =
            tokio::sync::mpsc::channel::<(EventAction, String)>(256);

        std::thread::spawn(move || {
            let mut inotify = match Inotify::init() {
                Ok(i)  => i,
                Err(e) => { warn!("FilesystemCollector: inotify init failed: {e}"); return; }
            };

            // Map watch descriptor → watched directory path
            let mut wd_to_path = std::collections::HashMap::new();
            for &path in WATCH_PATHS {
                match inotify.watches().add(path, WATCH_MASK) {
                    Ok(wd) => { wd_to_path.insert(wd, path); }
                    Err(e) => warn!("FilesystemCollector: cannot watch {path}: {e}"),
                }
            }

            let mut buf = [0u8; 4096];
            loop {
                let events = match inotify.read_events_blocking(&mut buf) {
                    Ok(e)  => e,
                    Err(e) => { warn!("FilesystemCollector: inotify read error: {e}"); break; }
                };

                for event in events {
                    let action = mask_to_action(event.mask);
                    let action = match action {
                        Some(a) => a,
                        None    => continue,
                    };

                    let dir = wd_to_path
                        .get(&event.wd)
                        .copied()
                        .unwrap_or("unknown");

                    let path = match event.name {
                        Some(name) => format!("{dir}/{}", name.to_string_lossy()),
                        None       => dir.to_string(),
                    };

                    if fs_tx.blocking_send((action, path)).is_err() {
                        return; // receiver dropped — agent is shutting down
                    }
                }
            }
        });

        // Async consumer: convert raw events to AgentEvents and forward to pipeline
        while let Some((action, path)) = fs_rx.recv().await {
            let event = AgentEvent::new(
                agent_id,
                hostname.clone(),
                EventClass::Filesystem,
                action,
                Severity::Info,
                EventData::FileEvent(FileEventData { path }),
            );
            if tx.send(event).await.is_err() {
                return Ok(());
            }
        }

        Ok(())
    }
}

fn mask_to_action(mask: EventMask) -> Option<EventAction> {
    if mask.contains(EventMask::CREATE) || mask.contains(EventMask::MOVED_TO) {
        Some(EventAction::Create)
    } else if mask.contains(EventMask::DELETE) || mask.contains(EventMask::MOVED_FROM) {
        Some(EventAction::Delete)
    } else if mask.contains(EventMask::MODIFY) {
        Some(EventAction::Modify)
    } else {
        None
    }
}
