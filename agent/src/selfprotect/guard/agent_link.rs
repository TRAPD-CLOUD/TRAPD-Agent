//! The agent's side of the guard pair: ping the guard, watch it, restart it,
//! announce stops to it, and ship the records it (or this side) left behind.
//!
//! Started early in the process (before enrollment, which can wait for a human
//! to pair the device), so the guard never mistakes a pairing wait for a hang.
//! Events are attached later, once the pipeline and identity exist; records
//! wait in the spool directory until then.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};
use trapd_schema::AgentEvent;

use super::{
    classify, read_records, record_event, remove_record, NoticeKind, Peer, PeerMonitor, Ping,
    StopNotice, PING_INTERVAL, PROTOCOL_VERSION,
};
use crate::selfprotect::stop_marker::StopMarker;

#[cfg(any(windows, target_os = "linux"))]
use super::{control, ipc, supervise};

static STARTED: Once = Once::new();
static RUNNING: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_FLAG: OnceLock<std::sync::Arc<AtomicBool>> = OnceLock::new();
static SEQ: AtomicU64 = AtomicU64::new(0);
static STOP: Mutex<Option<StopNotice>> = Mutex::new(None);
static SINK: OnceLock<Sink> = OnceLock::new();
/// Pid of the guard as last verified over the channel (OS-reported peer pid,
/// on Windows also matched against the SCM's pid of the guard service).
/// 0 = unknown. Read by the handle watch; never taken from a file an
/// attacker could pre-write.
static VERIFIED_GUARD_PID: AtomicU32 = AtomicU32::new(0);

/// The guard's pid, if the channel has verified one and it has not exited.
// Only the Windows handle watch consumes it so far.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn verified_guard_pid() -> Option<u32> {
    match VERIFIED_GUARD_PID.load(Ordering::Relaxed) {
        0 => None,
        pid => Some(pid),
    }
}

struct Sink {
    tx: Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
}

/// How long the final stop notice may take; the shutdown budget is a few seconds.
const NOTICE_BUDGET: Duration = Duration::from_secs(1);

/// `TRAPD_GUARD=0` turns the pair off (a host that must run without it).
pub fn switched_off() -> bool {
    std::env::var("TRAPD_GUARD").is_ok_and(|v| matches!(v.trim(), "0" | "false" | "off"))
}

/// Start pinging the guard if this run is a service with a guard installed.
/// `as_service` is the Windows SCM flag; on Linux the unit's `INVOCATION_ID`
/// plays that role, so a developer's `cargo run` never nags for a guard.
#[cfg(any(windows, target_os = "linux"))]
pub fn start(as_service: bool) {
    let service = if cfg!(windows) {
        as_service
    } else {
        std::env::var_os("INVOCATION_ID").is_some()
    };
    if !service || switched_off() {
        return;
    }
    STARTED.call_once(|| {
        if !control::installed(Peer::Guard) {
            info!("no guard service installed; the agent runs unpaired");
            return;
        }
        RUNNING.store(true, Ordering::SeqCst);
        tokio::spawn(link_loop());
    });
}

/// Where the events of guard records go. Safe to call once; later calls are no-ops.
pub fn attach(tx: Sender<AgentEvent>, agent_id: String, hostname: String) {
    let _ = SINK.set(Sink {
        tx,
        agent_id,
        hostname,
    });
}

/// The agent is about to stop. Tell the guard what kind of stop it is (the same
/// marker the stop announcer consumed) and stop restarting it ourselves. Never
/// fails, bounded by [`NOTICE_BUDGET`].
pub async fn announce_stop(kind: NoticeKind, marker: Option<&StopMarker>) {
    shutting_down_flag().store(true, Ordering::SeqCst);
    if !RUNNING.load(Ordering::SeqCst) {
        return;
    }
    let notice = StopNotice {
        kind,
        marker: marker.cloned(),
    };
    if let Ok(mut slot) = STOP.lock() {
        *slot = Some(notice.clone());
    }
    #[cfg(any(windows, target_os = "linux"))]
    {
        let ping = Ping {
            v: PROTOCOL_VERSION,
            seq: SEQ.fetch_add(1, Ordering::SeqCst),
            stop: Some(notice),
        };
        if ipc::ping_guard(&ping, NOTICE_BUDGET).await.is_err() {
            debug!("the guard did not take the stop notice");
        }
    }
}

#[cfg(any(windows, target_os = "linux"))]
async fn link_loop() {
    let state_dir = crate::paths::state_dir().to_path_buf();
    let mut supervisor = supervise::Supervisor::new(
        Peer::Guard,
        state_dir.clone(),
        shutting_down_flag(),
        supervise::SystemActions,
    );
    let mut monitor = PeerMonitor::new(Instant::now());
    let mut watch: Option<(
        u32,
        std::sync::Arc<AtomicBool>,
        tokio::task::JoinHandle<bool>,
    )> = None;
    let mut tick = tokio::time::interval(PING_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if shutting_down_flag().load(Ordering::SeqCst) {
            // Stop notice sent; nothing more to supervise.
            return;
        }
        let stop = STOP.lock().ok().and_then(|g| g.clone());
        let ping = Ping {
            v: PROTOCOL_VERSION,
            seq: SEQ.fetch_add(1, Ordering::SeqCst),
            stop,
        };
        match ipc::ping_guard(&ping, super::EXCHANGE_TIMEOUT).await {
            Ok((pong, pid)) if server_is_the_guard(pid) => {
                let class = pong
                    .stop
                    .as_ref()
                    .map(|n| classify(n, chrono::Utc::now().timestamp()));
                monitor.observe(Instant::now(), pid, class);
                if let Some(pid) = pid {
                    VERIFIED_GUARD_PID.store(pid, Ordering::Relaxed);
                    if watch.as_ref().map(|(p, _, _)| *p) != Some(pid) {
                        if let Some((_, cancel, _)) = watch.take() {
                            cancel.store(true, Ordering::Relaxed);
                        }
                        let cancel = std::sync::Arc::new(AtomicBool::new(false));
                        let handle =
                            tokio::spawn(control::wait_exit(pid, std::sync::Arc::clone(&cancel)));
                        watch = Some((pid, cancel, handle));
                    }
                }
            }
            Ok((_, pid)) => warn!(
                ?pid,
                "the guard channel is served by a process that is not the guard service"
            ),
            Err(e) => debug!(error = %e, "guard ping failed"),
        }
        if watch.as_ref().is_some_and(|(_, _, h)| h.is_finished()) {
            if let Some((_, _, handle)) = watch.take() {
                if handle.await.unwrap_or(false) {
                    VERIFIED_GUARD_PID.store(0, Ordering::Relaxed);
                    monitor.mark_exited();
                }
            }
        }
        if let Some(loss) = monitor.poll(Instant::now()) {
            // An authorized stop of the guard never ends the agent.
            let _ = supervisor.handle(loss, monitor.pid()).await;
        }
        if let Some(sink) = SINK.get() {
            drain(sink, &state_dir).await;
        }
    }
}

#[cfg(any(windows, target_os = "linux"))]
fn server_is_the_guard(pid: Option<u32>) -> bool {
    if cfg!(windows) {
        pid.is_some() && pid == control::service_pid(Peer::Guard)
    } else {
        true
    }
}

/// Hand every waiting record to the event pipeline, oldest first. A record is
/// removed only once the pipeline took its event.
async fn drain(sink: &Sink, state_dir: &std::path::Path) {
    let dir = state_dir.to_path_buf();
    let records = tokio::task::spawn_blocking(move || read_records(&dir))
        .await
        .unwrap_or_default();
    for (path, record) in records {
        let event = record_event(&record, &sink.agent_id, &sink.hostname);
        match tokio::time::timeout(Duration::from_secs(1), sink.tx.send(event)).await {
            Ok(Ok(())) => remove_record(&path),
            _ => return,
        }
    }
}

/// Drain once, outside the link loop (tests).
#[cfg(test)]
async fn drain_now(
    tx: &Sender<AgentEvent>,
    agent_id: &str,
    hostname: &str,
    state_dir: &std::path::Path,
) {
    let sink = Sink {
        tx: tx.clone(),
        agent_id: agent_id.to_owned(),
        hostname: hostname.to_owned(),
    };
    drain(&sink, state_dir).await;
}

fn shutting_down_flag() -> std::sync::Arc<AtomicBool> {
    std::sync::Arc::clone(SHUTDOWN_FLAG.get_or_init(Default::default))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selfprotect::guard::{
        write_record, Loss, LossReason, Record, RestartOutcome, StopClass,
    };

    fn dir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("trapd-agentlink-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn record() -> Record {
        let loss = Loss {
            reason: LossReason::Hung,
            class: Some(StopClass::Unauthorized),
            first: true,
            grace_expired: false,
        };
        Record::peer_lost(
            Peer::Agent,
            &loss,
            RestartOutcome::Started,
            chrono::Utc::now(),
        )
    }

    #[tokio::test]
    async fn waiting_records_become_events_and_are_removed() {
        let d = dir();
        let r = record();
        write_record(&d, &r).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        drain_now(&tx, "agent-1", "host-1", &d).await;
        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_id, r.event_id);
        assert_eq!(super::super::pending_count(&d), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn a_record_stays_when_the_pipeline_is_full() {
        let d = dir();
        write_record(&d, &record()).unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        tx.send(record_event(&record(), "a", "h")).await.unwrap();
        drain_now(&tx, "agent-1", "host-1", &d).await;
        assert_eq!(
            super::super::pending_count(&d),
            1,
            "kept for the next drain"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn forged_or_oversized_files_are_dropped_not_shipped() {
        let d = dir();
        let spool = super::super::spool_dir(&d);
        std::fs::create_dir_all(&spool).unwrap();
        std::fs::write(spool.join("1-a.json"), b"{\"v\":1}").unwrap();
        std::fs::write(spool.join("2-b.json"), vec![b'x'; 5000]).unwrap();
        // Structurally valid but semantically inconsistent (hash on a peer_lost).
        let mut bad = record();
        bad.current_hash = Some("sha256:".to_owned() + &"a".repeat(64));
        std::fs::write(spool.join("3-c.json"), serde_json::to_vec(&bad).unwrap()).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        drain_now(&tx, "a", "h", &d).await;
        assert!(rx.try_recv().is_err());
        assert_eq!(super::super::pending_count(&d), 0);
        let _ = std::fs::remove_dir_all(&d);
    }
}
