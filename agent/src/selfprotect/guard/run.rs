//! The guard process (`trapd-agent guard`): hosts the channel, watches the
//! agent, restarts it. It holds no backend credentials and sends nothing over
//! the network; its findings are records for the agent to ship.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::control;
use super::ipc::{self, Listener};
use super::supervise::{Handled, Supervisor, SystemActions};
use super::{
    classify, pending_count, NoticeKind, Peer, PeerMonitor, Pong, StopNotice, EXCHANGE_TIMEOUT,
    PROTOCOL_VERSION,
};

/// How often the monitor is evaluated.
const MAX_EXCHANGES: usize = 8;
const TICK: Duration = Duration::from_secs(1);
/// On a stop the guard keeps answering for up to this long so the agent can
/// read the stop notice from a pong (the agent pings every `PING_INTERVAL`).
const NOTICE_DELIVERY_WAIT: Duration = Duration::from_secs(3);

#[derive(Debug, PartialEq, Eq)]
pub enum Exit {
    /// Stopped by the service manager / a signal.
    Shutdown(NoticeKind),
    /// The agent was stopped with a maintenance authorization.
    AuthorizedStopOfThePair,
}

struct Observation {
    pid: Option<u32>,
    notice: Option<StopNotice>,
}

/// The notice the guard hands the agent in its pongs once it is stopping: the
/// marker is only *read* (the agent's stop announcer is the one that consumes
/// it), so a planned stop of the pair looks planned from both ends.
fn own_stop_notice(kind: NoticeKind, state_dir: &std::path::Path) -> StopNotice {
    StopNotice {
        kind,
        marker: (kind == NoticeKind::ServiceStop)
            .then(|| super::super::stop_marker::peek(state_dir, chrono::Utc::now().timestamp()))
            .flatten(),
    }
}

/// Windows: the pipe client must be the process the SCM reports for the agent
/// service. Linux: the socket's `SO_PEERCRED` root check already ran.
fn client_is_the_agent(pid: Option<u32>) -> bool {
    if cfg!(windows) {
        pid.is_some() && pid == control::service_pid(Peer::Agent)
    } else {
        true
    }
}

/// Linux entry: run until SIGTERM / SIGINT. A SIGTERM during a host shutdown is
/// reported to the agent as such.
#[cfg(target_os = "linux")]
pub async fn run_until_signal() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).context("install the SIGTERM handler")?;
    run(async move {
        let sigterm = tokio::select! {
            _ = tokio::signal::ctrl_c() => false,
            _ = term.recv() => true,
        };
        if sigterm
            && crate::selfprotect::stop::classify_sigterm().await
                == crate::selfprotect::stop::StopKind::HostShutdown
        {
            NoticeKind::HostShutdown
        } else {
            NoticeKind::ServiceStop
        }
    })
    .await
    .map(|_| ())
}

/// Run until `shutdown` completes (SCM stop / signal) or the agent is stopped
/// with a maintenance authorization.
pub async fn run(shutdown: impl std::future::Future<Output = NoticeKind>) -> Result<Exit> {
    if super::agent_link::switched_off() {
        // The agent does not ping either (same switch); watching it would only
        // restart a healthy agent.
        info!("TRAPD_GUARD is off; the guard exits");
        return Ok(Exit::AuthorizedStopOfThePair);
    }
    let state_dir = crate::paths::state_dir().to_path_buf();
    let mut listener = Listener::bind().context("create the guard channel")?;
    info!("guard started; watching the agent");

    let stopping = Arc::new(Mutex::new(None::<StopNotice>));
    let delivered = Arc::new(AtomicBool::new(false));
    let exchanges = Arc::new(tokio::sync::Semaphore::new(MAX_EXCHANGES));
    let mut accept_after = tokio::time::Instant::now();
    let (obs_tx, mut obs_rx) = mpsc::channel::<Observation>(16);
    let shutting_down = Arc::new(AtomicBool::new(false));
    let mut supervisor = Supervisor::new(
        Peer::Agent,
        state_dir.clone(),
        Arc::clone(&shutting_down),
        SystemActions,
    );
    let mut monitor = PeerMonitor::new(Instant::now());
    let mut watch: Option<(u32, Arc<AtomicBool>, tokio::task::JoinHandle<bool>)> = None;
    let mut peer_proc: Option<control::ProcessIdentity> = None;
    let mut tick = tokio::time::interval(TICK);
    tokio::pin!(shutdown);

    let result = loop {
        // The exit watch resolves to `true` when the agent's process ended.
        let watch_done = async {
            match watch.as_mut() {
                Some((_, _, handle)) => handle.await.unwrap_or(false),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            kind = &mut shutdown => break Exit::Shutdown(kind),
            accepted = async {
                tokio::time::sleep_until(accept_after).await;
                listener.accept().await
            } => {
                let (mut stream, pid) = match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        warn!(error = %e, "guard channel accept failed");
                        accept_after = tokio::time::Instant::now() + TICK;
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&exchanges).try_acquire_owned() else {
                    crate::telemetry::metrics::metrics().state_capacity_dropped(1);
                    continue;
                };
                let tx = obs_tx.clone();
                let state = state_dir.clone();
                let stopping = Arc::clone(&stopping);
                let delivered = Arc::clone(&delivered);
                tokio::spawn(async move {
                    let _permit = permit;
                    let notice = stopping.lock().ok().and_then(|g| g.clone());
                    let carries_notice = notice.is_some();
                    let served = tokio::time::timeout(EXCHANGE_TIMEOUT, ipc::serve(&mut stream, |p| Pong {
                        v: PROTOCOL_VERSION,
                        seq: p.seq,
                        pending: pending_count(&state) > 0,
                        stop: notice,
                    })).await;
                    if let Ok(Ok(ping)) = served {
                        if carries_notice {
                            delivered.store(true, Ordering::SeqCst);
                        }
                        if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(Observation { pid, notice: ping.stop }) {
                            crate::telemetry::metrics::metrics().state_capacity_dropped(1);
                        }
                    }
                });
            }
            Some(obs) = obs_rx.recv() => {
                if !client_is_the_agent(obs.pid) {
                    warn!(pid = ?obs.pid, "ignored a ping from a process that is not the agent service");
                    continue;
                }
                let class = obs.notice.as_ref().map(|n| classify(n, chrono::Utc::now().timestamp()));
                monitor.observe(Instant::now(), obs.pid, class);
                if let Some(pid) = obs.pid {
                    if watch.as_ref().map(|(p, _, _)| *p) != Some(pid) {
                        // Pin the pid to its process generation while it is freshly authenticated.
                        peer_proc = Some(control::ProcessIdentity::observe(pid));
                        if let Some((_, cancel, _)) = watch.take() {
                            cancel.store(true, Ordering::Relaxed);
                        }
                        let cancel = Arc::new(AtomicBool::new(false));
                        let handle = tokio::spawn(control::wait_exit(pid, Arc::clone(&cancel)));
                        watch = Some((pid, cancel, handle));
                    }
                }
            }
            ended = watch_done => {
                watch = None;
                if ended {
                    monitor.mark_exited();
                }
            }
            _ = tick.tick() => {
                if let Some(loss) = monitor.poll(Instant::now()) {
                    let handled = tokio::select! {
                        h = supervisor.handle(loss, peer_proc.filter(|p| Some(p.pid) == monitor.pid())) => h,
                        kind = &mut shutdown => break Exit::Shutdown(kind),
                    };
                    if handled == Handled::WatcherExits {
                        break Exit::AuthorizedStopOfThePair;
                    }
                }
            }
        }
    };

    shutting_down.store(true, Ordering::SeqCst);
    if let Some((_, cancel, _)) = watch.take() {
        cancel.store(true, Ordering::Relaxed);
    }
    if let Exit::Shutdown(kind) = result {
        // Tell the agent this is a stop, not a kill, then leave.
        if let Ok(mut slot) = stopping.lock() {
            *slot = Some(own_stop_notice(kind, &state_dir));
        }
        let wait = async {
            while !delivered.load(Ordering::SeqCst) {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let _permit = permit;
                    let notice = stopping.lock().ok().and_then(|g| g.clone());
                    let ok = tokio::time::timeout(
                        EXCHANGE_TIMEOUT,
                        ipc::serve(&mut stream, |p| Pong {
                            v: PROTOCOL_VERSION,
                            seq: p.seq,
                            pending: false,
                            stop: notice,
                        }),
                    )
                    .await;
                    if matches!(ok, Ok(Ok(_))) {
                        break;
                    }
                }
            }
        };
        let _ = tokio::time::timeout(NOTICE_DELIVERY_WAIT, wait).await;
    }
    info!(?result, "guard stopped");
    Ok(result)
}
