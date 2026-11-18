//! What to do once a peer is lost; shared by the guard (watching the agent) and
//! the agent (watching the guard).
//!
//! Order of events, deliberately: wait a moment (so a coordinated stop of the
//! pair can reach this process first), refuse to restart a binary that fails
//! its integrity check, restart rate limited, then leave the record for the
//! agent to ship. The record is written after the restart so it says how it
//! went.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Utc;
use tracing::{error, info, warn};

use super::{
    decide, write_record, Loss, LossReason, Peer, Record, RestartLimiter, RestartOutcome,
    RestartPolicy, Tracer,
};

/// Grace before acting on a loss: a `systemctl stop` / SCM stop of both
/// processes must be able to reach this one first.
pub const SETTLE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Integrity {
    Ok,
    Tampered { expected: String, current: String },
}

/// The effects, behind a seam so the policy is testable without a service
/// manager. Blocking; called from the blocking pool.
pub trait Actions: Send + Sync + 'static {
    fn integrity(&self) -> Integrity;
    /// Returns the foreign ptrace holder that had to be ended, if any.
    fn restart(&self, peer: Peer, kill_pid: Option<u32>) -> Result<Option<Tracer>>;
}

#[cfg(any(windows, target_os = "linux"))]
pub struct SystemActions;

#[cfg(any(windows, target_os = "linux"))]
impl Actions for SystemActions {
    fn integrity(&self) -> Integrity {
        use crate::selfprotect::binary_integrity::{recheck_installed, Drift};
        match recheck_installed() {
            Ok(Drift::Modified { expected, current }) => Integrity::Tampered { expected, current },
            Ok(_) => Integrity::Ok,
            Err(e) => {
                // Unreadable binary: it cannot be started either, so the
                // restart attempt fails by itself; do not invent a verdict.
                warn!(error = %e, "binary integrity could not be checked before the restart");
                Integrity::Ok
            }
        }
    }

    fn restart(&self, peer: Peer, kill_pid: Option<u32>) -> Result<Option<Tracer>> {
        super::control::restart(peer, kill_pid)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Handled {
    Continue,
    /// An authorized stop of the pair: the guard ends too.
    WatcherExits,
}

pub struct Supervisor<A: Actions> {
    peer: Peer,
    state_dir: PathBuf,
    limiter: RestartLimiter,
    shutting_down: Arc<AtomicBool>,
    settle: Duration,
    actions: Arc<A>,
}

impl<A: Actions> Supervisor<A> {
    pub fn new(peer: Peer, state_dir: PathBuf, shutting_down: Arc<AtomicBool>, actions: A) -> Self {
        Self {
            peer,
            state_dir,
            limiter: RestartLimiter::new(),
            shutting_down,
            settle: SETTLE,
            actions: Arc::new(actions),
        }
    }

    #[cfg(test)]
    fn without_settle(mut self) -> Self {
        self.settle = Duration::ZERO;
        self
    }

    /// Handle one loss. `peer_pid` is the pid last seen for the peer (killed
    /// first when the peer is hung).
    pub async fn handle(&mut self, loss: Loss, peer_pid: Option<u32>) -> Handled {
        let decision = decide(loss.class, loss.grace_expired);
        if decision.watcher_exits && self.peer == Peer::Agent {
            info!("the agent stopped with a maintenance authorization; the guard stops too");
            return Handled::WatcherExits;
        }
        if decision.restart == RestartPolicy::Never && !decision.report {
            return Handled::Continue;
        }
        if !self.settle.is_zero() {
            tokio::time::sleep(self.settle).await;
        }
        if self.shutting_down.load(Ordering::SeqCst) {
            return Handled::Continue;
        }

        let mut outcome = RestartOutcome::Refused;
        let mut tampered = None;
        let mut tracer = None;
        if decision.restart == RestartPolicy::Now {
            let actions = Arc::clone(&self.actions);
            let integrity = tokio::task::spawn_blocking(move || actions.integrity())
                .await
                .unwrap_or(Integrity::Ok);
            match integrity {
                Integrity::Tampered { expected, current } => {
                    error!(
                        peer = self.peer.as_str(),
                        "binary failed its integrity check; not restarting"
                    );
                    tampered = Some((expected, current));
                }
                Integrity::Ok if self.limiter.try_acquire(Instant::now()) => {
                    let actions = Arc::clone(&self.actions);
                    let (peer, kill) = (
                        self.peer,
                        (loss.reason == LossReason::Hung)
                            .then_some(peer_pid)
                            .flatten(),
                    );
                    let result =
                        tokio::task::spawn_blocking(move || actions.restart(peer, kill)).await;
                    outcome = match result {
                        Ok(Ok(held_by)) => {
                            if let Some(t) = &held_by {
                                warn!(
                                    peer = self.peer.as_str(),
                                    tracer_pid = t.pid,
                                    tracer_exe = %t.exe,
                                    "peer was held under ptrace; ended the tracer so it can restart"
                                );
                            }
                            tracer = held_by;
                            RestartOutcome::Started
                        }
                        Ok(Err(e)) => {
                            warn!(error = %e, "peer restart failed");
                            RestartOutcome::Failed
                        }
                        Err(_) => RestartOutcome::Failed,
                    };
                }
                Integrity::Ok => {
                    warn!(
                        peer = self.peer.as_str(),
                        "restart rate limit reached; not restarting"
                    );
                    outcome = RestartOutcome::Suppressed;
                }
            }
        }

        if loss.first {
            let now = Utc::now();
            if decision.report {
                self.record(&Record::peer_lost(self.peer, &loss, outcome, now).with_tracer(tracer));
            }
            if let Some((expected, current)) = tampered {
                self.record(&Record::binary_tampered(
                    self.peer, &loss, &expected, &current, now,
                ));
            }
        }
        Handled::Continue
    }

    fn record(&self, record: &Record) {
        if let Err(e) = write_record(&self.state_dir, record) {
            error!(error = %e, "could not write the guard record");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selfprotect::guard::{read_records, RecordKind, StopClass};
    use std::sync::Mutex;

    struct Fake {
        integrity: Integrity,
        restarts: Mutex<Vec<(Peer, Option<u32>)>>,
        fail: bool,
        tracer: Option<Tracer>,
    }
    impl Fake {
        fn ok() -> Arc<Self> {
            Arc::new(Self {
                integrity: Integrity::Ok,
                restarts: Mutex::new(vec![]),
                fail: false,
                tracer: None,
            })
        }
    }
    struct Shared(Arc<Fake>);
    impl Actions for Shared {
        fn integrity(&self) -> Integrity {
            self.0.integrity.clone()
        }
        fn restart(&self, peer: Peer, kill_pid: Option<u32>) -> Result<Option<Tracer>> {
            self.0.restarts.lock().unwrap().push((peer, kill_pid));
            if self.0.fail {
                anyhow::bail!("scm refused");
            }
            Ok(self.0.tracer.clone())
        }
    }

    fn dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!("trapd-supervise-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn loss(reason: LossReason, class: Option<StopClass>, first: bool) -> Loss {
        Loss {
            reason,
            class,
            first,
            grace_expired: false,
        }
    }

    fn sup(fake: &Arc<Fake>, dir: &std::path::Path) -> Supervisor<Shared> {
        Supervisor::new(
            Peer::Agent,
            dir.to_path_buf(),
            Arc::new(AtomicBool::new(false)),
            Shared(Arc::clone(fake)),
        )
        .without_settle()
    }

    #[tokio::test]
    async fn an_unannounced_loss_is_restarted_and_reported_once() {
        let (fake, d) = (Fake::ok(), dir());
        let mut s = sup(&fake, &d);
        s.handle(loss(LossReason::Died, None, true), Some(42)).await;
        s.handle(loss(LossReason::Died, None, false), Some(42))
            .await;
        assert_eq!(
            fake.restarts.lock().unwrap().len(),
            2,
            "retried while still lost"
        );
        let records = read_records(&d);
        assert_eq!(records.len(), 1, "reported once per episode");
        let r = &records[0].1;
        assert_eq!(r.kind, RecordKind::PeerLost);
        assert_eq!(r.restart, RestartOutcome::Started);
        assert!(!r.announced_stop && !r.maintenance_authorized);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn a_hung_peer_is_killed_before_the_restart_a_dead_one_is_not() {
        let (fake, d) = (Fake::ok(), dir());
        let mut s = sup(&fake, &d);
        s.handle(loss(LossReason::Hung, None, true), Some(4242))
            .await;
        s.handle(loss(LossReason::Died, None, false), Some(4242))
            .await;
        let restarts = fake.restarts.lock().unwrap().clone();
        assert_eq!(
            restarts,
            vec![(Peer::Agent, Some(4242)), (Peer::Agent, None)]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn an_authorized_or_shutdown_stop_neither_restarts_nor_reports() {
        for class in [
            StopClass::Authorized,
            StopClass::HostShutdown,
            StopClass::Planned,
        ] {
            let (fake, d) = (Fake::ok(), dir());
            let mut s = sup(&fake, &d);
            let handled = s
                .handle(loss(LossReason::Died, Some(class), true), None)
                .await;
            assert!(fake.restarts.lock().unwrap().is_empty(), "{class:?}");
            assert!(read_records(&d).is_empty(), "{class:?}");
            // Only a maintenance-authorized stop ends the guard.
            assert_eq!(
                handled == Handled::WatcherExits,
                class == StopClass::Authorized,
                "{class:?}"
            );
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[tokio::test]
    async fn an_unauthorized_announced_stop_is_still_reported_and_restarted() {
        let (fake, d) = (Fake::ok(), dir());
        let mut s = sup(&fake, &d);
        s.handle(
            loss(LossReason::Died, Some(StopClass::Unauthorized), true),
            None,
        )
        .await;
        assert_eq!(fake.restarts.lock().unwrap().len(), 1);
        let r = &read_records(&d)[0].1;
        assert!(r.announced_stop && !r.maintenance_authorized);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn a_planned_stop_that_never_came_back_is_reported_as_authorized() {
        let (fake, d) = (Fake::ok(), dir());
        let mut s = sup(&fake, &d);
        let mut l = loss(LossReason::Died, Some(StopClass::Planned), true);
        l.grace_expired = true;
        s.handle(l, None).await;
        assert_eq!(fake.restarts.lock().unwrap().len(), 1);
        let r = &read_records(&d)[0].1;
        assert!(r.announced_stop && r.maintenance_authorized);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn a_tampered_binary_is_not_restarted_and_is_reported() {
        let d = dir();
        let h = |c: char| format!("sha256:{}", c.to_string().repeat(64));
        let fake = Arc::new(Fake {
            integrity: Integrity::Tampered {
                expected: h('a'),
                current: h('b'),
            },
            restarts: Mutex::new(vec![]),
            fail: false,

            tracer: None,
        });
        let mut s = sup(&fake, &d);
        s.handle(loss(LossReason::Died, None, true), None).await;
        assert!(fake.restarts.lock().unwrap().is_empty());
        let kinds: Vec<_> = read_records(&d).iter().map(|(_, r)| r.kind).collect();
        assert!(kinds.contains(&RecordKind::PeerBinaryTampered));
        assert!(kinds.contains(&RecordKind::PeerLost));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn restarts_are_rate_limited_and_the_suppression_is_recorded() {
        let (fake, d) = (Fake::ok(), dir());
        let mut s = sup(&fake, &d);
        for _ in 0..super::super::MAX_RESTARTS {
            s.handle(loss(LossReason::Died, None, false), None).await;
        }
        s.handle(loss(LossReason::Died, None, true), None).await;
        assert_eq!(
            fake.restarts.lock().unwrap().len(),
            super::super::MAX_RESTARTS
        );
        assert_eq!(read_records(&d)[0].1.restart, RestartOutcome::Suppressed);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn a_failed_restart_is_recorded_as_failed() {
        let d = dir();
        let fake = Arc::new(Fake {
            integrity: Integrity::Ok,
            restarts: Mutex::new(vec![]),
            fail: true,

            tracer: None,
        });
        let mut s = sup(&fake, &d);
        s.handle(loss(LossReason::Died, None, true), None).await;
        assert_eq!(read_records(&d)[0].1.restart, RestartOutcome::Failed);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn nothing_happens_once_this_side_is_shutting_down() {
        let (fake, d) = (Fake::ok(), dir());
        let flag = Arc::new(AtomicBool::new(true));
        let mut s = Supervisor::new(
            Peer::Guard,
            d.clone(),
            Arc::clone(&flag),
            Shared(Arc::clone(&fake)),
        );
        s.settle = Duration::ZERO;
        s.handle(loss(LossReason::Died, None, true), None).await;
        assert!(fake.restarts.lock().unwrap().is_empty());
        assert!(read_records(&d).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn an_authorized_guard_stop_does_not_stop_the_agent() {
        let (fake, d) = (Fake::ok(), dir());
        let mut s = Supervisor::new(
            Peer::Guard,
            d.clone(),
            Arc::new(AtomicBool::new(false)),
            Shared(Arc::clone(&fake)),
        )
        .without_settle();
        let handled = s
            .handle(
                loss(LossReason::Died, Some(StopClass::Authorized), true),
                None,
            )
            .await;
        assert_eq!(handled, Handled::Continue);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn a_ptrace_holder_ended_for_the_restart_is_in_the_record() {
        let d = dir();
        let fake = Arc::new(Fake {
            integrity: Integrity::Ok,
            restarts: Mutex::new(vec![]),
            fail: false,
            tracer: Some(Tracer {
                pid: 4242,
                exe: "/usr/bin/gdb".into(),
            }),
        });
        let mut s = sup(&fake, &d);
        s.handle(loss(LossReason::Hung, None, true), Some(42)).await;
        assert_eq!(fake.restarts.lock().unwrap()[0], (Peer::Agent, Some(42)));
        let records = read_records(&d);
        let r = &records[0].1;
        assert_eq!(r.restart, RestartOutcome::Started);
        assert_eq!(r.tracer.as_ref().map(|t| t.pid), Some(4242));
        let ev = super::super::record_event(r, "a", "h");
        let trapd_schema::EventData::Detection(det) = &ev.data else {
            panic!("detection expected")
        };
        assert_eq!(det.evidence["tracer_exe"], "/usr/bin/gdb");
    }
}
