//! Announced vs. unannounced stop of the agent (self-protection WP1).
//!
//! A user-mode agent cannot stop an administrator from stopping it, so the
//! stop itself has to be reported. Two things can end the process in an orderly
//! way and they mean opposite things to an analyst:
//!
//! * [`StopKind::ServiceStop`] - somebody stopped the service (`sc stop`,
//!   `systemctl stop`, a signal). This is a defense-evasion indicator: the agent
//!   queues a high-severity `selfprotect.service_stop_requested` finding and
//!   makes one bounded attempt to deliver it before it exits.
//! * [`StopKind::HostShutdown`] - the host is going down (reboot, power off).
//!   Nothing is raised. The agent sends a final heartbeat flagged
//!   `host_shutdown`, so the backend keeps its long "silent agent" threshold for
//!   that outage instead of the short one used for unexplained silence.
//!
//! Both paths are best effort and strictly time-boxed: they never extend the
//! shutdown beyond [`STOP_FLUSH_BUDGET`] / [`SHUTDOWN_ANNOUNCE_BUDGET`], a
//! failure is logged and never fatal, and when in doubt a stop is classified as
//! a service stop (a false alert is recoverable, a missed one is not).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::{info, warn};

use crate::heartbeat::Heartbeat;
use crate::pipeline::Spool;
use crate::schema::{AgentEvent, DetectionData, EventAction, EventClass, EventData, Severity};
use crate::selfprotect::stop_marker::{self, StopMarker};
use crate::transport::Transport;

pub const SERVICE_STOP_RULE_ID: &str = "selfprotect.service_stop_requested";
/// Informational counterpart for a planned stop (see `stop_marker`).
pub const SERVICE_STOP_AUTHORIZED_RULE_ID: &str = "selfprotect.service_stop_authorized";

/// How long a stop may wait for the backend to take the finding. Well inside the
/// SCM wait hint (30 s) and systemd's default stop timeout (90 s).
pub const STOP_FLUSH_BUDGET: Duration = Duration::from_secs(3);
/// The final host-shutdown heartbeat gets less: Windows gives services very
/// little time at shutdown and the message is optional.
pub const SHUTDOWN_ANNOUNCE_BUDGET: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopKind {
    /// The service was stopped while the host stays up.
    ServiceStop,
    /// The host is shutting down or rebooting.
    HostShutdown,
}

/// What stopped the service, for the finding's evidence (never trusted).
// Each platform constructs only its own variants.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopSource {
    /// Windows SCM `SERVICE_CONTROL_STOP`.
    ScmStop,
    /// `SIGTERM` that was not part of a host shutdown.
    Sigterm,
    /// `SIGINT` / Ctrl-C.
    Interrupt,
    /// The service verified and claimed a maintenance token (Windows). Evidence
    /// only: the backend decides from its own record of the token, never from
    /// this claim.
    MaintenanceToken,
}

impl StopSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::ScmStop => "scm_stop",
            Self::Sigterm => "sigterm",
            Self::Interrupt => "interrupt",
            Self::MaintenanceToken => "maintenance_token",
        }
    }
}

/// The finding for a stop request.
pub fn stop_finding(source: StopSource) -> DetectionData {
    DetectionData {
        rule_id: SERVICE_STOP_RULE_ID.into(),
        title: "TRAPD agent service was stopped".into(),
        category: "defense_evasion".into(),
        mitre_tactic: Some("TA0005 Defense Evasion".into()),
        mitre_technique: Some("T1562.001".into()),
        confidence: 90,
        subject: "trapd-agent".into(),
        detail: "The agent service received a stop request while the host was not shutting down. \
                 Sensing on this host ends until the service is started again."
            .into(),
        evidence: serde_json::json!({
            "source": source.as_str(),
            "host_shutdown": false,
        }),
        ..Default::default()
    }
}

/// The detection event carrying [`stop_finding`]. High severity is the agent's
/// stamp; the backend decides severity from its own catalog.
pub fn stop_event(agent_id: &str, hostname: &str, source: StopSource) -> AgentEvent {
    AgentEvent::new(
        agent_id.to_string(),
        hostname.to_string(),
        EventClass::Detection,
        EventAction::Detected,
        Severity::High,
        EventData::Detection(Box::new(stop_finding(source))),
    )
}

/// The informational finding for a stop the agent was told about beforehand.
/// Everything in it is the agent's claim: the backend matches `token_nonce`
/// against its consumed-token record and the versions against the version it
/// sees afterwards, and treats an unmatched claim like an unauthorized stop.
pub fn authorized_stop_finding(source: StopSource, marker: &StopMarker) -> DetectionData {
    DetectionData {
        rule_id: SERVICE_STOP_AUTHORIZED_RULE_ID.into(),
        title: "TRAPD agent service was stopped for planned maintenance".into(),
        category: "maintenance".into(),
        confidence: 100,
        subject: "trapd-agent".into(),
        detail: "The agent service stopped with a short-lived authorization written by the \
                 installer, updater or maintenance command. The backend must match it against \
                 its own records."
            .into(),
        evidence: serde_json::json!({
            "source": source.as_str(),
            "host_shutdown": false,
            "reason": marker.reason.as_str(),
            "token_nonce": marker.token_nonce,
            "from_version": marker.from_version,
            "to_version": marker.to_version,
            "marker_issued_at": marker.issued_at,
        }),
        ..Default::default()
    }
}

/// The event for a stop: the authorized informational one when a valid marker
/// was consumed, otherwise the high finding. Fails toward the finding.
pub fn stop_event_for(
    agent_id: &str,
    hostname: &str,
    source: StopSource,
    marker: Option<&StopMarker>,
) -> AgentEvent {
    match marker {
        None => stop_event(agent_id, hostname, source),
        Some(m) => AgentEvent::new(
            agent_id.to_string(),
            hostname.to_string(),
            EventClass::Detection,
            EventAction::Detected,
            Severity::Info,
            EventData::Detection(Box::new(authorized_stop_finding(source, m))),
        ),
    }
}

/// `systemctl is-system-running` prints `stopping` while the manager runs the
/// shutdown transaction (poweroff, reboot, halt, kexec). Anything else,
/// including an empty or unreadable answer, is not a host shutdown.
pub fn kind_from_system_state(state: Option<&str>) -> StopKind {
    match state.map(str::trim) {
        Some("stopping") => StopKind::HostShutdown,
        _ => StopKind::ServiceStop,
    }
}

/// Classify a `SIGTERM`. Fails toward [`StopKind::ServiceStop`]: if systemd
/// cannot be asked within a second, the stop is reported.
#[cfg(unix)]
pub async fn classify_sigterm() -> StopKind {
    kind_from_system_state(system_state().await.as_deref())
}

#[cfg(unix)]
async fn system_state() -> Option<String> {
    use std::process::Stdio;
    let bin = ["/usr/bin/systemctl", "/bin/systemctl"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())?;
    let mut cmd = tokio::process::Command::new(bin);
    cmd.arg("is-system-running")
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    // Exit status is non-zero for every state but `running`; only stdout counts.
    let out = tokio::time::timeout(Duration::from_secs(1), cmd.output())
        .await
        .ok()?
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    // The answer is one short token; refuse anything else.
    (text.len() <= 32).then(|| text.trim().to_string())
}

/// Outcome of a time-boxed delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Delivered,
    Failed,
    TimedOut,
}

/// Run `attempt` for at most `budget`. The attempt reports whether it
/// delivered; running out of time is reported separately from a failure.
pub async fn within<F>(budget: Duration, attempt: F) -> Delivery
where
    F: std::future::Future<Output = bool>,
{
    match tokio::time::timeout(budget, attempt).await {
        Ok(true) => Delivery::Delivered,
        Ok(false) => Delivery::Failed,
        Err(_) => Delivery::TimedOut,
    }
}

/// Everything the shutdown path needs to report how the agent ended. Built
/// while the agent starts, so shutdown does not construct HTTP clients under
/// time pressure. Backend parts are `None` offline.
pub struct StopAnnouncer {
    agent_id: String,
    hostname: String,
    spool: Arc<Mutex<Spool>>,
    transport: Option<Transport>,
    heartbeat: Option<Heartbeat>,
    /// Where the authorized-stop marker lives (`<state>/maintenance`).
    state_dir: std::path::PathBuf,
}

impl StopAnnouncer {
    /// Offline announcer: a stop is only queued locally.
    pub fn new(agent_id: String, hostname: String, spool: Arc<Mutex<Spool>>) -> Self {
        Self {
            agent_id,
            hostname,
            spool,
            transport: None,
            heartbeat: None,
            state_dir: crate::paths::state_dir().to_path_buf(),
        }
    }

    #[cfg(test)]
    fn with_state_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.state_dir = dir;
        self
    }

    /// Give the announcer its own (idle) transport and heartbeat sender. They
    /// share the spool and credentials with the running ones; the running tasks
    /// are aborted before the announcement is made.
    pub fn with_backend(mut self, transport: Transport, heartbeat: Heartbeat) -> Self {
        self.transport = Some(transport);
        self.heartbeat = Some(heartbeat);
        self
    }

    /// Report the stop. Never fails and never takes longer than the budget of
    /// the chosen path.
    pub async fn announce(&self, kind: StopKind, source: StopSource) {
        self.announce_authorized(kind, source, None).await
    }

    /// Like [`announce`](Self::announce), for a stop the caller itself has
    /// authorized (Windows service after claiming a maintenance token). No
    /// marker file is involved; a stale one is still consumed so it cannot be
    /// reused, and exactly one event is produced.
    pub async fn announce_authorized(
        &self,
        kind: StopKind,
        source: StopSource,
        authorization: Option<StopMarker>,
    ) {
        match kind {
            StopKind::ServiceStop => self.announce_service_stop(source, authorization).await,
            StopKind::HostShutdown => self.announce_host_shutdown().await,
        }
    }

    async fn announce_service_stop(&self, source: StopSource, authorization: Option<StopMarker>) {
        let mode = crate::output::OutputMode::from_env();
        self.announce_service_stop_authorized(
            source,
            authorization,
            STOP_FLUSH_BUDGET,
            move |event| async move {
                crate::output::write_events(std::slice::from_ref(&event), &mode)
                    .await
                    .is_ok()
            },
        )
        .await;
    }

    #[cfg(test)]
    async fn announce_service_stop_with<W, Fut>(
        &self,
        source: StopSource,
        budget: Duration,
        write_local: W,
    ) where
        W: FnOnce(AgentEvent) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        self.announce_service_stop_authorized(source, None, budget, write_local)
            .await
    }

    /// The whole stop notice (local write, spool insertion and delivery) runs
    /// under one deadline of `budget`, so a slow disk can never hold up the
    /// shutdown. `write_local` is the seam for the local output.
    async fn announce_service_stop_authorized<W, Fut>(
        &self,
        source: StopSource,
        authorization: Option<StopMarker>,
        budget: Duration,
        write_local: W,
    ) where
        W: FnOnce(AgentEvent) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        // Consume the planned-stop marker (single use) before anything else; a
        // missing, expired or malformed one yields the high finding. A stop the
        // service authorized itself takes precedence; the file is still
        // consumed so one stop never yields two events or leaves a marker.
        let consumed = stop_marker::consume(&self.state_dir, chrono::Utc::now().timestamp());
        let marker = authorization.or(consumed);
        let event = stop_event_for(&self.agent_id, &self.hostname, source, marker.as_ref());
        // This event bypasses the consumer, so it is written to the configured
        // local output itself, online and offline alike, independent of
        // whether the backend takes it.
        let local_copy = event.clone();
        let local = async {
            if write_local(local_copy).await {
                info!("stop notice written to local output");
            } else {
                warn!("stop notice could not be written to local output");
            }
        };
        // `Spool::push` is synchronous (journal write, fsync, compaction), so
        // it runs on the blocking pool. If the deadline passes first, the
        // task is abandoned (it may still finish while the process exits).
        let spool = Arc::clone(&self.spool);
        let transport = self.transport.as_ref();
        let queue_and_deliver = async move {
            let queued = tokio::task::spawn_blocking(move || match spool.lock() {
                Ok(mut spool) => spool.push(event).map_err(|r| format!("{r:?}")),
                Err(e) => Err(format!("spool unavailable: {e}")),
            })
            .await;
            let seq = match queued {
                Ok(Ok(seq)) => seq,
                Ok(Err(reason)) => {
                    warn!(%reason, "stop notice: could not queue the finding");
                    return None;
                }
                Err(e) => {
                    warn!(error = %e, "stop notice: queueing task failed");
                    return None;
                }
            };
            // Queued: if delivery fails, the journal replays it on the next
            // start, so the finding is late rather than lost.
            match transport {
                Some(t) => Some(t.deliver(seq).await),
                None => Some(true),
            }
        };
        let work = async { tokio::join!(local, queue_and_deliver).1 };
        match tokio::time::timeout(budget, work).await {
            Ok(Some(true)) => {
                if self.transport.is_some() {
                    info!("stop notice delivered to the backend");
                }
            }
            Ok(Some(false)) => {
                warn!("stop notice not delivered; it stays queued for the next start")
            }
            Ok(None) => {}
            Err(_) => warn!(
                budget_ms = budget.as_millis() as u64,
                "stop notice not completed in time; it stays queued for the next start"
            ),
        }
    }

    async fn announce_host_shutdown(&self) {
        let Some(heartbeat) = &self.heartbeat else {
            return;
        };
        match within(SHUTDOWN_ANNOUNCE_BUDGET, heartbeat.send_host_shutdown()).await {
            Delivery::Delivered => info!("host shutdown announced to the backend"),
            Delivery::Failed | Delivery::TimedOut => {
                warn!("host shutdown could not be announced to the backend")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_stopping_manager_means_host_shutdown() {
        assert_eq!(
            kind_from_system_state(Some("stopping")),
            StopKind::HostShutdown
        );
        assert_eq!(
            kind_from_system_state(Some("stopping\n")),
            StopKind::HostShutdown
        );
    }

    #[test]
    fn every_other_answer_is_a_service_stop() {
        for state in [
            "running",
            "degraded",
            "maintenance",
            "starting",
            "initializing",
            "offline",
            "unknown",
            "",
            "Stopping",
            "stopping now",
        ] {
            assert_eq!(
                kind_from_system_state(Some(state)),
                StopKind::ServiceStop,
                "{state:?}"
            );
        }
        assert_eq!(kind_from_system_state(None), StopKind::ServiceStop);
    }

    #[test]
    fn the_finding_is_high_signal_defense_evasion() {
        let event = stop_event("a1", "h1", StopSource::Sigterm);
        assert_eq!(event.severity, Severity::High);
        assert!(matches!(event.class, EventClass::Detection));
        let EventData::Detection(d) = event.data else {
            panic!("not a detection");
        };
        assert_eq!(d.rule_id, "selfprotect.service_stop_requested");
        assert_eq!(d.category, "defense_evasion");
        assert_eq!(d.mitre_technique.as_deref(), Some("T1562.001"));
        assert_eq!(d.evidence["source"], "sigterm");
        assert!(d.confidence >= 80);
    }

    #[tokio::test]
    async fn a_hanging_attempt_is_cut_off_at_the_budget() {
        let budget = Duration::from_millis(100);
        let started = std::time::Instant::now();
        let out = within(budget, std::future::pending::<bool>()).await;
        assert_eq!(out, Delivery::TimedOut);
        assert!(started.elapsed() >= budget);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn a_failed_or_successful_attempt_returns_immediately() {
        assert_eq!(
            within(STOP_FLUSH_BUDGET, async { true }).await,
            Delivery::Delivered
        );
        assert_eq!(
            within(STOP_FLUSH_BUDGET, async { false }).await,
            Delivery::Failed
        );
    }

    #[test]
    fn the_budgets_stay_inside_the_scm_wait_hint() {
        assert!(STOP_FLUSH_BUDGET <= Duration::from_secs(3));
        assert!(SHUTDOWN_ANNOUNCE_BUDGET <= STOP_FLUSH_BUDGET);
    }

    #[tokio::test]
    async fn without_a_backend_the_finding_is_only_queued() {
        let spool = Arc::new(Mutex::new(Spool::in_memory(10)));
        let a = StopAnnouncer::new("a".into(), "h".into(), Arc::clone(&spool));
        a.announce(StopKind::ServiceStop, StopSource::ScmStop).await;
        assert_eq!(spool.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_host_shutdown_queues_no_finding() {
        let spool = Arc::new(Mutex::new(Spool::in_memory(10)));
        let a = StopAnnouncer::new("a".into(), "h".into(), Arc::clone(&spool));
        a.announce(StopKind::HostShutdown, StopSource::ScmStop)
            .await;
        assert_eq!(spool.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn the_finding_is_written_to_the_local_output() {
        let spool = Arc::new(Mutex::new(Spool::in_memory(10)));
        let a = StopAnnouncer::new("a".into(), "h".into(), Arc::clone(&spool));
        let written = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&written);
        a.announce_service_stop_with(
            StopSource::Sigterm,
            STOP_FLUSH_BUDGET,
            move |e| async move {
                sink.lock().unwrap().push(e);
                true
            },
        )
        .await;
        assert_eq!(written.lock().unwrap().len(), 1);
        assert_eq!(spool.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_slow_spool_insertion_cannot_hold_up_the_shutdown() {
        let spool = Arc::new(Mutex::new(Spool::in_memory(10)));
        let a = StopAnnouncer::new("a".into(), "h".into(), Arc::clone(&spool));
        // Hold the lock so the blocking insertion cannot finish.
        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let holder = {
            let spool = Arc::clone(&spool);
            std::thread::spawn(move || {
                let _guard = spool.lock().unwrap();
                locked_tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(600));
            })
        };
        locked_rx.recv().unwrap();
        let written = Arc::new(Mutex::new(0));
        let sink = Arc::clone(&written);
        let started = std::time::Instant::now();
        a.announce_service_stop_with(
            StopSource::Sigterm,
            Duration::from_millis(150),
            move |_| async move {
                *sink.lock().unwrap() += 1;
                true
            },
        )
        .await;
        assert!(started.elapsed() < Duration::from_secs(2));
        // The local copy does not depend on the queue.
        assert_eq!(*written.lock().unwrap(), 1);
        holder.join().unwrap();
    }

    // ── planned stops ────────────────────────────────────────────────────────

    use crate::selfprotect::stop_marker::{Reason, StopMarker};

    fn unique_dir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("trapd-stop-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
    /// Random per process (32 hex characters), never a literal.
    fn nonce() -> &'static str {
        static N: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        N.get_or_init(|| uuid::Uuid::new_v4().simple().to_string())
    }

    #[test]
    fn without_a_marker_the_stop_is_the_high_finding() {
        let e = stop_event_for("a", "h", StopSource::ScmStop, None);
        assert_eq!(e.severity, Severity::High);
        let EventData::Detection(d) = e.data else {
            panic!()
        };
        assert_eq!(d.rule_id, SERVICE_STOP_RULE_ID);
    }

    #[test]
    fn with_a_marker_the_stop_is_informational_and_carries_the_claim() {
        let now = chrono::Utc::now().timestamp();
        let m = StopMarker::new(
            Reason::Uninstall,
            Some(nonce().into()),
            Some("0.8.0".into()),
            None,
            now,
        );
        let e = stop_event_for("a", "h", StopSource::ScmStop, Some(&m));
        assert_eq!(e.severity, Severity::Info);
        let EventData::Detection(d) = e.data else {
            panic!()
        };
        assert_eq!(d.rule_id, SERVICE_STOP_AUTHORIZED_RULE_ID);
        assert_eq!(d.evidence["reason"], "uninstall");
        assert_eq!(d.evidence["token_nonce"], nonce());
        assert_eq!(d.evidence["from_version"], "0.8.0");
        assert!(d.mitre_technique.is_none());
    }

    async fn announced_rule(dir: std::path::PathBuf) -> (String, Severity, Arc<Mutex<Spool>>) {
        let spool = Arc::new(Mutex::new(Spool::in_memory(10)));
        let a = StopAnnouncer::new("a".into(), "h".into(), Arc::clone(&spool)).with_state_dir(dir);
        let seen = Arc::new(Mutex::new(None));
        let sink = Arc::clone(&seen);
        a.announce_service_stop_with(
            StopSource::ScmStop,
            STOP_FLUSH_BUDGET,
            move |e| async move {
                *sink.lock().unwrap() = Some(e);
                true
            },
        )
        .await;
        let e = seen.lock().unwrap().take().unwrap();
        let EventData::Detection(d) = e.data else {
            panic!()
        };
        (d.rule_id, e.severity, spool)
    }

    /// Windows service-side token stop: authorized directly from the claimed
    /// token (source maintenance_token), no marker file, exactly one event, and
    /// the evidence names the fields the backend matches on.
    #[tokio::test]
    async fn claimed_token_stop_is_authorized_without_a_marker() {
        let dir = unique_dir();
        let now = chrono::Utc::now().timestamp();
        // A stale marker from another planned stop must not add a second event
        // or survive.
        stop_marker::write(
            &dir,
            &StopMarker::new(Reason::Upgrade, None, Some("0.8.0".into()), None, now),
        )
        .unwrap();
        let spool = Arc::new(Mutex::new(Spool::in_memory(10)));
        let a = StopAnnouncer::new("a".into(), "h".into(), Arc::clone(&spool))
            .with_state_dir(dir.clone());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        a.announce_service_stop_authorized(
            StopSource::MaintenanceToken,
            StopMarker::for_claimed_token(nonce(), now),
            STOP_FLUSH_BUDGET,
            move |e| async move {
                sink.lock().unwrap().push(e);
                true
            },
        )
        .await;
        let events = seen.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::Info);
        let EventData::Detection(d) = &events[0].data else {
            panic!()
        };
        assert_eq!(d.rule_id, SERVICE_STOP_AUTHORIZED_RULE_ID);
        assert_eq!(d.evidence["source"], "maintenance_token");
        assert_eq!(d.evidence["reason"], "maintenance");
        assert_eq!(d.evidence["token_nonce"], nonce());
        assert!(d.evidence["marker_issued_at"].is_i64());
        assert!(!stop_marker::marker_path(&dir).exists());
        // A malformed nonce yields no authorization (fails toward the finding).
        assert!(StopMarker::for_claimed_token("XYZ", now).is_none());
    }

    #[tokio::test]
    async fn announcer_consumes_a_valid_marker_once() {
        let dir = unique_dir();
        let now = chrono::Utc::now().timestamp();
        let m = StopMarker::new(
            Reason::SelfUpdate,
            None,
            Some("0.7.9".into()),
            Some("0.8.0".into()),
            now,
        );
        stop_marker::write(&dir, &m).unwrap();
        let (rule, sev, _) = announced_rule(dir.clone()).await;
        assert_eq!(
            (rule.as_str(), sev),
            (SERVICE_STOP_AUTHORIZED_RULE_ID, Severity::Info)
        );
        // Second stop: the marker is gone, so it is the high finding again.
        let (rule, sev, _) = announced_rule(dir.clone()).await;
        assert_eq!((rule.as_str(), sev), (SERVICE_STOP_RULE_ID, Severity::High));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn expired_or_forged_markers_do_not_authorize() {
        let dir = unique_dir();
        let old = chrono::Utc::now().timestamp() - 3600;
        let m = StopMarker::new(Reason::Upgrade, None, None, None, old);
        stop_marker::write(&dir, &m).unwrap();
        let (rule, _, _) = announced_rule(dir.clone()).await;
        assert_eq!(rule, SERVICE_STOP_RULE_ID);
        // Hand-written: token-backed reason without a nonce.
        let now = chrono::Utc::now().timestamp();
        let p = stop_marker::marker_path(&dir);
        std::fs::write(
            &p,
            format!(
                r#"{{"v":1,"reason":"uninstall","issued_at":{now},"expires_at":{}}}"#,
                now + 60
            ),
        )
        .unwrap();
        let (rule, _, _) = announced_rule(dir.clone()).await;
        assert_eq!(rule, SERVICE_STOP_RULE_ID);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_host_shutdown_leaves_the_marker_alone() {
        let dir = unique_dir();
        let now = chrono::Utc::now().timestamp();
        stop_marker::write(
            &dir,
            &StopMarker::new(Reason::Upgrade, None, None, None, now),
        )
        .unwrap();
        let spool = Arc::new(Mutex::new(Spool::in_memory(10)));
        let a = StopAnnouncer::new("a".into(), "h".into(), spool).with_state_dir(dir.clone());
        a.announce(StopKind::HostShutdown, StopSource::ScmStop)
            .await;
        assert!(stop_marker::marker_path(&dir).exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
