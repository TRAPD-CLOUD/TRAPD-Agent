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
use crate::transport::Transport;

pub const SERVICE_STOP_RULE_ID: &str = "selfprotect.service_stop_requested";

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
}

impl StopSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::ScmStop => "scm_stop",
            Self::Sigterm => "sigterm",
            Self::Interrupt => "interrupt",
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
        }
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
        match kind {
            StopKind::ServiceStop => self.announce_service_stop(source).await,
            StopKind::HostShutdown => self.announce_host_shutdown().await,
        }
    }

    async fn announce_service_stop(&self, source: StopSource) {
        let event = stop_event(&self.agent_id, &self.hostname, source);
        let seq = match self.spool.lock() {
            Ok(mut spool) => spool.push(event),
            Err(e) => {
                warn!(error = %e, "stop notice: spool unavailable");
                return;
            }
        };
        let seq = match seq {
            Ok(seq) => seq,
            Err(reason) => {
                warn!(?reason, "stop notice: could not queue the finding");
                return;
            }
        };
        // Queued: if delivery below fails, the journal replays it on the next
        // start, so the finding is late rather than lost.
        let Some(transport) = &self.transport else {
            return;
        };
        match within(STOP_FLUSH_BUDGET, transport.deliver(seq)).await {
            Delivery::Delivered => info!("stop notice delivered to the backend"),
            Delivery::Failed => {
                warn!("stop notice not delivered; it stays queued for the next start")
            }
            Delivery::TimedOut => warn!(
                budget_ms = STOP_FLUSH_BUDGET.as_millis() as u64,
                "stop notice not delivered in time; it stays queued for the next start"
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
}
