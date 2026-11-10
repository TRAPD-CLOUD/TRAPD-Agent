//! Generic collector supervision: restart a collector that exits with an error
//! using capped exponential backoff, and surface the failure in coverage and
//! metrics so a dead sensor is visible instead of silently missing.
//!
//! A collector that returns `Ok(())` finished on purpose (disabled by policy,
//! pipeline closed) and is not restarted. `SensorSupervisor` keeps its own,
//! sensor-specific restart logic and is only observed, not restarted, here.

use std::time::Duration;

use tokio::sync::mpsc::Sender;
use tracing::{error, info, warn};

use super::Collector;
use crate::schema::AgentEvent;

#[derive(Debug, Clone, Copy)]
pub struct RestartPolicy {
    pub initial_delay: Duration,
    pub max_delay: Duration,
    /// A run that lasts this long counts as healthy: backoff and the failed
    /// marker are reset.
    pub stable_after: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(300),
            stable_after: Duration::from_secs(120),
        }
    }
}

impl RestartPolicy {
    /// Delay before restart number `consecutive_failures` (1-based).
    pub fn delay(&self, consecutive_failures: u32) -> Duration {
        let exp = consecutive_failures.saturating_sub(1).min(16);
        self.initial_delay
            .saturating_mul(1u32 << exp)
            .min(self.max_delay)
    }

    /// Failure streak after a run that lasted `ran_for` and then failed.
    pub fn next_streak(&self, previous: u32, ran_for: Duration) -> u32 {
        if ran_for >= self.stable_after {
            1
        } else {
            previous.saturating_add(1)
        }
    }
}

/// Record a collector failure in metrics and coverage.
fn report_failure(name: &str) {
    crate::telemetry::metrics::metrics().collector_failed();
    if name == "WindowsProcessCollector" {
        crate::telemetry::metrics::metrics()
            .set_collector_mode(crate::telemetry::metrics::CollectorMode::Failed);
    }
    crate::telemetry::coverage::set_collector_failed(name, true);
}

/// Run `collector` until it finishes on purpose or the pipeline closes,
/// restarting it after errors. With `restart == false` a failure is only
/// reported (used for collectors that own their restart logic).
pub async fn supervise<C: Collector>(
    mut collector: C,
    tx: Sender<AgentEvent>,
    agent_id: String,
    hostname: String,
    policy: RestartPolicy,
    restart: bool,
) {
    let name = collector.name();
    let mut streak = 0u32;
    loop {
        let started = tokio::time::Instant::now();
        let outcome = {
            let run = collector.run(tx.clone(), agent_id.clone(), hostname.clone());
            tokio::pin!(run);
            let stable = tokio::time::sleep(policy.stable_after);
            tokio::pin!(stable);
            let mut recovered = streak == 0;
            loop {
                tokio::select! {
                    result = &mut run => break result,
                    _ = &mut stable, if !recovered => {
                        recovered = true;
                        crate::telemetry::coverage::set_collector_failed(name, false);
                        if streak > 0 {
                            info!(collector = name, "collector is stable again");
                        }
                    }
                }
            }
        };
        match outcome {
            Ok(()) => {
                crate::telemetry::coverage::set_collector_failed(name, false);
                return;
            }
            Err(e) => {
                report_failure(name);
                streak = policy.next_streak(streak, started.elapsed());
                error!("{name} exited with error: {e:#}");
                if !restart {
                    return;
                }
                if tx.is_closed() {
                    return;
                }
                let delay = policy.delay(streak);
                warn!(
                    collector = name,
                    attempt = streak,
                    delay_s = delay.as_secs(),
                    "restarting collector"
                );
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = tx.closed() => return,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn backoff_doubles_and_is_capped() {
        let p = RestartPolicy::default();
        assert_eq!(p.delay(1), Duration::from_secs(5));
        assert_eq!(p.delay(2), Duration::from_secs(10));
        assert_eq!(p.delay(3), Duration::from_secs(20));
        assert_eq!(p.delay(7), Duration::from_secs(300));
        assert_eq!(p.delay(u32::MAX), Duration::from_secs(300));
    }

    #[test]
    fn stable_run_resets_the_streak() {
        let p = RestartPolicy::default();
        assert_eq!(p.next_streak(4, Duration::from_secs(3)), 5);
        assert_eq!(p.next_streak(4, Duration::from_secs(121)), 1);
    }

    struct Flaky {
        runs: Arc<AtomicU32>,
        fail_times: u32,
        restartable_marker: &'static str,
    }

    #[async_trait]
    impl Collector for Flaky {
        fn name(&self) -> &'static str {
            self.restartable_marker
        }
        async fn run(&mut self, _: Sender<AgentEvent>, _: String, _: String) -> Result<()> {
            let n = self.runs.fetch_add(1, Ordering::SeqCst) + 1;
            if n <= self.fail_times {
                Err(anyhow!("boom {n}"))
            } else {
                Ok(())
            }
        }
    }

    fn fast() -> RestartPolicy {
        RestartPolicy {
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(4),
            stable_after: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn failing_collector_is_restarted_until_it_finishes() {
        let runs = Arc::new(AtomicU32::new(0));
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let c = Flaky {
            runs: Arc::clone(&runs),
            fail_times: 3,
            restartable_marker: "SupervisorTestRestart",
        };
        supervise(c, tx, "a".into(), "h".into(), fast(), true).await;
        assert_eq!(runs.load(Ordering::SeqCst), 4);
        assert!(!crate::telemetry::coverage::snapshot()
            .failed_collectors
            .contains(&"SupervisorTestRestart".to_string()));
    }

    #[tokio::test]
    async fn unrestarted_collector_stays_marked_failed() {
        let runs = Arc::new(AtomicU32::new(0));
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let c = Flaky {
            runs: Arc::clone(&runs),
            fail_times: 10,
            restartable_marker: "SupervisorTestOnce",
        };
        supervise(c, tx, "a".into(), "h".into(), fast(), false).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        assert!(crate::telemetry::coverage::snapshot()
            .failed_collectors
            .contains(&"SupervisorTestOnce".to_string()));
    }

    #[tokio::test]
    async fn closed_pipeline_stops_restarts() {
        let runs = Arc::new(AtomicU32::new(0));
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);
        let c = Flaky {
            runs: Arc::clone(&runs),
            fail_times: 10,
            restartable_marker: "SupervisorTestClosed",
        };
        supervise(c, tx, "a".into(), "h".into(), fast(), true).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }
}
