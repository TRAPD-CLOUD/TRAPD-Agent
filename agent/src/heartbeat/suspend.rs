//! Announce that the host is about to suspend.
//!
//! A suspended laptop goes as quiet as a stopped agent. Without telling the
//! two apart, the backend has to keep its long "silent agent" threshold for
//! every ordinary host, and an unannounced `sc stop` / `kill -9` stays unseen
//! for hours. Before the host suspends, the agent therefore sends the same
//! final beat it sends before a host shutdown (`host_shutdown: true`).
//!
//! Triggers: the Windows SCM power event `PBT_APMSUSPEND`, and on Linux a
//! systemd sleep hook that signals the agent (`SIGUSR2`). Modern Standby
//! (S0ix) hosts may not deliver `PBT_APMSUSPEND`; they keep the network up and
//! keep beating less often, which the backend then sees as silence. That is a
//! known gap, not a silent failure: the finding is raised, not suppressed.
//!
//! The announcement is an untrusted hint (anyone who can signal the agent can
//! send it). The backend only uses it to keep its long threshold, and only
//! while it is the agent's last word; it never suppresses a stop finding.

use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tracing::{info, warn};

use crate::selfprotect::stop::{within, Delivery};

/// Time for one announcement. Windows gives a service about two seconds to
/// handle `PBT_APMSUSPEND` before it suspends anyway.
pub const ANNOUNCE_BUDGET: Duration = Duration::from_millis(1500);

/// How long a caller waits for the acknowledgement: the budget plus slack for
/// scheduling, still inside the two seconds Windows grants.
#[cfg_attr(not(windows), allow(dead_code))]
pub const ACK_WAIT: Duration = Duration::from_millis(1800);

/// One request: the sender is signalled once the announcement finished
/// (delivered, failed or timed out).
pub type Request = std_mpsc::Sender<()>;

/// The platform side (SCM control handler, signal listener) of the channel.
#[derive(Clone)]
pub struct SuspendNotifier(UnboundedSender<Request>);

impl SuspendNotifier {
    /// Request an announcement and block for at most `wait` until it is done.
    /// Blocking: call it from the SCM control handler thread, never from a
    /// Tokio worker. Returns whether it finished in time.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn announce_blocking(&self, wait: Duration) -> bool {
        let (ack, done) = std_mpsc::channel();
        if self.0.send(ack).is_err() {
            return false;
        }
        done.recv_timeout(wait).is_ok()
    }

    /// Request an announcement without waiting (signal listener).
    #[cfg_attr(windows, allow(dead_code))]
    pub fn announce(&self) {
        let (ack, _done) = std_mpsc::channel();
        let _ = self.0.send(ack);
    }
}

pub fn channel() -> (SuspendNotifier, UnboundedReceiver<Request>) {
    let (tx, rx) = unbounded_channel();
    (SuspendNotifier(tx), rx)
}

/// Serve announcement requests until every notifier is dropped. `announce`
/// sends the beat and reports whether the backend accepted it.
pub async fn serve<F, Fut>(mut requests: UnboundedReceiver<Request>, mut announce: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    while let Some(ack) = requests.recv().await {
        match within(ANNOUNCE_BUDGET, announce()).await {
            Delivery::Delivered => info!("host suspend announced to the backend"),
            Delivery::Failed | Delivery::TimedOut => {
                warn!("host suspend could not be announced to the backend")
            }
        }
        let _ = ack.send(());
    }
}

/// Linux: a systemd sleep hook sends `SIGUSR2` before the host suspends (see
/// `deploy/trapd-agent-sleep`). Installs the handler synchronously, so call
/// it first thing in `main`: SIGUSR2's default action terminates the process,
/// and the hook must never be able to kill an agent that is still starting or
/// runs offline. Without a server the request is dropped.
#[cfg(unix)]
pub fn install_sleep_signal(notifier: SuspendNotifier) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut usr2 = match signal(SignalKind::user_defined2()) {
        Ok(s) => s,
        Err(e) => {
            warn!("could not install SIGUSR2 handler, suspend is not announced: {e}");
            return;
        }
    };
    tokio::spawn(async move {
        while usr2.recv().await.is_some() {
            notifier.announce();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn a_request_is_acknowledged_after_the_announcement() {
        let (notifier, requests) = channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let server = tokio::spawn(serve(requests, move || {
            counted.fetch_add(1, Ordering::SeqCst);
            async { true }
        }));
        let done = tokio::task::spawn_blocking(move || notifier.announce_blocking(ACK_WAIT))
            .await
            .unwrap();
        assert!(done);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        server.await.unwrap(); // the notifier was dropped: the server ends
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hanging_backend_is_cut_off_at_the_budget() {
        let (notifier, requests) = channel();
        let server = tokio::spawn(serve(requests, std::future::pending::<bool>));
        let started = std::time::Instant::now();
        let caller = notifier.clone();
        let done = tokio::task::spawn_blocking(move || caller.announce_blocking(ACK_WAIT))
            .await
            .unwrap();
        let took = started.elapsed();
        assert!(
            done,
            "acknowledged once the budget ran out, inside ACK_WAIT"
        );
        assert!(took >= ANNOUNCE_BUDGET, "not before the budget: {took:?}");
        drop(notifier);
        server.await.unwrap();
    }

    #[test]
    fn without_a_server_the_caller_does_not_block() {
        let (notifier, requests) = channel();
        drop(requests);
        assert!(!notifier.announce_blocking(ACK_WAIT));
    }

    #[test]
    fn the_wait_fits_the_windows_suspend_window() {
        assert!(ANNOUNCE_BUDGET < ACK_WAIT);
        assert!(ACK_WAIT < Duration::from_secs(2));
    }
}
