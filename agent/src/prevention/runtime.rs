//! Prevention runtime: builds and starts the enforcement engine, the signed
//! command puller and the honeytoken health checker.
//!
//! Shared by the Linux `main` and the Windows service runtime so both agents
//! start the same subsystem the same way; everything platform-specific lives
//! behind the engine's leaf modules (`process`, `network`, `quarantine`, …).

use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use tracing::{info, warn};

use super::{
    audit::AuditEmitter,
    command_pubkey_path,
    command_puller::CommandPuller,
    commands::Verifier,
    engine::{Engine, EngineConfig},
    ensure_state_dirs, local_policy_path,
    network::{detect_backend, ensure_chains},
    nonce_store,
    policy::{load_local_policy, PolicyHandle},
};
use crate::config::AgentConfig;

/// Build / spawn the prevention subsystem.  Returns the sender used by the
/// tee in the main consumer to forward events to the enforcement engine.
pub async fn start(
    backend_url: &str,
    agent_id: &str,
    token: &str,
    hostname: &str,
    pipeline_tx: tokio::sync::mpsc::Sender<crate::schema::AgentEvent>,
    cfg_handle: Arc<RwLock<AgentConfig>>,
    reconcile_signal: Arc<tokio::sync::Notify>,
) -> Result<tokio::sync::mpsc::Sender<crate::schema::AgentEvent>> {
    ensure_state_dirs();

    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<crate::schema::AgentEvent>(1024);

    let audit = AuditEmitter::new(pipeline_tx.clone(), agent_id.into(), hostname.into());

    let policy_path = local_policy_path();
    let store = load_local_policy(&policy_path)
        .with_context(|| format!("load {}", policy_path.display()))?;
    let policy = PolicyHandle::new(store);

    let backend = detect_backend();
    if let Err(e) = ensure_chains(backend) {
        warn!(error = %e, "could not initialise the network containment backend — IP/isolation actions will fail");
    }

    let allowlist = build_isolation_allowlist(backend_url, &cfg_handle);

    let engine_cfg = EngineConfig {
        net_backend: backend,
        default_isolation_allowlist: allowlist,
    };

    let verifier = match Verifier::new(&command_pubkey_path(), agent_id.to_string(), &nonce_store())
    {
        Ok(v) => Some(Arc::new(v)),
        Err(e) => {
            warn!(error = %e, "command verifier unavailable — backend commands will not be processed");
            None
        }
    };

    // Register of honeytokens this host has deployed (deploy/revoke lifecycle).
    let honeytokens = Arc::new(crate::deception::HoneytokenStore::load());
    info!(count = honeytokens.len(), "Honeytoken register loaded");

    // Periodic on-disk verification: confirms each planted token still exists
    // (and is unchanged), so the backend can flag one deleted/tampered
    // out-of-band — i.e. without tripping the eBPF access detector. Also kicked
    // immediately after a deploy/revoke via `reconcile_signal`.
    spawn_honeytoken_health(
        audit.clone(),
        Arc::clone(&honeytokens),
        Arc::clone(&reconcile_signal),
    );

    let engine = Arc::new(
        Engine::new(
            policy.clone(),
            audit.clone(),
            engine_cfg,
            Arc::clone(&honeytokens),
            Arc::clone(&cfg_handle),
        )
        .with_reconcile_signal(reconcile_signal),
    );
    Arc::clone(&engine).spawn_event_loop(event_rx);

    if let Some(v) = verifier {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(64);
        let poll_secs = cfg_handle
            .read()
            .map(|c| c.command_poll_interval_secs)
            .unwrap_or(5);
        let puller = CommandPuller::new(
            backend_url,
            agent_id,
            token.to_string(),
            v,
            audit.clone(),
            cmd_tx,
            poll_secs,
        )?;
        tokio::spawn(async move { puller.run().await });
        Arc::clone(&engine).spawn_command_loop(cmd_rx);
    }

    Ok(event_tx)
}

/// Periodic honeytoken health/existence verifier.
///
/// Answers a question the eBPF access detector cannot: *is the planted token
/// still there, and unchanged?* — catching a token deleted or edited
/// out-of-band (while the agent was down, or by a tool the content-read gate
/// does not cover). Emits one `prevention.honeytoken_health` audit event per
/// registered token each pass, which the backend correlates into the token's
/// `file_status` / `last_verified_at`. Runs on a modest interval and also fires
/// immediately on a deploy/revoke kick so a fresh token is verified within ms.
fn spawn_honeytoken_health(
    audit: AuditEmitter,
    store: Arc<crate::deception::HoneytokenStore>,
    reconcile_signal: Arc<tokio::sync::Notify>,
) {
    use crate::schema::{EventAction, Severity};
    // Slow enough to stay near-silent on a steady host, fresh enough that an
    // out-of-band deletion surfaces within a minute.
    const HEALTH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HEALTH_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = reconcile_signal.notified() => {}
            }
            // The engine mutates this same register on deploy/revoke, so the live
            // Arc already reflects the current set of planted tokens.
            for rec in store.list() {
                let rec_for_check = rec.clone();
                let health = match tokio::task::spawn_blocking(move || {
                    crate::deception::verify_record(&rec_for_check)
                })
                .await
                {
                    Ok(health) => health,
                    Err(error) => {
                        warn!(%error, token_id = %rec.id, "honeytoken verification task failed");
                        continue;
                    }
                };
                let severity = if health.present && !health.modified {
                    Severity::Info
                } else {
                    Severity::High
                };
                let reason = match health.status_label() {
                    "missing" => format!("honeytoken '{}' is missing from disk", rec.kind),
                    "modified" if health.actual_sha256.is_none() => {
                        format!("honeytoken '{}' cannot be safely verified", rec.kind)
                    }
                    "modified" => {
                        format!("honeytoken '{}' content changed since deployment", rec.kind)
                    }
                    _ => format!("honeytoken '{}' present and unchanged", rec.kind),
                };
                audit.emit(
                    EventAction::HoneytokenHealth,
                    severity,
                    "honeytoken_health",
                    rec.path.clone(),
                    health.present && !health.modified,
                    reason,
                    None,
                    // No command_id: health is autonomous telemetry, not a
                    // command result — leaving it out keeps the backend from
                    // mistaking it for the deploy command's completion.
                    None,
                    serde_json::json!({
                        "id": rec.id,
                        "kind": rec.kind,
                        "present": health.present,
                        "modified": health.modified,
                        "file_status": health.status_label(),
                        "expected_sha256": rec.sha256,
                        "actual_sha256": health.actual_sha256,
                        // Is anything actually watching this token?
                        "detection": detection_mode(),
                    }),
                );
            }
        }
    });
}

/// What is actually watching the planted tokens right now. Linux reports the
/// eBPF sensor (`kernel` / `none`); Windows reports how decoy reads are
/// detected (`kernel`, `audit`, `last_access`, `tamper_only`), so the console
/// never calls a host protected whose decoy sits on disk unwatched.
fn detection_mode() -> String {
    #[cfg(target_os = "linux")]
    {
        crate::detection::honeytoken::kernel_detection_mode().to_string()
    }
    #[cfg(not(target_os = "linux"))]
    {
        crate::telemetry::coverage::snapshot()
            .decoy_detection
            .unwrap_or_else(|| "none".to_string())
    }
}

fn build_isolation_allowlist(
    backend_url: &str,
    cfg: &Arc<RwLock<AgentConfig>>,
) -> Vec<std::net::IpAddr> {
    let mut out: Vec<std::net::IpAddr> = Vec::new();

    if let Some(host) = backend_host(backend_url) {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            out.push(ip);
        } else if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&format!("{host}:443")) {
            for a in addrs {
                out.push(a.ip());
            }
        }
    }

    if let Ok(c) = cfg.read() {
        for raw in &c.isolation_allowlist_ips {
            if let Ok(ip) = raw.parse::<std::net::IpAddr>() {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }

    out
}

fn backend_host(url: &str) -> Option<String> {
    let s = url.split("://").nth(1).unwrap_or(url);
    let s = s.split('/').next().unwrap_or(s);
    let s = s.split(':').next().unwrap_or(s);
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_host_extracts_hostname() {
        assert_eq!(
            backend_host("https://api.example.com/path"),
            Some("api.example.com".into())
        );
        assert_eq!(
            backend_host("https://api.example.com:8443"),
            Some("api.example.com".into())
        );
        assert_eq!(
            backend_host("http://10.0.0.1:9000"),
            Some("10.0.0.1".into())
        );
        assert_eq!(backend_host(""), None);
    }
}
