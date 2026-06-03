//! Shared HTTP client construction for **all** backend communication.
//!
//! Previously only [`crate::transport`] built a TLS-pinned / mTLS client while
//! enrollment, heartbeat and config-pull each used a bare
//! `reqwest::Client::new()`.  That inconsistency meant a backend fronted by a
//! private CA would reject enrollment (bare client → unknown issuer) even
//! though event ingest worked — a confusing, hard-to-debug "enrollment is
//! unstable" failure.
//!
//! Every component now goes through [`build_client`] so the TLS posture,
//! timeouts and connection pooling are identical end-to-end.
//!
//! TLS material is read from the configuration directory (default
//! `/etc/trapd`, overridable via `TRAPD_CONFIG_DIR`):
//!
//! | File         | Purpose                                    |
//! |--------------|--------------------------------------------|
//! | `ca.crt`     | PEM CA certificate to **pin** the backend  |
//! | `agent.crt`  | PEM client certificate for **mTLS**        |
//! | `agent.key`  | PEM private key for the client certificate |
//!
//! `agent.crt`/`agent.key` (mTLS) are optional. `ca.crt` is **not**: the
//! control channel is *fail-closed*. Without a pinned `ca.crt` the agent
//! refuses to build a client (any CA the host trusts could otherwise MITM the
//! kill/isolate/install command channel) unless the operator explicitly accepts
//! the system trust store via `TRAPD_TLS_ALLOW_SYSTEM_ROOTS=1`.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::ClientBuilder;
use tracing::{info, warn};

use crate::paths;

const USER_AGENT: &str = concat!("trapd-agent/", env!("CARGO_PKG_VERSION"));

/// Opt-out that lets the control channel fall back to the host's **system trust
/// store** when no `<config>/ca.crt` is provisioned. Unset by default so the
/// agent is fail-closed: a remote-control agent that receives `kill_pid` /
/// `isolate_network` / `install_package` must not trust every CA the host does.
/// Set to `1`/`true`/`yes`/`on` only when the backend is fronted by a
/// publicly-trusted CA and pinning is deliberately not used.
const ALLOW_SYSTEM_ROOTS_ENV: &str = "TRAPD_TLS_ALLOW_SYSTEM_ROOTS";

/// Client tuned for the **enrollment / control plane**: short, bounded timeouts
/// so a stalled backend never hangs startup indefinitely.
///
/// Fail-closed: returns `Err` when the control channel cannot be secured (no
/// pinned `ca.crt` and no explicit opt-out, or a TLS build error). Callers must
/// not silently fall back to an unpinned/plain client.
pub fn control_client() -> Result<reqwest::Client> {
    build_client(Duration::from_secs(30), Duration::from_secs(10))
}

/// Client tuned for **event streaming**: a more generous request timeout to
/// accommodate large batches, still bounded so a flush can never hang forever.
/// Fail-closed identically to [`control_client`].
pub fn streaming_client() -> Result<reqwest::Client> {
    build_client(Duration::from_secs(60), Duration::from_secs(10))
}

/// Whether the operator has explicitly opted into the system trust store.
fn system_roots_opt_in() -> bool {
    std::env::var(ALLOW_SYSTEM_ROOTS_ENV)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Build a `reqwest::Client` with:
///   - rustls TLS backend (memory-safe, no OpenSSL dependency)
///   - **mandatory** CA certificate pinning (`<config>/ca.crt`), unless the
///     operator opts into the system trust store via `TRAPD_TLS_ALLOW_SYSTEM_ROOTS`
///   - optional mTLS client identity (`<config>/agent.{crt,key}`)
///   - bounded total + connect timeouts
///   - a stable `User-Agent` carrying the agent version
///
/// Fail-closed: any unrecoverable TLS-configuration problem returns `Err`
/// instead of degrading to a plain `reqwest::Client::new()`. A remote-control
/// agent must never ship commands/telemetry over a channel it could not pin.
pub fn build_client(total_timeout: Duration, connect_timeout: Duration) -> Result<reqwest::Client> {
    let builder = ClientBuilder::new()
        .use_rustls_tls()
        .user_agent(USER_AGENT)
        .timeout(total_timeout)
        .connect_timeout(connect_timeout);

    let builder = apply_ca_pinning(builder)?;
    let builder = apply_mtls_identity(builder);

    builder.build().context("http: failed to build TLS client")
}

/// Add `<config>/ca.crt` as the *only* trusted root certificate, pinning the
/// backend to that CA (equivalent to HPKP without the header mechanism).
///
/// Fail-closed: a missing `ca.crt` is an error unless `TRAPD_TLS_ALLOW_SYSTEM_ROOTS`
/// is set; a present-but-unreadable/unparseable `ca.crt` is *always* an error
/// (never a silent fall-back to system roots, which would defeat pinning).
fn apply_ca_pinning(builder: ClientBuilder) -> Result<ClientBuilder> {
    let path = paths::config_dir().join("ca.crt");
    if !pin_required(path.exists(), system_roots_opt_in()).with_context(|| {
        format!(
            "TLS: no pinned CA at {} — refusing to open the control channel over the system \
             trust store (any host-trusted CA could MITM kill/isolate/install commands). \
             Provision a pinned CA at that path, or set {}=1 to explicitly accept system roots.",
            path.display(),
            ALLOW_SYSTEM_ROOTS_ENV,
        )
    })? {
        // Operator has explicitly accepted the system trust store. Still
        // INSECURE for a remote-control agent, so warn loudly every build.
        warn!(
            expected = %path.display(),
            env = ALLOW_SYSTEM_ROOTS_ENV,
            "TLS: no pinned CA — {ALLOW_SYSTEM_ROOTS_ENV} is set, trusting the system root \
             store for the command channel. This is INSECURE; provision ca.crt to pin."
        );
        return Ok(builder);
    }

    let pem = std::fs::read(&path)
        .with_context(|| format!("TLS: cannot read pinned CA {}", path.display()))?;
    let cert = reqwest::Certificate::from_pem(&pem)
        .with_context(|| format!("TLS: cannot parse pinned CA {}", path.display()))?;
    info!(ca = %path.display(), "TLS: pinning backend to custom CA");
    Ok(builder
        .tls_built_in_root_certs(false)
        .add_root_certificate(cert))
}

/// Pure pinning decision (factored out so it is testable without touching the
/// global config dir or process environment):
///   - `ca_exists`         → pin to the provisioned CA (`Ok(true)`).
///   - else `opt_in`       → system trust store is explicitly allowed (`Ok(false)`).
///   - else                → fail-closed (`Err`): no pin, no opt-out.
fn pin_required(ca_exists: bool, opt_in: bool) -> Result<bool> {
    if ca_exists {
        Ok(true)
    } else if opt_in {
        Ok(false)
    } else {
        Err(anyhow!(
            "control channel is unpinned and system roots are not opted in"
        ))
    }
}

/// Load a PEM client certificate + key for mutual TLS authentication.  Both
/// files must be present; otherwise mTLS is skipped (TLS still applies).
fn apply_mtls_identity(builder: ClientBuilder) -> ClientBuilder {
    let cert_path = paths::config_dir().join("agent.crt");
    let key_path = paths::config_dir().join("agent.key");

    if !cert_path.exists() || !key_path.exists() {
        return builder;
    }

    let cert_pem = match std::fs::read(&cert_path) {
        Ok(b) => b,
        Err(e) => {
            warn!("mTLS: cannot read {}: {e}", cert_path.display());
            return builder;
        }
    };
    let key_pem = match std::fs::read(&key_path) {
        Ok(b) => b,
        Err(e) => {
            warn!("mTLS: cannot read {}: {e}", key_path.display());
            return builder;
        }
    };

    // `Identity::from_pem` expects the certificate chain and private key
    // concatenated in a single PEM buffer.
    let mut combined = cert_pem;
    combined.extend_from_slice(b"\n");
    combined.extend_from_slice(&key_pem);

    match reqwest::Identity::from_pem(&combined) {
        Ok(identity) => {
            info!("mTLS: client identity loaded — mutual TLS enabled");
            builder.identity(identity)
        }
        Err(e) => {
            warn!(
                "mTLS: cannot build identity from {} + {}: {e}",
                cert_path.display(),
                key_path.display()
            );
            builder
        }
    }
}

/// Normalise a backend base URL: trim whitespace and any trailing slashes so
/// callers can safely do `format!("{base}/api/...")` without producing `//`.
pub fn normalize_base_url(raw: &str) -> String {
    raw.trim().trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::{normalize_base_url, pin_required};

    #[test]
    fn pins_when_ca_present() {
        // A provisioned CA is always pinned, regardless of the opt-out.
        assert!(pin_required(true, false).unwrap());
        assert!(pin_required(true, true).unwrap());
    }

    #[test]
    fn fail_closed_without_ca_and_without_optout() {
        // The crux of H-B: no pinned CA and no explicit opt-out must refuse to
        // build a control-channel client (no silent system-root fall-back).
        assert!(pin_required(false, false).is_err());
    }

    #[test]
    fn system_roots_allowed_only_with_explicit_optout() {
        // System roots are used only when the operator opted in; the decision is
        // "do not pin" (Ok(false)), never an error.
        assert!(!pin_required(false, true).unwrap());
    }

    #[test]
    fn trims_trailing_slash() {
        assert_eq!(
            normalize_base_url("https://api.example.com/"),
            "https://api.example.com"
        );
    }

    #[test]
    fn trims_multiple_trailing_slashes() {
        assert_eq!(
            normalize_base_url("https://api.example.com///"),
            "https://api.example.com"
        );
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(
            normalize_base_url("  https://api.example.com/  "),
            "https://api.example.com"
        );
    }

    #[test]
    fn leaves_clean_url_untouched() {
        assert_eq!(
            normalize_base_url("https://api.example.com"),
            "https://api.example.com"
        );
    }

    #[test]
    fn preserves_path_prefix() {
        assert_eq!(
            normalize_base_url("https://h.example.com/base/"),
            "https://h.example.com/base"
        );
    }
}
