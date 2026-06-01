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
//! All three are optional; absent any of them the agent falls back to the
//! system trust store and bearer-token-only auth.

use std::time::Duration;

use reqwest::ClientBuilder;
use tracing::{info, warn};

use crate::paths;

const USER_AGENT: &str = concat!("trapd-agent/", env!("CARGO_PKG_VERSION"));

/// Client tuned for the **enrollment / control plane**: short, bounded timeouts
/// so a stalled backend never hangs startup indefinitely.
pub fn control_client() -> reqwest::Client {
    build_client(Duration::from_secs(30), Duration::from_secs(10))
}

/// Client tuned for **event streaming**: a more generous request timeout to
/// accommodate large batches, still bounded so a flush can never hang forever.
pub fn streaming_client() -> reqwest::Client {
    build_client(Duration::from_secs(60), Duration::from_secs(10))
}

/// Build a `reqwest::Client` with:
///   - rustls TLS backend (memory-safe, no OpenSSL dependency)
///   - optional CA certificate pinning (`<config>/ca.crt`)
///   - optional mTLS client identity (`<config>/agent.{crt,key}`)
///   - bounded total + connect timeouts
///   - a stable `User-Agent` carrying the agent version
///
/// Falls back to a plain client on any TLS configuration error so the agent can
/// still ship events even on a misconfigured deployment.
pub fn build_client(total_timeout: Duration, connect_timeout: Duration) -> reqwest::Client {
    let builder = ClientBuilder::new()
        .use_rustls_tls()
        .user_agent(USER_AGENT)
        .timeout(total_timeout)
        .connect_timeout(connect_timeout);

    let builder = apply_ca_pinning(builder);
    let builder = apply_mtls_identity(builder);

    builder.build().unwrap_or_else(|e| {
        warn!("http: failed to build TLS client ({e}) — falling back to default");
        reqwest::Client::new()
    })
}

/// Add `<config>/ca.crt` as the *only* trusted root certificate, pinning the
/// backend to that CA (equivalent to HPKP without the header mechanism).
fn apply_ca_pinning(builder: ClientBuilder) -> ClientBuilder {
    let path = paths::config_dir().join("ca.crt");
    if !path.exists() {
        // No pinned CA: the agent — which receives remote commands such as
        // kill_pid, isolate_network and install_package — falls back to the OS
        // trust store, so *any* CA trusted by the host (a corporate proxy CA, a
        // rogue CA planted by malware) could MITM the control channel. Emit a
        // persistent warning so an operator running without pinning is doing so
        // knowingly. Deploy a `<config>/ca.crt` to pin the backend.
        warn!(
            expected = %path.display(),
            "TLS: no pinned CA — trusting the system root store for the command \
             channel. This is INSECURE for a remote-control agent; provision ca.crt to pin."
        );
        return builder;
    }

    match std::fs::read(&path) {
        Ok(pem) => match reqwest::Certificate::from_pem(&pem) {
            Ok(cert) => {
                info!(ca = %path.display(), "TLS: pinning backend to custom CA");
                builder
                    .tls_built_in_root_certs(false)
                    .add_root_certificate(cert)
            }
            Err(e) => {
                warn!("TLS: cannot parse {}: {e} — using system roots", path.display());
                builder
            }
        },
        Err(e) => {
            warn!("TLS: cannot read {}: {e} — using system roots", path.display());
            builder
        }
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
    use super::normalize_base_url;

    #[test]
    fn trims_trailing_slash() {
        assert_eq!(normalize_base_url("https://api.example.com/"), "https://api.example.com");
    }

    #[test]
    fn trims_multiple_trailing_slashes() {
        assert_eq!(normalize_base_url("https://api.example.com///"), "https://api.example.com");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(normalize_base_url("  https://api.example.com/  "), "https://api.example.com");
    }

    #[test]
    fn leaves_clean_url_untouched() {
        assert_eq!(normalize_base_url("https://api.example.com"), "https://api.example.com");
    }

    #[test]
    fn preserves_path_prefix() {
        assert_eq!(normalize_base_url("https://h.example.com/base/"), "https://h.example.com/base");
    }
}
