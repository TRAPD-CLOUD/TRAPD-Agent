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

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::ClientBuilder;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;
use tracing::{info, warn};

use crate::paths;
use crate::selfprotect::network_guard::tls_pin::{self, PinningVerifier};

const USER_AGENT: &str = concat!("trapd-agent/", env!("CARGO_PKG_VERSION"));

/// Opt-out that lets the control channel fall back to the host's **system trust
/// store** when no `<config>/ca.crt` is provisioned. Unset by default so the
/// agent is fail-closed: a remote-control agent that receives `kill_pid` /
/// `isolate_network` / `install_package` must not trust every CA the host does.
/// Set to `1`/`true`/`yes`/`on` only when the backend is fronted by a
/// publicly-trusted CA and pinning is deliberately not used.
const ALLOW_SYSTEM_ROOTS_ENV: &str = "TRAPD_TLS_ALLOW_SYSTEM_ROOTS";

/// Buffer a control-plane reply only while it fits the endpoint's budget.
/// Enforce the limit on received chunks too, including replies without a length.
pub(crate) async fn bounded_body(mut response: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    if response.content_length().is_some_and(|n| n > max as u64) {
        anyhow::bail!("HTTP response exceeds the {max}-byte limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > max - body.len() {
            anyhow::bail!("HTTP response exceeds the {max}-byte limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Small JSON replies from enrollment, session and audit endpoints.
pub(crate) const CONTROL_REPLY_BYTES: usize = 64 * 1024;

pub(crate) async fn control_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T> {
    Ok(serde_json::from_slice(
        &bounded_body(response, CONTROL_REPLY_BYTES).await?,
    )?)
}

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
///   - optional SPKI pinning / observation of the presented chain
///     ([`crate::selfprotect::network_guard::tls_pin`])
///   - optional mTLS client identity (`<config>/agent.{crt,key}`)
///   - bounded total + connect timeouts
///   - a stable `User-Agent` carrying the agent version
///
/// Fail-closed: any unrecoverable TLS-configuration problem returns `Err`
/// instead of degrading to a plain `reqwest::Client::new()`. A remote-control
/// agent must never ship commands/telemetry over a channel it could not pin.
pub fn build_client(total_timeout: Duration, connect_timeout: Duration) -> Result<reqwest::Client> {
    base_builder(total_timeout, connect_timeout)
        .use_preconfigured_tls(tls_config()?)
        .build()
        .context("http: failed to build TLS client")
}

/// Settings shared by every backend client, apart from TLS.
///
/// No idle connection is kept: SPKI pins are checked when a connection is *established*, never on
/// a reused one, and a signed config can add, change or remove pins at any time. A pooled
/// connection would otherwise keep serving requests under the old policy for as long as it stays
/// busy (the heartbeat and transport reuse theirs every few seconds). A fresh handshake per
/// request makes every policy change take effect on the next request; the control channels are
/// low-rate, so the extra handshake is the price of that guarantee.
fn base_builder(total_timeout: Duration, connect_timeout: Duration) -> ClientBuilder {
    ClientBuilder::new()
        .user_agent(USER_AGENT)
        .timeout(total_timeout)
        .connect_timeout(connect_timeout)
        .pool_max_idle_per_host(0)
}

/// rustls configuration shared by every backend client: trust anchors, the
/// pinning verifier and the optional client identity.
fn tls_config() -> Result<rustls::ClientConfig> {
    let roots = trust_anchors()?;
    let verifier = PinningVerifier::new(roots, Arc::clone(tls_pin::global()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("TLS: unsupported protocol version set")?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut cfg = match mtls_identity() {
        Some((certs, key)) => match builder.clone().with_client_auth_cert(certs, key) {
            Ok(cfg) => {
                info!("mTLS: client identity loaded — mutual TLS enabled");
                cfg
            }
            Err(e) => {
                warn!("mTLS: client identity rejected: {e}");
                builder.with_no_client_auth()
            }
        },
        None => builder.with_no_client_auth(),
    };
    finish_tls_config(&mut cfg);
    Ok(cfg)
}

fn finish_tls_config(cfg: &mut rustls::ClientConfig) {
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    // rustls skips `verify_server_cert` on resumed handshakes, so a cached session would bypass a
    // pin policy that changed after it was established. Every handshake must run the verifier.
    cfg.resumption = rustls::client::Resumption::disabled();
}

/// `<config>/ca.crt` as the *only* trusted root, pinning the backend to that CA
/// (equivalent to HPKP without the header mechanism).
///
/// Fail-closed: a missing `ca.crt` is an error unless `TRAPD_TLS_ALLOW_SYSTEM_ROOTS`
/// is set; a present-but-unreadable/unparseable `ca.crt` is *always* an error
/// (never a silent fall-back to system roots, which would defeat pinning).
fn trust_anchors() -> Result<RootCertStore> {
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
        return Ok(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        });
    }

    let pem = crate::paths::bounded_regular_bytes(&path, 1024 * 1024)
        .with_context(|| format!("TLS: cannot read pinned CA {}", path.display()))?;
    let mut roots = RootCertStore::empty();
    let mut count = 0usize;
    for cert in CertificateDer::pem_slice_iter(&pem) {
        let cert =
            cert.with_context(|| format!("TLS: cannot parse pinned CA {}", path.display()))?;
        roots
            .add(cert)
            .with_context(|| format!("TLS: cannot use pinned CA {}", path.display()))?;
        count += 1;
    }
    if count == 0 {
        return Err(anyhow!(
            "TLS: pinned CA {} contains no certificate",
            path.display()
        ));
    }
    info!(ca = %path.display(), "TLS: pinning backend to custom CA");
    Ok(roots)
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

/// Load a PEM client certificate chain + key for mutual TLS. Both files must be
/// present and parse; otherwise mTLS is skipped (TLS still applies).
fn mtls_identity() -> Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_path = paths::config_dir().join("agent.crt");
    let key_path = paths::config_dir().join("agent.key");

    if !cert_path.exists() || !key_path.exists() {
        return None;
    }
    let cert_pem = crate::paths::bounded_regular_bytes(&cert_path, 1024 * 1024)
        .map_err(|e| warn!("mTLS: cannot read {}: {e}", cert_path.display()))
        .ok()?;
    let key_pem = crate::paths::bounded_regular_bytes(&key_path, 64 * 1024)
        .map_err(|e| warn!("mTLS: cannot read {}: {e}", key_path.display()))
        .ok()?;
    let certs = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| warn!("mTLS: cannot parse {}: {e}", cert_path.display()))
        .ok()?;
    if certs.is_empty() {
        warn!("mTLS: {} contains no certificate", cert_path.display());
        return None;
    }
    let key = PrivateKeyDer::from_pem_slice(&key_pem)
        .map_err(|e| warn!("mTLS: cannot parse {}: {e}", key_path.display()))
        .ok()?;
    Some((certs, key))
}

/// Normalise a backend base URL: trim whitespace and any trailing slashes so
/// callers can safely do `format!("{base}/api/...")` without producing `//`.
pub fn normalize_base_url(raw: &str) -> String {
    raw.trim().trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    #[tokio::test]
    async fn every_request_opens_a_new_connection_so_a_pin_change_takes_effect_at_once() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    // keep-alive offered: a pooled client would reuse this connection
                    while let Ok(n) = sock.read(&mut buf).await {
                        if n == 0 {
                            return;
                        }
                        let _ = sock
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .await;
                    }
                });
            }
        });
        let client = super::base_builder(Duration::from_secs(5), Duration::from_secs(2))
            .no_proxy()
            .build()
            .unwrap();
        for _ in 0..3 {
            let r = client.get(format!("http://{addr}/")).send().await.unwrap();
            assert_eq!(r.text().await.unwrap(), "ok");
        }
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn body_budget_applies_to_chunked_and_declared_lengths() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn reply(framing: &'static [u8]) -> reqwest::Response {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0; 1024];
                socket.read(&mut buf).await.unwrap();
                socket.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
                socket.write_all(framing).await.unwrap();
            });
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .get(format!("http://{addr}/"))
                .send()
                .await
                .unwrap()
        }
        let chunked = b"Transfer-Encoding: chunked\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n";
        assert_eq!(
            super::bounded_body(reply(chunked).await, 4).await.unwrap(),
            b"abcd"
        );
        assert!(super::bounded_body(reply(chunked).await, 3).await.is_err());
        let declared = b"Content-Length: 4\r\n\r\nabcd";
        assert!(super::bounded_body(reply(declared).await, 3).await.is_err());
    }

    use super::{normalize_base_url, pin_required};

    #[test]
    fn tls_session_resumption_is_disabled_so_every_handshake_checks_the_pins() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        super::finish_tls_config(&mut cfg);
        let dbg = format!("{:?}", cfg.resumption);
        let disabled = format!("{:?}", rustls::client::Resumption::disabled());
        assert_eq!(dbg, disabled);
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

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
