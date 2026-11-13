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
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(USER_AGENT)
        .timeout(total_timeout)
        .connect_timeout(connect_timeout);

    let builder = apply_ca_pinning(builder)?;
    let builder = apply_mtls_identity(builder)?;

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

/// Load an optional PEM identity. A partly provisioned or invalid identity is
/// a configuration error; never silently downgrade a configured mTLS client.
fn apply_mtls_identity(builder: ClientBuilder) -> Result<ClientBuilder> {
    let cert_path = paths::config_dir().join("agent.crt");
    let key_path = paths::config_dir().join("agent.key");
    let read_optional = |path: &std::path::Path| -> Result<Option<Vec<u8>>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A dangling symlink is configured material, not absence.
                match std::fs::symlink_metadata(path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    _ => Err(anyhow!("mTLS: configured identity is unreadable")),
                }
            }
            Err(_) => Err(anyhow!("mTLS: configured identity is unreadable")),
        }
    };
    let cert = read_optional(&cert_path)?;
    let key = read_optional(&key_path)?;
    match (cert, key) {
        (None, None) => Ok(builder),
        (Some(mut cert), Some(key)) => {
            cert.extend_from_slice(b"\n");
            cert.extend_from_slice(&key);
            let identity = reqwest::Identity::from_pem(&cert)
                .context("mTLS: configured certificate/key identity is invalid")?;
            info!("mTLS: client identity loaded");
            Ok(builder.identity(identity))
        }
        _ => Err(anyhow!(
            "mTLS: certificate and private key must both be provisioned"
        )),
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

    // Run in a subprocess so TLS configuration cannot race other tests' env.
    #[test]
    fn rejects_http_before_transmitting_credentials() {
        if std::env::var_os("TRAPD_HTTP_SECURITY_TEST_CHILD").is_some() {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let client = super::control_client().unwrap();
                let request = client
                    .get(format!("http://{address}/commands"))
                    .bearer_auth("secret-must-never-leave-host")
                    .timeout(std::time::Duration::from_millis(100))
                    .send()
                    .await;
                assert!(request.is_err(), "HTTP must be rejected before I/O");
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(50), listener.accept())
                        .await
                        .is_err(),
                    "credentials reached plaintext listener"
                );
            });
            return;
        }
        let dir = std::env::temp_dir().join(format!("trapd-http-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "http::tests::rejects_http_before_transmitting_credentials",
                "--nocapture",
            ])
            .env("TRAPD_HTTP_SECURITY_TEST_CHILD", "1")
            .env("TRAPD_TLS_ALLOW_SYSTEM_ROOTS", "1")
            .env("TRAPD_CONFIG_DIR", &dir)
            .output()
            .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn incomplete_or_malformed_mtls_never_degrades_to_no_identity() {
        if std::env::var_os("TRAPD_MTLS_SECURITY_TEST_CHILD").is_some() {
            let dir = crate::paths::config_dir();
            std::fs::write(dir.join("agent.crt"), b"malformed cert").unwrap();
            assert!(
                super::control_client().is_err(),
                "missing key must fail closed"
            );
            std::fs::write(dir.join("agent.key"), b"malformed key").unwrap();
            assert!(
                super::control_client().is_err(),
                "bad identity must fail closed"
            );
            std::fs::remove_file(dir.join("agent.crt")).unwrap();
            assert!(
                super::control_client().is_err(),
                "missing certificate must fail closed"
            );
            std::fs::create_dir(dir.join("agent.crt")).unwrap();
            assert!(
                super::control_client().is_err(),
                "unreadable identity must fail closed"
            );
            return;
        }
        let dir = std::env::temp_dir().join(format!("trapd-mtls-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "http::tests::incomplete_or_malformed_mtls_never_degrades_to_no_identity",
                "--nocapture",
            ])
            .env("TRAPD_MTLS_SECURITY_TEST_CHILD", "1")
            .env("TRAPD_TLS_ALLOW_SYSTEM_ROOTS", "1")
            .env("TRAPD_CONFIG_DIR", &dir)
            .output()
            .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
