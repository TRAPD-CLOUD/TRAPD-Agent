//! Session-holder tests against a local mock backend (plain HTTP on loopback,
//! same approach as the updater test).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::identity::Protection;

struct TestKey(SigningKey);

impl TestKey {
    fn new() -> Self {
        Self(SigningKey::from_slice(&[9u8; 32]).unwrap())
    }
}

impl IdentityKey for TestKey {
    fn public_key_spki_der(&self) -> Vec<u8> {
        let p = self.0.verifying_key().to_encoded_point(false);
        crate::identity::spki_from_xy(
            p.x().unwrap().as_slice().try_into().unwrap(),
            p.y().unwrap().as_slice().try_into().unwrap(),
        )
    }
    fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let sig: Signature = self.0.sign(msg);
        Ok(sig.to_der().as_bytes().to_vec())
    }
    fn protection(&self) -> Protection {
        Protection::Software
    }
}

#[derive(Clone, Debug)]
struct Req {
    path: String,
    auth: String,
    body: String,
}

type Handler = Arc<dyn Fn(&Req) -> (u16, String) + Send + Sync>;

struct Mock {
    base: String,
    log: Arc<StdMutex<Vec<Req>>>,
}

impl Mock {
    async fn start(handler: Handler) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let log = Arc::new(StdMutex::new(Vec::new()));
        let log2 = Arc::clone(&log);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let handler = Arc::clone(&handler);
                let log = Arc::clone(&log2);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head_end, len) = loop {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..p]).to_ascii_lowercase();
                            let len = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            break (p + 4, len);
                        }
                    };
                    while buf.len() < head_end + len {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let path = head
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("")
                        .to_string();
                    let auth = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("authorization")
                                .then(|| v.trim().to_string())
                        })
                        .unwrap_or_default();
                    let body = String::from_utf8_lossy(&buf[head_end..head_end + len]).to_string();
                    let req = Req { path, auth, body };
                    log.lock().unwrap().push(req.clone());
                    let (status, resp) = handler(&req);
                    let out = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{resp}",
                        resp.len()
                    );
                    let _ = sock.write_all(out.as_bytes()).await;
                });
            }
        });
        Mock { base, log }
    }

    fn count(&self, suffix: &str) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path.ends_with(suffix))
            .count()
    }

    fn first(&self, suffix: &str) -> Req {
        self.log
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.path.ends_with(suffix))
            .cloned()
            .unwrap_or_else(|| panic!("no request to {suffix}"))
    }
}

const NONCE: &str = "bm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm9uY2U=";

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("trapd-sess-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_legacy_creds(path: &std::path::Path) {
    let c = Credentials {
        agent_id: "agent-1".into(),
        agent_secret: "legacy-secret".into(),
        project_id: "proj-1".into(),
    };
    crate::enrollment::write_credentials_at(path, &c).unwrap();
}

fn holder(base: &str, path: Option<PathBuf>, mode: Mode, probe: bool) -> SessionTokens {
    let mut st = State::new(mode);
    st.probe_session_first = probe;
    SessionTokens {
        net: Some(Net {
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
            base: base.to_string(),
            agent_id: "agent-1".into(),
            project_id: "proj-1".into(),
            creds_path: path,
            key: Some(Arc::new(TestKey::new())),
        }),
        state: Mutex::new(st),
    }
}

fn legacy() -> Mode {
    Mode::Legacy {
        secret: Zeroizing::new("legacy-secret".into()),
        bind: Bind::Pending,
    }
}

/// Mock backend that verifies the signature like the real server does and
/// hands out `tok-N` tokens living `lifetime_ms`.
fn backend(bind_status: u16, lifetime_ms: i64, tokens_issued: Arc<AtomicU32>) -> Handler {
    Arc::new(move |req: &Req| {
        if req.path.ends_with("/identity/bind") {
            return (bind_status, r#"{"bound_at":"2026-01-01T00:00:00Z"}"#.into());
        }
        if req.path.ends_with("/session/challenge") {
            return (200, format!(r#"{{"nonce":"{NONCE}","expires_in":60}}"#));
        }
        if req.path.ends_with("/session") {
            let v: serde_json::Value = serde_json::from_str(&req.body).unwrap();
            assert_eq!(v["nonce"], NONCE);
            let sig = B64.decode(v["signature"].as_str().unwrap()).unwrap();
            let vk = crate::identity::tests::vk_from_spki(&TestKey::new().public_key_spki_der());
            let msg = format!("trapd-agent-session-v1\nagent-1\n{NONCE}");
            if vk
                .verify(msg.as_bytes(), &Signature::from_der(&sig).unwrap())
                .is_err()
            {
                return (401, "{}".into());
            }
            let n = tokens_issued.fetch_add(1, Ordering::SeqCst) + 1;
            let exp = (Utc::now() + chrono::Duration::milliseconds(lifetime_ms))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            return (
                200,
                format!(r#"{{"token":"tok-{n}","expires_at":"{exp}"}}"#),
            );
        }
        (404, "{}".into())
    })
}

#[test]
fn renew_after_is_two_thirds_of_lifetime() {
    assert_eq!(
        renew_after(Duration::from_secs(900)),
        Duration::from_secs(600)
    );
    assert_eq!(renew_after(Duration::from_secs(3)), Duration::from_secs(2));
}

#[tokio::test]
async fn bind_200_signs_session_and_drops_the_secret_after_the_bind() {
    let dir = scratch("bind200");
    let path = dir.join("credentials.json");
    write_legacy_creds(&path);
    let issued = Arc::new(AtomicU32::new(0));
    let inner = backend(200, 900_000, Arc::clone(&issued));
    // The file must still hold the secret while the bind is in flight.
    let seen_during_bind = Arc::new(StdMutex::new(String::new()));
    let (p2, seen2) = (path.clone(), Arc::clone(&seen_during_bind));
    let handler: Handler = Arc::new(move |req: &Req| {
        if req.path.ends_with("/identity/bind") {
            *seen2.lock().unwrap() = std::fs::read_to_string(&p2).unwrap();
        }
        inner(req)
    });
    let mock = Mock::start(handler).await;
    let h = holder(&mock.base, Some(path.clone()), legacy(), false);

    assert_eq!(h.current().await, "tok-1");
    assert_eq!(
        h.current().await,
        "tok-1",
        "token is reused until 2/3 of its life"
    );
    assert_eq!(issued.load(Ordering::SeqCst), 1);

    let bind = mock.first("/identity/bind");
    assert_eq!(bind.auth, "Bearer legacy-secret");
    let body: serde_json::Value = serde_json::from_str(&bind.body).unwrap();
    assert_eq!(body["protection"], "software");
    assert_eq!(
        body["public_key"],
        B64.encode(TestKey::new().public_key_spki_der())
    );
    assert!(seen_during_bind.lock().unwrap().contains("legacy-secret"));

    let after = std::fs::read_to_string(&path).unwrap();
    assert!(
        !after.contains("legacy-secret") && !after.contains("agent_secret"),
        "{after}"
    );
    assert!(after.contains("agent-1") && after.contains("proj-1"));
    assert_eq!(
        mock.count("/identity/bind"),
        1,
        "bind is not repeated once bound"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn bind_404_keeps_the_legacy_secret_and_never_touches_the_file() {
    let dir = scratch("bind404");
    let path = dir.join("credentials.json");
    write_legacy_creds(&path);
    let before = std::fs::read_to_string(&path).unwrap();
    let mock = Mock::start(backend(404, 900_000, Arc::new(AtomicU32::new(0)))).await;
    let h = holder(&mock.base, Some(path.clone()), legacy(), false);

    assert_eq!(h.current().await, "legacy-secret");
    assert_eq!(h.current().await, "legacy-secret");
    assert_eq!(
        mock.count("/identity/bind"),
        1,
        "no re-probe within the window"
    );
    assert_eq!(mock.count("/session/challenge"), 0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn bind_409_stops_the_identity_without_fallback() {
    let dir = scratch("bind409");
    let path = dir.join("credentials.json");
    write_legacy_creds(&path);
    let before = std::fs::read_to_string(&path).unwrap();
    let mock = Mock::start(backend(409, 900_000, Arc::new(AtomicU32::new(0)))).await;
    let h = holder(&mock.base, Some(path.clone()), legacy(), false);

    assert_eq!(h.current().await, "", "no fallback to the legacy secret");
    assert!(h.is_stopped().await);
    assert_eq!(h.current().await, "");
    assert_eq!(mock.count("/identity/bind"), 1);
    assert_eq!(mock.count("/session"), 0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn transient_bind_failure_keeps_legacy_and_the_secret_on_disk() {
    let dir = scratch("bind500");
    let path = dir.join("credentials.json");
    write_legacy_creds(&path);
    let mock = Mock::start(backend(500, 900_000, Arc::new(AtomicU32::new(0)))).await;
    let h = holder(&mock.base, Some(path.clone()), legacy(), false);

    assert_eq!(h.current().await, "legacy-secret");
    assert!(std::fs::read_to_string(&path)
        .unwrap()
        .contains("legacy-secret"));
    assert!(!h.is_stopped().await);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn crash_after_bind_is_recovered_without_rebinding() {
    // Backend already bound the key and nulled the secret (bind would 401), but
    // the file still holds the secret.
    let dir = scratch("crash");
    let path = dir.join("credentials.json");
    write_legacy_creds(&path);
    let mock = Mock::start(backend(401, 900_000, Arc::new(AtomicU32::new(0)))).await;
    let h = holder(&mock.base, Some(path.clone()), legacy(), true);

    assert_eq!(h.current().await, "tok-1");
    assert_eq!(mock.count("/identity/bind"), 0);
    assert!(!std::fs::read_to_string(&path)
        .unwrap()
        .contains("legacy-secret"));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn token_is_renewed_at_two_thirds_of_its_lifetime() {
    let issued = Arc::new(AtomicU32::new(0));
    let mock = Mock::start(backend(200, 4_500, Arc::clone(&issued))).await;
    let h = holder(&mock.base, None, Mode::Session, false);

    assert_eq!(h.current().await, "tok-1");
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        h.current().await,
        "tok-1",
        "before 2/3 (3s) nothing is renewed"
    );
    tokio::time::sleep(Duration::from_millis(2_000)).await;
    assert_eq!(h.current().await, "tok-2", "after 2/3 the token is renewed");
    assert_eq!(issued.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_401_triggers_exactly_one_renewal() {
    let issued = Arc::new(AtomicU32::new(0));
    let mock = Mock::start(backend(200, 900_000, Arc::clone(&issued))).await;
    let h = holder(&mock.base, None, Mode::Session, false);

    let t1 = h.current().await;
    assert_eq!(t1, "tok-1");
    // A 401 for a token that is not the current one is ignored.
    h.report_unauthorized("stale").await;
    assert_eq!(h.current().await, "tok-1");

    h.report_unauthorized(&t1).await;
    let t2 = h.current().await;
    assert_eq!(t2, "tok-2");
    // The backend keeps answering 401: no renewal storm.
    h.report_unauthorized(&t2).await;
    assert_eq!(h.current().await, "tok-2");
    assert_eq!(issued.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn rejected_signature_backs_off_instead_of_hammering() {
    let mock = Mock::start(Arc::new(|req: &Req| {
        if req.path.ends_with("/session/challenge") {
            (200, format!(r#"{{"nonce":"{NONCE}","expires_in":60}}"#))
        } else {
            (401, "{}".into())
        }
    }))
    .await;
    let h = holder(&mock.base, None, Mode::Session, false);
    assert_eq!(h.current().await, "");
    assert_eq!(h.current().await, "");
    assert_eq!(
        mock.count("/session/challenge"),
        1,
        "second call is inside the backoff"
    );
}

#[tokio::test]
async fn fixed_holder_returns_its_token_without_network() {
    let h = SessionTokens::fixed("static");
    assert_eq!(h.current().await, "static");
    h.report_unauthorized("static").await;
    assert_eq!(h.current().await, "static");
}
