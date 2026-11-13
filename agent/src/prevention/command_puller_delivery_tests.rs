use super::*;
use crate::prevention::commands::CommandPayload;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn server(responses: Vec<(u16, String)>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/commands", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        let mut requests = Vec::new();
        for (status, body) in responses {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let header_end;
            loop {
                let mut byte = [0];
                connection.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16384);
                if request.ends_with(b"\r\n\r\n") {
                    header_end = request.len();
                    break;
                }
            }
            let head = String::from_utf8_lossy(&request);
            let length = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|n| n.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            request.resize(header_end + length, 0);
            connection
                .read_exact(&mut request[header_end..])
                .await
                .unwrap();
            requests.push(String::from_utf8(request).unwrap());
            let response=format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
            connection.write_all(response.as_bytes()).await.unwrap();
        }
        requests
    });
    (url, handle)
}
fn fixture(
    url: String,
) -> (
    CommandPuller,
    tokio::sync::mpsc::Receiver<CommandEnvelope>,
    SignedCommand,
    std::path::PathBuf,
) {
    let dir = std::env::temp_dir().join(format!("trapd-delivery-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let key = SigningKey::from_bytes(&[47; 32]);
    let public = dir.join("pub");
    std::fs::write(&public, key.verifying_key().as_bytes()).unwrap();
    let verifier =
        Arc::new(Verifier::new(&public, "agent-test".into(), &dir.join("nonces.json")).unwrap());
    let journal = Arc::new(CommandJournal::open(&dir.join("journal")).unwrap());
    let now = chrono::Utc::now();
    let envelope = CommandEnvelope {
        command_id: uuid::Uuid::new_v4(),
        nonce: uuid::Uuid::new_v4(),
        agent_id: "agent-test".into(),
        issued_at: now,
        expires_at: now + chrono::Duration::minutes(1),
        payload: CommandPayload::DeisolateNetwork,
    };
    let signature = base64::engine::general_purpose::STANDARD
        .encode(key.sign(&serde_json::to_vec(&envelope).unwrap()).to_bytes());
    let signed = SignedCommand {
        envelope,
        signature,
    };
    let (out, rx) = tokio::sync::mpsc::channel(1);
    let (audit_tx, _) = tokio::sync::mpsc::channel(1);
    // Plain loopback HTTP is injected only for transport-independent protocol
    // tests. Production new() always constructs the HTTPS-only pinned client.
    let puller = CommandPuller {
        client: reqwest::Client::new(),
        url,
        token: "test-token".into(),
        verifier,
        journal,
        audit: AuditEmitter::new(audit_tx, "test".into(), "test".into()),
        out,
        interval: Duration::from_secs(2),
        result_offset: AtomicUsize::new(0),
    };
    (puller, rx, signed, dir)
}
#[tokio::test]
async fn duplicate_delivery_executes_once_and_returns_durable_result() {
    // Build the signed envelope before binding the fixture to its test server.
    let (mut puller, mut rx, signed, dir) = fixture(String::new());
    let batch = serde_json::to_string(&vec![signed.clone()]).unwrap();
    let (url, requests) = server(vec![
        (200, batch.clone()),
        (200, "{}".into()),
        (200, batch),
        (200, "{}".into()),
    ])
    .await;
    puller.url = url;
    assert_eq!(puller.poll_once().await, PollOutcome::Delivered);
    let command = rx.try_recv().unwrap();
    puller.journal.start(command.command_id).unwrap();
    let result = CommandResult {
        action: "network_deisolated".into(),
        kind: "network_deisolate".into(),
        success: true,
        reason: Some("done".into()),
        details: serde_json::Value::Null,
        reported_at: chrono::Utc::now(),
    };
    puller.journal.complete(command.command_id, result).unwrap();
    assert_eq!(puller.poll_once().await, PollOutcome::Delivered);
    assert!(
        rx.try_recv().is_err(),
        "duplicate must never dispatch again"
    );
    puller.flush_results().await;
    assert!(puller.journal.pending_results().unwrap().is_empty());
    let requests = requests.await.unwrap();
    assert!(requests[0]
        .to_ascii_lowercase()
        .contains("x-trapd-command-receipts: 1"));
    assert!(requests[1].contains("\"state\":\"acked\""));
    assert!(requests[3].contains("\"state\":\"completed\""));
    std::fs::remove_dir_all(dir).unwrap();
}
#[tokio::test]
async fn failed_ack_and_full_execution_queue_never_dispatch_the_effect() {
    for full in [false, true] {
        let (mut puller, mut rx, signed, dir) = fixture(String::new());
        if full {
            puller.out.try_send(signed.envelope.clone()).unwrap();
        }
        let (url, requests) = server(vec![
            (200, serde_json::to_string(&vec![signed]).unwrap()),
            (if full { 200 } else { 503 }, "{}".into()),
        ])
        .await;
        puller.url = url;
        assert_eq!(puller.poll_once().await, PollOutcome::Delivered);
        if full {
            rx.try_recv().unwrap();
        }
        assert!(rx.try_recv().is_err());
        let outcomes = puller.journal.pending_results().unwrap();
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].1.success);
        assert!(outcomes[0]
            .1
            .reason
            .as_deref()
            .unwrap()
            .contains("no effect"));
        requests.await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
