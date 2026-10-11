use super::{is_valid_target_pid, Engine, EngineConfig, ResponseLevel};
use crate::config::AgentConfig;
use crate::deception::HoneytokenStore;
use crate::prevention::audit::AuditEmitter;
use crate::prevention::network::Backend;
use crate::prevention::policy::{Match, PolicyHandle, PolicyStore, RuleAction};
use crate::prevention::response::{self, AutoAction, Targets};
use crate::schema::{AgentEvent, EventAction, EventData};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

/// Build an `Engine` wired to an in-memory audit channel for command-path
/// tests. The honeytoken store points at a throwaway temp path (missing →
/// starts empty) and the network backend is `None` so nothing touches the
/// host firewall.
fn test_engine() -> (Engine, mpsc::Receiver<AgentEvent>) {
    let (tx, rx) = mpsc::channel(16);
    let audit = AuditEmitter::new(tx, "test-agent".into(), "test-host".into());
    let ht_path = std::env::temp_dir().join(format!(
        "trapd-test-ht-{}-{:p}.json",
        std::process::id(),
        &rx
    ));
    let engine = Engine::new(
        PolicyHandle::new(PolicyStore::default()),
        audit,
        EngineConfig {
            net_backend: Backend::None,
            management_host: None,
        },
        Arc::new(HoneytokenStore::load_from(ht_path)),
        Arc::new(RwLock::new(AgentConfig::default())),
    );
    (engine, rx)
}

#[tokio::test]
async fn isolation_dns_preflight_rejects_before_any_firewall_mutation() {
    use crate::prevention::network::tests::{no_calls, setup};
    use crate::prevention::runtime::tests::fake_management_dns;
    let (mut engine, mut audit_rx) = test_engine();
    engine.cfg.net_backend = Backend::Iptables;
    engine.cfg.management_host = Some("control.example.test".into());
    engine.cfg_handle.write().unwrap().prevention_enabled = true;
    let backend = "192.0.2.1".parse().unwrap();
    let dns = "192.0.2.53".parse().unwrap();
    let dns_v6 = "2001:db8::53".parse().unwrap();
    for servers in [Ok(vec![dns, dns_v6]), Ok(vec![]), Err("OS DNS unavailable")] {
        let _fixture = fake_management_dns([Ok(vec![backend])].into(), servers);
        setup(false);
        engine.cmd_isolate(vec![dns], "dns-preflight").await;
        assert!(no_calls(), "DNS preflight failure must preserve rules");
        let EventData::Prevention(audit) = audit_rx.try_recv().unwrap().data else {
            panic!("audit");
        };
        assert!(!audit.success);
        assert!(audit.reason.contains("DNS"), "{}", audit.reason);
    }
    // A backend address must not implicitly authorize a DNS-server exception.
    let _fixture = fake_management_dns([Ok(vec![backend])].into(), Ok(vec![backend]));
    setup(false);
    engine.cmd_isolate(vec![], "dns-preflight").await;
    assert!(no_calls());
}

#[tokio::test]
async fn isolation_dns_preflight_accepts_explicit_resolvers_and_literal_backends() {
    use crate::prevention::network::tests::{called, setup};
    use crate::prevention::runtime::tests::fake_management_dns;
    let (mut engine, _) = test_engine();
    engine.cfg.net_backend = Backend::Iptables;
    engine.cfg.management_host = Some("control.example.test".into());
    engine.cfg_handle.write().unwrap().prevention_enabled = true;
    let backend = "192.0.2.1".parse().unwrap();
    let dns = "192.0.2.53".parse().unwrap();
    let dns_v6 = "2001:db8::53".parse().unwrap();
    let _fixture = fake_management_dns(
        [Ok(vec![backend]), Ok(vec![backend])].into(),
        Ok(vec![dns, dns_v6]),
    );
    engine.cfg_handle.write().unwrap().isolation_allowlist_ips = vec![dns.to_string()];
    let allow = engine.isolation_allowlist(&[dns_v6]).await.unwrap();
    assert_eq!(allow.len(), 3);
    assert!(allow.contains(&backend) && allow.contains(&dns) && allow.contains(&dns_v6));
    setup(false);
    engine
        .cmd_isolate(vec![dns_v6], "dns-preflight-allowed")
        .await;
    assert!(called(
        "iptables",
        &["-A", "TRAPD_ISOLATE", "-d", "192.0.2.53", "-j", "ACCEPT"]
    ));
    assert!(called(
        "ip6tables",
        &["-A", "TRAPD_ISOLATE", "-d", "2001:db8::53", "-j", "ACCEPT"]
    ));
    engine.cfg.management_host = Some("2001:db8::1".into());
    let allow = engine.isolation_allowlist(&[]).await.unwrap();
    assert!(allow.contains(&"2001:db8::1".parse().unwrap()));
}

#[tokio::test]
async fn isolation_resolves_the_backend_hostname_at_action_time() {
    let (mut engine, _) = test_engine();
    engine.cfg.management_host = Some("localhost".into());
    let allow = engine.isolation_allowlist(&[]).await.unwrap();
    assert!(
        allow.iter().any(std::net::IpAddr::is_loopback),
        "backend DNS was not refreshed: {allow:?}"
    );
}

#[tokio::test]
async fn isolation_refreshes_rotated_dns_for_all_paths_and_fails_before_mutation() {
    use crate::prevention::network::tests::{called, no_calls, setup};
    use crate::prevention::runtime::tests::fake_management_answers;
    let (mut engine, mut audit_rx) = test_engine();
    engine.cfg.net_backend = Backend::Iptables;
    engine.cfg.management_host = Some("control.example.test".into());
    {
        let mut cfg = engine.cfg_handle.write().unwrap();
        cfg.prevention_enabled = true;
        cfg.honeytoken_response = "isolate".into();
    }
    let old = "192.0.2.1".parse().unwrap();
    let new = "192.0.2.2".parse().unwrap();
    let ipv6 = "2001:db8::2".parse().unwrap();
    let _answers = fake_management_answers(
        [
            Ok(vec![old]),
            Ok(vec![new, ipv6, new]),
            Ok(vec![new, ipv6]),
            Ok(vec![new, ipv6]),
            Err("DNS unavailable"),
            Ok(vec![]),
        ]
        .into(),
    );
    setup(false);
    engine.cmd_isolate(vec![], "initial-dns").await;
    assert!(called(
        "iptables",
        &["-A", "TRAPD_ISOLATE", "-d", "192.0.2.1", "-j", "ACCEPT"]
    ));
    for path in ["command", "automatic", "honeytoken"] {
        setup(false);
        match path {
            "command" => engine.cmd_isolate(vec![], "rotated-dns").await,
            "automatic" => {
                engine
                    .execute_auto(
                        "dns-fixture",
                        "test",
                        "host",
                        &Targets {
                            pid: None,
                            process_start_time: None,
                            file_path: None,
                        },
                        &response::Decision {
                            action: AutoAction::Isolate,
                            reason: "fixture".into(),
                        },
                    )
                    .await
            }
            _ => {
                let mut data = access(false, None);
                data.accessor.pid = 0;
                engine.respond_honeytoken(&data).await;
            }
        }
        assert!(
            called(
                "iptables",
                &["-A", "TRAPD_ISOLATE", "-d", "192.0.2.2", "-j", "ACCEPT"]
            ),
            "{path}"
        );
        assert!(
            called(
                "ip6tables",
                &["-A", "TRAPD_ISOLATE", "-d", "2001:db8::2", "-j", "ACCEPT"]
            ),
            "{path}"
        );
        assert!(
            !called(
                "iptables",
                &["-A", "TRAPD_ISOLATE", "-d", "192.0.2.1", "-j", "ACCEPT"]
            ),
            "stale DNS allowance on {path}"
        );
    }
    while audit_rx.try_recv().is_ok() {}
    for cmd in ["failed-dns", "empty-dns"] {
        setup(false);
        engine
            .cmd_isolate(vec!["198.51.100.1".parse().unwrap()], cmd)
            .await;
        assert!(no_calls(), "failed resolution must not alter rules");
        let EventData::Prevention(audit) = audit_rx.try_recv().unwrap().data else {
            panic!("audit");
        };
        assert!(!audit.success);
    }
}

#[tokio::test]
async fn isolation_rechecks_live_prevention_setting_before_firewall_mutation() {
    use crate::prevention::network::tests::{no_calls, setup};
    let (mut engine, mut audit_rx) = test_engine();
    engine.cfg.net_backend = Backend::Iptables;
    engine.cfg.management_host = Some("::1".into());
    engine.cfg_handle.write().unwrap().prevention_enabled = false;
    setup(false);
    engine.cmd_isolate(vec![], "disabled-prevention").await;
    assert!(no_calls());
    let EventData::Prevention(audit) = audit_rx.try_recv().unwrap().data else {
        panic!("audit");
    };
    assert!(!audit.success);
}

#[tokio::test]
async fn isolation_uses_live_allowlist_for_commands_and_automatic_responses() {
    use crate::prevention::network::tests::{called, setup};
    let (mut engine, _audit_rx) = test_engine();
    engine.cfg.net_backend = Backend::Iptables;
    engine.cfg.management_host = Some("2001:db8::1".into());
    {
        let mut cfg = engine.cfg_handle.write().unwrap();
        cfg.prevention_enabled = true;
        cfg.honeytoken_response = "isolate".into();
        cfg.isolation_allowlist_ips = vec!["192.0.2.10".into()];
    }
    setup(false);
    engine.cmd_isolate(vec![], "initial").await;
    assert!(called(
        "iptables",
        &["-A", "TRAPD_ISOLATE", "-d", "192.0.2.10", "-j", "ACCEPT"]
    ));
    engine.cfg_handle.write().unwrap().isolation_allowlist_ips =
        vec!["192.0.2.20".into(), "invalid".into()];
    for response_path in ["command", "automatic", "honeytoken"] {
        setup(false);
        match response_path {
            "command" => {
                engine
                    .cmd_isolate(vec!["192.0.2.30".parse().unwrap()], "updated")
                    .await
            }
            "automatic" => {
                engine
                    .execute_auto(
                        "test-rule",
                        "test",
                        "test",
                        &Targets {
                            pid: None,
                            process_start_time: None,
                            file_path: None,
                        },
                        &response::Decision {
                            action: AutoAction::Isolate,
                            reason: "test".into(),
                        },
                    )
                    .await
            }
            _ => {
                let mut data = access(false, None);
                data.accessor.pid = 0;
                engine.respond_honeytoken(&data).await;
            }
        }
        assert!(
            called(
                "ip6tables",
                &["-A", "TRAPD_ISOLATE", "-d", "2001:db8::1", "-j", "ACCEPT"]
            ),
            "{response_path}"
        );
        assert!(
            called(
                "iptables",
                &["-A", "TRAPD_ISOLATE", "-d", "192.0.2.20", "-j", "ACCEPT"]
            ),
            "{response_path}"
        );
        assert!(
            !called(
                "iptables",
                &["-A", "TRAPD_ISOLATE", "-d", "192.0.2.10", "-j", "ACCEPT"]
            ),
            "removed allowance on {response_path}"
        );
        if response_path == "command" {
            assert!(called(
                "iptables",
                &["-A", "TRAPD_ISOLATE", "-d", "192.0.2.30", "-j", "ACCEPT"]
            ));
        }
    }
}

#[cfg(windows)]
#[tokio::test]
#[ignore = "blocks TEST-NET; requires elevated enforcing Windows host"]
async fn native_windows_firewall_engine_expiry_updates_dedup_and_audit() {
    let (mut engine, mut audit_rx) = test_engine();
    engine.cfg.net_backend = Backend::WindowsFirewall;
    engine
        .cmd_block_ip("203.0.113.81/32", Some(0), "command-expiry")
        .await;
    assert!(engine.blocked.lock().await.contains("203.0.113.81/32"));
    let blocked_event = audit_rx.recv().await.unwrap();
    assert!(matches!(blocked_event.action, EventAction::IpBlocked));
    match blocked_event.data {
        EventData::Prevention(data) => assert!(data.success),
        _ => panic!("expected prevention audit"),
    }
    engine.reconcile_firewall_expiry().await;
    assert!(engine.blocked.lock().await.is_empty());
    let expired_event = audit_rx.recv().await.unwrap();
    assert!(matches!(expired_event.action, EventAction::IpUnblocked));
    match expired_event.data {
        EventData::Prevention(data) => {
            assert!(data.success);
            assert_eq!(data.target, "203.0.113.81");
            assert_eq!(data.command_id.as_deref(), Some("command-expiry"));
        }
        _ => panic!("expected prevention audit"),
    }
}

#[cfg(any(target_os = "linux", windows))]
struct ChildFixture(std::process::Child);

#[cfg(any(target_os = "linux", windows))]
impl ChildFixture {
    fn new() -> Self {
        #[cfg(windows)]
        let mut command = {
            let mut c = std::process::Command::new("ping");
            c.args(["-n", "60", "127.0.0.1"]);
            c
        };
        #[cfg(target_os = "linux")]
        let mut command = {
            let mut c = std::process::Command::new("sleep");
            c.arg("60");
            c
        };
        Self(
            command
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    fn pid(&self) -> i32 {
        self.0.id() as i32
    }
}

#[cfg(any(target_os = "linux", windows))]
impl Drop for ChildFixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(any(target_os = "linux", windows))]
fn memory_command(
    pid: i32,
    generation: Option<u64>,
) -> crate::prevention::commands::CommandEnvelope {
    let mut payload =
        serde_json::json!({ "kind": "collect_process_memory", "pid": pid, "max_bytes": 4096 });
    if let Some(start) = generation {
        payload["process_start_time"] = serde_json::json!(start);
    }
    serde_json::from_value(serde_json::json!({
        "command_id": uuid::Uuid::new_v4(),
        "issued_at": chrono::Utc::now(),
        "expires_at": chrono::Utc::now() + chrono::Duration::minutes(1),
        "agent_id": "test-agent",
        "nonce": uuid::Uuid::new_v4(),
        "payload": payload,
    }))
    .unwrap()
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn memory_commands_reject_zero_and_stale_generations_without_artifacts() {
    let child = ChildFixture::new();
    let start = crate::telemetry::identity::process_start_time(child.pid()).unwrap();
    for generation in [0, start + 1] {
        let (engine, mut rx) = test_engine();
        engine.cfg_handle.write().unwrap().rtr_enabled = true;
        let env = memory_command(child.pid(), Some(generation));
        let command_id = env.command_id.to_string();
        engine.handle(env).await;
        let event = rx.try_recv().unwrap();
        assert!(matches!(event.action, EventAction::CommandRejected));
        let EventData::Prevention(audit) = event.data else {
            panic!("audit")
        };
        assert!(!audit.success);
        assert_eq!(audit.command_id.as_deref(), Some(command_id.as_str()));
        assert_eq!(audit.details["process_start_time"], generation);
        assert!(
            audit.details.get("memory_b64").is_none(),
            "refusals must not include a memory artifact"
        );
    }
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn memory_command_early_refusals_preserve_the_requested_generation() {
    for (pid, enabled, reason) in [
        (1, true, "invalid target"),
        (54321, false, "RTR is disabled"),
    ] {
        let (engine, mut rx) = test_engine();
        engine.cfg_handle.write().unwrap().rtr_enabled = enabled;
        engine.handle(memory_command(pid, Some(7))).await;
        let event = rx.try_recv().unwrap();
        assert!(matches!(event.action, EventAction::CommandRejected));
        let EventData::Prevention(audit) = event.data else {
            panic!("audit")
        };
        assert!(!audit.success);
        assert!(audit.reason.contains(reason));
        assert_eq!(audit.details["process_start_time"], 7);
        assert!(audit.details.get("memory_b64").is_none());
    }
}

#[cfg(windows)]
#[tokio::test]
async fn memory_commands_reject_missing_generation_on_windows_without_an_artifact() {
    let child = ChildFixture::new();
    let (engine, mut rx) = test_engine();
    engine.cfg_handle.write().unwrap().rtr_enabled = true;
    engine.handle(memory_command(child.pid(), None)).await;
    let event = rx.try_recv().unwrap();
    assert!(matches!(event.action, EventAction::CommandRejected));
    let EventData::Prevention(audit) = event.data else {
        panic!("audit")
    };
    assert!(!audit.success);
    assert_eq!(
        audit.details.get("process_start_time"),
        Some(&serde_json::Value::Null)
    );
    assert!(audit.details.get("memory_b64").is_none());
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn memory_commands_read_the_observed_child_and_audit_the_generation() {
    let child = ChildFixture::new();
    let start = crate::telemetry::identity::process_start_time(child.pid()).unwrap();
    let generations = if cfg!(windows) {
        vec![Some(start)]
    } else {
        vec![Some(start), None]
    };
    for generation in generations {
        let (engine, mut rx) = test_engine();
        engine.cfg_handle.write().unwrap().rtr_enabled = true;
        engine.handle(memory_command(child.pid(), generation)).await;
        let event = rx.try_recv().unwrap();
        assert!(matches!(event.action, EventAction::CommandAccepted));
        let EventData::Prevention(audit) = event.data else {
            panic!("audit")
        };
        assert!(audit.success);
        assert_eq!(
            audit.details["process_start_time"],
            serde_json::json!(generation)
        );
        let memory = audit.details["memory_b64"].as_str().unwrap();
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(memory)
            .unwrap();
        assert!(!bytes.is_empty());
        assert!(bytes.len() <= 4096);
    }
}

#[cfg(any(target_os = "linux", windows))]
fn process_command(
    kind: &str,
    pid: i32,
    generation: Option<u64>,
) -> crate::prevention::commands::CommandEnvelope {
    let mut payload = serde_json::json!({ "kind": kind, "pid": pid });
    if let Some(start) = generation {
        payload["process_start_time"] = serde_json::json!(start);
    }
    serde_json::from_value(serde_json::json!({
        "command_id": uuid::Uuid::new_v4(), "issued_at": chrono::Utc::now(),
        "expires_at": chrono::Utc::now() + chrono::Duration::minutes(1),
        "agent_id": "test-agent", "nonce": uuid::Uuid::new_v4(), "payload": payload,
    }))
    .unwrap()
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn manual_process_commands_reject_wrong_generations_without_collecting_snapshots() {
    for kind in ["kill_pid", "freeze_pid", "thaw_pid"] {
        for stale in [false, true] {
            let mut child = ChildFixture::new();
            let start = crate::telemetry::identity::process_start_time(child.pid()).unwrap();
            let generation = if stale { start + 1 } else { 0 };
            let (engine, mut rx) = test_engine();
            engine
                .handle(process_command(kind, child.pid(), Some(generation)))
                .await;
            let event = rx.try_recv().unwrap();
            assert!(matches!(event.action, EventAction::CommandRejected));
            let EventData::Prevention(audit) = event.data else {
                panic!("audit")
            };
            assert!(!audit.success);
            assert_eq!(audit.details["process_start_time"], generation);
            assert!(
                audit.details.get("snapshot").is_none(),
                "refusal must not inspect a different generation"
            );
            assert!(child.0.try_wait().unwrap().is_none());
        }
    }
}

#[cfg(windows)]
#[tokio::test]
async fn manual_process_commands_reject_missing_windows_generations() {
    for kind in ["kill_pid", "freeze_pid", "thaw_pid"] {
        let mut child = ChildFixture::new();
        let (engine, mut rx) = test_engine();
        engine
            .handle(process_command(kind, child.pid(), None))
            .await;
        let event = rx.try_recv().unwrap();
        assert!(matches!(event.action, EventAction::CommandRejected));
        let EventData::Prevention(audit) = event.data else {
            panic!("audit")
        };
        assert!(!audit.success);
        assert_eq!(
            audit.details.get("process_start_time"),
            Some(&serde_json::Value::Null)
        );
        assert!(audit.details.get("snapshot").is_none());
        assert!(child.0.try_wait().unwrap().is_none());
    }
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn manual_process_commands_control_the_observed_child_and_preserve_linux_legacy() {
    let legacy_modes = if cfg!(windows) {
        vec![false]
    } else {
        vec![false, true]
    };
    for legacy in legacy_modes {
        // This child would exit in one second unless freeze actually stops it.
        #[cfg(windows)]
        let mut command = {
            let mut c = std::process::Command::new("ping");
            c.args(["-n", "2", "127.0.0.1"]);
            c
        };
        #[cfg(target_os = "linux")]
        let mut command = {
            let mut c = std::process::Command::new("sleep");
            c.arg("1");
            c
        };
        let mut child = ChildFixture(
            command
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let start = crate::telemetry::identity::process_start_time(child.pid()).unwrap();
        let generation = (!legacy).then_some(start);
        let (engine, mut rx) = test_engine();
        engine
            .handle(process_command("freeze_pid", child.pid(), generation))
            .await;
        let event = rx.try_recv().unwrap();
        assert!(matches!(event.action, EventAction::ProcessFrozen));
        let EventData::Prevention(audit) = event.data else {
            panic!("audit")
        };
        assert!(audit.success);
        assert_eq!(
            audit.details["process_start_time"],
            serde_json::json!(generation)
        );
        assert_eq!(audit.details["snapshot"]["frozen"], true);
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "freeze must stop the short-lived child"
        );

        engine
            .handle(process_command("thaw_pid", child.pid(), generation))
            .await;
        let event = rx.try_recv().unwrap();
        assert!(matches!(event.action, EventAction::ProcessThawed));
        let EventData::Prevention(audit) = event.data else {
            panic!("audit")
        };
        assert!(audit.success);
        assert_eq!(
            audit.details["process_start_time"],
            serde_json::json!(generation)
        );
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while child.0.try_wait().unwrap().is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("thaw must allow the child to exit");

        let mut target = ChildFixture::new();
        let start = crate::telemetry::identity::process_start_time(target.pid()).unwrap();
        let generation = (!legacy).then_some(start);
        engine
            .handle(process_command("kill_pid", target.pid(), generation))
            .await;
        let event = rx.try_recv().unwrap();
        assert!(matches!(event.action, EventAction::ProcessBlocked));
        let EventData::Prevention(audit) = event.data else {
            panic!("audit")
        };
        assert!(audit.success);
        assert_eq!(
            audit.details["process_start_time"],
            serde_json::json!(generation)
        );
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while target.0.try_wait().unwrap().is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("kill must terminate the observed child");
    }
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn automatic_execution_never_kills_an_unknown_or_reused_generation() {
    for stale in [false, true] {
        let mut child = ChildFixture::new();
        let start = crate::telemetry::identity::process_start_time(child.pid()).unwrap();
        let (engine, mut rx) = test_engine();
        engine
            .execute_auto(
                "memory.inject",
                "memory",
                "fixture",
                &Targets {
                    pid: Some(child.pid()),
                    process_start_time: stale.then_some(start + 1),
                    file_path: None,
                },
                &response::Decision {
                    action: AutoAction::Kill,
                    reason: "test fixture".into(),
                },
            )
            .await;
        let EventData::Prevention(audit) = rx.try_recv().unwrap().data else {
            panic!("audit");
        };
        assert!(!audit.success);
        assert_eq!(audit.details["killed"], false);
        assert!(child.0.try_wait().unwrap().is_none());
    }
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn honeytoken_actions_never_control_an_unknown_or_reused_generation() {
    for level in ["kill", "freeze"] {
        for stale in [false, true] {
            let mut child = ChildFixture::new();
            let start = crate::telemetry::identity::process_start_time(child.pid()).unwrap();
            let (engine, mut rx) = test_engine();
            engine.cfg_handle.write().unwrap().honeytoken_response = level.into();
            let mut data = access(false, None);
            data.accessor.pid = child.pid();
            data.accessor.process_start_time = stale.then_some(start + 1);
            engine.respond_honeytoken(&data).await;
            let EventData::Prevention(audit) = rx.try_recv().unwrap().data else {
                panic!("audit");
            };
            assert_eq!(audit.details["killed"], false);
            assert_eq!(audit.details["frozen"], false);
            assert!(child.0.try_wait().unwrap().is_none());
        }
    }
}

#[cfg(any(target_os = "linux", windows))]
#[tokio::test]
async fn network_actions_never_kill_an_unknown_or_reused_generation() {
    for stale in [false, true] {
        let mut child = ChildFixture::new();
        let start = crate::telemetry::identity::process_start_time(child.pid()).unwrap();
        let (engine, mut rx) = test_engine();
        engine
            .enforce_net_match(
                "203.0.113.7".parse().unwrap(),
                443,
                Some(child.pid()),
                stale.then_some(start + 1),
                Match {
                    rule_id: "fixture".into(),
                    action: RuleAction::Block,
                    reason: "fixture".into(),
                },
                "flow",
                None,
            )
            .await;
        let EventData::Prevention(audit) = rx.try_recv().unwrap().data else {
            panic!("audit");
        };
        assert_eq!(audit.details["killed"], false);
        assert!(child.0.try_wait().unwrap().is_none());
    }
}

#[tokio::test]
async fn disabled_prevention_rejects_commands_before_policy_mutation() {
    let (engine, mut rx) = test_engine();
    engine.cfg_handle.write().unwrap().prevention_enabled = false;
    let now = chrono::Utc::now();
    engine
        .handle(crate::prevention::commands::CommandEnvelope {
            command_id: uuid::Uuid::new_v4(),
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(1),
            agent_id: "test-agent".into(),
            nonce: uuid::Uuid::new_v4(),
            payload: crate::prevention::commands::CommandPayload::UpdatePolicy {
                rules: vec![crate::prevention::policy::IocRule::Comm {
                    id: "x".into(),
                    value: "bash".into(),
                    action: crate::prevention::policy::RuleAction::Block,
                }],
            },
        })
        .await;
    assert!(
        engine.policy.read().rules().is_empty(),
        "disabled prevention must not dispatch commands"
    );
    assert!(matches!(
        rx.try_recv().unwrap().action,
        EventAction::CommandRejected
    ));
}

#[tokio::test]
async fn disabled_prevention_does_not_enforce_dns_rules() {
    let (engine, mut rx) = test_engine();
    engine.cfg_handle.write().unwrap().prevention_enabled = false;
    engine.policy.replace(
        PolicyStore::from_rules(vec![crate::prevention::policy::IocRule::Domain {
            id: "block".into(),
            value: "evil.example".into(),
            action: crate::prevention::policy::RuleAction::Block,
        }])
        .unwrap(),
    );
    engine
        .enforce_dns_resolution(&crate::schema::DnsResolutionData {
            qname: "evil.example".into(),
            qtype: "A".into(),
            resolved_ips: vec!["198.51.100.9".into()],
            cnames: vec![],
            server_addr: "10.0.0.1".into(),
            client_addr: "10.0.0.2".into(),
            transaction_id: 42,
            rcode: "NOERROR".into(),
        })
        .await;
    assert!(
        rx.try_recv().is_err(),
        "disabled prevention must not enforce DNS"
    );
}

#[test]
fn valid_target_pid_rejects_broadcast_init_and_self() {
    let own = 4242;
    // kill(2) broadcast / process-group selectors and init are never valid.
    assert!(!is_valid_target_pid(-1, own), "pid -1 (all processes)");
    assert!(!is_valid_target_pid(0, own), "pid 0 (process group)");
    assert!(!is_valid_target_pid(1, own), "pid 1 (init)");
    // The agent must never target itself via the command channel.
    assert!(!is_valid_target_pid(own, own), "own pid");
    // A real, individual, foreign PID is accepted.
    assert_eq!(is_valid_target_pid(2, own), !cfg!(windows));
    assert_eq!(is_valid_target_pid(4, own), !cfg!(windows));
    assert!(is_valid_target_pid(31337, own));
}

/// A signed `KillPid` whose target is a broadcast selector / init / the
/// agent itself must be rejected with a `CommandRejected` audit event and
/// must NOT reach `process::kill_pid` (which would SIGKILL every process the
/// root agent can signal). Issue #59.
#[test]
fn cmd_kill_pid_rejects_dangerous_targets_without_killing() {
    let own = std::process::id() as i32;
    for &pid in &[-1, 0, 1, own] {
        let (engine, mut rx) = test_engine();
        engine.cmd_kill_pid(pid, None, "cmd-1");

        let ev = rx.try_recv().expect("a rejection event must be emitted");
        assert!(
            matches!(ev.action, EventAction::CommandRejected),
            "pid {pid} must be rejected, not killed"
        );
        match ev.data {
            EventData::Prevention(p) => {
                assert!(!p.success);
                assert_eq!(p.kind, "process_block");
                assert_eq!(p.command_id.as_deref(), Some("cmd-1"));
            }
            other => panic!("expected a prevention event, got {other:?}"),
        }
        // Exactly one event (the rejection) — no ProcessBlocked follow-up.
        assert!(rx.try_recv().is_err(), "no further events for pid {pid}");
    }
}

/// The same guard protects the freeze (SIGSTOP) and thaw (SIGCONT) paths,
/// which would otherwise suspend/resume every process on `pid <= 0`.
#[test]
fn cmd_freeze_and_thaw_reject_dangerous_targets() {
    for &pid in &[-1, 0, 1] {
        let (engine, mut rx) = test_engine();
        engine.cmd_freeze_pid(pid, None, "cmd-f");
        let ev = rx.try_recv().expect("freeze rejection event");
        assert!(matches!(ev.action, EventAction::CommandRejected));

        let (engine, mut rx) = test_engine();
        engine.cmd_thaw_pid(pid, None, "cmd-t");
        let ev = rx.try_recv().expect("thaw rejection event");
        assert!(matches!(ev.action, EventAction::CommandRejected));
    }
}

/// A backend `Ip` Block rule must drive an inline `IpBlocked` enforcement
/// audit on a matching outbound flow (Phase 0 network enforcement). With the
/// `None` firewall backend nothing touches the host, but the decision still
/// fires and is audited — proving the wiring, not the side effect.
#[tokio::test]
async fn enforce_network_blocks_matching_ip_rule() {
    use crate::prevention::policy::{IocRule, RuleAction};
    use crate::schema::NetworkConnectionData;

    let (engine, mut rx) = test_engine();
    let rules = vec![IocRule::Ip {
        id: "ioc-c2".into(),
        value: "203.0.113.7".parse().unwrap(),
        action: RuleAction::Block,
    }];
    engine
        .policy
        .replace(PolicyStore::from_rules(rules).unwrap());

    let flow = NetworkConnectionData {
        protocol: "tcp".into(),
        src_addr: "10.0.0.5".into(),
        src_port: 44321,
        dst_addr: "203.0.113.7".into(),
        dst_port: 443,
        state: "established".into(),
        pid: Some(424242),
        process_start_time: None,
        process: Some("curl".into()),
        duration_ms: None,
        bytes_sent: None,
        bytes_recv: None,
        packets_sent: None,
        packets_recv: None,
        rtt_us: None,
    };
    engine.enforce_network(&flow).await;

    let ev = rx.try_recv().expect("an enforcement event must be emitted");
    assert!(matches!(ev.action, EventAction::IpBlocked));
    match ev.data {
        EventData::Prevention(p) => {
            assert_eq!(p.kind, "network_block");
            assert_eq!(p.rule_id.as_deref(), Some("ioc-c2"));
        }
        other => panic!("expected a prevention event, got {other:?}"),
    }
}

/// A non-matching destination must produce no enforcement event at all.
#[tokio::test]
async fn enforce_network_ignores_unmatched_flow() {
    use crate::schema::NetworkConnectionData;
    let (engine, mut rx) = test_engine();
    let flow = NetworkConnectionData {
        protocol: "tcp".into(),
        src_addr: "10.0.0.5".into(),
        src_port: 5000,
        dst_addr: "93.184.216.34".into(),
        dst_port: 443,
        state: "established".into(),
        pid: Some(1234),
        process_start_time: None,
        process: Some("firefox".into()),
        duration_ms: None,
        bytes_sent: None,
        bytes_recv: None,
        packets_sent: None,
        packets_recv: None,
        rtt_us: None,
    };
    engine.enforce_network(&flow).await;
    assert!(rx.try_recv().is_err(), "no rule → no enforcement event");
}

/// A `Domain` Block rule must drop every resolved A/AAAA from a matching DNS
/// answer (one enforcement audit per resolved address).
#[tokio::test]
async fn enforce_dns_resolution_blocks_resolved_ips() {
    use crate::prevention::policy::{IocRule, RuleAction};
    use crate::schema::DnsResolutionData;

    let (engine, mut rx) = test_engine();
    let rules = vec![IocRule::Domain {
        id: "ioc-evil-domain".into(),
        value: "evil.example".into(),
        action: RuleAction::Block,
    }];
    engine
        .policy
        .replace(PolicyStore::from_rules(rules).unwrap());

    let answer = DnsResolutionData {
        qname: "evil.example".into(),
        qtype: "A".into(),
        resolved_ips: vec!["198.51.100.9".into(), "198.51.100.10".into()],
        cnames: vec![],
        server_addr: "10.0.0.1".into(),
        client_addr: "10.0.0.5".into(),
        transaction_id: 4242,
        rcode: "NOERROR".into(),
    };
    engine.enforce_dns_resolution(&answer).await;

    let mut blocked = 0;
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev.action, EventAction::IpBlocked) {
            blocked += 1;
        }
    }
    assert_eq!(blocked, 2, "both resolved IPs must be blocked");
}

#[test]
fn response_level_parses_escalation_ladder() {
    assert_eq!(ResponseLevel::parse("none"), ResponseLevel::None);
    assert_eq!(ResponseLevel::parse("alert"), ResponseLevel::Alert);
    assert_eq!(ResponseLevel::parse("kill"), ResponseLevel::Kill);
    assert_eq!(ResponseLevel::parse("isolate"), ResponseLevel::Isolate);
    assert_eq!(
        ResponseLevel::parse("isolate_network"),
        ResponseLevel::Isolate
    );
    // Unknown values fail safe to the non-destructive default.
    assert_eq!(ResponseLevel::parse("wat"), ResponseLevel::Alert);
    // Case/whitespace insensitive.
    assert_eq!(ResponseLevel::parse("  KILL "), ResponseLevel::Kill);
}

#[test]
fn freeze_and_jail_both_mean_freeze_not_isolate() {
    // "jail" is the process-freeze response (SIGSTOP), NOT network isolation.
    assert_eq!(ResponseLevel::parse("freeze"), ResponseLevel::Freeze);
    assert_eq!(ResponseLevel::parse("jail"), ResponseLevel::Freeze);
    assert_eq!(ResponseLevel::Freeze.as_str(), "freeze");
}

#[test]
fn metadata_access_never_kills_or_freezes() {
    let mut data = access(false, None);
    data.access_kind = "stat".into();
    assert!(ResponseLevel::Kill.for_access(&data).is_none());
}

fn access(allowlisted: bool, tty: Option<&str>) -> crate::schema::HoneytokenAccessData {
    crate::schema::HoneytokenAccessData {
        sensor: None,
        assessment: None,
        assessment_reasons: Vec::new(),
        mode: None,
        token_id: "t".into(),
        path: "/home/alice/.ssh/id_ed25519".into(),
        kind: "ssh_private_key".into(),
        access_kind: "open".into(),
        open_flags: 0,
        confidence: 100,
        mitre_tactic: String::new(),
        mitre_technique: String::new(),
        accessor: crate::schema::ProcessLineage {
            pid: 4242,
            process_start_time: None,
            uid: 0,
            gid: 0,
            username: "root".into(),
            comm: "restic".into(),
            exe: None,
            cmdline: None,
            ancestors: Vec::new(),
        },
        session: tty.map(|t| crate::schema::SessionContext {
            tty: Some(t.into()),
            ..Default::default()
        }),
        allowlisted_accessor: allowlisted,
        scheduled_sweep: allowlisted && tty.is_none(),
    }
}

#[test]
fn verified_sweepers_are_never_disrupted_automatically() {
    for level in [
        ResponseLevel::Freeze,
        ResponseLevel::Kill,
        ResponseLevel::Isolate,
    ] {
        // Scheduled backup/AV run (as judged by the detector): no response.
        assert_eq!(level.for_access(&access(true, None)), None);
        // Same tool from a terminal: alert, but nothing disruptive.
        assert_eq!(
            level.for_access(&access(true, Some("pts/1"))),
            Some(ResponseLevel::Alert)
        );
        // Anyone else gets the configured response.
        assert_eq!(level.for_access(&access(false, None)), Some(level));
    }
    assert_eq!(
        ResponseLevel::None.for_access(&access(true, Some("pts/1"))),
        Some(ResponseLevel::None)
    );
}
