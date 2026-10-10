//! Exercise the Linux startup signal handler while enrollment is still pending.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Agent(Child);
impl Agent {
    fn stop_watchdog(&self) {
        // The detached watchdog would otherwise restart our test process.
        let path = format!("/proc/{}/task/{}/children", self.0.id(), self.0.id());
        for pid in std::fs::read_to_string(path)
            .unwrap_or_default()
            .split_whitespace()
        {
            if let Ok(pid) = pid.parse::<i32>() {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
    }
}
impl Drop for Agent {
    fn drop(&mut self) {
        self.stop_watchdog();
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn pending_linux_pairing_records_clean_signals_and_unclean_kills() {
    for signal in [
        nix::sys::signal::Signal::SIGTERM,
        nix::sys::signal::Signal::SIGINT,
        nix::sys::signal::Signal::SIGKILL,
    ] {
        let root = std::env::temp_dir().join(format!("trapd-shutdown-{}", uuid::Uuid::new_v4()));
        let config = root.join("config");
        let state = root.join("state");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let marker = state.join("run_state");
        std::fs::write(&marker, "clean").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            while Instant::now() < deadline {
                if let Ok((mut socket, _)) = listener.accept() {
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut chunk = [0; 4096];
                    loop {
                        let n = socket.read(&mut chunk).unwrap();
                        assert_ne!(n, 0);
                        request.extend_from_slice(&chunk[..n]);
                        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            let header = String::from_utf8_lossy(&request[..end]).to_lowercase();
                            let length: usize = header
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .unwrap()
                                .trim()
                                .parse()
                                .unwrap();
                            if request.len() >= end + 4 + length {
                                break;
                            }
                        }
                    }
                    let body = r#"{"device_code":"secret","user_code":"ABCDE-FGHJK","verification_uri":"http://example.test/pair","expires_in":600,"interval":60}"#;
                    write!(
                        socket,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .unwrap();
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("agent did not start pairing");
        });
        let mut agent = Agent(
            Command::new(env!("CARGO_BIN_EXE_trapd-agent"))
                .env("TRAPD_CONFIG_DIR", &config)
                .env("TRAPD_STATE_DIR", &state)
                .env("TRAPD_LOG_DIR", root.join("logs"))
                .env("TRAPD_OUTPUT", "file")
                .env("TRAPD_BACKEND_URL", format!("http://{addr}"))
                .env("TRAPD_TLS_ALLOW_SYSTEM_ROOTS", "1")
                .env_remove("TRAPD_OFFLINE")
                .env_remove("TRAPD_ENROLL_TOKEN")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let file = state.join("pairing.txt");
        // Debug binaries contain large symbol tables; the startup integrity
        // check hashes the entire executable before enrollment begins.
        let deadline = Instant::now() + Duration::from_secs(60);
        while !file.exists() && Instant::now() < deadline {
            assert!(
                agent.0.try_wait().unwrap().is_none(),
                "agent exited before pairing"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(file.exists(), "pairing instructions were never published");
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "running",
            "pending enrollment must claim the process lifecycle before credentials exist"
        );
        assert!(
            !state.join("spool/queue.journal").exists(),
            "pairing must not start the event pipeline"
        );
        assert!(
            !root.join("logs/events.ndjson").exists(),
            "pairing must not emit telemetry"
        );
        agent.stop_watchdog();
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(agent.0.id() as i32), signal).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = agent.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "shutdown did not cancel enrollment"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        if signal == nix::sys::signal::Signal::SIGKILL {
            assert!(
                !status.success(),
                "killed process exited successfully: {status}"
            );
            assert_eq!(
                std::fs::read_to_string(&marker).unwrap(),
                "running",
                "abrupt exit during pairing must retain the unclean-shutdown marker"
            );
        } else {
            assert!(status.success(), "shutdown was not graceful: {status}");
            assert!(!file.exists(), "shutdown left stale pairing instructions");
            assert_eq!(
                std::fs::read_to_string(&marker).unwrap(),
                "clean",
                "signal-driven exit while pairing must record an orderly shutdown"
            );
        }
        assert!(
            !root.join("logs/events.ndjson").exists(),
            "cancelled pairing must not emit telemetry"
        );
        server.join().unwrap();
        drop(agent);
        std::fs::remove_dir_all(root).unwrap();
    }
}
