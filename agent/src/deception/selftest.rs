//! End-to-end self-test of a deployed honeytoken.
//!
//! A decoy that does not raise an alert is worse than none: the operator believes
//! the host is covered. So the agent regularly proves it. It starts a short-lived
//! child process that opens the token, and the sensor (eBPF on Linux, the audit
//! trail on Windows) reports that access through the real pipeline. The access
//! carries `selftest = true` because the sensor asked [`trapd_detection::selftest`],
//! which only this module arms for exactly this child and this path — nothing a
//! monitored process does can set the mark.
//!
//! The agent also watches its own sensor: if the child's access was not reported
//! within [`OBSERVE_TIMEOUT`], the alarm path is broken on this host and the agent
//! says so with a failure report. A pass needs no report of its own, because the
//! marked event reaching the backend is the proof.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tracing::warn;

use super::{verify_record, HoneytokenRecord, HoneytokenStore};
use crate::prevention::audit::AuditEmitter;
use crate::schema::{EventAction, Severity};

/// How long the agent waits for its own sensor to report the child's access.
pub const OBSERVE_TIMEOUT: Duration = Duration::from_secs(10);
/// The mark stays valid a little beyond the first report so that follow-up calls
/// of the same child (a metadata call after the open) are part of the same test.
const GRACE: Duration = Duration::from_secs(2);
/// Upper bound the registry stays armed, whatever happens to this task.
const ARM_TTL: Duration = Duration::from_secs(30);

/// Why a self-test did not pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The token is not in this agent's register.
    NotRegistered,
    /// Another self-test is running.
    Busy,
    /// The file is gone or no longer what the agent planted.
    FileMissing,
    /// The path cannot be opened safely by the test child on this platform.
    #[cfg_attr(unix, allow(dead_code))]
    Unsupported,
    /// The test child could not be started.
    SpawnFailed,
    /// The child ran but the agent's own sensor never reported its access.
    SensorSilent,
}

impl Failure {
    pub fn as_str(self) -> &'static str {
        match self {
            Failure::NotRegistered => "not_registered",
            Failure::Busy => "busy",
            Failure::FileMissing => "file_missing",
            Failure::Unsupported => "unsupported",
            Failure::SpawnFailed => "spawn_failed",
            Failure::SensorSilent => "sensor_silent",
        }
    }
}

/// Something the self-test can test: a token from the command-deployed register, or (Windows) a
/// decoy file the agent planted from its signed config.
#[derive(Debug, Clone)]
pub struct Target {
    pub path: String,
    pub kind: String,
    pub id: Option<uuid::Uuid>,
    /// The register record when there is one (its digest is verified before the test).
    pub record: Option<HoneytokenRecord>,
}

/// Every testable decoy of this host: the register of deployed tokens, plus on Windows the
/// config-planted decoy files that the register does not know.
pub fn targets(store: &HoneytokenStore) -> Vec<Target> {
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut out: Vec<Target> = store
        .list()
        .into_iter()
        .map(|r| Target {
            path: r.path.clone(),
            kind: r.kind.clone(),
            id: Some(r.id),
            record: Some(r),
        })
        .collect();
    #[cfg(windows)]
    for path in crate::collectors::windows::honeytokens::owned_decoy_paths() {
        let text = path.display().to_string();
        if !out.iter().any(|t| t.path == text) {
            out.push(Target {
                path: text,
                kind: "windows_decoy_file".to_string(),
                id: None,
                record: None,
            });
        }
    }
    out
}

static RUNNING: AtomicBool = AtomicBool::new(false);

struct RunGuard;
impl RunGuard {
    fn acquire() -> Option<Self> {
        RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| RunGuard)
    }
}
impl Drop for RunGuard {
    fn drop(&mut self) {
        // Late sensor events of the child stay attributable for a bounded time.
        trapd_detection::selftest::finish();
        RUNNING.store(false, Ordering::Release);
    }
}

/// Run one self-test of the token at `path` and report the result to the backend.
/// `command_id` is set when an operator asked for it, so the command completes.
pub async fn run(
    store: &HoneytokenStore,
    audit: &AuditEmitter,
    path: &str,
    command_id: Option<&str>,
) -> Result<Duration, Failure> {
    let started = Instant::now();
    let result = execute(store, path).await;
    let latency_ms = started.elapsed().as_millis() as u64;
    let target = targets(store).into_iter().find(|t| t.path == path);
    let kind = target.as_ref().map(|t| t.kind.clone()).unwrap_or_default();
    let (success, severity, reason) = match &result {
        Ok(_) => (
            true,
            Severity::Info,
            "honeytoken self-test passed".to_string(),
        ),
        Err(f) => (
            false,
            Severity::Medium,
            format!("honeytoken self-test failed: {}", f.as_str()),
        ),
    };
    // A rejected attempt (busy, not ours) says nothing about the token's health:
    // report it as the command's result only.
    let about_health = !matches!(result, Err(Failure::Busy | Failure::NotRegistered));
    audit.emit(
        EventAction::HoneytokenHealth,
        severity,
        "honeytoken_selftest",
        path.to_string(),
        success,
        reason,
        None,
        command_id.map(str::to_string),
        if about_health {
            json!({
                "id": target.as_ref().and_then(|t| t.id),
                "kind": kind,
                "selftest": {
                    "ok": success,
                    "reason": result.as_ref().err().map(|f| f.as_str()),
                    "latency_ms": latency_ms,
                },
            })
        } else {
            json!({ "selftest": null, "reason": result.as_ref().err().map(|f| f.as_str()) })
        },
    );
    result.map(|_| started.elapsed())
}

async fn execute(store: &HoneytokenStore, path: &str) -> Result<(), Failure> {
    execute_with(store, path, OBSERVE_TIMEOUT).await
}

async fn execute_with(
    store: &HoneytokenStore,
    path: &str,
    observe_timeout: Duration,
) -> Result<(), Failure> {
    let rec = targets(store)
        .into_iter()
        .find(|t| t.path == path)
        .ok_or(Failure::NotRegistered)?;
    let _guard = RunGuard::acquire().ok_or(Failure::Busy)?;

    // Do not blame the sensor for a file that is simply gone.
    let present = {
        let rec = rec.clone();
        tokio::task::spawn_blocking(move || match &rec.record {
            Some(record) => verify_record(record).present,
            // A config-planted decoy has no digest in a register: it must at least still be a file.
            None => std::fs::symlink_metadata(&rec.path).is_ok_and(|m| m.file_type().is_file()),
        })
        .await
        .map_err(|_| Failure::SpawnFailed)?
    };
    if !present {
        return Err(Failure::FileMissing);
    }

    let mut child = spawn_child(&rec)?;
    let pid = child.id().and_then(|p| i32::try_from(p).ok()).unwrap_or(0);
    if !trapd_detection::selftest::arm(pid, &rec.path, ARM_TTL) {
        let _ = child.kill().await;
        return Err(Failure::SpawnFailed);
    }
    // Release the child only now: it is waiting for its first input byte, so the
    // registry is armed before it touches the file.
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(b"\n").await.is_err() {
            let _ = child.kill().await;
            return Err(Failure::SpawnFailed);
        }
    }

    let deadline = Instant::now() + observe_timeout;
    while !trapd_detection::selftest::observed() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let seen = trapd_detection::selftest::observed();
    if seen {
        // Let trailing events of the same child be marked as well.
        tokio::time::sleep(GRACE).await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    let _ = child.kill().await;

    if seen {
        Ok(())
    } else {
        warn!(path = %rec.path, "honeytoken self-test: the sensor did not report the access");
        Err(Failure::SensorSilent)
    }
}

/// The test child waits for one input byte, then opens the token and exits. It is
/// a plain shell/`cmd` process (no agent code runs in it), so what the sensor sees
/// is an ordinary read by an unrelated process.
fn spawn_child(rec: &Target) -> Result<Child, Failure> {
    let path = Path::new(&rec.path);
    #[cfg(unix)]
    {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(r#"IFS= read -r _l; exec cat -- "$1" >/dev/null 2>&1"#)
            .arg("sh")
            .arg(path);
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        cmd.spawn().map_err(|_| Failure::SpawnFailed)
    }
    #[cfg(windows)]
    {
        // `cmd` parses its own command line: refuse anything it would interpret.
        let text = rec.path.as_str();
        if text.contains(['"', '%', '^', '&', '|', '<', '>', '\r', '\n']) || !path.is_absolute() {
            return Err(Failure::Unsupported);
        }
        let mut cmd = Command::new("cmd.exe");
        cmd.raw_arg("/D /C \"pause >nul & type \"")
            .raw_arg(text)
            .raw_arg("\" >nul 2>&1\"");
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        cmd.spawn().map_err(|_| Failure::SpawnFailed)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(Failure::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use tokio::sync::mpsc;

    // The registry and RUNNING are process-global: tests that run a self-test
    // must not interleave.
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn record(path: &Path) -> HoneytokenRecord {
        HoneytokenRecord {
            id: uuid::Uuid::new_v4(),
            path: path.display().to_string(),
            kind: "aws_credentials".into(),
            mode: 0o600,
            size_bytes: 8,
            sha256: String::new(),
            mimic_neighbor: false,
            neighbor_path: None,
            canary_marker: None,
            out_of_band: None,
            deployed_at: chrono::Utc::now(),
            command_id: None,
            breadcrumbs: Vec::new(),
        }
    }

    struct Fixture {
        dir: std::path::PathBuf,
        file: std::path::PathBuf,
        store: Arc<HoneytokenStore>,
        audit: AuditEmitter,
        rx: mpsc::Receiver<crate::schema::AgentEvent>,
    }

    fn fixture() -> Fixture {
        let dir = std::env::temp_dir().join(format!("trapd-selftest-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("credentials");
        std::fs::write(&file, b"bait=1\n").unwrap();
        let store = Arc::new(HoneytokenStore::load_from(dir.join("register.json")));
        store.insert(record(&file)).unwrap();
        let (tx, rx) = mpsc::channel(16);
        Fixture {
            dir,
            file,
            store,
            audit: AuditEmitter::new(tx, "agent-1".into(), "host".into()),
            rx,
        }
    }

    fn selftest_details(rx: &mut mpsc::Receiver<crate::schema::AgentEvent>) -> serde_json::Value {
        let event = rx.try_recv().expect("a report");
        let value = serde_json::to_value(&event).unwrap();
        value["data"]["details"].clone()
    }

    #[tokio::test]
    async fn a_sensor_that_reports_the_childs_access_passes() {
        let _g = SERIAL.lock().await;
        let mut f = fixture();
        // Stand in for the eBPF sensor: report an access of exactly the armed child.
        let sensor = tokio::spawn(async {
            for _ in 0..200 {
                if let Some((pid, path)) = trapd_detection::selftest::armed() {
                    assert!(trapd_detection::selftest::claim(pid, &path, None));
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("the test never armed the registry");
        });
        let path = f.file.display().to_string();
        let result = run(&f.store, &f.audit, &path, Some("cmd-1")).await;
        sensor.await.unwrap();
        assert!(result.is_ok(), "{result:?}");
        let details = selftest_details(&mut f.rx);
        assert_eq!(details["selftest"]["ok"], json!(true));
        assert!(
            !trapd_detection::selftest::observed(),
            "disarmed afterwards"
        );
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[tokio::test]
    async fn a_silent_sensor_is_reported_as_a_failure() {
        let _g = SERIAL.lock().await;
        let mut f = fixture();
        let path = f.file.display().to_string();
        // No sensor: `execute` waits for the real timeout, so use the short one.
        let result = super::execute_with(&f.store, &path, Duration::from_millis(400)).await;
        assert_eq!(result, Err(Failure::SensorSilent));
        assert!(
            !trapd_detection::selftest::observed(),
            "disarmed afterwards"
        );
        // The public entry point reports the same through the audit trail.
        assert!(
            f.rx.try_recv().is_err(),
            "execute_with reports nothing itself"
        );
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[tokio::test]
    async fn a_missing_file_is_not_blamed_on_the_sensor() {
        let _g = SERIAL.lock().await;
        let mut f = fixture();
        std::fs::remove_file(&f.file).unwrap();
        let path = f.file.display().to_string();
        let result = run(&f.store, &f.audit, &path, None).await;
        assert_eq!(result, Err(Failure::FileMissing));
        let details = selftest_details(&mut f.rx);
        assert_eq!(details["selftest"]["reason"], json!("file_missing"));
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[tokio::test]
    async fn only_registered_tokens_are_tested_and_say_nothing_about_health() {
        let _g = SERIAL.lock().await;
        let mut f = fixture();
        let result = run(&f.store, &f.audit, "/etc/passwd", Some("cmd-2")).await;
        assert_eq!(result, Err(Failure::NotRegistered));
        let details = selftest_details(&mut f.rx);
        assert!(
            details["selftest"].is_null(),
            "no health claim about a foreign path"
        );
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    #[test]
    fn failure_labels_are_stable() {
        // The backend stores these in its own audit trail; do not rename them.
        assert_eq!(Failure::SensorSilent.as_str(), "sensor_silent");
        assert_eq!(Failure::FileMissing.as_str(), "file_missing");
        assert_eq!(Failure::NotRegistered.as_str(), "not_registered");
    }

    #[tokio::test]
    async fn only_one_self_test_runs_at_a_time() {
        let _g = SERIAL.lock().await;
        let first = RunGuard::acquire();
        assert!(first.is_some());
        assert!(
            RunGuard::acquire().is_none(),
            "a second test must be refused"
        );
        drop(first);
        assert!(RunGuard::acquire().is_some(), "released on drop");
    }
}
