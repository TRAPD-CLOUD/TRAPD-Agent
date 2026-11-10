//! Windows entry point: CLI verbs + Service Control Manager integration.
//!
//! ```text
//! trapd-agent.exe install     DEV ONLY: register as a Windows Service and start it
//! trapd-agent.exe uninstall   DEV ONLY: stop + delete the service, remove the binary
//! trapd-agent.exe run         run in the foreground (console / debugging)
//! trapd-agent.exe             service entry (started by the SCM); falls back
//!                             to console mode when launched interactively
//! ```
//!
//! `install` / `uninstall` bypass the MSI (no failure actions, no directory
//! ACLs) and are refused on an MSI-managed machine; see `refuse_if_msi_managed`.
//! Production installs, upgrades and removal go through the MSI.
//!
//! The actual agent runtime (enrollment, heartbeat, collectors, transport)
//! lives in [`run`], built from the same shared modules as the Linux agent.

mod evtlog;
mod run;

use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceDependency, ServiceErrorControl,
    ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

const SERVICE_NAME: &str = "trapd-agent";
const SERVICE_DISPLAY_NAME: &str = "TRAPD Agent";
const SERVICE_DESCRIPTION: &str =
    "TRAPD endpoint security agent — telemetry collection and backend reporting.";

/// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`: the process was started from a
/// console rather than by the SCM.
const ERROR_NOT_A_SERVICE: i32 = 1063;

pub fn entry() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("--version") => {
            println!("trapd-agent v{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("install") => {
            refuse_if_msi_managed("install")?;
            install()
        }
        Some("uninstall") => {
            refuse_if_msi_managed("uninstall")?;
            uninstall()
        }
        // Started by the service (from a copy of itself) after it staged a
        // verified update; see `update::windows`.
        Some("--apply-update") => {
            run::init_tracing_file();
            crate::paths::init_state_dir();
            crate::update::run_apply_helper()
        }
        // Invoked by the MSI (`CleanupDecoys`, Return="check") before the
        // service and binary are removed. Decoy removal is best-effort and
        // runs first so a firewall failure cannot skip it; leftover
        // containment rules can keep the host isolated with no agent left to
        // lift them, so only that failure is returned (non-zero exit) and
        // blocks the uninstall, with the cause in agent.log.
        Some("cleanup") => {
            run::init_tracing_file();
            crate::collectors::windows::honeytokens::uninstall();
            crate::prevention::winfirewall::cleanup()
                .inspect_err(|e| tracing::error!("firewall cleanup failed: {e:#}"))
                .context("remove containment firewall rules")
        }
        Some("diagnostics") if std::env::args().nth(2).as_deref() == Some("telemetry") => {
            print!("{}", crate::telemetry::diagnostics::run());
            Ok(())
        }
        Some("diagnostics") if std::env::args().nth(2).as_deref() == Some("config") => {
            println!(
                "{}",
                serde_json::to_string_pretty(&crate::config::load_persisted()?)?
            );
            Ok(())
        }
        Some("run") | Some("--console") => run_console(),
        None => match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
            Ok(()) => Ok(()),
            Err(windows_service::Error::Winapi(ref e))
                if e.raw_os_error() == Some(ERROR_NOT_A_SERVICE) =>
            {
                run_console()
            }
            Err(e) => Err(e).context("service dispatcher failed"),
        },
        Some(other) => {
            bail!("unknown command {other:?} — usage: trapd-agent.exe [install|uninstall|run]")
        }
    }
}

// ── Console mode ──────────────────────────────────────────────────────────────

/// How long the runtime may take to drop its blocking tasks (Event Log
/// reads, firewall COM calls) on shutdown before they are abandoned. Dropping
/// a runtime waits for `spawn_blocking` tasks indefinitely, which would leave
/// the service in STOP_PENDING until the SCM kills it.
const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

fn run_console() -> Result<()> {
    run::init_tracing_stderr();
    // Single-threaded here: no runtime exists yet (see `load_config_env`).
    run::load_config_env();
    let rt = tokio::runtime::Runtime::new().context("build tokio runtime")?;
    let result = rt.block_on(async {
        let (stop_tx, stop_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = stop_tx.send(());
        });
        run::run_agent(stop_rx, || {}).await
    });
    rt.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    result
}

// ── Service mode ──────────────────────────────────────────────────────────────

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    // Errors here cannot reach a console — log to the file sink and report a
    // non-zero service exit code so the SCM records the failure.
    run::init_tracing_file();
    if let Err(e) = run_service() {
        tracing::error!("service failed: {e:#}");
        // Top-level message only: the Application log is world-readable.
        evtlog::notify(
            evtlog::Event::Fatal,
            &format!("TRAPD Agent service failed: {e}. See agent.log for details."),
        );
    }
}

/// Lifecycle phase reported to the SCM.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    /// Initialising, up to and including the self-integrity check.
    Starting,
    Running,
    Stopping,
    /// Terminates the reporter thread; the caller reports `Stopped` itself.
    Done,
}

/// Wait hint for pending states; the reporter bumps the checkpoint well inside it.
const PENDING_WAIT_HINT: Duration = Duration::from_secs(30);
const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(2);

/// The SCM status for a phase. Pending states accept no controls and carry a
/// checkpoint + wait hint; `Running` accepts stop/shutdown.
fn status_for(phase: Phase, checkpoint: u32, exit: ServiceExitCode) -> ServiceStatus {
    let (state, accepted, hint) = match phase {
        Phase::Starting => (
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            PENDING_WAIT_HINT,
        ),
        Phase::Running => (
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            Duration::default(),
        ),
        Phase::Stopping => (
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            PENDING_WAIT_HINT,
        ),
        Phase::Done => (
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            Duration::default(),
        ),
    };
    let pending = matches!(phase, Phase::Starting | Phase::Stopping);
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code: exit,
        checkpoint: if pending { checkpoint } else { 0 },
        wait_hint: hint,
        process_id: None,
    }
}

fn report_status(handle: &ServiceStatusHandle, status: ServiceStatus) {
    let state = status.current_state;
    if let Err(e) = handle.set_service_status(status) {
        tracing::warn!(error = %e, ?state, "could not report service status to the SCM");
    }
}

/// Drive SCM status from phase changes and keep pending states alive with
/// increasing checkpoints until the phase changes.
fn spawn_status_reporter(
    handle: ServiceStatusHandle,
    phases: mpsc::Receiver<Phase>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let ok = ServiceExitCode::Win32(0);
        let mut phase = Phase::Starting;
        let mut checkpoint = 1u32;
        report_status(&handle, status_for(phase, checkpoint, ok));
        loop {
            match phases.recv_timeout(CHECKPOINT_INTERVAL) {
                Ok(Phase::Done) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                Ok(next) => {
                    // Never leave Stopping once entered (a late Running must not win).
                    if phase == Phase::Stopping && next != Phase::Stopping {
                        continue;
                    }
                    phase = next;
                    checkpoint = 1;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => checkpoint += 1,
            }
            report_status(&handle, status_for(phase, checkpoint, ok));
        }
    })
}

fn run_service() -> Result<()> {
    // Still single-threaded: configure the environment before the control
    // handler thread and the Tokio runtime exist.
    run::load_config_env();

    let (stop_tx, stop_rx) = tokio::sync::mpsc::unbounded_channel();
    let (phase_tx, phase_rx) = mpsc::channel::<Phase>();

    let handler_phase_tx = phase_tx.clone();
    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = handler_phase_tx.send(Phase::Stopping);
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("register service control handler")?;
    // START_PENDING immediately, then checkpoints until the agent is ready.
    let reporter = spawn_status_reporter(status_handle, phase_rx);

    // Startup failures are reported as SERVICE_STOPPED with a nonzero exit
    // code. Include those failures in the MSI-provisioned recovery policy.
    if let Err(e) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .and_then(|manager| manager.open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG))
        .and_then(|service| service.set_failure_actions_on_non_crash_failures(true))
    {
        tracing::warn!(error = %e, "could not enable service recovery for startup failures");
    }

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = phase_tx.send(Phase::Done);
            let _ = reporter.join();
            report_status(
                &status_handle,
                status_for(Phase::Done, 0, ServiceExitCode::ServiceSpecific(1)),
            );
            return Err(e).context("build tokio runtime");
        }
    };
    let ready_tx = phase_tx.clone();
    let result = rt.block_on(run::run_agent(stop_rx, move || {
        // Past the integrity check: only now is the service Running.
        let _ = ready_tx.send(Phase::Running);
        evtlog::notify(
            evtlog::Event::Started,
            &format!("TRAPD Agent v{} started.", env!("CARGO_PKG_VERSION")),
        );
    }));

    // Stopping (stop request, or the agent ended on its own): keep the SCM
    // informed while blocking tasks wind down, but never wait for them forever.
    let _ = phase_tx.send(Phase::Stopping);
    rt.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);

    if result.is_ok() {
        evtlog::notify(evtlog::Event::Stopped, "TRAPD Agent stopped.");
    }
    let exit = match &result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(_) => ServiceExitCode::ServiceSpecific(1),
    };
    let _ = phase_tx.send(Phase::Done);
    let _ = reporter.join();
    report_status(&status_handle, status_for(Phase::Done, 0, exit));
    result
}

// ── install / uninstall ───────────────────────────────────────────────────────

/// `install`/`uninstall` register the service with plain defaults: no failure
/// actions, no directory ACLs, and `uninstall` deletes the binary behind the
/// installer's back. They exist for developer machines only, so they refuse to
/// touch a machine the MSI manages (`HKLM\SOFTWARE\TRAPD\Agent`, `Installed=1`).
/// That marker is `Permanent` (configuration survives removal), so a dev box
/// that once had the MSI must set `TRAPD_ALLOW_DEV_INSTALL=1` explicitly.
fn refuse_if_msi_managed(verb: &str) -> Result<()> {
    use windows_sys::Win32::System::Registry::RRF_SUBKEY_WOW6464KEY;
    let managed = crate::collectors::windows::registry::dword(
        "SOFTWARE\\TRAPD\\Agent",
        "Installed",
        RRF_SUBKEY_WOW6464KEY,
    ) == Some(1);
    if managed && !crate::env_truthy("TRAPD_ALLOW_DEV_INSTALL") {
        bail!(
            "`{verb}` is for development builds only and is disabled because this machine is \
             managed by the TRAPD MSI. Use `msiexec /i` / `msiexec /x` (or set \
             TRAPD_ALLOW_DEV_INSTALL=1 on a development machine to override)."
        );
    }
    Ok(())
}

fn install() -> Result<()> {
    let exe = std::env::current_exe().context("resolve current executable path")?;

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("connect to the service manager (run from an elevated prompt)")?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        // Auto-start: the agent comes up with the OS, matching the systemd
        // `WantedBy=multi-user.target` posture of the Linux unit.
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        // The windows-service crate quotes this path when it contains
        // whitespace (CWE-428 unquoted service path); no manual quoting here.
        executable_path: exe.clone(),
        launch_arguments: vec![],
        // EventLog only (matches the MSI). Not BFE: with a third-party firewall
        // BFE may be disabled, and the agent must still start.
        dependencies: vec![ServiceDependency::Service(OsString::from("EventLog"))],
        // None = LocalSystem, the standard identity for an endpoint sensor.
        account_name: None,
        account_password: None,
    };

    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("create service (already installed? run `trapd-agent.exe uninstall` first)")?;
    service
        .set_description(SERVICE_DESCRIPTION)
        .context("set service description")?;

    match service.start::<&std::ffi::OsStr>(&[]) {
        Ok(()) => println!(
            "Service '{SERVICE_NAME}' installed and started ({})",
            exe.display()
        ),
        Err(e) => println!(
            "Service '{SERVICE_NAME}' installed ({}) but did not start: {e}\n\
             Start it manually with: sc.exe start {SERVICE_NAME}",
            exe.display()
        ),
    }
    Ok(())
}

fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("connect to the service manager (run from an elevated prompt)")?;

    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::QUERY_STATUS | ServiceAccess::DELETE,
        )
        .context("open service (is it installed?)")?;

    // 1. Stop — best-effort, then wait for the SCM to report Stopped.
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        for _ in 0..30 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    if service.query_status()?.current_state != ServiceState::Stopped {
        bail!("service did not stop; refusing uninstall while containment can be recreated");
    }
    crate::prevention::winfirewall::cleanup().context("remove containment firewall rules")?;

    // 2. Delete the service registration.
    service.delete().context("delete service")?;
    println!("Service '{SERVICE_NAME}' stopped and deleted");

    // 3. Remove the host artifacts the agent planted: honeytoken decoy files +
    //    registry decoys (the Linux agent revokes these over the signed command
    //    channel, so this local cleanup is Windows-only).
    crate::paths::init_state_dir();
    crate::collectors::windows::honeytokens::uninstall();
    println!("Honeytoken decoy files + registry decoys removed");

    // 4. Remove the binary. Windows cannot delete a running executable, so
    //    hand the deletion to a detached cmd.exe that waits for this process
    //    to exit first. Best-effort: a failure leaves only an inert file.
    if let Ok(exe) = std::env::current_exe() {
        let exe_str = exe.to_string_lossy().into_owned();
        match std::process::Command::new("cmd")
            .args([
                "/C",
                &format!("ping -n 3 127.0.0.1 > nul & del /f /q \"{exe_str}\""),
            ])
            .spawn()
        {
            Ok(_) => println!("Binary removal scheduled: {exe_str}"),
            Err(e) => {
                println!("Could not schedule binary removal ({e}); delete {exe_str} manually")
            }
        }
    }
    Ok(())
}
