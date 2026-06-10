//! Windows entry point: CLI verbs + Service Control Manager integration.
//!
//! ```text
//! trapd-agent.exe install     register as a Windows Service (auto-start) and start it
//! trapd-agent.exe uninstall   stop the service, delete it, remove the binary
//! trapd-agent.exe run         run in the foreground (console / debugging)
//! trapd-agent.exe             service entry (started by the SCM); falls back
//!                             to console mode when launched interactively
//! ```
//!
//! The actual agent runtime (enrollment, heartbeat, collectors, transport)
//! lives in [`run`], built from the same shared modules as the Linux agent.

mod run;

use std::ffi::OsString;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
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
        Some("install") => install(),
        Some("uninstall") => uninstall(),
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

fn run_console() -> Result<()> {
    run::init_tracing_stderr();
    let rt = tokio::runtime::Runtime::new().context("build tokio runtime")?;
    rt.block_on(async {
        let (stop_tx, stop_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = stop_tx.send(());
        });
        run::run_agent(stop_rx).await
    })
}

// ── Service mode ──────────────────────────────────────────────────────────────

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    // Errors here cannot reach a console — log to the file sink and report a
    // non-zero service exit code so the SCM records the failure.
    run::init_tracing_file();
    if let Err(e) = run_service() {
        tracing::error!("service failed: {e:#}");
    }
}

fn run_service() -> Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::mpsc::unbounded_channel();

    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("register service control handler")?;

    let set_state = |state: ServiceState, exit: ServiceExitCode| {
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: exit,
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })
    };

    set_state(ServiceState::Running, ServiceExitCode::Win32(0))
        .context("report SERVICE_RUNNING")?;

    let rt = tokio::runtime::Runtime::new().context("build tokio runtime")?;
    let result = rt.block_on(run::run_agent(stop_rx));

    let exit = match &result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(_) => ServiceExitCode::ServiceSpecific(1),
    };
    let _ = set_state(ServiceState::Stopped, exit);
    result
}

// ── install / uninstall ───────────────────────────────────────────────────────

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
        executable_path: exe.clone(),
        launch_arguments: vec![],
        dependencies: vec![],
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
        Ok(()) => println!("Service '{SERVICE_NAME}' installed and started ({})", exe.display()),
        Err(e) => println!(
            "Service '{SERVICE_NAME}' installed ({}) but did not start: {e}\n\
             Start it manually with: sc.exe start {SERVICE_NAME}",
            exe.display()
        ),
    }
    Ok(())
}

fn uninstall() -> Result<()> {
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
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

    // 2. Delete the service registration.
    service.delete().context("delete service")?;
    println!("Service '{SERVICE_NAME}' stopped and deleted");

    // 3. Remove the binary. Windows cannot delete a running executable, so
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
            Err(e) => println!("Could not schedule binary removal ({e}); delete {exe_str} manually"),
        }
    }
    Ok(())
}
