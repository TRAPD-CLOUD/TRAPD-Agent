//! Watchdog subprocess — CrowdStrike-style agent self-restart.
//!
//! Design
//! ──────
//! 1. The main agent detects it is **not** running in watchdog mode
//!    (no `--watchdog-for <PID>` argument) and calls [`spawn_detached`].
//! 2. [`spawn_detached`] forks a detached child that runs the same binary
//!    with `--watchdog-for <MAIN_PID>`.  The child calls `setsid(2)` so it
//!    survives the parent's death and is invisible to systemd.
//! 3. The watchdog polls `/proc/<MAIN_PID>` every [`POLL_INTERVAL_SECS`]
//!    seconds.  When the directory disappears the watchdog waits
//!    [`RESTART_DELAY_SECS`] and re-executes the agent binary (without the
//!    `--watchdog-for` flag, so the new instance spawns its own watchdog).
//! 4. After a successful restart the watchdog exits.  Systemd's
//!    `Restart=always` ensures the chain is never permanently broken.
//!
//! Detection
//! ─────────
//! Call [`detect`] **first** in `main()`.  It returns `Some(pid)` when this
//! process is a watchdog, in which case `main()` should call
//! [`run_watchdog`] and never return.

use std::path::Path;
use std::process;
use std::time::Duration;

use tracing::{info, warn};

const POLL_INTERVAL_SECS: u64 = 5;
const RESTART_DELAY_SECS: u64 = 3;
const MAX_RESTART_ATTEMPTS: u32 = 5;

/// CLI argument that marks this invocation as a watchdog.
pub const WATCHDOG_ARG: &str = "--watchdog-for";

// ── Public API ────────────────────────────────────────────────────────────────

/// Return `Some(monitored_pid)` if the current process was spawned as a watchdog.
///
/// Must be called before any async runtime is started.
pub fn detect() -> Option<u32> {
    let args: Vec<String> = std::env::args().collect();
    args.windows(2).find_map(|pair| {
        (pair[0] == WATCHDOG_ARG).then(|| pair[1].parse::<u32>().ok()).flatten()
    })
}

/// Spawn a detached watchdog subprocess that will restart us on death.
///
/// Non-fatal: if spawning fails a warning is logged and the agent continues
/// without a watchdog (systemd's `Restart=always` provides a fallback).
pub fn spawn_detached() {
    let exe = match std::env::current_exe() {
        Ok(p)  => p,
        Err(e) => { warn!("Watchdog: cannot locate current binary: {e}"); return; }
    };

    let my_pid = process::id();

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;

        let mut cmd = process::Command::new(&exe);
        cmd.arg(WATCHDOG_ARG).arg(my_pid.to_string());

        // Inherit the full environment so the restarted agent can re-enroll.
        // setsid() makes the child a new session leader — it outlives the parent
        // even when the parent is killed with SIGKILL.
        unsafe {
            cmd.pre_exec(|| {
                nix::unistd::setsid()
                    .map(|_| ())
                    .map_err(|e| std::io::Error::other(e.to_string()))
            });
        }

        match cmd.spawn() {
            Ok(child) => info!(watchdog_pid = child.id(), agent_pid = my_pid, "Watchdog spawned"),
            Err(e)    => warn!("Watchdog: spawn failed: {e} — agent runs without watchdog"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    warn!("Watchdog: only supported on Linux — skipping");
}

/// Run the watchdog loop.  This function **never returns**.
///
/// Monitors the process at `monitored_pid`; on death restarts the agent
/// binary (up to [`MAX_RESTART_ATTEMPTS`] times) and exits.
pub fn run_watchdog(monitored_pid: u32) -> ! {
    info!(monitored_pid, "Watchdog mode: monitoring agent process");

    let exe = std::env::current_exe()
        .expect("Watchdog: cannot resolve current executable path");

    let proc_dir = format!("/proc/{monitored_pid}");

    // Wait until the monitored process disappears.
    loop {
        std::thread::sleep(Duration::from_secs(POLL_INTERVAL_SECS));
        if !Path::new(&proc_dir).exists() {
            break;
        }
    }

    info!(
        monitored_pid,
        "Watchdog: agent process terminated — restarting in {RESTART_DELAY_SECS}s"
    );

    for attempt in 1..=MAX_RESTART_ATTEMPTS {
        std::thread::sleep(Duration::from_secs(RESTART_DELAY_SECS));

        match process::Command::new(&exe).spawn() {
            Ok(child) => {
                info!(
                    new_pid = child.id(),
                    attempt,
                    "Watchdog: agent restarted successfully — exiting watchdog"
                );
                // The new agent instance will spawn its own watchdog.
                // Drop the child handle so it is detached and runs independently.
                drop(child);
                process::exit(0);
            }
            Err(e) => {
                warn!(attempt, max = MAX_RESTART_ATTEMPTS, "Watchdog: restart attempt failed: {e}");
            }
        }
    }

    warn!(
        "Watchdog: all {MAX_RESTART_ATTEMPTS} restart attempts failed — \
         exiting (systemd Restart=always will recover)"
    );
    process::exit(1);
}
