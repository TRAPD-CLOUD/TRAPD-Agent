#[cfg(target_os = "linux")] // ptrace is a Linux concept; spawned from the Linux startup path only
pub mod anti_ptrace;
pub mod binary_integrity;
// Hash-chained, signed local journal of security-relevant events (Phase 09, L5).
pub mod journal;
#[cfg(target_os = "linux")]
pub mod kernel_hardening;
pub mod maintenance;
// L4: anti-silencing / anti-redirection of the backend channel (phase 09).
pub mod network_guard;
// Pure SDDL constant + parser are testable everywhere; the apply path is Windows-only.
pub mod guard;
#[cfg(any(target_os = "windows", test))]
pub mod process_dacl;
// The policy plan is portable (and tested everywhere); applying it is Windows-only.
#[cfg(any(target_os = "windows", test))]
pub mod process_mitigation;
pub mod stop;
pub mod stop_marker;
// Windows: runtime integrity recheck + health watchdog (SCM recovery handles process death).
#[cfg(any(target_os = "windows", test))]
pub mod runtime_guard;
// Linux watchdog subprocess; Windows uses SCM recovery plus runtime_guard.
#[cfg(target_os = "linux")]
pub mod watchdog;
// Local event-log / journald record of every selfprotect.* finding.
pub mod local_log;
// Best-effort report of a binary-integrity failure before the fail-closed exit.
pub mod tamper_alert;
// Windows: System-log read-back (service stop/config change, driver install,
// unexpected shutdown) since the previous run. Classification is portable.
#[cfg(any(target_os = "windows", test))]
pub mod restart_forensics;
// Expected ACLs of the service, its registry keys and directories (WP2/WP3).
// The constants and comparison are portable; the guard that reads and applies
// them is Windows-only.
#[cfg(target_os = "windows")]
pub mod acl_guard;
#[cfg(any(target_os = "windows", test))]
pub mod acl_policy;
// L3 process integrity: periodic self-checks (code patching, injected modules,
// remote threads, debuggers, foreign handles). Windows and Linux only.
#[cfg(any(target_os = "windows", target_os = "linux"))]
pub mod process_integrity;
// L5 platform posture, measured boot and clock-jump detection.
pub mod posture;
