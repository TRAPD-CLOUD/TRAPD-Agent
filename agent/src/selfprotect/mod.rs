#[cfg(target_os = "linux")] // ptrace is a Linux concept; spawned from the Linux startup path only
pub mod anti_ptrace;
pub mod binary_integrity;
#[cfg(target_os = "linux")]
pub mod kernel_hardening;
#[cfg(target_os = "windows")]
pub mod process_mitigation;
// Windows: runtime integrity recheck + health watchdog (SCM recovery handles process death).
#[cfg(any(target_os = "windows", test))]
pub mod runtime_guard;
// Linux watchdog subprocess; Windows uses SCM recovery plus runtime_guard.
#[cfg(target_os = "linux")]
pub mod watchdog;
