#[cfg(target_os = "linux")] // ptrace is a Linux concept; spawned from the Linux startup path only
pub mod anti_ptrace;
pub mod binary_integrity;
#[cfg(target_os = "linux")]
pub mod kernel_hardening;
#[cfg(target_os = "linux")] // Windows relies on the SCM recovery actions configured by the MSI
pub mod watchdog;
