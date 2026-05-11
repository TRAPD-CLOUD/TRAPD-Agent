#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

mod dns;
mod exec;
mod file_manip;
mod file_open;
mod fork;
mod kill;
mod mmap;
mod module_load;
mod namespace;
mod network;
mod ptrace;
mod shm;
mod write;

// ── Shared constants ─────────────────────────────────────────────────────────
/// Kernel task comm name length (task_struct.comm is 16 bytes incl. NUL).
pub(crate) const COMM_LEN: usize = 16;
/// Maximum path length captured in eBPF (stack-safe; full PATH_MAX = 4096).
pub(crate) const PATH_LEN: usize = 256;

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
