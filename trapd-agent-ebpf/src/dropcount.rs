//! Shared ring-buffer drop counters (issue #52).
//!
//! Every event-emitting eBPF program submits into its own [`RingBuf`]. When the
//! buffer is full, `RingBuf::reserve()` returns `None`, the event is dropped and
//! — previously — that loss was completely silent. Under load (an exec/fork/DNS
//! storm during an attack or a noisy build) it is exactly the security-relevant
//! events that vanish, and operators have no way to tell.
//!
//! We now count those drops in a single shared `PerCpuArray<u64>`, one slot per
//! program. A *single* shared map (rather than one map per program) keeps the
//! number of BPF maps small and gives userspace one place to read. Per-CPU
//! storage means the increment is lock-free and contention-free on the hot path.
//!
//! Userspace (`agent/src/collectors/linux/ebpf_drops.rs`) reads this map
//! periodically, sums the per-CPU values, logs a warning on sustained drops and
//! exports the totals.
//!
//! IMPORTANT: the `SLOT_*` indices below are a wire contract — they MUST stay in
//! sync with `SLOT_NAMES` in `agent/src/collectors/linux/ebpf_drops.rs`.
//!
//! ## Ring-buffer sizes
//!
//! Each program's ring buffer is sized at compile time via
//! `RingBuf::with_byte_size(..)` in its own module. The current allocations:
//!
//! | Program            | Map                        | Size   |
//! |--------------------|----------------------------|--------|
//! | exec               | `EXEC_EVENTS`              | 1 MiB  |
//! | file_open          | `FILE_OPEN_EVENTS`        | 512 KiB|
//! | network            | `NET_EVENTS`              | 512 KiB|
//! | honeytoken         | `HONEYTOKEN_ACCESS_EVENTS`| 64 KiB |
//! | all others         | `*_EVENTS`                | 256 KiB|
//!
//! exec gets the largest buffer because exec/fork storms are the most bursty
//! (≈ 4 000 events/s at ≈ 256 B/event ≈ 1 MiB/s of headroom). To raise a buffer,
//! edit the `with_byte_size(..)` argument in the owning module and rebuild; aya
//! ring buffers are fixed-capacity kernel maps, so the size is a compile-time
//! constant rather than a runtime/Config knob. The `DROPPED` counters exported
//! by userspace tell you *which* buffer to grow.

use aya_ebpf::{macros::map, maps::PerCpuArray};

// ── Slot indices (keep in sync with userspace `DropSlot`) ────────────────────
pub const SLOT_EXEC: u32 = 0;
pub const SLOT_DNS: u32 = 1;
pub const SLOT_FORK: u32 = 2;
pub const SLOT_FILE_OPEN: u32 = 3;
pub const SLOT_HONEYTOKEN: u32 = 4;
pub const SLOT_NET: u32 = 5;
pub const SLOT_MODULE_LOAD: u32 = 6;
pub const SLOT_UNLINK: u32 = 7;
pub const SLOT_RENAME: u32 = 8;
pub const SLOT_CHMOD: u32 = 9;
pub const SLOT_CHOWN: u32 = 10;
pub const SLOT_NS: u32 = 11;
pub const SLOT_SETUID: u32 = 12;
pub const SLOT_WRITE_RATE: u32 = 13;
pub const SLOT_MEMFD: u32 = 14;
pub const SLOT_SHM: u32 = 15;
pub const SLOT_MMAP: u32 = 16;
pub const SLOT_PTRACE: u32 = 17;
pub const SLOT_KILL: u32 = 18;

/// Number of slots — also the `max_entries` of the `DROPPED` map. Bump this
/// (and add a `SLOT_*` above) when a new event ring buffer is introduced.
pub const SLOT_COUNT: u32 = 19;

/// Per-CPU drop counters, indexed by `SLOT_*`. Map name `DROPPED` is the lookup
/// key used by userspace.
#[map]
static DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(SLOT_COUNT, 0);

/// Record one dropped event for `slot`. Call this in the `None`/`Err` branch of
/// a failed `RingBuf::reserve()`. Per-CPU, so no locking and no cross-CPU
/// contention on the hot path; a missing slot (out-of-range index) is a no-op.
#[inline(always)]
pub fn record_drop(slot: u32) {
    if let Some(ptr) = DROPPED.get_ptr_mut(slot) {
        unsafe {
            *ptr += 1;
        }
    }
}
