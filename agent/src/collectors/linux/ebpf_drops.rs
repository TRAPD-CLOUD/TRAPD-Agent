//! Periodic reader/exporter for the eBPF ring-buffer drop counters (issue #52).
//!
//! Each event-emitting eBPF program submits into its own ring buffer. When the
//! buffer is full, the kernel side cannot reserve a slot, the event is lost, and
//! — to make that loss observable instead of silent — the eBPF programs bump a
//! per-program counter in a shared `PerCpuArray<u64>` named `DROPPED`
//! (`trapd-agent-ebpf/src/dropcount.rs`).
//!
//! [`DropMonitor`] reads that map on an interval, sums the per-CPU values,
//! tracks deltas between polls, logs a warning whenever new drops appear
//! (sustained-drop signal) and produces an [`EbpfDropsData`] event for export to
//! the backend.

use aya::maps::{MapData, PerCpuArray};
use tracing::warn;

use crate::schema::EbpfDropsData;

/// Number of drop-counter slots. MUST equal `SLOT_COUNT` in
/// `trapd-agent-ebpf/src/dropcount.rs`.
pub const SLOT_COUNT: usize = 19;

/// Human-readable program name per slot. Index == slot. MUST stay in sync with
/// the `SLOT_*` indices in `trapd-agent-ebpf/src/dropcount.rs`.
pub const SLOT_NAMES: [&str; SLOT_COUNT] = [
    "exec",        // SLOT_EXEC        = 0
    "dns",         // SLOT_DNS         = 1
    "fork",        // SLOT_FORK        = 2
    "file_open",   // SLOT_FILE_OPEN   = 3
    "honeytoken",  // SLOT_HONEYTOKEN  = 4
    "network",     // SLOT_NET         = 5
    "module_load", // SLOT_MODULE_LOAD = 6
    "unlink",      // SLOT_UNLINK      = 7
    "rename",      // SLOT_RENAME      = 8
    "chmod",       // SLOT_CHMOD       = 9
    "chown",       // SLOT_CHOWN       = 10
    "namespace",   // SLOT_NS          = 11
    "setuid",      // SLOT_SETUID      = 12
    "write_rate",  // SLOT_WRITE_RATE  = 13
    "memfd",       // SLOT_MEMFD       = 14
    "shm",         // SLOT_SHM         = 15
    "mmap",        // SLOT_MMAP        = 16
    "ptrace",      // SLOT_PTRACE      = 17
    "kill",        // SLOT_KILL        = 18
];

/// Reads and tracks the shared `DROPPED` per-CPU drop-counter map.
pub struct DropMonitor {
    map:           PerCpuArray<MapData, u64>,
    prev_per_slot: [u64; SLOT_COUNT],
    prev_total:    u64,
}

impl DropMonitor {
    pub fn new(map: PerCpuArray<MapData, u64>) -> Self {
        Self {
            map,
            prev_per_slot: [0; SLOT_COUNT],
            prev_total:    0,
        }
    }

    /// Read every slot, summing the per-CPU values into a single total per slot.
    /// The counters are monotonic since agent start.
    fn read(&self) -> ([u64; SLOT_COUNT], u64) {
        let mut per_slot = [0u64; SLOT_COUNT];
        let mut total = 0u64;
        for (slot, out) in per_slot.iter_mut().enumerate() {
            if let Ok(values) = self.map.get(&(slot as u32), 0) {
                let sum: u64 = values.iter().copied().sum();
                *out = sum;
                total = total.saturating_add(sum);
            }
        }
        (per_slot, total)
    }

    /// Poll the counters. Returns `Some` only when new drops occurred since the
    /// previous poll (so the caller emits an event only when something changed),
    /// and logs a warning naming the programs that grew this interval.
    pub fn poll(&mut self) -> Option<EbpfDropsData> {
        let (per_slot, total) = self.read();
        let delta = total.saturating_sub(self.prev_total);
        if delta == 0 {
            return None;
        }

        // Programs that grew this interval — the actionable part of the warning.
        let grew: String = (0..SLOT_COUNT)
            .filter(|&s| per_slot[s] > self.prev_per_slot[s])
            .map(|s| format!("{}=+{}", SLOT_NAMES[s], per_slot[s] - self.prev_per_slot[s]))
            .collect::<Vec<_>>()
            .join(" ");

        warn!(
            new_drops = delta,
            total_drops = total,
            programs = %grew,
            "eBPF ring buffer full — events dropped (detection blind-spot under load); \
             consider raising the affected ring-buffer size"
        );

        // Cumulative per-program totals (only non-zero programs).
        let mut per_program = std::collections::BTreeMap::new();
        for (slot, &count) in per_slot.iter().enumerate() {
            if count > 0 {
                per_program.insert(SLOT_NAMES[slot].to_string(), count);
            }
        }

        self.prev_per_slot = per_slot;
        self.prev_total = total;

        Some(EbpfDropsData {
            per_program,
            total,
            delta,
        })
    }
}
