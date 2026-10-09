//! Explicit integration point for host clocks and enrichment instrumentation.
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub fn next_sequence() -> u64 {
    SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1
}
pub fn issued_sequences() -> u64 {
    SEQUENCE.load(Ordering::Relaxed)
}
pub trait Runtime: Send + Sync {
    fn boot_id(&self) -> String;
    fn monotonic_ns(&self) -> u64;
    fn enrichment_failure(&self) {}
    fn enrichment_truncation(&self) {}
    fn enrichment_partial(&self) {}
}
struct DefaultRuntime {
    boot_id: String,
    start: std::time::Instant,
}
impl Runtime for DefaultRuntime {
    fn boot_id(&self) -> String {
        self.boot_id.clone()
    }
    fn monotonic_ns(&self) -> u64 {
        self.start.elapsed().as_nanos().min(u64::MAX as u128) as u64
    }
}
static RUNTIME: OnceLock<Arc<dyn Runtime>> = OnceLock::new();
/// Install host services before creating events. Installation never resets sequence numbers.
pub fn install(runtime: Arc<dyn Runtime>) -> Result<(), Arc<dyn Runtime>> {
    RUNTIME.set(runtime)
}
pub fn runtime() -> &'static dyn Runtime {
    RUNTIME
        .get_or_init(|| {
            Arc::new(DefaultRuntime {
                boot_id: uuid::Uuid::new_v4().to_string(),
                start: std::time::Instant::now(),
            })
        })
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventOrigin;
    #[test]
    fn sequences_are_strictly_increasing() {
        let a = next_sequence();
        let b = next_sequence();
        let c = next_sequence();
        assert!(a < b && b < c, "sequence must be strictly increasing");
    }

    #[test]
    fn sequences_are_unique_across_threads() {
        // Gap detection depends on the counter never handing out a duplicate.
        let handles: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(|| (0..500).map(|_| next_sequence()).collect::<Vec<_>>()))
            .collect();
        let mut all: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        let total = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), total, "sequence numbers must never repeat");
    }

    #[test]
    fn origin_carries_boot_sequence_and_clock() {
        let o = EventOrigin::new("ebpf_exec");
        assert_eq!(o.boot_id, crate::runtime::runtime().boot_id());
        assert!(o.sequence_number > 0);
        assert!(o.monotonic_timestamp_ns > 0);
        assert_eq!(o.source.as_deref(), Some("ebpf_exec"));
    }

    #[test]
    fn origin_round_trips_through_json() {
        let o = EventOrigin::new("proc_poll");
        let back: EventOrigin = serde_json::from_str(&serde_json::to_string(&o).unwrap()).unwrap();
        assert_eq!(o, back);
    }
}
