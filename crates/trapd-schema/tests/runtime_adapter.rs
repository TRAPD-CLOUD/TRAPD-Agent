use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use trapd_schema::{Enrichment, EnrichmentError, EventOrigin};

#[derive(Default)]
struct Host {
    failures: AtomicU64,
    truncations: AtomicU64,
    partial: AtomicU64,
}
impl trapd_schema::runtime::Runtime for Host {
    fn boot_id(&self) -> String {
        "host-boot".into()
    }
    fn monotonic_ns(&self) -> u64 {
        1234
    }
    fn enrichment_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
    fn enrichment_truncation(&self) {
        self.truncations.fetch_add(1, Ordering::Relaxed);
    }
    fn enrichment_partial(&self) {
        self.partial.fetch_add(1, Ordering::Relaxed);
    }
}
#[test]
fn host_clocks_metrics_and_sequence_are_shared() {
    let host = Arc::new(Host::default());
    assert!(trapd_schema::runtime::install(host.clone()).is_ok());
    let first = EventOrigin::new("collector");
    let second = EventOrigin::unsourced();
    assert_eq!(first.boot_id, "host-boot");
    assert_eq!(first.monotonic_timestamp_ns, 1234);
    assert_eq!(second.sequence_number, first.sequence_number + 1);
    assert_eq!(
        trapd_schema::runtime::issued_sequences(),
        second.sequence_number
    );
    let mut enrichment = Enrichment::new();
    enrichment.fail("cmdline", EnrichmentError::ProcessExited);
    enrichment.truncated("path", Some(trapd_schema::Truncation::new(100, 10)));
    let result = enrichment.finish(2);
    assert_eq!(result.status(), trapd_schema::EnrichmentStatus::Partial);
    assert_eq!(host.failures.load(Ordering::Relaxed), 1);
    assert_eq!(host.truncations.load(Ordering::Relaxed), 1);
    assert_eq!(host.partial.load(Ordering::Relaxed), 1);
    assert!(trapd_schema::runtime::install(Arc::new(Host::default())).is_err());
    assert_eq!(
        EventOrigin::unsourced().sequence_number,
        second.sequence_number + 1
    );
}
