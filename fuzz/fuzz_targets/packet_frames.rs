#![no_main]

// Arbitrary captured IP frames: DNS answers and TLS handshakes come straight
// from the network. Several frames share one TLS tracker so segment
// reassembly across frames is exercised, not only single-packet parsing.

use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};
use trapd_schema as schema;

mod collectors {
    #[async_trait::async_trait]
    pub trait Collector: Send + Sync + 'static {
        fn name(&self) -> &'static str;
        async fn run(
            &mut self,
            tx: tokio::sync::mpsc::Sender<crate::schema::AgentEvent>,
            agent_id: String,
            hostname: String,
        ) -> anyhow::Result<()>;
    }
}
mod pipeline {
    pub fn try_emit(
        _: &tokio::sync::mpsc::Sender<crate::schema::AgentEvent>,
        _: crate::schema::AgentEvent,
        _: &str,
    ) -> bool {
        true
    }
}
mod telemetry {
    #[allow(dead_code)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum DropReason {
        EnrichmentTimeout,
        EventTooLarge,
        RateLimitApplied,
    }
    pub mod metrics {
        pub struct Metrics;
        impl Metrics {
            pub fn event_dropped(&self, _: super::DropReason) {}
        }
        pub fn metrics() -> Metrics {
            Metrics
        }
    }
}

#[allow(dead_code)]
#[path = "../../agent/src/collectors/linux/packet_capture.rs"]
mod packet_capture;
#[allow(dead_code)]
#[path = "../../agent/src/collectors/linux/tls_flow.rs"]
mod tls_flow;

fuzz_target!(|data: &[u8]| {
    let mut tracker = tls_flow::TlsTracker::new();
    let start = Instant::now();
    let mut rest = data;
    let mut frame_no = 0u64;
    // Each frame: 2-byte little-endian length, then the frame bytes.
    while rest.len() >= 2 && frame_no < 64 {
        let len = usize::from(u16::from_le_bytes([rest[0], rest[1]])).min(rest.len() - 2);
        let (frame, tail) = rest[2..].split_at(len);
        let now = start + Duration::from_millis(frame_no * 10);
        let _ = packet_capture::parse_frame(frame, &mut tracker, now);
        rest = tail;
        frame_no += 1;
    }
});
