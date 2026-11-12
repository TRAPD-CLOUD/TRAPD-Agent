//! Burst measurement for the collector->consumer channel (GAP-MATRIX L1).
//!
//! Drives the *real* downstream stages — [`try_emit`], [`next_batch`],
//! `consume_batch` (classification, accounting, local write, SIEM hook) and the
//! durable [`Spool`] journal in a temp directory — with synthetic bursts, and
//! reports drops, peak channel occupancy and drain time per channel capacity.
//! Nothing touches the network and no collector runs.
//!
//! The producer is a plain OS thread calling `try_emit`, which is how the
//! ring-buffer consumer threads feed the channel in production.
//!
//! ```text
//! cargo test --release -p trapd-agent pipeline::burst -- --ignored --nocapture
//! ```
//!
//! Drops are counted from `try_emit`'s return value, not from the global
//! metrics, so concurrently running tests cannot skew the numbers.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::{next_batch, try_emit, Spool, CHANNEL_CAPACITY, MAX_BATCH};
use crate::schema::{
    AgentEvent, EventAction, EventClass, EventData, ExecEventData, FileOpenData, Severity,
};

#[derive(Clone, Copy, Debug)]
enum Kind {
    Process,
    File,
}

fn event(kind: Kind, i: u64) -> AgentEvent {
    match kind {
        Kind::Process => AgentEvent::new(
            "agent-burst".to_string(),
            "burst-host".to_string(),
            EventClass::Process,
            EventAction::Exec,
            Severity::Info,
            EventData::ProcessExec(Box::new(ExecEventData {
                pid: i as i32,
                ppid: 1,
                uid: 1000,
                gid: 1000,
                username: "alice".into(),
                comm: "cc1plus".into(),
                exe: "/usr/lib/gcc/x86_64-linux-gnu/13/cc1plus".into(),
                cmdline: "/usr/lib/gcc/x86_64-linux-gnu/13/cc1plus -quiet -I include -I src \
                          -D NDEBUG -O2 -std=gnu++20 -o /tmp/ccXXXXXX.s src/module.cpp"
                    .into(),
                cwd: "/home/alice/build".into(),
                ..Default::default()
            })),
        ),
        Kind::File => AgentEvent::new(
            "agent-burst".to_string(),
            "burst-host".to_string(),
            EventClass::Filesystem,
            EventAction::Open,
            Severity::Info,
            EventData::FileOpen(FileOpenData {
                pid: (i % 4000) as i32,
                uid: 1000,
                gid: 1000,
                username: "alice".into(),
                comm: "node".into(),
                path: format!("/home/alice/project/node_modules/pkg{}/index.js", i % 5000),
                flags: 0,
            }),
        ),
    }
}

/// How the producer paces itself.
#[derive(Clone, Copy, Debug)]
enum Load {
    /// `total` events as fast as the producer thread can emit them.
    Max { total: u64 },
    /// `per_sec` events/s for `secs` seconds (catch-up bursts every ~1 ms tick).
    Rate { per_sec: u64, secs: u64 },
}

impl Load {
    fn total(self) -> u64 {
        match self {
            Load::Max { total } => total,
            Load::Rate { per_sec, secs } => per_sec * secs,
        }
    }
}

#[derive(Debug)]
struct Outcome {
    sent: u64,
    dropped: u64,
    peak_occupancy: usize,
    drain: Duration,
    spooled: usize,
    spool_dropped: u64,
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "trapd_burst_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run one scenario against a channel of `capacity` and the real consumer.
///
/// `consume` = `false` withholds the consumer until the producer has finished,
/// which is the deterministic worst case (a stalled consumer).
fn run(kind: Kind, load: Load, capacity: usize, consume: bool) -> Outcome {
    let dir = TempDir::new();
    // Large enough that the spool itself never sheds: this isolates the channel.
    let spool = Spool::durable_at(dir.0.join("queue.journal"), 200_000);
    let spool = Arc::new(Mutex::new(spool));
    let siem = crate::output::siem::SiemForwarder::from_config(
        &crate::config::AgentConfig::default(),
        env!("CARGO_PKG_VERSION"),
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let (tx, mut rx) = mpsc::channel::<AgentEvent>(capacity);
    let consumed = Arc::new(AtomicU64::new(0));
    let (go_tx, go_rx) = tokio::sync::oneshot::channel::<()>();
    let mut go_tx = Some(go_tx);

    let consumer = {
        let spool = Arc::clone(&spool);
        let consumed = Arc::clone(&consumed);
        rt.spawn(async move {
            let _ = go_rx.await;
            let mut checkpoints = crate::detection::CheckpointTracker::default();
            let mut batch = Vec::with_capacity(MAX_BATCH);
            while next_batch(&mut rx, &mut batch).await {
                let n = batch.len() as u64;
                crate::consume_batch(
                    std::mem::take(&mut batch),
                    &mut checkpoints,
                    None,
                    &crate::output::OutputMode::Off,
                    &spool,
                    &siem,
                )
                .await;
                consumed.fetch_add(n, Ordering::Relaxed);
            }
        })
    };
    if consume {
        let _ = go_tx.take().map(|g| g.send(()));
    }

    let total = load.total();
    let producer = std::thread::spawn(move || {
        let (mut sent, mut dropped, mut peak) = (0u64, 0u64, 0usize);
        let start = Instant::now();
        let mut emit = |i: u64, tx: &mpsc::Sender<AgentEvent>| {
            if try_emit(tx, event(kind, i), "burst") {
                sent += 1;
            } else {
                dropped += 1;
            }
            peak = peak.max(tx.max_capacity() - tx.capacity());
        };
        match load {
            Load::Max { total } => (0..total).for_each(|i| emit(i, &tx)),
            Load::Rate { per_sec, .. } => {
                let mut i = 0u64;
                while i < total {
                    let due = ((start.elapsed().as_secs_f64() * per_sec as f64) as u64).min(total);
                    while i < due {
                        emit(i, &tx);
                        i += 1;
                    }
                    std::thread::sleep(Duration::from_micros(200));
                }
            }
        }
        (sent, dropped, peak, tx)
    });
    let (sent, dropped, peak, tx) = producer.join().unwrap();
    let done = Instant::now();
    if let Some(g) = go_tx.take() {
        let _ = g.send(());
    }
    while consumed.load(Ordering::Relaxed) < sent {
        std::thread::sleep(Duration::from_millis(1));
    }
    let drain = done.elapsed();
    drop(tx);
    rt.block_on(consumer).unwrap();
    assert_eq!(sent + dropped, total);

    let (spooled, spool_dropped) = {
        let s = spool.lock().unwrap();
        (s.len(), s.dropped_total())
    };
    Outcome {
        sent,
        dropped,
        peak_occupancy: peak,
        drain,
        spooled,
        spool_dropped,
    }
}

// ---------------------------------------------------------------------------
// Fast, deterministic regression tests
// ---------------------------------------------------------------------------

/// The worst case for a burst of exactly `CHANNEL_CAPACITY` events: the consumer
/// makes no progress at all while it arrives. Nothing may be dropped, and every
/// event must then reach the spool. No clocks involved.
#[test]
fn a_burst_up_to_the_configured_capacity_is_not_dropped_even_with_a_stalled_consumer() {
    let out = run(
        Kind::Process,
        Load::Max {
            total: CHANNEL_CAPACITY as u64,
        },
        CHANNEL_CAPACITY,
        false,
    );
    assert_eq!(out.dropped, 0, "{out:?}");
    assert_eq!(out.peak_occupancy, CHANNEL_CAPACITY);
    assert_eq!(out.spooled as u64, out.sent, "{out:?}");
    assert_eq!(out.spool_dropped, 0);
}

/// The loss is exactly the overflow and nothing else: attribution stays exact.
#[test]
fn overflow_beyond_capacity_is_counted_exactly_and_the_rest_is_delivered() {
    let extra = 100u64;
    let out = run(
        Kind::File,
        Load::Max {
            total: 1_024 + extra,
        },
        1_024,
        false,
    );
    assert_eq!(out.dropped, extra, "{out:?}");
    assert_eq!(out.sent, 1_024);
    assert_eq!(out.spooled, 1_024);
}

// ---------------------------------------------------------------------------
// Measurement (ignored: timing-dependent, run on a reference machine)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "measurement, prints a table; run with --release -- --ignored --nocapture"]
fn burst_measurement_table() {
    let scenarios: [(&str, Kind, Load); 6] = [
        ("max 1k", Kind::Process, Load::Max { total: 1_000 }),
        ("max 5k", Kind::Process, Load::Max { total: 5_000 }),
        ("max 20k", Kind::Process, Load::Max { total: 20_000 }),
        ("max 50k", Kind::Process, Load::Max { total: 50_000 }),
        (
            "process storm 2k/s x5s",
            Kind::Process,
            Load::Rate {
                per_sec: 2_000,
                secs: 5,
            },
        ),
        (
            "file storm 10k/s x2s",
            Kind::File,
            Load::Rate {
                per_sec: 10_000,
                secs: 2,
            },
        ),
    ];
    println!(
        "| scenario | capacity | sent | dropped (userspace_channel_full) | peak occupancy | drain ms | spooled | spool drops |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    for (name, kind, load) in scenarios {
        for cap in [1_024usize, 4_096, 16_384] {
            let o = run(kind, load, cap, true);
            println!(
                "| {name} | {cap} | {} | {} | {} | {} | {} | {} |",
                o.sent,
                o.dropped,
                o.peak_occupancy,
                o.drain.as_millis(),
                o.spooled,
                o.spool_dropped
            );
        }
    }
}
