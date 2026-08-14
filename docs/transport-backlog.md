# Event transport backlog design

## Root cause

The durable spool was healthy but its consumer attempted exactly one 100-event
batch per five-second tick.  That hard-capped delivery at 20 events/s regardless
of backend capacity.  The queue is FIFO (retry-ineligible records are skipped),
so broad inotify watches could put process and detection telemetry behind many
low-value file notifications.  Restarting correctly replayed the journal and
therefore could not remove the lag.

## Production defaults and backpressure

The transport now flushes once per second in normal mode.  At 200 queued events
it enters catch-up mode and sends another batch 25 ms after each successful
response: at most 40 requests/s and 4,000 events/s with the existing 100-event /
4 MiB backend contract.  Only one request is in flight, bounding cloned request
memory to one batch. Backend response latency therefore provides natural
backpressure. Transient responses and timeouts retain every event and use the
existing jittered exponential backoff (1 second through 5 minutes); permanent
4xx and partial acknowledgements keep their existing explicit accounting.

The queue remains durable and acknowledgement is still idempotent by spool
sequence. This intentionally avoids priority reordering: sequence gaps remain
meaningful and a crash cannot create ambiguous priority-lane state. Near-real
time is instead obtained by rapid catch-up plus source noise reduction.

Generic filesystem telemetry coalesces identical `(path, action)` notifications
for two seconds and suppresses cache/editor temporary artifacts. Credential,
SSH, sudoers, cron, systemd, executable, and agent configuration paths always
bypass suppression. Ransomware, FIM, YARA, honeytoken, and tamper detections run
before this generic filter and are unaffected.

Diagnostics expose queue depth/bytes, oldest-event age, catch-up state, last
batch size, request latency, successful/failed batches, retries, acknowledged
events, drops, and end-to-end latency percentiles in `telemetry.json` and the
`diagnostics telemetry` command.

## Load validation

Run correctness and the existing sustained 100/1,000 events/s, 5,000 events/s
burst, large-record, and 200,000-record recovery workloads:

```sh
cargo test --manifest-path agent/Cargo.toml
cargo test --release --manifest-path agent/Cargo.toml --test telemetry_load -- --ignored --nocapture
```

For an environment-specific ingest benchmark, queue at least 50,000 synthetic
events while returning 503, restore 2xx responses, and sample once per second:

```sh
trapd-agent diagnostics telemetry
/usr/bin/time -v trapd-agent
```

Expected upper bound against a near-zero-latency backend is 4,000 events/s;
actual catch-up throughput is `100 / (backend_latency_seconds + 0.025)` and must
remain above the measured producer rate. Record queue depth over time, process
CPU and maximum RSS from `time -v`, and request/end-to-end average and P95 from
backend and agent telemetry. These host/backend-dependent figures must be
measured in staging rather than claimed from a developer machine.

## End-to-end verification

1. Deploy with the production CA pin and record a healthy diagnostics baseline.
2. Temporarily make ingest return 503 while generating filesystem load; verify
   the journal survives an agent restart and retries rise without queue loss.
3. Restore ingest and verify `catching_up`, falling depth/oldest age, then
   `healthy` below 200 records.
4. Run `touch /tmp/trapd-detection-test` and a short-lived process/network test.
5. Correlate the stable `event_id` through ingest, Kafka, stream processor,
   detection engine, ClickHouse and Findings Console; target visibility is a
   few seconds once the queue returns to normal mode.
