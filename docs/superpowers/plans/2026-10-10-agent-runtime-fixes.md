# Agent runtime fixes

## Goal and design

Fix the confirmed registry/backend contract mismatch and make journal durability
failures actionable. Preserve registry snapshots across restarts and complement
snapshot/ETW collection with persisted native Windows events. Reuse the existing
schema, bounded state storage, authenticated ingest and event-log cursors. Add no
driver, dependency or automatic audit-policy change.

Windows Security process/registry events require the relevant audit policy and,
for registry operations, SACLs. Sysmon process-access events are an optional source
for observed LSASS access; this does not promise access telemetry on machines
without that source. Live-process ETW enrichment remains best effort.

## Tasks

- [x] Backend: regress the public normalizer with real agent registry envelopes,
  map to existing DCS registry fields and retain old/new/category metadata. Trace
  ingest identity and raw-data retention. Work in the isolated platform branch.
- [x] Journal: reproduce sync failure after successful append, mark the spool
  degraded, count only successful fsyncs, continue bounded memory collection,
  publish durability loss in diagnostics/heartbeat and actionable health. Test
  healthy, failed and recovered cases without falsifying event-loss counters.
- [x] Registry baseline: version and bound persistent snapshots. Preserve silent
  first install, report offline modifications on restart, retain prior baseline
  on incomplete reads and avoid false deletions from unloaded user hives.
- [x] Windows native events: normalize persisted Security 4688/4657 and optional
  Sysmon process, registry and process-access events. Test malformed and unrelated
  events, native timestamps and PID parsing. Keep raw source logs and cursors.
- [x] Review combined changes for validation, false attribution, resource bounds,
  failure handling, replay and tenant identity; run full agent tests, Linux and
  Windows checks/builds plus platform detection tests.
- [x] Prepare agent changes for PR 135 and the isolated platform fix for PR 204;
  document Windows field-test prerequisites and unavailable host validation.
  Require final-head CI before resolving review threads.

## Review focus

Never infer registry writer identity from the hive owner. Do not turn registry
read failures into deletion events or overwrite a valid baseline with an
incomplete scan. Do not count failed persistence as successfully synced or as
already-lost events. Event source/provider IDs must match before interpretation.
Optional missing Windows channels must not stop the standard collectors.

## Implementation notes

Historical source records bypass live PID enrichment and automatic response.
Signal/shadow findings do not authorize automatic response. Checkpointing sensors
wait for durable journal receipts; native normalized findings can be coalesced,
so only their raw source records carry cursor receipts. Native channel/audit
prerequisites are reported separately in coverage. Platform catalog sync retains
project overrides and is tracked in TRAPD PR 204 (all five CI jobs passed).

Local final verification: 1296 Linux unit tests and 16 integration tests passed;
Linux release build and Windows GNU build passed. Strict Linux and Windows GNU
all-target checks include the native XML truncation regression. Repository-wide
agent formatting has existing debt; new files and changed hunks are formatted.
The physical CLT-MBL field test is unavailable in this environment.

Additional GitHub review fixes: hosts deletion/rename-away, startup lifecycle
before enrollment, bounded logon failure history across alert thresholds, and
stale signature invalidation on MSI/deb/script upgrades. Real Ubuntu/Debian
package and full script-installer tests pass, including checksum rejection that
leaves integrity state unchanged. MSI validates signature restoration on
failed upgrades and stale-signature removal on successful upgrades in CI.

Final review follow-up: native authentication uses its recorded UTC timeline in
a tracker separate from live elapsed time. Domain-qualified accounts prevent
identity collisions. Structured logons precede raw durable receipts, with
bounded per-channel record IDs preventing duplicate counting during retries.
Sysmon renames retain typed original/destination names and emit a conservative
Low/Signal policy without inventing value data. Both canonical catalogs contain
106 rules; the platform migration syncs 26 policies and preserves tenant overrides.
The published registry ingest contract matches the implementation.
