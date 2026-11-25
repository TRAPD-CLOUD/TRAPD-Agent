# Endpoint telemetry verification

Source baseline `9e00c89` on Linux. The binding quality standard was read from
`docs/agent-quality-standard:CLAUDE.md` because it was absent on the base commit.
The conclusions below distinguish code inspection from host measurements.

## Parser inventory

The first inputs to review are network frames and configured datagram listeners,
followed by application-generated log text. Both can carry third-party data before
the process has a trusted event identity. Kernel and Event Log records cross OS
interfaces. Configuration, persisted events and offsets have different provenance
and need compatibility fixtures. A parseable signed envelope alone confers no authority.

| Input | Production entry points | Existing verification | Suitable input for an isolated parser test |
|---|---|---|---|
| UDP / Unix syslog, file logs | `collectors/logs/parser.rs::parse`, `parse_auto`, RFC3164 and RFC5424, JSON, nginx/Apache access and error, PostgreSQL, MySQL, Docker, sshd, sudo, auditd, IIS, KV, CEF | Format-specific examples in parser module | Text |
| File boundaries and multiline | `frame_bytes`, MultilineAggregator, W3cAggregator and AuditAggregator `push`, `audit_event_id`, FileTail::poll | Framing, rotation and checkpoint tests | Byte chunks and ordered lines. Poll also needs files |
| systemd journal | `JournalTail::next_line`, `read_line_bounded`, `parse_journal_json`, `json_str`, `realtime_ts`, `priority_name` | Async bounded-reader and JSON fixtures | Bytes and text |
| Authentication file reader | Linux authlog collector | Module tests | Text |
| Packet and socket telemetry | `parse_frame`, IP/UDP/TCP decoders, DNS response and name decoding, ClientHello and ServerHello, netlink dump / socket / TCP_INFO decoding | Packet, flow and inet_diag unit fixtures | Bytes with bounded tracker state |
| Windows Event Log | `eventlog::render`, `parse`, `windows_native` normalization and provenance | Native XML, Unicode, time, replay and projection fixtures | XML and normalized fields. Rendering requires a native handle |
| Windows ETW | Provider/TDH reads in `windows/etw.rs`, projections in `etw_map.rs` | Portable mapping fixtures plus Windows tests | Mapping inputs. Native callback pointers require a live provider |
| eBPF | Exec collector ring read in `run`, syscall collector `read_raw<T>` and ring dispatch | Layout and compatibility fixtures in syscall module, native integration separately | Record bytes for fixed-layout types. Attachment needs kernel privileges |
| procfs and OS text | Process stat/identity, cgroup, maps, environment, mounts, sessions, socket and module lists in Linux collectors, forensics, rootkit and telemetry identity | Procfs library plus module-local example and live-process tests | Text/bytes where parsing is separate. Live snapshots require an OS |
| Signed config, policy and command | Serde decode to SignedConfig, PolicyFile, CommandEnvelope / SignedCommand and ProcessGeneration | Compatibility vectors and rejection cases in config/prevention | JSON deserialization only |
| Queue, log offsets and event envelopes | `pipeline/journal.rs::read_line_bounded`, `decode`, JournalRecord, CheckpointStore::load, schema OCSF reverse mapping | CRC, version, torn tail, bounded reader, deterministic mutation, replay and schema fixtures | Framed bytes and typed JSON |

Paths abbreviated under `agent/src` unless specified. See the source index below
for individual functions. Presence of tests in a module does not establish branch coverage.

## Coverage visibility and parity

Implemented means a production path is wired. Partial means prerequisites, polling
or narrower semantics limit the specified feature. Missing describes that named
capability on the platform. Collector supervision observes returned errors. It
cannot infer individual missing observations inside a successful poll.

| Collector / feature | Linux | Windows | Failure, loss and limits | Baseline documentation |
|---|---|---|---|---|
| System snapshot, inventory | Implemented | Implemented | Sampled snapshots. Field availability varies with OS APIs | Repo guide, Windows matrix |
| Process lifecycle | Implemented (eBPF and proc) | Implemented (ETW and polling) | Kernel drop counters, enrichment health, ETW provider and fallback state. Polling observes snapshots only | Both, Windows polling description stale |
| Network connections | Implemented | Implemented | Polling and event-driven sources differ. Windows tables do not give Linux flow depth | Both |
| Packet capture, TLS and DNS | Implemented | Partial (ETW DNS) | No Windows packet/TLS stream. Provider health and kernel drops measure different boundaries | Both |
| File watches and FIM | Implemented | Implemented | Change notifications and periodic baselines, configured roots and scan limits. Watch handoff can drop at capacity | Both |
| Auth log and user sessions | Implemented (authlog, proc context) | Implemented (Security, WTS) | Native record availability depends on policy. Channel status cannot prove individual records exist | Both |
| Generic logs | Implemented | Missing | Rate-limit counters, journal size cap, file checkpoints. Reader failures need separate accounting below | Windows matrix |
| Native Windows logs, registry and ETW file actor | Missing | Implemented | Per-channel reads, registry notification fallbacks, provider state. Attribution and policy-dependent fields can be absent | Native event guide, Windows matrix incomplete |
| Sensitive file opens and file decoys | Implemented | Partial (SACL/4663 and file decoys) | Attachment and audit availability reported. Different decoy detection modes | Both |
| Agent protection, OS/network integrity | Implemented | Partial (service, ACL and binary monitoring) | Sensor-specific integrity state and protection findings | Both |
| Module scans, driver loads | Implemented | Implemented | Periodic snapshots on Linux supplement event hooks. Windows ETW provider and inventory are distinct | ETW driver state missing from Windows matrix |
| Containers, namespaces, cross-view rootkit | Implemented | Missing | Linux OS views and optional hooks. Individual empty views require host validation | Repo guide |
| Memory inspection | Implemented | Implemented | Separate OS implementations. Protected or exited processes may be inaccessible | Windows-specific sweep missing from Windows matrix |
| Device attach/remove | Implemented | Implemented | Device inventory deltas, optional serial capture. Polling cannot prove continuous presence | Windows matrix incomplete |
| Named pipes and AMSI | Missing (Windows provider semantics) | Partial | Provider enablement, session losses, pipe throttling and script-content opt-in are distinct | Coverage record, Windows matrix incomplete |
| Queue and delivery | Implemented | Implemented | Attributed drops, corruption, retry, acknowledgements and durable replay | Both |

## Time, typing and minimization

AgentEvent assigns a UUID, UTC wall time, optional origin and typed payload.
Origin sequence is process-local. A restart on the same Linux boot can reuse
sequence numbers. Concurrent construction and asynchronous delivery can also
reorder observations. Compare boot, monotonic time, source identifiers and
native record IDs where available. UTC receipt time alone cannot order
historical input across a wall-clock step. RFC3164 has no offset or year.
The parser assumes UTC and infers a previous year on rollover. A local-time
sender can therefore produce a plausible but wrong timestamp.

AgentEvent's Rust class, action and payload are separate fields. Typing alone
does not enforce all combinations. The native envelope has no explicit version.
OCSF export pins 1.9.0, preserves native data in a version-1 extension and has
an independent offline schema check. Journal framing and inventory versions
are separate contracts. See [OCSF validation](../ocsf-validation.md) for evidence
and fallback classes. No new unjustified OCSF mapping was established in this review.

Process identity, command lines, DNS and file paths support correlation and
response. LogEventData retains the source message and arbitrary structured
fields. For example, the journal reader copies MESSAGE into the message and
retains it in the field map. No separate consumer requirement for that duplicate
was established here. Signed source selection, exclusions, EPS/line limits and
filesystem roots control collection at source granularity. Script content and
device serial capture default off. Source budgets bound volume but do not
redact secrets from a selected record.

## Findings at baseline

| ID | File and line | Description and scenario | Severity | Proposed fix |
|---|---|---|---|---|
| TV-1 | agent/src/collectors/logs/journal.rs:112, agent/src/collectors/logs/mod.rs:443 | Unterminated oversized journal input and invalid JSON lack attributable loss | should | Count oversize once at the size decision and malformed records once at decode |
| TV-2 | agent/src/telemetry/coverage.rs:122 | Four polled Windows channels lack heartbeat read status when permission or availability changes | should | Include every fixed channel in coverage, reset on disable and exit |
| TV-3 | agent/src/collectors/logs/mod.rs:498 | A datagram longer than the receive buffer appears complete | should | Detect overflow at the receive boundary and attribute the discard |
| TV-4 | deploy/README-windows.md, platform coverage | Matrix omits current sensors. Poller still maintains a baseline while ETW emits starts | should | Update operational documentation |
| TV-5 | agent/src/collectors/logs/parser.rs:367 | Zone-free syslog text interpreted as UTC on non-UTC sources | should | Define an explicit source timezone policy before changing historical ordering |
| TV-6 | crates/trapd-schema/src/origin.rs:29 | Sequence numbering restarts independently of Linux boot identity | should | Agree on a run namespace with consumers before changing the wire contract |
| TV-7 | agent/src/collectors/logs/journal.rs:183 | Journal message duplicated in field bag | optional | Validate downstream field consumers before stripping it |
| TV-8 | agent/src/collectors/logs/mod.rs:166 | Journal/syslog source exits enter cooldown with only a warning | should | Report failed collector attempts through existing metrics |

## Verification and out of scope

Native real-host resource measurements and Atomic Red Team runs require separate
host evidence. No detection behavior, command handling, signing or update change
is proposed. No cargo-fuzz campaign was performed.

