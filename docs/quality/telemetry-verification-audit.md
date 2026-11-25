# Endpoint telemetry verification

Source baseline `9e00c89` on Linux. The binding quality standard was read from
`docs/agent-quality-standard:CLAUDE.md` because it was absent on the base commit.
The conclusions below distinguish code inspection from host measurements.

## Parser inventory

The Fuzz column below describes whether the production boundary accepts bounded generated inputs (pure), requires state/OS fixtures (mixed) or needs native execution (native).

The first inputs to review are network frames and configured datagram listeners,
followed by application-generated log text. Both can carry third-party data before
the process has a trusted event identity. Kernel and Event Log records cross OS
interfaces. Configuration, persisted events and offsets have different provenance
and need compatibility fixtures. A parseable signed envelope alone confers no authority.

| Input | Production entry points | Existing verification | Suitable input for an isolated parser test | Fuzz |
|---|---|---|---| --- |
| UDP / Unix syslog, file logs | `collectors/logs/parser.rs::parse`, `parse_auto`, RFC3164 and RFC5424, JSON, nginx/Apache access and error, PostgreSQL, MySQL, Docker, sshd, sudo, auditd, IIS, KV, CEF | Format-specific examples in parser module | Text | mixed |
| File boundaries and multiline | `frame_bytes`, MultilineAggregator, W3cAggregator and AuditAggregator `push`, `audit_event_id`, FileTail::poll | Framing, rotation and checkpoint tests | Byte chunks and ordered lines. Poll also needs files | mixed |
| systemd journal | `JournalTail::next_record`, `read_line_bounded`, `parse_journal_json`, `json_str`, `realtime_ts`, `priority_name` | Async bounded-reader and JSON fixtures | Bytes and text | pure |
| Authentication file reader | Linux authlog collector | Module tests | Text | pure |
| Packet and socket telemetry | `parse_frame`, IP/UDP/TCP decoders, DNS response and name decoding, ClientHello and ServerHello, netlink dump / socket / TCP_INFO decoding | Packet, flow and inet_diag unit fixtures | Bytes with bounded tracker state | pure |
| Windows Event Log | `eventlog::render`, `parse`, `windows_native` normalization and provenance | Native XML, Unicode, time, replay and projection fixtures | XML and normalized fields. Rendering requires a native handle | mixed |
| Windows ETW | Provider/TDH reads in `windows/etw.rs`, projections in `etw_map.rs` | Portable mapping fixtures plus Windows tests | Mapping inputs. Native callback pointers require a live provider | mixed |
| eBPF | Exec collector ring read in `run`, syscall collector `read_raw<T>` and ring dispatch | Layout and compatibility fixtures in syscall module, native integration separately | Record bytes for fixed-layout types. Attachment needs kernel privileges | mixed |
| procfs and OS text | Process stat/identity, cgroup, maps, environment, mounts, sessions, socket and module lists in Linux collectors, forensics, rootkit and telemetry identity | Procfs library plus module-local example and live-process tests | Text/bytes where parsing is separate. Live snapshots require an OS | mixed |
| Signed config, policy and command | Serde decode to SignedConfig, PolicyFile, CommandEnvelope / SignedCommand and ProcessGeneration | Compatibility vectors and rejection cases in config/prevention | JSON deserialization only | pure |
| Queue, log offsets and event envelopes | `pipeline/journal.rs::read_line_bounded`, `decode`, JournalRecord, CheckpointStore::load, schema OCSF reverse mapping | CRC, version, torn tail, bounded reader, deterministic mutation, replay and schema fixtures | Framed bytes and typed JSON | mixed |

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
| Generic logs | Implemented | Partial (files and UDP, service mode) | Rate-limit counters, journal size cap, file checkpoints. Reader failures need separate accounting below | Windows matrix |
| Native Windows logs, registry and ETW file actor | Missing | Implemented | Per-channel reads, registry notification fallbacks, provider state. Attribution and policy-dependent fields can be absent | Native event guide, Windows matrix incomplete |
| Sensitive file opens and file decoys | Implemented | Partial (SACL/4663 and file decoys) | Attachment and audit availability reported. Different decoy detection modes | Both |
| Agent protection, OS/network integrity | Implemented | Partial (service, ACL and binary monitoring) | Sensor-specific integrity state and protection findings | Both |
| Module scans, driver loads | Implemented | Implemented | Periodic snapshots on Linux supplement event hooks. Windows ETW provider and inventory are distinct | ETW driver state missing from Windows matrix |
| Containers, namespaces, cross-view rootkit | Implemented | Missing | Linux OS views and optional hooks. Individual empty views require host validation | Repo guide |
| Memory inspection | Implemented | Implemented | Separate OS implementations. Protected or exited processes may be inaccessible | Windows-specific sweep missing from Windows matrix |
| Device attach/remove | Implemented | Implemented | Linux uevents and Windows SetupAPI deltas, optional serial capture. Windows polling cannot prove continuous presence | Windows matrix incomplete |
| Named pipes and AMSI | Missing (Windows provider semantics) | Partial | Provider enablement, session losses, pipe throttling and script-content opt-in are distinct | Coverage record, Windows matrix incomplete |
| Queue and delivery | Implemented | Implemented | Attributed drops, corruption, retry, acknowledgements and durable replay | Both |

### Collector-level interpretation

| Source | What contributes to health or coverage | What an idle or healthy report cannot establish |
|---|---|---|
| SystemCollector | Startup/task errors at the runner | A snapshot describes its sampling instant |
| Linux ProcessCollector / Windows process polling | Collector mode, per-field enrichment and ETW fallback. Linux enumeration errors retain the baseline and report a failed proc input | Very short processes and processes with inaccessible per-PID fields can be missed |
| EbpfExecCollector / EbpfSyscallCollector | Hook availability, kernel counters, userspace queue accounting and invalid-record count | Hooks absent from a given host cannot generate events |
| NetworkCollector (Linux) | Per-family proc-table read state. Failed family retains its last flow set. Other families keep emitting | A missing owner or optional inet_diag counter is not a zero measurement |
| NetworkCollector (Windows) | ETW provider state and TCP snapshot read failure | IP Helper supplies snapshots, not continuous packet counts |
| PacketCaptureCollector | Raw-socket open failure reaches collector health. TLS tracker counts capacity and timeout outcomes | Socket-level packet loss before decode is not quantified by eBPF ring loss |
| Linux AuthLogCollector / generic LogCollector | Auth source availability, reader errors, rate/size counters, file/journal cursors | File discovery, datagram delivery before receive, and historical records before initial tail position |
| Linux FilesystemCollector / FimCollector | Unavailable inotify roots, inotify queue overflows, dead worker threads and periodic task exit surface separately | Periodic tree walks can omit files on access errors or at the file cap |
| Windows FilesystemCollector | Notification-queue overflow and callback errors. Incomplete FIM scan or persistence failure sets a recoverable marker | The configured roots and file budgets constrain coverage |
| AgentProtectCollector / process and network integrity monitors | Inotify overflow/rate limits and terminal reader failures. Binary/network integrity use their own observations | No actor identity from inotify itself |
| ContainerWatchCollector / ModScanCollector | Container lifecycle requires cgroup v2. Inotify overflow, rate caps and failed module-scan jobs have counters | An unreadable process mapping can look like a process that exited between samples |
| DeviceCollector | Linux uevent budget/queue and Windows capped snapshot accounting | Windows attach-detach events entirely between polls |
| Linux and Windows MemScanCollector | Collector task errors reach the runner | Per-process access limitations and scan scope. No uniform per-process completeness metric |
| RootkitCollector | Sweep findings and truncation metadata. Unavailable comparison inputs disable the corresponding comparison | An absent cross-view finding cannot establish that every view was readable |
| Windows SensorSupervisor, EtwCollector and EtwFileActorCollector | Session/provider state and ETW loss. Optional actor-session startup retries are logged | Attribution requires the corresponding observation. No direct ETW-vs-poll missed-process counter |
| EventLogCollector / UserSessionCollector | Per-channel read state, malformed record counter, cursor recovery and WTS enumeration failures | Audit policy and SACL configuration decide which records Windows generates |
| RegistryWatchCollector / registry notifications | Notification fallback reasons, incomplete snapshots and bounded-scope coverage | A readable key alone does not establish an uninterrupted change history |
| Windows HoneytokenCollector / Linux decoy and sensitive-file readers | Audit SACL or eBPF attachment, fallback detection mode, rate counters and explicit handoff losses | A configured decoy can lack a usable OS sensor |

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

| ID | File and line | Description and scenario | Severity | Proposed fix | Disposition |
|---|---|---|---|---| --- |
| TV-1 | agent/src/collectors/logs/journal.rs:112, agent/src/collectors/logs/mod.rs:443 | Unterminated oversized journal input and invalid JSON lack attributable loss | should | Count oversize once at the size decision and malformed records once at decode | Addressed |
| TV-2 | agent/src/telemetry/coverage.rs:122 | Four polled Windows channels lack heartbeat read status when permission or availability changes | should | Include every fixed channel in coverage, reset on disable and exit | Addressed |
| TV-3 | agent/src/collectors/logs/mod.rs:498 | A datagram longer than the receive buffer appears complete | should | Detect overflow at the receive boundary and attribute the discard | Addressed |
| TV-4 | deploy/README-windows.md:94 | Matrix omits current sensors. Poller still maintains a baseline while ETW emits starts | should | Update operational documentation | Addressed |
| TV-5 | agent/src/collectors/logs/parser.rs:367 | Zone-free syslog text interpreted as UTC on non-UTC sources | should | Define an explicit source timezone policy before changing historical ordering | Deferred |
| TV-6 | crates/trapd-schema/src/origin.rs:29 | Sequence numbering restarts independently of Linux boot identity | should | Agree on a run namespace with consumers before changing the wire contract | Deferred |
| TV-7 | agent/src/collectors/logs/journal.rs:183 | Journal message duplicated in field bag | optional | Validate downstream field consumers before stripping it | Deferred |
| TV-8 | agent/src/collectors/logs/mod.rs:166 | Journal/syslog source exits enter cooldown with only a warning | should | Expose retry cooldown through failed_collectors and clear on recovery | Addressed |
| TV-9 | agent/src/collectors/linux/ebpf_exec.rs:309, ebpf_syscalls.rs:1075, sensitive_files.rs:637 | Rejected records from mismatched kernel/userspace layouts were absent from loss totals | should | Attribute a rejected record once as internal_error | Addressed |
| TV-10 | agent/src/collectors/logs/mod.rs:251 | A file poll or syslog receive error inside a running source was visible only in local logs | should | Mark the source failed while reads fail and clear on recovery/removal | Addressed |
| TV-11 | agent/src/collectors/linux/authlog.rs:60, agent/src/collectors/windows/network.rs:305 | Missing both auth inputs, a failed journal follower, and a failed TCP snapshot were logged locally while the collector stayed running | should | Publish separate, recoverable input status | Addressed |
| TV-12 | agent/src/collectors/windows/filesystem.rs:660, regwatch.rs:137 | Incomplete FIM scans, failed FIM checkpoint writes and incomplete registry snapshots had local warnings only | should | Mark the affected subcomponent until it recovers | Addressed |
| TV-13 | agent/src/collectors/windows/honeytokens.rs:1183 | Notification queue saturation shed lifecycle/detection records with only a log | should | Use shared try_emit drop accounting | Addressed |
| TV-14 | agent/src/collectors/logs/parser.rs:701 | PostgreSQL timestamp-prefix extraction assumed a byte offset was a UTF-8 boundary | blocking | Safely try the prefix and retain the original message if absent | Addressed |
| TV-15 | agent/src/collectors/linux/filesystem.rs:92 | Detached Linux FIM / inotify readers could exit while their parent remained active | should | Publish distinct failed subcomponents for terminal errors and unsuccessful watch registration | Addressed |
| TV-16 | agent/src/collectors/linux/process.rs:224, network.rs:213 | An unreadable process list or socket table looked empty during snapshot reconciliation | should | Preserve the affected snapshot and mark its source unavailable | Addressed |
| TV-17 | agent/src/collectors/linux/containerwatch.rs:500, agent_protect.rs:383 | Inactive cgroup or inotify input was only logged | should | Report the unavailable source in coverage | Addressed |
| TV-18 | agent/src/collectors/linux/fim.rs:130 | Per-entry walk errors and the file cap can make a partial baseline look complete | should | Mark the scan partial and retain unobserved baseline entries within the existing cap. Continue comparing observed files | Addressed |

## Disposition

TV-1, TV-2, TV-3, TV-8, TV-9, TV-10 and TV-11 have implementation changes. File
read errors publish one marker per source, independent of the number of
matching files. Between retries the log supervisor sets a shared cooldown
marker. This observes reader errors and does not measure packets discarded by
the network before they reach the socket. A legitimate empty discovery glob or
an expected file that has never appeared remains indistinguishable at that layer.
TV-18 retains unobserved baseline entries during partial scans and reports scan and persistence failures. Confirmed deletions resume on a complete scan. TV-16 retains the last complete observation separately for each socket family. TV-12, TV-13, TV-15 and TV-17 use existing coverage or pipeline accounting. TV-14 was found by inspection and received a minimal parser fix. TV-4 updates the deployment guide. TV-5 and TV-6 require source/consumer
contract decisions. TV-7 requires a downstream usage audit.

## Verification and out of scope

| Local check | Result |
|---|---|
| Workspace and fuzz workspace formatting | Passed |
| cargo clippy --all-targets -- -D warnings | Passed |
| cargo test | 1,910 passed, 14 ignored, 0 failed across the workspace |
| cargo build | Passed on Linux |
| cargo check --all-targets --target x86_64-pc-windows-gnu | Passed using a worktree-local MinGW toolchain |
| scripts/ocsf_validate.sh | 802 fixtures, 780 class/action pairs and nine OCSF classes passed |
| cargo fuzz build --target x86_64-unknown-linux-gnu | All eight targets built under nightly-2025-08-15 |

Native real-host resource measurements and Atomic Red Team runs require separate
host evidence. No detection behavior, command handling, signing or update change
is proposed. Native ETW/TDH callbacks, eBPF attachment, Windows audit policy
and backend/UI preservation of coverage fields require separate environment evidence.

### Bounded parser properties

The independent `fuzz/Cargo.toml` uses libfuzzer-sys only for verification.
The binary crate's parser modules are included by path. The targets generate
well-formed records and check their meaning. Generated corpus files stay under
the ignored `fuzz/corpus` directory. No dependency enters the agent binary.

| Target | Seed source | Checked property |
|---|---|---|
| log_fields | Combined access, RFC5424, SSH and database examples in collectors/logs/parser.rs | Field type and value, equivalent UTC times, PID, identity and port across log formats |
| queue_roundtrip | System snapshot and sequence in pipeline/journal.rs tests | Production encode, bounded chunked read, decode and re-encode preserve all bytes |
| proc_fields | Namespace, tty and session fixtures in forensics/session.rs | Native ID, tty, namespace and cgroup reconstruction |
| etw_connection | network_connect_decodes_network_order in collectors/etw_map.rs | Provider port byte order and endpoint direction for connect and accept |

Local Linux run with address sanitizer, rustc nightly-2025-08-15 and cargo-fuzz 0.13.2.
All four exited successfully with zero property failures or crashes.

| Target | Reported seconds | Executions | Result |
|---|---:|---:|---|
| etw_connection | 301 | 1,620,991 | Passed |
| log_fields | 301 | 80,671 | Passed |
| proc_fields | 301 | 1,688,601 | Passed |
| queue_roundtrip | 303 | 99,322 | Passed |

The seed files encode fixture field values in the generators' input layouts.
To reproduce a run from the repository root with cargo-fuzz 0.13.2:

```sh
cargo +nightly-2025-08-15 fuzz build --target x86_64-unknown-linux-gnu
for name in $(cargo +nightly-2025-08-15 fuzz list); do
    mkdir -p "fuzz/corpus/$name"
    cargo +nightly-2025-08-15 fuzz run --target x86_64-unknown-linux-gnu "$name" "fuzz/corpus/$name" "fuzz/seeds/$name" -- -max_total_time=300 -print_final_stats=1
done
```

### Arbitrary-input targets

These targets take raw bytes, not generated well-formed records. The journal
and Event Log parsers moved unchanged into I/O-free files
(`collectors/logs/journal_json.rs`, `collectors/windows/eventlog_xml.rs`) so the
fuzz crate can include them by path. `parse_frame` in `packet_capture.rs` is
now `pub(super)` for the same reason.

| Target | Input | Checked property |
|---|---|---|
| journal_json | Any `journalctl --output=json` line | No panic; `__CURSOR` never stays in forwarded fields |
| eventlog_xml | Any rendered event XML on four channels | No panic; message ≤ 64 KiB, ≤ 258 fields, each ≤ 16 KiB, offset = record ID |
| packet_frames | Up to 64 length-prefixed IP frames through one TLS tracker | No panic in IPv4/IPv6, UDP/DNS, TCP reassembly and TLS hello parsing |
| signed_command | Any polled command batch | No panic; nothing verifies without the signing key; a decoded envelope re-signed after an encode/decode round trip still verifies |

Local run, same toolchain, address sanitizer:

| Target | Seconds | Executions | Result |
|---|---:|---:|---|
| journal_json | 121 | 4,443,301 | Passed |
| eventlog_xml | 121 | 2,257,556 | Passed |
| packet_frames | 181 | 3,639,461 | Passed |
| signed_command | 121 | 1,668,334 | Passed |

The CI job runs every target for 15 seconds with
`--target x86_64-unknown-linux-gnu`. The prebuilt cargo-fuzz otherwise
defaults to musl, which the address sanitizer cannot use. eBPF ring buffer
records are not fuzzed: they come from the agent's own kernel programs and are
accepted only after a size check and a plausibility canary. Signed
configuration shares `verify_canonical` with commands but its decoder is not
a separate target.

## Source function index

Function names below are relative to `agent/src`. “Direct” means a co-located test calls that function by name. Dispatcher tests also exercise helpers indirectly. A module test is weaker evidence than a format-specific assertion. Native live-handle paths are integration-test candidates.

| Module | Entry points and decoding helpers | Direct calls in module tests |
|---|---|---|
| `collectors/logs/parser.rs` | `parse`, `parse_auto`, `looks_like_syslog`, `looks_like_combined_access`, `parse_json`, `first_string`, `first_i64`, `parse_syslog`, `strip_pri`, `decode_pri`, `facility_name`, `severity_name`, `parse_rfc5424`, `split_sd`, `dash_opt`, `parse_rfc3164`, `rfc3164_prefix`, `month_num`, `parse_rfc3164_ts`, `split_tag`, `parse_iis`, `parse_nginx_access`, `parse_combined_access`, `split_once_space`, `parse_two_quoted`, `parse_nginx_time`, `parse_nginx_error`, `parse_apache_error`, `parse_apache_error_ts`, `extract_after`, `split_host_port`, `parse_postgresql`, `parse_mysql`, `parse_docker`, `parse_sshd`, `parse_sshd_inner`, `parse_accepted`, `parse_failed_ssh`, `parse_failed_tail`, `parse_sudo`, `parse_sudo_inner`, `parse_auditd`, `audit_ts`, `kv_value`, `merge_kv`, `parse_kv`, `parse_cef`, `map_word_severity`, `parse_ts` | `parse` |
| `collectors/logs/framing.rs` | `as_str`, `frame_bytes`, `cut_utf8`, `push`, `is_start`, `append`, `audit_event_id` | `as_str`, `frame_bytes`, `push`, `audit_event_id` |
| `collectors/logs/reader.rs` | `poll`, `take_incomplete`, `read_available`, `w3c_fields_before` | `poll`, `w3c_fields_before` |
| `collectors/logs/journal.rs` | `read_record`, `read_line_bounded`, `parse_journal_json`, `json_str`, `realtime_ts`, `priority_name` | `read_record`, `read_line_bounded`, `parse_journal_json` |
| `collectors/logs/checkpoint.rs` | `load` | `load` |
| `collectors/linux/authlog.rs` | `is_valid_cursor`, `parse_journal_record`, `read_bounded_line`, `parse_auth_line`, `parse_accepted`, `parse_failed`, `parse_failed_for`, `parse_session` | `parse_journal_record`, `read_bounded_line`, `parse_auth_line`, `parse_failed` |
| `collectors/linux/packet_capture.rs` | `parse_frame`, `parse_l3`, `parse_ipv4`, `parse_ipv6`, `parse_udp`, `parse_tcp`, `qtype_name`, `rcode_name`, `parse_dns_response`, `read_name`, `tls_version_name`, `parse_client_hello`, `parse_extension` | `parse_frame`, `parse_l3`, `parse_udp`, `parse_tcp`, `parse_dns_response`, `read_name`, `parse_client_hello` |
| `collectors/linux/tls_flow.rs` | `parse_server_hello`, `extract_handshake`, `insert`, `starts_with_hello`, `on_tcp`, `client_segment`, `server_segment` | `parse_server_hello`, `extract_handshake`, `insert`, `on_tcp` |
| `collectors/linux/inet_diag.rs` | `parse_dump`, `parse_inet_diag_msg`, `parse_socket`, `read_addr`, `parse_tcp_info` | `parse_inet_diag_msg`, `parse_socket`, `parse_tcp_info` |
| `collectors/windows/eventlog.rs` | `render`, `read_batch`, `parse`, `native_provenance`, `capture_logon_type`, `script_block_events` | `parse`, `script_block_events` |
| `collectors/windows/etw.rs` | `utf16`, `event_callback`, `decode_record`, `read_property`, `interpret` | No direct call identified |
| `collectors/etw_map.rs` | `filetime_timestamp`, `device_to_dos`, `process_start`, `process_stop`, `image_load`, `driver_load`, `pipe_create`, `payload_mentions_pipe`, `decode_amsi_text`, `amsi_scan`, `address`, `port`, `network_connection`, `parse_query_results`, `dns_query`, `dns_server_hint`, `record_key` | Process, file, network, DNS and AMSI fixtures |
| `collectors/windows_native.rs` | `number`, `pid`, `registry_path`, `rename_object`, `normalize` | `normalize` |
| `collectors/device.rs` | `clean_text`, `parse_product`, `parse_uevent`, `event_from_uevent`, `parse_instance_id` | `clean_text`, `parse_product`, `parse_uevent`, `event_from_uevent`, `parse_instance_id` |
| `collectors/windows/network.rs` | `table`, `snapshot` | `snapshot` |
| `collectors/linux/ebpf_exec.rs` | `cstr`, `proc_ppid`, `proc_cmdline`, `proc_cwd`, `proc_container_id`, `proc_username`, `run` | No direct call identified |
| `collectors/linux/ebpf_syscalls.rs` | `honeytoken_observed_ns`, `cstr`, `format_ipv4`, `format_ipv6`, `format_addr`, `ns_flags_to_string`, `read_raw` | `honeytoken_observed_ns`, `read_raw` (lifecycle_tests) |
| `collectors/linux/sensitive_files.rs` | `decode`, `cstr` | `decode` |
| `collectors/linux/memscan.rs` | `parse_maps`, `parse_maps_line`, `ld_preload_from_environ` | `parse_maps`, `parse_maps_line`, `ld_preload_from_environ` |
| `collectors/linux/proc_enrich.rs` | `interpreter_context`, `inline_script_arg`, `decode_base64_blobs`, `parse_cgroup`, `strip_runtime_prefix` | `interpreter_context`, `parse_cgroup`, `strip_runtime_prefix` |
| `collectors/linux/modscan.rs` | `read_snapshot` | No direct call identified |
| `collectors/linux/containerwatch.rs` | `container_from_dir`, `first_pid` | `container_from_dir`, `first_pid` |
| `collectors/linux/process.rs` | `check_rwx_maps` | No direct call identified |
| `collectors/linux/privilege_change.rs` | `parse_status` (proc credentials) | Proc status fixtures |
| `collectors/registry_watch.rs` | `decode_baseline` | Baseline serialization/validation fixtures |
| `inventory/collect.rs` | `parse_os_release`, `decode_vfs_cap` | OS release and vfs capability fixtures |
| `forensics/session.rs` | `parse_id_field`, `parse_tty_nr_from_stat`, `tty_from_nr`, `parse_ns_inode`, `most_specific_cgroup`, `container_from_cgroup`, `is_hex_id` | `parse_id_field`, `parse_tty_nr_from_stat`, `tty_from_nr`, `parse_ns_inode`, `most_specific_cgroup`, `container_from_cgroup` |
| `telemetry/identity.rs` | `process_start_time`, `parse_start_time` | `process_start_time`, `parse_start_time` |
| `rootkit/hidden_file.rs` | `parse_dirents64`, `mapped_paths` | `parse_dirents64`, `mapped_paths` |
| `rootkit/hidden_login.rs` | `parse_utmp`, `cstr`, `parse_stat_session` | `parse_utmp`, `parse_stat_session` |
| `rootkit/hidden_mount.rs` | `unescape_mount_path`, `parse_mounts`, `parse_mountinfo`, `parse_mountstats` | `unescape_mount_path`, `parse_mounts`, `parse_mountinfo` |
| `rootkit/modules.rs` | `parse_proc_modules` | `parse_proc_modules` |
| `config/mod.rs` | `ConfigPuller::apply_body`, `ConfigVerifier::new`, `load_persisted_from` | `load_persisted_from`, verifier compatibility fixtures |
| `prevention/command_puller.rs` | `decode_batch` | `decode_batch` |
| `prevention/commands.rs` | `deserialize`, `new` | No direct call identified |
| `prevention/policy.rs` | `load_local_policy` | No direct call identified |
| `pipeline/journal.rs` | `decode`, `read_line_bounded` | `decode`, `read_line_bounded` |

Config polling deserializes SignedConfig inside the HTTP response handler. JSON policy, command-batch and nonce readers delegate field decoding to Serde. Procfs library readers, Win32/TDH extraction, and macro-expanded eBPF dispatch do not all have separately named Rust parsing functions. This index covers the reviewed boundaries. It is not a whole-program call graph.
