# TRAPD-Agent Repo Guide

This repository contains the Linux TRAPD telemetry and response agent. Use this file as the working context for future Codex/agent sessions and as the backend API contract reference.

## Repository Overview

- Language/runtime: Rust 2021, Tokio async runtime.
- Workspace members: `agent`, `xtask`.
- Standalone crate: `trapd-agent-ebpf` is intentionally outside the root workspace because it targets `bpfel-unknown-none`.
- Main binary: `agent/src/main.rs` builds `trapd-agent`.
- Current package version: `trapd-agent` `0.2.0`.
- Primary output: structured JSON events, written locally as NDJSON and/or sent to the backend.
- Platform focus: Linux. Some schema types are intentionally OS-neutral for future Windows support.

## Important Paths

- `agent/src/schema/mod.rs`: primary telemetry event envelope and event payload schemas.
- `agent/src/enrollment/mod.rs`: first-run enrollment request/response and persisted credentials.
- `agent/src/heartbeat/mod.rs`: heartbeat payload schema.
- `agent/src/inventory/mod.rs`: asset inventory payload schema.
- `agent/src/config/mod.rs`: backend-delivered agent config schema.
- `agent/src/prevention/commands.rs`: signed response command schema.
- `agent/src/prevention/policy.rs`: IoC policy/rule schema.
- `agent/src/deception/`: honeytoken deception subsystem — `profiler.rs` (deterministic recon profile / token candidates), `registry.rs` (deployed-token register at `<state>/honeytokens.json`), `mod.rs` (camouflaged deploy + safe revoke). Step 1 places and manages tokens; no detection yet.
- `agent/src/transport/mod.rs`: event ingest transport.
- `agent/src/output/mod.rs`: local stdout/file NDJSON output.
- `agent/src/http/mod.rs`: shared HTTP client, TLS pinning, mTLS, timeouts.
- `trapd-agent-ebpf/src/*.rs`: eBPF kernel-side event structs.
- `xtask/src/main.rs`: helper command for eBPF builds.
- `deploy/`: install script, systemd unit, logrotate config.
- `target/`: build artifacts; do not edit.

## Build And Test

- Build agent: `cargo build --release --manifest-path agent/Cargo.toml`
- Test agent: `cargo test --manifest-path agent/Cargo.toml`
- Clippy: `cargo clippy --manifest-path agent/Cargo.toml -- -D warnings`
- Build eBPF programs: `cargo xtask build-ebpf --release`
- eBPF prerequisites: `bpf-linker`, pinned nightly toolchain from `trapd-agent-ebpf/rust-toolchain.toml`, `rust-src`.

## Runtime Modes

- Online mode requires `TRAPD_BACKEND_URL`; first run also requires `TRAPD_ENROLL_TOKEN`.
- Offline mode is enabled by `TRAPD_OFFLINE=1` or by missing `TRAPD_BACKEND_URL`.
- Offline mode skips enrollment, ingest, heartbeat, config pull, and command pull; telemetry is emitted locally.
- Output mode is controlled by `TRAPD_OUTPUT`: `file` writes to `<log_dir>/events.ndjson`; anything else uses stdout.

## Filesystem Layout

- State dir: default `/var/lib/trapd`, override `TRAPD_STATE_DIR`; contains `device_id`, `credentials.json`, nonces, baselines, `honeytokens.json` (deployed-honeytoken register, `0600`).
- Config dir: default `/etc/trapd`, override `TRAPD_CONFIG_DIR`; contains `agent.env`, `policy.json`, `ca.crt`, `agent.crt`, `agent.key`, `command_signing.pub`.
- Log dir: default `/var/log/trapd`, override `TRAPD_LOG_DIR`; contains `events.ndjson`.
- State dir is hardened to `0700`; credentials are atomically written as `0600`.

## HTTP Conventions

- Backend base URL is normalized by trimming whitespace and trailing slashes.
- Online authenticated endpoints use `Authorization: Bearer <agent_secret>`.
- HTTP client uses rustls, bounded timeouts, optional CA pinning from `<config>/ca.crt`, optional mTLS from `<config>/agent.crt` + `<config>/agent.key`.
- Control-plane timeout: 30s total, 10s connect.
- Streaming ingest timeout: 60s total, 10s connect.
- User-Agent: `trapd-agent/<package_version>`.

## Backend API Endpoints

### `POST /api/v1/agents/enroll`

- Auth: none.
- Request body: `EnrollRequest`.
- Response body on 2xx: `EnrollResponse`.
- Transient errors retried: network/timeouts, 5xx, 408, 425, 429, invalid transient 2xx bodies.
- Permanent errors: other 4xx statuses.

### `POST /api/v1/ingest/events`

- Auth: bearer `agent_secret`.
- Request body: JSON array of `AgentEvent`.
- Batch size: up to 100 events.
- Flush interval: every 5 seconds.
- Any 2xx drains events from the local ring buffer; non-2xx leaves them buffered.

### `POST /api/v1/agents/{agent_id}/heartbeat`

- Auth: bearer `agent_secret`.
- Request body: `HeartbeatPayload`.
- Cadence: every 30 seconds.
- Any non-2xx is logged and ignored by the agent.

### `GET /api/v1/agents/{agent_id}/config`

- Auth: bearer `agent_secret`.
- Request headers: optional `If-None-Match` with previous ETag.
- Success responses: `200` with `AgentConfig`, or `304`.
- Response `ETag` is cached by the agent.
- Poll cadence: every 60 seconds.

### `GET /api/v1/agents/{agent_id}/commands`

- Auth: bearer `agent_secret`.
- Response body: JSON array of `SignedCommand`.
- Poll cadence: `command_poll_interval_secs`, minimum 2 seconds.
- Every command must verify against raw 32-byte Ed25519 public key `<config>/command_signing.pub`.
- Signature input is canonical JSON serialization of `CommandEnvelope`.
- Accepted command nonces are stored in `<state>/command_nonces.json`; replayed nonces are rejected.

### `POST /api/v1/agents/{agent_id}/inventory`

- Auth: bearer `agent_secret`.
- Request body: `InventorySnapshot`.
- Cadence: once 15 seconds after startup, then every 6 hours.
- Offline behavior: writes `<state>/inventory.json` instead of POSTing.

## Serialization Rules

- Rust field names serialize as snake_case unless explicitly noted.
- `DateTime<Utc>` serializes as RFC3339 timestamp strings.
- `Uuid` serializes as UUID strings.
- `EventClass` serializes lowercase.
- `EventAction`, `Severity`, `RuleAction`, `CommandPayload.kind`, and `IocRule.type` use snake_case.
- `EventData` is `serde(untagged)`: the payload is not wrapped with a discriminator. Use `class` + `action` from `AgentEvent` to route it on the backend.
- Fields annotated with `skip_serializing_if = "Option::is_none"` are omitted when null.
- `serde_json::Value` fields using `skip_serializing_if = "serde_json::Value::is_null"` are omitted when null/default.

## Core Event Schema

### `AgentEvent`

```json
{
  "event_id": "uuid",
  "agent_id": "string",
  "hostname": "string",
  "timestamp": "RFC3339 UTC datetime",
  "class": "process|network|system|user|filesystem|memory|kernel|ipc|prevention|detection",
  "action": "EventAction",
  "severity": "info|low|medium|high|critical",
  "data": "EventData"
}
```

### `EventAction`

```text
create, terminate, exec, connection, snapshot, logon, logon_failed,
session_open, session_close, delete, modify, open, bind, accept, fork,
unlink, rename, chmod, chown, mmap, ptrace, module_load, shmget, shmat,
ns_change, dns_query, integrity_violation, ransomware_indicator,
agent_tamper, write_rate_anomaly, kill_attempt, process_blocked,
network_isolated, network_deisolated, ip_blocked, ip_unblocked,
file_quarantined, file_restored, policy_updated, command_rejected,
command_accepted, detected, package_installed, package_removed,
package_upgraded, honeytoken_deployed, honeytoken_revoked, honeytoken_access
```

## EventData Schemas

### `ProcessCreateData`

```json
{
  "pid": "i32",
  "ppid": "i32",
  "name": "string",
  "exe": "string",
  "cmdline": "string",
  "uid": "u32",
  "username": "string"
}
```

### `ProcessTerminateData`

```json
{
  "pid": "i32",
  "name": "string"
}
```

### `ExecEventData`

```json
{
  "pid": "i32",
  "ppid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "exe": "string",
  "cmdline": "string",
  "cwd": "string",
  "container_id": "string, optional"
}
```

### `NetworkConnectionData`

```json
{
  "protocol": "string",
  "src_addr": "string",
  "src_port": "u16",
  "dst_addr": "string",
  "dst_port": "u16",
  "state": "string",
  "pid": "i32, optional",
  "process": "string, optional"
}
```

### `SystemSnapshotData`

```json
{
  "os": "string",
  "kernel": "string",
  "distro": "string",
  "cpu_count": "usize",
  "cpu_usage_pct": "f32",
  "memory_total_mb": "u64",
  "memory_used_mb": "u64",
  "memory_free_mb": "u64",
  "uptime_secs": "u64",
  "load_avg": ["f64", "f64", "f64"]
}
```

### `UserLogonData`

```json
{
  "username": "string",
  "src_addr": "string, optional",
  "src_port": "u16, optional",
  "auth_method": "string, optional",
  "success": "bool"
}
```

### `UserSessionData`

```json
{
  "username": "string"
}
```

### `FileEventData`

```json
{
  "path": "string"
}
```

### `FileOpenData`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "path": "string",
  "flags": "u64"
}
```

### `NetworkSocketData`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "op": "string",
  "family": "string",
  "addr": "string",
  "port": "u16"
}
```

### `ForkData`

```json
{
  "parent_pid": "i32",
  "child_pid": "i32",
  "parent_comm": "string",
  "child_comm": "string"
}
```

### `FileUnlinkData`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "path": "string"
}
```

### `FileRenameData`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "old_path": "string",
  "new_path": "string"
}
```

### `FileChmodData`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "path": "string",
  "mode": "u32"
}
```

### `FileChownData`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "path": "string",
  "new_uid": "u32",
  "new_gid": "u32"
}
```

### `MmapData`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "addr": "u64",
  "len": "u64",
  "prot": "u32",
  "flags": "u32",
  "description": "string"
}
```

### `PtraceData`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "request": "u32",
  "target_pid": "i32"
}
```

### `ModuleLoadData`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "name": "string",
  "taints": "u32"
}
```

### `ShmData`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "op": "string",
  "key": "i32",
  "size": "u64",
  "flags": "i32"
}
```

### `NsChangeData`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "op": "string",
  "namespaces": "string",
  "flags": "u64"
}
```

### `DnsData`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "dst_addr": "string",
  "dst_port": "u16"
}
```

### `IntegrityViolationData`

```json
{
  "path": "string",
  "expected_hash": "string",
  "actual_hash": "string",
  "size_delta": "i64"
}
```

### `RansomwareIndicatorData`

```json
{
  "indicator_type": "string",
  "path": "string, optional",
  "pid": "i32, optional",
  "comm": "string, optional",
  "entropy": "f64, optional",
  "write_rate": "u64, optional",
  "details": "string"
}
```

### `AgentTamperData`

```json
{
  "path": "string",
  "action": "string"
}
```

### `WriteRateAnomalyData`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "write_count": "u64",
  "burst_threshold": "u64"
}
```

### `KillAttemptData`

```json
{
  "sender_pid": "u32",
  "sender_uid": "u32",
  "sender_gid": "u32",
  "sender_comm": "string",
  "target_pid": "i32",
  "signal": "i32",
  "signal_name": "string"
}
```

### `PreventionEventData`

```json
{
  "kind": "string",
  "target": "string",
  "success": "bool",
  "reason": "string",
  "rule_id": "string, optional",
  "command_id": "string, optional",
  "details": "object|array|string|number|bool|null, optional"
}
```

Known `kind` values include `process_block`, `network_isolate`, `network_deisolate`, `ip_block`, `ip_unblock`, `quarantine`, `restore`, `policy_update`, `command_rejected`, `command_accepted`, `honeytoken_deploy`, `honeytoken_revoke`, `honeytoken_response`.

### `HoneytokenAccessData`

Emitted (`class=detection`, `action=honeytoken_access`, severity `critical`) when a
deployed honeytoken is opened. By construction no legitimate workflow reads a
honeytoken, so `confidence` is always `100`. The payload binds the access to the
accessor's full process lineage (the "flight recorder" idea) so the backend can
reconstruct how the touching process came to exist.

```json
{
  "token_id": "string (matches HoneytokenRecord.id)",
  "path": "string (absolute path opened)",
  "kind": "string (token family)",
  "open_flags": "u64 (read-only access still fires)",
  "confidence": "u8 (always 100)",
  "mitre_tactic": "string",
  "mitre_technique": "string",
  "accessor": "ProcessLineage"
}
```

### `ProcessLineage` / `ProcessAncestor`

```json
{
  "pid": "i32",
  "uid": "u32",
  "gid": "u32",
  "username": "string",
  "comm": "string",
  "exe": "string, optional",
  "cmdline": "string, optional",
  "ancestors": ["ProcessAncestor"]
}
```

```json
{
  "pid": "i32",
  "comm": "string",
  "exe": "string, optional",
  "cmdline": "string, optional"
}
```

`ancestors` lists the parent chain nearest-first, walking up toward PID 1
(bounded depth). The `honeytoken_response` prevention event (above) records the
policy-driven reaction (`alert`/`kill`/`isolate`) taken for each access.

### `DetectionData`

```json
{
  "rule_id": "string",
  "title": "string",
  "category": "string",
  "mitre_tactic": "string, optional",
  "mitre_technique": "string, optional",
  "confidence": "u8, 0-100",
  "subject": "string",
  "detail": "string",
  "evidence": "object|array|string|number|bool|null, optional"
}
```

## Enrollment Schemas

### `EnrollRequest`

```json
{
  "enrollment_token": "string",
  "device_id": "string",
  "hostname": "string",
  "os_version": "string",
  "arch": "string",
  "agent_version": "string"
}
```

### `EnrollResponse`

```json
{
  "agent_id": "string",
  "agent_secret": "string",
  "project_id": "string"
}
```

### `Credentials`

Persisted locally in `credentials.json`.

```json
{
  "agent_id": "string",
  "agent_secret": "string",
  "project_id": "string"
}
```

## Heartbeat Schemas

### `HeartbeatPayload`

```json
{
  "agent_id": "string",
  "hostname": "string",
  "agent_version": "string",
  "timestamp": "RFC3339 UTC datetime",
  "metrics": "Metrics"
}
```

### `Metrics`

```json
{
  "cpu_usage_pct": "f32",
  "cpu_logical_cores": "usize",
  "memory_total_mb": "u64",
  "memory_used_mb": "u64",
  "memory_used_pct": "f32",
  "swap_total_mb": "u64",
  "swap_used_mb": "u64",
  "disk_total_mb": "u64",
  "disk_used_mb": "u64",
  "disk_used_pct": "f32",
  "load_avg": ["f64", "f64", "f64"],
  "uptime_secs": "u64",
  "process_count": "usize"
}
```

## Inventory Schemas

### `InventorySnapshot`

Current `schema_version` is `2` (v2 added `recon_profile`).

```json
{
  "schema_version": "u32",
  "agent_id": "string",
  "device_id": "string",
  "hostname": "string",
  "agent_version": "string",
  "collected_at": "RFC3339 UTC datetime",
  "os": "OsInfo",
  "hardware": "HardwareInfo",
  "network": ["NetInterface"],
  "software": "SoftwareInventory",
  "users": ["UserAccount"],
  "recon_profile": "ReconProfile"
}
```

### `ReconProfile`

Deception recon profile: deterministic honeytoken candidates derived on-agent
from the observed context (users + installed software + cheap on-host
existence checks). Sent to the backend so it can generate believable content
and rank placements. Candidates are pre-sorted by descending `score`.

The candidate set follows the attacker playbook (MITRE **T1552** Unsecured
Credentials / **T1083** File & Directory Discovery). The governing rule: a
candidate is only proposed where the genuine artefact is plausible (e.g. no
`~/.aws/credentials` unless `awscli` is installed), so the placement does not
reveal the trap.

```json
{
  "schema_version": "u32",
  "candidates": ["TokenCandidate"]
}
```

### `TokenCandidate`

```json
{
  "kind": "string (ssh_private_key|aws_credentials|pgpass|my_cnf|docker_config|kube_config|webroot_env|root_backup_keys|passwords_kdbx|shell_history)",
  "path": "string (absolute path where the genuine artefact would live)",
  "mitre_technique": "string (e.g. T1552.004)",
  "rationale": "string (which observed evidence justified this candidate)",
  "context": ["string (tags: user:<name>, pkg:<name>, dir:<path>, …)"],
  "score": "u8 (0-100, context strength × attacker attractiveness)",
  "mode": "u32 (octal file mode, e.g. 384 = 0o600)",
  "mimic_neighbor": "bool"
}
```

Backend responsibilities for the recon profile:

- **Content generation (LLM):** turn each chosen candidate into believable,
  host-specific bait — a `.env` matching the detected app stack, fake secrets
  in the correct format (AWS `AKIA…` layout, JWT structure, DB connection
  strings with plausible internal hostnames). Embed an out-of-band canary
  marker in the content.
- **Placement ranking:** decide which candidates to deploy first. Start with
  the deterministic `score` the agent already computed; a trained model
  replaces it in step 2 once hit/miss telemetry exists.
- Issue chosen candidates back as signed `deploy_honeytoken` commands.

## Deception Step 2: Access Detection, Response & ML Feedback Loop

### On-agent detection (eBPF + userspace)

- eBPF (`trapd-agent-ebpf/src/file_open.rs`): a `HONEYTOKEN_INODES` hash map
  (**inode number → token id**) plus a dedicated `HONEYTOKEN_ACCESS_EVENTS` ring
  buffer. A `vfs_open` kprobe resolves the opened inode (`path → dentry →
  d_inode → i_ino`) and, on a map hit, emits an access event **regardless of
  open flags** (the read-only detection fix). The `sys_enter_openat` read-only
  suppression on `FILE_OPEN_EVENTS` is unchanged.
- **Why inode, why `vfs_open`:** matching the resolved inode is robust against
  symlinks, relative paths and `..` (a single cheap hash lookup); path parsing
  in BPF would be fragile. `sys_enter_openat` has no resolved inode, so the
  match runs at `vfs_open` where the dentry/inode is known. The inode-walk uses
  fixed x86_64 struct offsets read with `bpf_probe_read_kernel`; **every read is
  fail-safe** (a wrong offset/bad pointer yields a miss, never a false
  positive), and userspace re-verifies the hit against the token's recorded
  inode. A BTF/CO-RE-driven offset resolution is the portability hardening
  tracked for later. The `vfs_open` kprobe attaches best-effort — if it is
  missing (older eBPF binary) the rest of the telemetry is unaffected.
- Userspace (`agent/src/collectors/linux/ebpf_syscalls.rs` +
  `agent/src/detection/honeytoken.rs`): a reconciler `stat()`s every registered
  token and arms `HONEYTOKEN_INODES` (inode → token id) from the on-disk
  register (`<state>/honeytokens.json`) every 15s; a consumer resolves the
  token id, enriches each hit with full `/proc` lineage, applies the
  false-positive allowlist + agent self-exclusion, and emits a `HoneytokenAccess`
  detection.
- The prevention engine reacts per `honeytoken_response` policy
  (`alert`/`kill`/`isolate`) and audits the decision as a `honeytoken_response`
  prevention event.

### Backend feedback loop (ML)

This is where real training data first exists — a token is either touched (by
whom, how soon after deployment) or never touched over N days. The backend
should:

- **Hit telemetry:** persist every `HoneytokenAccess` event and pair it with the
  originating `deploy_honeytoken` (via `token_id`) to derive the per-token
  signal (touched vs. dormant, latency-to-touch, accessor lineage).
- **Re-ranking:** feed that signal fleet-wide into the placement ranker from
  step 1b, learning which token archetypes & paths actually catch attackers vs.
  which are dead weight — closing the loop back onto candidate selection.
- **Rotation / aging:** rotate stale tokens (regenerate content, vary path) via
  `revoke_honeytoken` + `deploy_honeytoken` so a returning attacker cannot
  memorise them.
- **Drift:** when a host's `recon_profile` changes (new package → new plausible
  location), propose new placements.

### `OsInfo`

```json
{
  "family": "string",
  "name": "string",
  "version": "string",
  "pretty_name": "string",
  "kernel": "string",
  "arch": "string",
  "machine_id": "string, optional",
  "timezone": "string, optional",
  "boot_time_unix": "u64",
  "uptime_secs": "u64"
}
```

### `HardwareInfo`

```json
{
  "vendor": "string, optional",
  "product": "string, optional",
  "serial": "string, optional",
  "bios_vendor": "string, optional",
  "bios_version": "string, optional",
  "chassis": "string, optional",
  "virtualization": "string, optional",
  "cpu_model": "string",
  "cpu_physical_cores": "usize",
  "cpu_logical_cores": "usize",
  "memory_total_mb": "u64",
  "swap_total_mb": "u64",
  "disks": ["DiskInfo"]
}
```

### `DiskInfo`

```json
{
  "device": "string",
  "mount_point": "string",
  "fs_type": "string",
  "total_mb": "u64",
  "available_mb": "u64",
  "removable": "bool"
}
```

### `NetInterface`

```json
{
  "name": "string",
  "mac": "string, optional",
  "ipv4": ["string"],
  "ipv6": ["string"],
  "up": "bool"
}
```

### `SoftwareInventory`

```json
{
  "source": "string",
  "package_count": "usize",
  "packages": ["SoftwarePackage"]
}
```

### `SoftwarePackage`

```json
{
  "name": "string",
  "version": "string",
  "architecture": "string, optional"
}
```

### `UserAccount`

```json
{
  "username": "string",
  "uid": "u32",
  "gid": "u32",
  "home": "string",
  "shell": "string",
  "is_human": "bool"
}
```

## Config Schema

### `AgentConfig`

```json
{
  "poll_interval_secs": "u64, default 60",
  "enabled_collectors": ["string, default process/network/system/authlog/filesystem"],
  "fs_watch_paths": ["string, default /etc,/bin,/tmp"],
  "prevention_enabled": "bool, default true",
  "command_poll_interval_secs": "u64, default 10",
  "isolation_allowlist_ips": ["string"],
  "inventory_enabled": "bool, default true",
  "honeytoken_detection_enabled": "bool, default true",
  "honeytoken_response": "string, default \"alert\" (none|alert|kill|isolate)",
  "honeytoken_accessor_allowlist": ["string (extra benign accessor comms)"]
}
```

`honeytoken_response` escalates: `none` (detection only, no engine action) <
`alert` (critical prevention event) < `kill` (also SIGKILL the accessor) <
`isolate` (also full host network isolation). `honeytoken_accessor_allowlist`
extends the built-in sweeper allowlist (mlocate/updatedb, AV scanners, backup
tools, and the agent itself) used to suppress false positives.

## Command Schemas

### `SignedCommand`

```json
{
  "envelope": "CommandEnvelope",
  "signature": "base64 string; 64-byte Ed25519 signature over canonical_json(envelope)"
}
```

### `CommandEnvelope`

```json
{
  "command_id": "uuid",
  "issued_at": "RFC3339 UTC datetime",
  "expires_at": "RFC3339 UTC datetime",
  "agent_id": "string",
  "nonce": "uuid",
  "payload": "CommandPayload"
}
```

### `CommandPayload`

Discriminated by `kind`.

```json
{ "kind": "kill_pid", "pid": "i32" }
{ "kind": "isolate_network", "allowlist_ips": ["IP address string"] }
{ "kind": "deisolate_network" }
{ "kind": "quarantine_file", "path": "string" }
{ "kind": "restore_file", "quarantine_id": "string" }
{ "kind": "block_ip", "ip": "string", "ttl_secs": "u64, optional" }
{ "kind": "unblock_ip", "ip": "string" }
{ "kind": "update_policy", "rules": ["IocRule"] }
{ "kind": "install_package", "name": "string" }
{ "kind": "remove_package", "name": "string" }
{ "kind": "upgrade_package", "name": "string, optional" }
{ "kind": "deploy_honeytoken", "path": "string", "content_b64": "base64 string", "mode": "u32 octal, optional, default 0", "mimic_neighbor": "bool, optional, default false", "canary_marker": "string, optional", "token_kind": "string, optional" }
{ "kind": "revoke_honeytoken", "path": "string" }
```

#### `deploy_honeytoken` / `revoke_honeytoken` semantics

- `content_b64` is base64 of the **fully-formed** bait content the backend
  generated (the LLM content-generation job). The agent never generates
  content and no LLM runs on the endpoint.
- `mode` is an octal file mode encoded as an integer (e.g. `384` = `0o600`).
  `0` means "adopt the mimicked neighbour's mode"; if there is no neighbour the
  agent falls back to `0o600`.
- `mimic_neighbor=true` makes the agent copy owner/group and atime/mtime from a
  sibling file in the same directory so the token blends in.
- `canary_marker` is the out-of-band tracking marker embedded in `content_b64`
  by the backend (e.g. a fake AWS key id tied to a monitored honeypot account,
  or a tracking domain). It is recorded locally for correlation; the agent does
  not parse it back out of the content.
- `token_kind` is the recon candidate family echoed back (`ssh_private_key`,
  `aws_credentials`, …); recorded in the register for attribution.
- Safety invariants enforced on the agent: the target path must be **absolute**
  with no `..` component; the agent **refuses to overwrite** an existing file
  (so real user data is never clobbered); `revoke_honeytoken` only removes a
  path that is present in the local register (`<state>/honeytokens.json`), so a
  command can never make the agent delete a file it did not plant.
- Outcomes are reported as `class=prevention` audit events with
  `action=honeytoken_deployed` / `honeytoken_revoked` and `kind`
  `honeytoken_deploy` / `honeytoken_revoke`. The audit `details` carry only
  safe metadata (id, kind, mode, size, sha256, mimic info, `has_canary`) —
  never the bait content itself.

## Policy Schemas

### `PolicyFile`

Local file path: `<config>/policy.json`.

```json
{
  "rules": ["IocRule"]
}
```

### `RuleAction`

```text
block, alert
```

### `IocRule`

Discriminated by `type`.

```json
{ "type": "sha256", "id": "string", "value": "lowercase sha256 hex string", "action": "block|alert" }
{ "type": "path_glob", "id": "string", "value": "glob string", "action": "block|alert" }
{ "type": "comm", "id": "string", "value": "string", "action": "block|alert" }
{ "type": "parent_child", "id": "string", "parent": "string", "child": "string", "action": "block|alert" }
{ "type": "ip", "id": "string", "value": "IPv4 or IPv6 address string", "action": "block|alert" }
{ "type": "cidr", "id": "string", "value": "CIDR string", "action": "block|alert" }
{ "type": "port", "id": "string", "value": "u16", "action": "block|alert" }
{ "type": "domain", "id": "string", "value": "FQDN string", "action": "block|alert" }
```

## Backend Implementation Notes

- Event ingest must accept an array, not NDJSON, for `/api/v1/ingest/events`.
- Local file output is NDJSON: one serialized `AgentEvent` per line.
- Treat unknown `EventAction`/payload combinations defensively; the agent evolves with new eBPF and prevention actions.
- Because `EventData` is untagged, route and validate by `class` and `action`. Example mappings: `class=process, action=create` -> `ProcessCreateData`; `class=prevention` -> `PreventionEventData`; `class=detection, action=detected` -> `DetectionData`; `class=detection, action=honeytoken_access` -> `HoneytokenAccessData`.
- For command responses, return `[]` when no commands are pending.
- Do not return unsigned commands. The agent rejects commands without a valid Ed25519 signature, matching `agent_id`, unexpired window, and fresh nonce.
- Config endpoint should support `ETag` and `304 Not Modified`.
- Enrollment should never return empty `agent_id` or `agent_secret` on 2xx.
