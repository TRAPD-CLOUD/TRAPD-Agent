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
- `agent/src/deception/`: honeytoken deception subsystem — `profiler.rs` (deterministic recon profile / token candidates), `registry.rs` (deployed-token register at `<state>/honeytokens.json`, incl. out-of-band canary records), `validate.rs` (bait-content + out-of-band-canary validation and anti-fingerprinting guards), `mod.rs` (camouflaged deploy + safe revoke). Step 1 places and manages tokens; the on-host detection path lives in `detection/honeytoken.rs`.
- `agent/src/forensics/`: response forensics (issue #32, point 5) — `session.rs` (login/TTY/container/namespace/cgroup context from `/proc`), `snapshot.rs` (point-in-time process capture for the freeze response), `recorder.rs` (bounded flight recorder of recent pid-bearing telemetry + remote-IP correlation).
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

- State dir: default `/var/lib/trapd`, override `TRAPD_STATE_DIR`; contains `device_id`, `credentials.json`, nonces (`command_nonces.json`), `config_issued_at.json` (signed-config `issued_at` high-water mark, `0600`), baselines, `honeytokens.json` (deployed-honeytoken register, `0600`).
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
- Success responses: `200` with a `SignedConfig` (signed `AgentConfig`), or `304`.
- Response `ETag` is cached by the agent **only after the body verifies**, so a
  transiently bad/unsigned config can't latch the agent into `304`s.
- Poll cadence: every 60 seconds.
- The agent now **requires** the body to be a signed `SignedConfig` envelope —
  a bare `AgentConfig` is rejected and the last-known-good config is kept. The
  backend MUST emit `SignedConfig`. See *Backend Implementation Notes* →
  "Signed config delivery".

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

Known `kind` values include `process_block`, `network_isolate`, `network_deisolate`, `ip_block`, `ip_unblock`, `quarantine`, `restore`, `policy_update`, `command_rejected`, `command_accepted`, `honeytoken_deploy`, `honeytoken_revoke`, `honeytoken_response`, `process_freeze`, `process_thaw`, `deception_escalation`.

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
  "accessor": "ProcessLineage",
  "session": "SessionContext, optional (issue #32 point 5)"
}
```

### `SessionContext` (issue #32, point 5)

Captured from `/proc` at detection time and attached to `HoneytokenAccessData`
(and echoed, with the remote IP correlated, into the `honeytoken_response`
event). Binds the access to *who* and *where*: the login session, controlling
terminal, the originating remote IP, and the container/namespace/cgroup. All
fields are optional and omitted when unresolved.

```json
{
  "loginuid": "u32, optional",
  "login_user": "string, optional (resolved from loginuid)",
  "audit_session_id": "u32, optional",
  "tty": "string, optional (e.g. pts/3)",
  "cwd": "string, optional",
  "cgroup": "string, optional (most specific cgroup path)",
  "container_id": "string, optional (parsed from cgroup)",
  "container_runtime": "string, optional (docker|containerd|cri-o|podman|kubepods)",
  "namespaces": { "pid": "u64?", "net": "u64?", "mnt": "u64?", "user": "u64?", "cgroup": "u64?", "ipc": "u64?", "uts": "u64?" },
  "remote_addr": "string, optional (correlated from auth.log logons)",
  "remote_port": "u16, optional"
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
policy-driven reaction (`alert`/`freeze`/`kill`/`isolate`) taken for each access,
and its `details` bundle the point-5 forensics: `frozen`, the `snapshot`
(process state / exe / cwd / cmdline / open files when frozen), the correlated
`session`, the `flight_recorder` pre-history (recent pid-bearing telemetry for
the accessor + its ancestry), and `escalation_triggered`. The `freeze` level
sends SIGSTOP and snapshots instead of killing — "freeze, snapshot, then
decide"; an operator then issues `freeze_pid`/`thaw_pid`/`kill_pid`.

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
  strings with plausible internal hostnames).
- **Out-of-band canary (issue #32, point 2):** where the artefact supports it,
  mint a *second-channel* canary on monitored honeypot infra and pass it back in
  the `deploy_honeytoken` command's `out_of_band` block (a fake AWS key whose use
  trips CloudTrail; a Canarytokens-style tracking DNS/HTTP domain; a kube-config
  or SSH key aimed at honeypot infra). The agent validates and registers it; the
  backend ingests the resulting deploy `details` (channel + `tracking_id` +
  `markers` + host) so an inbound foreign signal can be attributed to the token,
  host and attacker — a detection path fully independent of the on-host eBPF gate.
- **Placement ranking:** decide which candidates to deploy first. Start with
  the deterministic `score` the agent already computed; a trained model
  replaces it in step 2 once hit/miss telemetry exists.
- Issue chosen candidates back as signed `deploy_honeytoken` commands.

## Deception Step 2: Access Detection, Response & ML Feedback Loop

### On-agent detection (eBPF + userspace)

- eBPF (`trapd-agent-ebpf/src/file_open.rs`): two new maps ride the existing
  `sys_enter_openat` program — `HONEYTOKEN_PATHS` (absolute path, NUL-padded to
  256 bytes → token id) and the dedicated `HONEYTOKEN_ACCESS_EVENTS` ring
  buffer. On an open whose path is in the table the program emits an access
  event **regardless of open flags** (the read-only detection fix), while the
  general read-only suppression on `FILE_OPEN_EVENTS` is unchanged.
- **Design note (path-gate + userspace inode verification):** matching is by
  exact path in the kernel rather than by inode. The codebase deliberately
  avoids dereferencing kernel structs in BPF (CO-RE is fragile across kernels —
  see `process_block.rs`), and `sys_enter_openat` exposes only the user path
  pointer. The userspace consumer re-verifies identity against the token's
  recorded device+inode, so the authoritative check is inode-based even though
  the cheap in-kernel gate is path-based. A future hardening is a BTF/CO-RE
  inode read to also catch relative-path / symlink opens at the kernel layer.
- Userspace (`agent/src/collectors/linux/ebpf_syscalls.rs` +
  `agent/src/detection/honeytoken.rs`): a reconciler arms `HONEYTOKEN_PATHS`
  from the on-disk register (`<state>/honeytokens.json`) every 15s; a consumer
  enriches each hit with full `/proc` lineage, applies the false-positive
  allowlist + agent self-exclusion, and emits a `HoneytokenAccess` detection.
- The prevention engine reacts per `honeytoken_response` policy
  (`alert`/`freeze`/`kill`/`isolate`) and audits the decision as a
  `honeytoken_response` prevention event. Beyond alert/kill/isolate (issue #32,
  point 5): `freeze` suspends the accessor (SIGSTOP) and captures a forensic
  `snapshot` instead of killing; every response bundles the accessor's
  `session` context and the `flight_recorder` pre-history; and when
  `honeytoken_deception_escalation` is enabled the hit also emits a
  `deception_escalation` signal for the backend to deploy more bait / redirect
  into a honeypot / tarpit. Operators drive the post-freeze decision with the
  signed `freeze_pid` / `thaw_pid` / `kill_pid` commands.

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
  "honeytoken_response": "string, default \"alert\" (none|alert|freeze|kill|isolate)",
  "honeytoken_accessor_allowlist": ["string (extra benign accessor comms)"],
  "honeytoken_deception_escalation": "bool, default false"
}
```

`honeytoken_response` escalates: `none` (detection only, no engine action) <
`alert` (critical prevention event) < `freeze` (alias `jail`: SIGSTOP the
accessor and snapshot it — "freeze, snapshot, then decide") < `kill` (SIGKILL
the accessor) < `isolate` (also full host network isolation).
`honeytoken_accessor_allowlist` extends the built-in sweeper allowlist
(mlocate/updatedb, AV scanners, backup tools, and the agent itself) used to
suppress false positives. `honeytoken_deception_escalation` (default `false`)
opts in to emitting a `deception_escalation` signal on each confirmed hit.

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
{ "kind": "freeze_pid", "pid": "i32" }
{ "kind": "thaw_pid", "pid": "i32" }
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
{ "kind": "deploy_honeytoken", "path": "string", "content_b64": "base64 string", "mode": "u32 octal, optional, default 0", "mimic_neighbor": "bool, optional, default false", "canary_marker": "string, optional", "out_of_band": { "channel": "aws_cloudtrail|dns|http|kube_api|ssh_honeypot", "tracking_id": "string", "markers": ["string"] }, "token_kind": "string, optional", "breadcrumbs": [ { "path": "string", "content_b64": "base64 string", "mode": "u32 octal, optional", "append": "bool, optional" } ] }
{ "kind": "revoke_honeytoken", "path": "string" }
{ "kind": "freeze_pid", "pid": "i32" }
{ "kind": "thaw_pid", "pid": "i32" }
```

#### `freeze_pid` / `thaw_pid` semantics (issue #32, point 5)

- `freeze_pid` sends **SIGSTOP** to suspend a process without killing it, then
  captures and audits a forensic `snapshot` (state, exe, cwd, cmdline, open
  files) while it is frozen and cannot react — the operator-driven half of
  "freeze, snapshot, then decide". Resume with `thaw_pid` (SIGCONT) or terminate
  with `kill_pid`. Both are best-effort: a process that already exited audits
  `success=false` rather than erroring.

#### `deploy_honeytoken` / `revoke_honeytoken` semantics

- `content_b64` is base64 of the **fully-formed** bait content the backend
  generated (the LLM content-generation job). The agent never generates
  content and no LLM runs on the endpoint.
- `mode` is an octal file mode encoded as an integer (e.g. `384` = `0o600`).
  `0` means "adopt the mimicked neighbour's mode"; if there is no neighbour the
  agent falls back to `0o600`.
- `mimic_neighbor=true` makes the agent copy owner/group and atime/mtime from a
  sibling file in the same directory so the token blends in.
- `canary_marker` is the legacy single-string out-of-band tracking marker
  embedded in `content_b64` by the backend (e.g. a fake AWS key id tied to a
  monitored honeypot account, or a tracking domain). It is recorded locally for
  correlation; the agent does not parse it back out of the content.
- `out_of_band` is the **structured** out-of-band canary (issue #32, point 2):
  the *second, independent* signal channel that fires when the bait is **used**
  off-host, on infrastructure the agent does not control. `channel` is one of
  `aws_cloudtrail` (fake AWS key → CloudTrail alarm), `dns`/`http`
  (Canarytokens-style tracking domain / web-bug URL), `kube_api` (kube-config to
  a honeypot API server) or `ssh_honeypot` (SSH key whose use logs a login).
  `tracking_id` is the backend-assigned correlation key echoed back in the
  foreign signal; `markers` are the *attacker-facing* identifiers embedded in the
  bait (the fake key id, tracking FQDN/URL, key fingerprint, endpoint). The agent
  **validates** the descriptor before placement (known channel; non-empty
  `tracking_id`; ≥1 marker; channel↔marker shape; no shared TRAPD watermark) and
  refuses to share any marker across tokens. It does **not** observe the channel
  itself — it publishes the registration (see audit `details` below) so the
  backend can correlate an inbound foreign signal back to this token and host
  (Token ↔ Host ↔ attacker). Backend ingestion of the foreign signal lives in
  the backend repo.
- `token_kind` is the recon candidate family echoed back (`ssh_private_key`,
  `aws_credentials`, …); recorded in the register for attribution.
- `breadcrumbs` are cross-linking artefacts placed alongside the token to make
  it discoverable (issue #32, point 3); `append:true` safely appends to an
  existing file (e.g. shell history) without truncation.
- Safety invariants enforced on the agent: the target path must be **absolute**
  with no `..` component; the agent **refuses to overwrite** an existing file
  (so real user data is never clobbered); `revoke_honeytoken` only removes a
  path that is present in the local register (`<state>/honeytokens.json`), so a
  command can never make the agent delete a file it did not plant.
- Outcomes are reported as `class=prevention` audit events with
  `action=honeytoken_deployed` / `honeytoken_revoked` and `kind`
  `honeytoken_deploy` / `honeytoken_revoke`. The audit `details` carry only
  safe metadata (id, kind, mode, size, sha256, mimic info, `has_canary`,
  breadcrumb count) — never the bait content itself. When the token has an
  `out_of_band` canary, the deploy `details` also carry an `out_of_band` block
  (`channel`, `tracking_id`, `markers`) — this is the agent's **registration** of
  the second channel, and together with the event's `agent_id`/`hostname` it is
  the Token ↔ Host ↔ marker correlation key the backend ingests to attribute a
  foreign signal. The revoke `details` echo `out_of_band.tracking_id` so the
  backend can retire that registration. Markers are the fake attacker-facing
  identifiers, never the bait content, so they are safe to publish.

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
- Because `EventData` is untagged, route and validate by `class` and `action`. Example mappings: `class=process, action=create` -> `ProcessCreateData`; `class=prevention` -> `PreventionEventData` (incl. `action=process_frozen`/`process_thawed`/`deception_escalation`); `class=detection, action=detected` -> `DetectionData`; `class=detection, action=honeytoken_access` -> `HoneytokenAccessData` (carries the optional `session` forensics).
- For command responses, return `[]` when no commands are pending.
- Do not return unsigned commands. The agent rejects commands without a valid Ed25519 signature, matching `agent_id`, unexpired window, and fresh nonce.
- Config endpoint should support `ETag` and `304 Not Modified`.
- Enrollment should never return empty `agent_id` or `agent_secret` on 2xx.

### Signed config delivery

`GET /api/v1/agents/{agent_id}/config` returns a **signed** config envelope
instead of a bare `AgentConfig`, closing the gap that an attacker able to
impersonate the control plane (e.g. via a TLS-stripping proxy or a compromised
intermediate) could push a permissive config to weaken the agent. The
**agent already enforces this** (`agent/src/config/mod.rs`: `ConfigVerifier`);
the backend MUST emit `SignedConfig`. Two requirements:

1. **Sign the envelope with the command-signing key.** The backend wraps the
   config in a `SignedConfig` and signs it with the **same** operator-held
   Ed25519 key the agent already pins for commands — the raw 32-byte public
   key at `<config>/command_signing.pub`. No new key material is introduced.
   The agent verifies the signature exactly as it does for `SignedCommand`
   (re-serialise the deserialised envelope with `serde_json::to_vec` to the
   canonical byte sequence and `verify_strict` against the pinned key) and
   **rejects an unsigned or badly-signed config**, keeping its last-known-good
   config. If no signing key is provisioned the agent ignores config updates
   entirely (fail-closed).
2. **`issued_at` must increase monotonically.** Each issued envelope carries
   an `issued_at` that is strictly greater than the previous one for that
   agent. The agent persists the highest `issued_at` it has accepted (in
   `<state>/config_issued_at.json`) and refuses any envelope whose `issued_at`
   is not greater, which defeats replay and rollback (re-serving a stale,
   more-permissive config) — even across restarts. This is the config-channel
   analogue of the command nonce store.

The `ETag` / `304 Not Modified` flow is unchanged, except the agent caches the
returned `ETag` **only after the body verifies**, so a bad/unsigned response
cannot latch it into `304`s and block a later good update.

This is independent of, and must not be conflated with, **#30**
(release-artifact / `install.sh` supply-chain signing): #30 anchors trust in
the *binary* shipped to a host, whereas this note anchors trust in the
*runtime configuration* delivered to an already-running agent. They use
different trust roots and protect different stages.

#### `SignedConfig`

Mirrors `SignedCommand`:

```json
{
  "envelope": "ConfigEnvelope",
  "signature": "base64 string; 64-byte Ed25519 signature over canonical_json(envelope)"
}
```

#### `ConfigEnvelope`

Field order is significant — the canonical signing bytes are
`serde_json::to_vec` of this struct in declaration order:

```json
{
  "issued_at": "RFC3339 UTC datetime (strictly increasing per agent)",
  "agent_id": "string (must match this agent)",
  "config": "AgentConfig"
}
```
