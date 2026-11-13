# TRAPD Agent

TRAPD Agent is the endpoint sensor of the TRAPD security platform for **Linux
and Windows**. It is a single Rust binary that runs as a system service. It
collects security telemetry, ships it to the TRAPD backend, runs a few
host-only checks (honeytokens, rootkit cross-view, memory injection, ransomware
indicators, self-protection) and executes signed response commands.

**Detection rules do not run in the agent.** Since 0.7.7 the agent sends raw
telemetry in the canonical schema and the backend evaluates the rules (Sigma,
correlation, baseline). Without a backend you get telemetry and the host-only
findings, but no rule-based alerts.

> **Version:** 0.7.7 (`agent/Cargo.toml`). Per-capability status and the
> Linux/Windows matrix: [CAPABILITIES.md](CAPABILITIES.md). Known collection
> gaps: [docs/telemetry-coverage-gaps.md](docs/telemetry-coverage-gaps.md).

---

## Contents

- [At a glance](#at-a-glance)
- [What the agent does](#what-the-agent-does)
- [How it was tested](#how-it-was-tested)
- [Not done yet](#not-done-yet)
- [Data we collect](#data-we-collect)
- [Network connections](#network-connections)
- [Security model](#security-model)
- [Installation](#installation)
- [Running offline](#running-offline)
- [Configuration](#configuration)
- [Event format and backend API](#event-format-and-backend-api)
- [Diagnostics](#diagnostics)
- [Building and testing](#building-and-testing)
- [Repository layout](#repository-layout)
- [License](#license)

---

## At a glance

| | Linux | Windows |
|---|---|---|
| **Platform** | x86_64; eBPF telemetry needs kernel 5.8+, otherwise `/proc` polling | x86_64 |
| **Package** | Signed install script, Debian package | MSI (SignPath-signed in release builds) |
| **Service** | systemd unit, root, hardened, bounded capabilities | Windows service, LocalSystem |
| **Main sources** | eBPF, `/proc`, auth logs, journal, inotify, AF_PACKET | ETW, Security/System/Application event logs, registry notifications |
| **Backend connection** | TLS with pinned CA, optional mTLS | same |

Modes:

- **Online:** `TRAPD_BACKEND_URL` set. Enrollment (token or device pairing),
  telemetry upload through a durable on-disk spool, heartbeat, signed config,
  signed commands, inventory, signed self-update.
- **Offline:** `TRAPD_OFFLINE=1` or no backend URL. No network connections.
  Events go to stdout or `events.ndjson`. No commands, no updates.

---

## What the agent does

### Telemetry

| Area | Linux | Windows |
|---|---|---|
| Processes (create, exec, exit, command line, hash, parent, user) | eBPF exec/fork + `/proc` poller, process snapshot at start | ETW + poller fallback, merged with event 4688 for short-lived processes |
| Network connections | eBPF connect/bind/accept, `/proc/net`, bytes/packets/RTT via INET_DIAG | ETW, native TCP table |
| DNS | passive capture of DNS responses | ETW DNS client |
| TLS | SNI, JA3, JA3S (ClientHello/ServerHello reassembled across segments) | not collected |
| Files | inotify on watched paths, eBPF open/unlink/rename/chmod/chown, FIM hashing | file events with acting process (Kernel-File ETW), FIM hashing |
| Sensitive file reads | opens of shadow, sudoers, SSH host/root keys (kernel-side inode filter) | — |
| Logins | auth.log / secure, journald | Security event log |
| Privilege changes | setuid / capability changes (eBPF) | — |
| Registry | — | real-time notifications on persistence keys (Run, services, IFEO, …) |
| PowerShell / AMSI | — | AMSI and script-block events; script **text** only with `script_block_capture_enabled` (off by default) |
| Named pipes | — | pipe create/connect (Kernel-File ETW) |
| Drivers / kernel modules | module load (eBPF), module tree | driver load events, loaded-driver inventory |
| Containers | start/stop (cgroup watch), container ID on processes | — |
| Removable media | USB/block device attach (kernel uevents) | device attach |
| Generic logs | files, journal, syslog; parsers for sshd, sudo, auditd, nginx, apache, PostgreSQL, MySQL, Docker, JSON, CEF … | IIS/http.sys (W3C), nginx, Apache, PostgreSQL, MySQL |
| Inventory (every 6 h) | OS, hardware, packages, users, SUID files, ports, modules, CIS-style checks, CycloneDX SBOM, CVE match against a local feed file | OS, registry software, ports, drivers, `WIN-*` hardening checks |

### Host-only findings

These need direct host access and therefore stay in the agent:

- **Honeytokens:** recon profile, placement with neighbour-mimicking metadata,
  content validation, access detection (eBPF on Linux, SACL + event 4663 on
  Windows), response `none` / `alert` / `freeze` / `kill` / `isolate`.
- **Rootkit cross-view (Linux):** hidden processes, sockets, files,
  directories, mounts, logins, kernel modules; package-verified system binaries
  (`dpkg`, `rpm`). See CAPABILITIES.md §2b.
- **Memory injection scan:** Linux RWX / memfd / deleted-image mappings;
  Windows threads starting in unbacked executable memory and injected PE
  images. Optional YARA over flagged regions (`--features yara`, Linux).
- **Ransomware indicators:** entropy, mass write/rename, suspicious
  extensions, backup deletion.
- **Self-protection:** watchdog, anti-ptrace, binary self-integrity, tamper
  events for config/state/binary paths, ETW session stop, audit-policy change.

### Response (signed commands only)

`kill_pid`, `freeze_pid`, `thaw_pid`, `quarantine_file`, `restore_file`,
`isolate_network`, `deisolate_network`, `block_ip` / `unblock_ip` (optional
TTL), `update_policy`, `deploy_honeytoken`, `revoke_honeytoken`,
`install_package` / `remove_package` / `upgrade_package` (Linux only), and the
RTR commands `run_script`, `collect_file`, `list_directory`,
`collect_process_memory` (only with `rtr_enabled`).

- Process actions are bound to the process generation (PID + start time), so
  a reused PID is never hit. Core system processes are refused; on Windows,
  LSASS and protected processes are refused for memory collection.
- Linux containment uses nftables (iptables fallback); Windows uses the native
  firewall API. The backend and allowlisted addresses stay reachable.
- Quarantine: Linux moves the file, `chmod 000`, `chattr +i`; Windows moves it
  into a SYSTEM-owned protected location and restores owner and DACL.
- Automatic response to host findings is **off by default**
  (`auto_response_enabled`).
- Windows can show the logged-in user a toast when an action affects them
  (`user_response_notifications_enabled`, off by default; no process, file or
  host names in the toast).

---

## How it was tested

Only what is listed here has been tested beyond unit tests.

**CI on every pull request** (`.github/workflows/ci.yml`, `windows-package.yml`):

| Check | Runner |
|---|---|
| `cargo build`, `clippy -D warnings`, `cargo test --workspace` | Linux |
| `cargo audit` against `Cargo.lock` | Linux |
| Quarantine restore under the real service capabilities (`agent/tests/native_linux_quarantine.sh`) | Linux |
| Honeytoken inode detection and fallback with the eBPF object loaded on a real kernel (`agent/tests/native_linux_honeytokens.sh`) | Linux |
| YARA build with file and process-memory scanning | Linux |
| OCSF output validated against the pinned official schema | Linux |
| Telemetry pipeline acceptance tests (spool, retry, acknowledgement, loss accounting) | Linux |
| Debian package install in Docker, deception drop-in, release-signature verification | Linux |
| Windows cross-compile + clippy (mingw) | Linux |
| Native build, clippy and unit tests (MSVC) | Windows |
| Native firewall containment, quarantine ownership and pinned file identity, audit SACL preservation, 4663 honeytoken read detection, ETW session restart | Windows |
| MSI build, install, telemetry check, uninstall (`deploy/windows/test-msi.ps1`) | Windows |

The merge batch of 2026-11-12 (PRs #160–#175) was tested locally (Linux
tests, Windows cross-clippy) because GitHub Actions minutes were exhausted.
The merged combination on `main` has no full CI run yet.

**Manual tests on real hosts:**

| Test | Date, version | Result |
|---|---|---|
| Windows 11 field test: processes, network/DNS, files, logins, registry persistence, ransomware rename burst, honeytoken read, offline buffering and replay. Events checked in ClickHouse. | 2026-10-10, 0.7.2 | Mixed, findings F1–F14 in [docs/windows-v0.7.2-field-test.md](docs/windows-v0.7.2-field-test.md). Fixed since: double-hex `exe_sha256`, short-lived command lines (4688 merge), registry watcher, honeytoken accessor (Audit File System), alert noise. Not re-run as a full field test. |
| Windows CPU and handle measurement on the same host | 2026-10-12 | Log collector 60 % → 9 % of one core; ETW process-handle leak fixed (PRs #138–#140) |
| Atomic Red Team in a Windows 11 VM against the dev backend (T1082, T1490) | 2026-11-11, 0.7.7 | Telemetry arrives and backend rules fire. A full Atomic run after the alert-folding change is still open. |
| Channel burst measurement (synthetic, `agent/src/pipeline/burst.rs`) | 2026-11 | No drops for 2k/s process and 10k/s file storms; table in docs/telemetry-coverage-gaps.md §E |

**Not tested on a real host yet:** the Linux agent end-to-end against the
backend after 0.7.7, the MSI audit-baseline path outside CI, Windows CPU cost
after the 0.7.7 changes, distributions other than Debian/Ubuntu.

---

## Not done yet

| Item | Platform |
|---|---|
| BPF-LSM enforcement (block exec/ptrace/mmap before it happens); today exec blocking is a kill after exec | Linux |
| Kernel-side exec blocking of any kind (needs a driver) | Windows |
| Memory-injection prevention (detection only today) | both |
| Rootkit cross-view detection | Windows (not planned) |
| LSASS handle-access telemetry without Sysmon | Windows |
| TLS SNI/JA3 and network byte/RTT depth | Windows |
| DNS client/server address and transaction ID (ETW does not provide them) | Windows |
| Package install/remove/upgrade commands | Windows |
| Live `dlopen` events | Linux |
| mTLS certificate rotation | both |
| Prometheus/OpenTelemetry metric export (JSON report only) | both |
| SIEM sinks beyond syslog and Splunk HEC (Kafka, Elastic, OTEL) | both |
| Threat-intel store (STIX/TAXII, live CVE feed); today a local feed file | both |
| Multi-day soak test in CI | both |

Backend-side gaps caused by moving detection out of the agent (cadence
beaconing, per-domain DNS tunnelling, setuid chains, IOC store) are listed in
[docs/telemetry-coverage-gaps.md](docs/telemetry-coverage-gaps.md) §A.

---

## Data we collect

Nothing leaves the host in offline mode. Online, the categories below go to
the configured backend. Retention is set by the backend operator.

| Category | Contents | Notes |
|---|---|---|
| Processes | PID, parent, executable path, command line, user, working dir, SHA-256, container ID, allowlisted environment variables | Command lines are truncated at a fixed length and marked. Secret-looking environment values become `***redacted***`. |
| Network | addresses, ports, protocol, owning process, counters | no payloads |
| DNS | queried name, type, answers | **Domain names are collected.** DoH/DoT is not visible. |
| TLS (Linux) | SNI, version, JA3/JA3S | no certificate contents, no payloads |
| Logins and logs | usernames, source IPs, log message text | **Log lines can contain personal data.** Limit sources with `logs`. |
| Files | paths and hashes | Contents are never sent. The ransomware check reads up to 8 MiB locally for entropy and sends only the value. |
| PowerShell script text (Windows) | script blocks | only with `script_block_capture_enabled` (off); can contain credentials |
| Devices | vendor, product | serial numbers only with `device_serial_capture_enabled` (off) |
| Inventory | OS, hardware incl. serial and machine ID, packages, users, ports, modules/drivers, posture results | serial and machine ID are persistent identifiers |
| Heartbeat (30 s) | hostname, version, uptime, CPU/memory/disk, pipeline counters, sensor coverage | |
| RTR artifacts | files, listings, script output, process memory | only on a signed command and with `rtr_enabled`; size-capped |

The agent has no keylogger, screen, clipboard, camera or microphone access,
records no packet payloads and sends no memory bytes except through an
explicit RTR memory collection.

---

## Network connections

| Destination | When | Controlled by |
|---|---|---|
| TRAPD backend (`TRAPD_BACKEND_URL`) | enrollment/pairing, then continuously | operator |
| GitHub release URLs | update checks and downloads | block in the firewall to disable updates |
| SIEM (syslog UDP/Unix socket, Splunk HEC) | only with `siem_enabled` | operator, off by default |
| System DNS resolver | name resolution | host configuration |

The code contains no telemetry, analytics or crash-reporting endpoints. The
agent opens no listening socket unless a syslog log source is configured
(never `:514` or `/dev/log` by default).

---

## Security model

- **TLS fail-closed:** the backend certificate must chain to `<config>/ca.crt`.
  The system trust store is used only with `TRAPD_TLS_ALLOW_SYSTEM_ROOTS=1`.
  mTLS with `agent.crt` / `agent.key` is supported.
- **Commands:** Ed25519 signature from `command_signing.pub`, bound to this
  agent, inside the expiry window, nonce not seen before (persisted; a lost
  nonce store fails closed).
- **Configuration:** signed the same way, monotonic `issued_at`, no rollback
  across restarts; the last verified config is kept on rejection.
- **Updates:** signed release statements, downloads only from this project's
  release URLs, atomic replace, rollback if the new version does not report
  healthy, on Linux and Windows.
- **Linux unit hardening:** `ProtectSystem=strict`, `ProtectHome=read-only`,
  `NoNewPrivileges`, `MemoryDenyWriteExecute`, syscall filter, capability
  bounding set (`CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_BPF`, `CAP_PERFMON`,
  `CAP_NET_RAW`, `CAP_IPC_LOCK`, `CAP_LINUX_IMMUTABLE`, `CAP_DAC_READ_SEARCH`,
  `CAP_KILL`). Runs as root because eBPF and process control need it.

---

## Installation

**Linux:** [deploy/README-linux-install.md](deploy/README-linux-install.md)
(install script, independently provisioned release key) or
[deploy/README-deb.md](deploy/README-deb.md). The installer needs Python 3.9+
and OpenSSL 3+ for signature checks; there is no checksum-only fallback.

```sh
less install.sh
sudo TRAPD_RELEASE_PUBKEY_B64='<independently obtained key>' bash install.sh
sudo systemctl status trapd-agent
```

**Windows:** [deploy/README-windows.md](deploy/README-windows.md). The MSI
enables "Audit Process Creation", command lines in event 4688 and "Audit File
System" (needed for honeytoken reads). `AUDITBASELINE=0` opts out; uninstall
reverts only what the MSI enabled.

**Enrollment:** set `TRAPD_ENROLL_TOKEN`, or leave it empty to start device
pairing (a short code is confirmed in the TRAPD web UI).

**Removal:** revoke honeytokens from the backend first; planted decoys stay on
disk until revoked.

---

## Running offline

To see what the agent collects without a backend:

```sh
cargo build --release --manifest-path agent/Cargo.toml
mkdir -p t/{state,cfg,log}
sudo TRAPD_OFFLINE=1 TRAPD_STATE_DIR=$PWD/t/state TRAPD_CONFIG_DIR=$PWD/t/cfg \
  TRAPD_LOG_DIR=$PWD/t/log TRAPD_OUTPUT=file RUST_LOG=info \
  ./target/release/trapd-agent
tail -f t/log/events.ndjson
```

Without root, eBPF, packet capture and parts of `/proc` are unavailable; the
agent logs which collectors did not start and keeps running.

---

## Configuration

### Environment (`/etc/trapd/agent.env`)

| Variable | Default | Purpose |
|---|---|---|
| `TRAPD_BACKEND_URL` | unset (offline) | backend base URL |
| `TRAPD_ENROLL_TOKEN` | unset | one-time token; unset starts pairing |
| `TRAPD_OFFLINE` | unset | `1` forces offline |
| `TRAPD_OUTPUT` | `stdout` on a terminal, else `off` (Windows service: `file`) | local mirror: `file`, `stdout`, `off` |
| `TRAPD_STATE_DIR`, `TRAPD_CONFIG_DIR`, `TRAPD_LOG_DIR` | `/var/lib/trapd`, `/etc/trapd`, `/var/log/trapd` | directories |
| `TRAPD_SPOOL_MAX`, `TRAPD_SPOOL_MAX_BYTES` | 50 000 events, 1 GiB | spool limits; evictions are counted |
| `TRAPD_TLS_ALLOW_SYSTEM_ROOTS` | off | not recommended |
| `TRAPD_EXEC_HASH` | on | `off` disables executable hashing |
| `TRAPD_ROOTKIT*` | on | rootkit sweep knobs, CAPABILITIES.md §2b |
| `RUST_LOG` | `info` | log level |

### Signed backend configuration (selected)

| Setting | Default |
|---|---|
| `prevention_enabled` | `true` |
| `auto_response_enabled` / `_action` / `_min_severity` / `_min_confidence` | `false` / `alert` / `critical` / `90` |
| `rtr_enabled` / `rtr_max_artifact_bytes` | `false` / `32768` |
| `honeytoken_detection_enabled` / `honeytoken_response` | `true` / `alert` |
| `memory_scan_enabled`, `fim_enabled`, `inventory_enabled`, `logs_enabled` | `true` |
| `sensitive_file_read_enabled` (Linux) | `true` |
| `etw_enabled` (Windows) | `true` |
| `script_block_capture_enabled` (Windows) | `false` |
| `user_response_notifications_enabled` (Windows) | `false` |
| `device_serial_capture_enabled` | `false` |
| `siem_enabled` / `siem_format` | `false` / `cef` |
| `vuln_scan_enabled` / `cis_benchmark_enabled` | `true` / `true` |

`sigma_enabled`, `sigma_rules` and `anomaly_detection_enabled` are still
accepted so existing signed configs stay valid, but they have no effect in the
agent. The full schema is in [AGENTS.md](AGENTS.md).

---

## Event format and backend API

Local output is OCSF 1.9.0. Upload starts in the legacy format and switches to
OCSF when the gateway advertises `x-trapd-event-formats: legacy,ocsf-1.9.0`.
`event_id` is assigned once; delivery is at-least-once, so the backend
deduplicates on `event_id`. Mapping: [docs/ocsf-validation.md](docs/ocsf-validation.md).

| Endpoint | Purpose |
|---|---|
| `POST /api/v1/agents/enroll`, `/pair/start`, `/pair/poll` | enrollment, pairing |
| `POST /api/v1/ingest/events` | event batches (≤ 100 events / 4 MiB) |
| `POST /api/v1/agents/{id}/heartbeat` | every 30 s |
| `GET /api/v1/agents/{id}/config` | signed config, every 60 s, `ETag` |
| `GET /api/v1/agents/{id}/commands?wait=25` | signed commands, long poll |
| `POST /api/v1/agents/{id}/inventory` | 15 s after start, then every 6 h |
| `GET /api/v1/agents/{id}/update` | signed update offer, hourly |

Ingest retries on 5xx, 408, 425, 429 and network errors; other 4xx drop the
batch and count it as `backend_rejected`. Details: [AGENTS.md](AGENTS.md).

---

## Diagnostics

```sh
trapd-agent --version
trapd-agent diagnostics telemetry   # collector mode, drops by reason, queue, latency
trapd-agent diagnostics rootkit     # size of each cross-view, current findings (Linux)
```

---

## Building and testing

```sh
cargo build --release --manifest-path agent/Cargo.toml
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# optional YARA (vendored libyara, needs a C compiler)
cargo build --release --manifest-path agent/Cargo.toml --features yara

# eBPF object (pinned nightly, separate crate)
cargo binstall bpf-linker
cargo xtask build-ebpf --release

# load profiles and burst measurement (ignored by default)
cargo test --release --test telemetry_load -- --ignored --nocapture
cargo test --release -p trapd-agent --bin trapd-agent burst_measurement_table -- --ignored --nocapture
```

Windows: `cargo build --release --target x86_64-pc-windows-msvc --manifest-path agent/Cargo.toml`,
MSI with `deploy/windows/build-msi.ps1`.

---

## Repository layout

```
agent/src/          trapd-agent binary
  collectors/       linux/, windows/, shared log and registry collectors
  prevention/       signed commands, kill/freeze, quarantine, firewall, RTR
  deception/        honeytoken profiling, placement, validation
  rootkit/          Linux cross-view checks
  selfprotect/      watchdog, anti-ptrace, integrity
  telemetry/        loss accounting, health, coverage
  transport/ http/ enrollment/ heartbeat/ config/ inventory/ update/ output/
crates/
  trapd-schema/     event types, provenance, truncation
  trapd-detection/  sensor-side policy only (honeytokens, fs heuristics, YARA)
trapd-agent-ebpf/   kernel-side eBPF programs
deploy/             installers, systemd units, deb, Windows MSI
docs/               coverage, validation and field-test documents
```

| Document | Contents |
|---|---|
| [CAPABILITIES.md](CAPABILITIES.md) | status per capability, platform matrix |
| [AGENTS.md](AGENTS.md) | API and schema reference |
| [docs/telemetry-coverage-gaps.md](docs/telemetry-coverage-gaps.md) | what is not collected, burst measurement |
| [docs/windows-v0.7.2-field-test.md](docs/windows-v0.7.2-field-test.md) | Windows field test |

---

## License

Apache License 2.0, see [LICENSE](LICENSE).
