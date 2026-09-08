# TRAPD-Agent — Capabilities & Roadmap

**Single source of truth** for what the Linux TRAPD agent does today and what is
still planned. Supersedes the former `FALCON_READINESS_TODOS.md` and
`TELEMETRY_DEPTH.md`. For build/run/API-contract details see `AGENTS.md`; for a
project overview see `README.md`.

Legend: ✅ implemented · 🟡 partial · ⏳ planned · 🧪 feature-gated/kernel-bound

---

## 1. Kernel & userspace telemetry (eBPF)

The agent ships **18 eBPF programs**, all ring-buffer based and consumed by the
userspace collectors (`agent/src/collectors/linux/ebpf_*.rs`), with a per-program
drop counter exported as `EbpfDrops` events:

| Domain | Programs | Status |
|--------|----------|--------|
| Process | `exec`, `fork`, `setuid` | ✅ |
| File | `file_open`, `file_manip` (unlink/rename/chmod/chown), `write` (rate anomaly) | ✅ |
| Memory | `mmap`, `memfd`, `ptrace`, `shm` | ✅ |
| Network | `network` (connect/bind/accept), `dns` | ✅ |
| Kernel/NS | `module_load`, `namespace` | ✅ |
| Response | `process_block` (`bpf_send_signal`), `dropcount` | ✅ / 🟡 |

Userspace enrichment: image SHA-256 per exec (cached), loaded-library inventory,
curated env + interpreter-script decode, container/K8s context, DNS responses
(AF_PACKET), netflow depth (INET_DIAG: bytes/packets/RTT), TLS SNI/JA3.

**Planned:** ⏳ live `dlopen`/`.so`-mmap events · ⏳ CRI/containerd lifecycle
stream · ⏳ JA3S + multi-segment ClientHello reassembly · ⏳ `BPF_MAP_TYPE_RINGBUF`
already used; XDP/TC packet-level visibility.

---

## 2. Detection engine (`agent/src/detection/`)

Platform-neutral analytics over every event; findings are first-class events fed
back through the pipeline (persist + backend + auto-response).

| Capability | Status | Notes |
|------------|--------|-------|
| ATT&CK-mapped behavioural heuristics | ✅ | reverse shell, LOLBin, fileless, creds, persistence, GTFOBins, LD_PRELOAD |
| Stateful IOA attack-chain correlation | ✅ | process-tree lineage + sliding-window chains |
| IOC matching (hash / IP / domain) | ✅ | hot-reloaded `<config>/iocs.json` |
| Beaconing / DNS-tunnel / port-scan / lateral / IMDS | ✅ | cadence + windowed analytics |
| Ransomware behaviour | ✅ | Shannon entropy + write-rate anomaly (`filesystem.rs`, eBPF `write`) |
| Privilege escalation (`setuid(0)`) | ✅ | direct + IOA chain |
| **Sigma rule engine** | ✅ **NEW** | `detection/sigma/` — Sigma YAML → in-process rules; logsource gating, field modifiers (`contains`/`startswith`/`endswith`/`re`/`cased`/`all`), value lists, keyword search, full condition grammar (`and`/`or`/`not`, `N of`, `all of them`, wildcards). Loaded from `<config>/sigma/*.yml` **and** inline over the signed config channel. |
| **Statistical anomaly baseline** | ✅ **NEW** | `detection/baseline.rs` — per-user binary novelty + EWMA exec-rate z-score (Poisson std floor), online-learning, bounded, runtime-gated. |
| Honeytoken access detection | ✅ | full deploy/detect/respond lifecycle |
| YARA scanning | 🧪 | `--features yara`; **file** scanning today. ⏳ process-memory scanning (memscan bytes already available). |
| Threat-intel feeds | 🟡 | JSON IOC feed + CVE feed file. ⏳ STIX/TAXII consumer · ⏳ SQLite IOC store with auto-sync · ⏳ IP/domain reputation lookup. |

---

## 2b. Rootkit & manipulation detection (`agent/src/rootkit/`) — ✅ NEW

Not a signature scanner. Every detector reads the **same fact through
interfaces a rootkit has to hook separately**, and reports the disagreement.
Hiding from one interface is easy; staying consistent across all of them is
the hard part, and that is what is measured.

| Detector | Views compared | Rule ids |
|---|---|---|
| Hidden processes | `/proc` listing · direct `/proc/<pid>` · `kill(pid,0)` liveness · eBPF exec/fork PIDs | `rootkit.process_hidden_from_listing`, `rootkit.process_hidden_from_procfs` |
| Hidden sockets | `/proc/net/{tcp,tcp6,udp,udp6}` · `sock_diag` netlink · eBPF bind sightings | `rootkit.socket_hidden_from_procfs`, `rootkit.listener_hidden_from_host_views` |
| Kernel modules | `/proc/modules` · `/sys/module` · eBPF `module_load` · `/lib/modules/<release>` | `rootkit.module_hidden_from_proc_modules`, `rootkit.module_hidden_after_load`, `rootkit.module_not_in_module_tree`, `rootkit.module_unsigned`, `rootkit.module_unloaded`, `rootkit.known_rootkit_module`, `rootkit.module_file_changed`, `rootkit.module_tree_bulk_change` |
| Hidden files & directories | libc `readdir` · raw `getdents64` · directory `st_nlink` · names from eBPF writes/unlinks/renames, `/proc/<pid>/fd` and `/proc/<pid>/maps` | `rootkit.file_hidden_from_listing`, `rootkit.dir_entry_hidden_from_libc`, `rootkit.subdirectory_hidden_from_listing`, `rootkit.file_listing_inconsistent` |
| Hidden mounts | `/proc/mounts` · `/proc/self/mountinfo` · `/proc/self/mountstats` | `rootkit.mount_hidden_from_interface`, `rootkit.file_shadowed_by_mount` |
| Unrecorded logins | `/var/run/utmp` · login sessions reconstructed from `/proc` | `rootkit.login_session_hidden_from_utmp` |
| System binaries | on-disk digest · the digest the distribution's package database records | `rootkit.system_binary_tampered`, `rootkit.system_binary_changed`, `rootkit.system_binary_shadowed`, `rootkit.system_binaries_bulk_change`, `rootkit.ld_preload_configured` |

Findings are ordinary `class=detection` / `action=detected` events with
`category: "rootkit"`, so auto-response, SIEM forwarding and the backend
pipeline apply unchanged.

**Nothing is hardcoded to a distribution.** Which binaries are watched is
derived from the host: a set of tool *names* per role (process visibility,
network visibility, module management, authentication, …) resolved through the
host's own `PATH`, plus every setuid/setgid executable discovered in those
directories at runtime. What they should contain comes from the host's own
package database (`dpkg` md5sums, `rpm --verify`) — the only source that can
tell an upgrade from tampering, because after an upgrade the file changed *and*
still matches its package.

**Hiding a file is the most common thing a rootkit does,** and it is done by
filtering directory reads. The file itself is untouched, so three separate
invariants still hold and each catches a different layer of the lie:

* **Directory link count.** `st_nlink` on a directory is `2` plus one per
  subdirectory, maintained by the filesystem as an inode field rather than by
  the code that answers directory reads. A deficit against the listed
  subdirectories finds a hidden *directory* with **no candidate name at all**,
  which is the only check that can find something nobody has touched. Run only
  on ext2/3/4, XFS and tmpfs; btrfs reports `1` for every directory and
  overlayfs does not maintain it, so there it is skipped rather than left to
  fire constantly.
* **libc `readdir` vs. raw `getdents64`.** The same directory, enumerated
  through deliberately different code. A name the syscall returns and libc does
  not localises the compromise to userspace — an `/etc/ld.so.preload` rootkit
  can only interpose the library call.
* **A known name vs. its parent's listing.** `lstat` answers directly and never
  consults the listing, so a file that stats but is absent from its directory
  is hidden. The difficulty is *getting* the name, since a filtered listing
  will not supply it; the names come from eBPF-observed writes, creates,
  unlinks and renames (below anything userspace can hook), from the targets of
  every open descriptor in `/proc/<pid>/fd` (rootkits keep their files open)
  and from file-backed regions in `/proc/<pid>/maps` (a preloaded library is
  mapped even when it is not open).

Overlayfs is treated as comparable for *listings* while being excluded from the
link-count check: it is what a container's root filesystem usually is, so
excluding it outright would disable the detector exactly where containers run.

**False positives are the design constraint,** since the value of a rootkit
alert is that it is worth waking someone for:

| Mechanism | Example |
|---|---|
| Benign-explanation filters | threads are absent from the `/proc` listing by design (`Tgid` check); built-in modules have no `/proc/modules` entry (`initstate` check); dual-stack sockets render identically in both views |
| Corroboration | a standing disagreement must survive consecutive sweeps; transition findings (unload, digest change) report immediately because they exist in exactly one sweep |
| Bulk collapse | a kernel package update or system upgrade becomes one `Low` finding instead of hundreds of `Critical` ones |
| Namespace guard | the eBPF cross-view is dropped when the agent is not in the initial PID namespace, where host PIDs cannot be compared against a namespaced `/proc` |
| Bracketed reads | a candidate file is `lstat`-ed before *and* after its directory listing and must show the same inode both times, so a file created or deleted around the read cannot look concealed |
| Filesystem eligibility | the synthetic trees (`/proc`, `/sys`, cgroup, …) and the filesystems answered by something other than local disk (FUSE, NFS, CIFS) are excluded from listing comparisons they cannot answer |
| Named exclusions | the file-level mounts every container runtime creates (`/etc/hosts`, `/etc/resolv.conf`, projected secrets) are excluded by name; a login session must descend from `sshd`/`login`/`getty`, which is what keeps `tmux` panes and `docker exec` out |

| Capability | Status | Notes |
|------------|--------|-------|
| Hidden-process cross-view | ✅ | four views; works without eBPF (three of them need no kernel programs) |
| Hidden-socket cross-view | ✅ | `sock_diag` dump extended to return socket identity, not just counters |
| Kernel module monitoring | ✅ | load is already real-time via eBPF, so this covers unload, concealment, provenance and the module tree |
| Package-verified binary integrity | ✅ | `dpkg` + `rpm`; falls back to a self-recorded digest baseline, which reports *change* but cannot prove *wrongness* |
| Hidden file & directory cross-view | ✅ | three checks; the link-count one needs no candidate name, so it finds a directory nobody has touched |
| Hidden mount cross-view | ✅ | three renderings of one kernel mount table, plus file-level mounts that shadow a system file while leaving its inode intact |
| Unrecorded login cross-view | ✅ | utmp is a writable file, so sessions are rebuilt from `/proc`; skipped where utmp records nothing, as in a container |
| `diagnostics rootkit` | ✅ | reports view sizes, not just findings — an interface that silently returns nothing is otherwise indistinguishable from a clean host |
| Kernel-layer inode gate for hidden files | 🟡 | the name sources are eBPF write-opens, `/proc/<pid>/fd` and `/proc/<pid>/maps`; a file only ever *read* by a relative path is not yet named, which a BTF/CO-RE inode read in the openat program would close |
| `kill(pid,0)` independence | 🟡 | a rootkit hooking the signal path as well as procfs defeats the liveness view; the eBPF view still names the process |
| utmp ABI | 🟡 | the 384-byte glibc record layout is assumed and refused when it does not match, so the check is inert on a musl host rather than wrong |

Runtime knobs are environment variables rather than signed-config fields on
purpose: the config envelope is signed over its canonical byte sequence, so a
new field changes the bytes the backend must produce and would make every agent
reject config from a backend not updated in lockstep.

| Variable | Default | Purpose |
|---|---|---|
| `TRAPD_ROOTKIT` | on | set to `0`/`off` to disable the sweeps |
| `TRAPD_ROOTKIT_INTERVAL_SECS` | `300` (floor 60) | process/socket/module/mount/login sweep interval |
| `TRAPD_ROOTKIT_INTEGRITY_INTERVAL_SECS` | `3600` (floor 300) | binary-integrity and directory-walk interval |
| `TRAPD_ROOTKIT_PID_SCAN_MAX` | `65536` | highest PID probed for procfs concealment |
| `TRAPD_ROOTKIT_CORROBORATION` | `2` | consecutive sweeps a standing disagreement must survive |
| `TRAPD_ROOTKIT_FILE_ROOTS` | `/etc,/bin,/sbin,/lib,/usr/bin,/usr/sbin,/usr/lib,/usr/local,/boot,/root,/tmp,/var/tmp,/dev/shm` | trees walked for concealed files |
| `TRAPD_ROOTKIT_DIR_SCAN_MAX` | `20000` | directories per file sweep; reaching it is logged, never silent |
| `TRAPD_ROOTKIT_DIR_SCAN_DEPTH` | `8` | how deep below a root the walk descends |

---

## 3. Prevention & active response (`agent/src/prevention/`)

| Capability | Status | Notes |
|------------|--------|-------|
| Process termination | ✅ | userspace SIGKILL + kernel `bpf_send_signal` (comm rules) |
| **Inline network IoC enforcement** | ✅ **NEW** | `Ip`/`Cidr`/`Port`/`Domain` Block rules now drop the destination (nft/iptables) **and** SIGKILL the connecting process on a matching flow; `Domain` rules drop every resolved A/AAAA. Network analogue of `enforce_exec`. |
| Network containment / isolation | ✅ | nftables (preferred) + iptables fallback, allow-list carve-outs |
| File quarantine | ✅ | move + `chmod 000` + `chattr +i`, restore by id |
| Auto-response playbooks | ✅ | opt-in, severity/confidence-gated, cooldown, allowlist, fully audited |
| Signed command channel | ✅ | Ed25519, nonce + monotonic replay protection |
| RTR (script exec, file/dir/memory collection) | ✅ | `rtr_enabled`-gated, signed, size-capped |
| Kernel-side SHA-256 inode blocking | 🟡 | intentionally userspace post-exec today; ⏳ resolve SHA-256→inode for kernel map |
| Real **BPF-LSM** enforcement | ⏳🧪 | replace tracepoint signal-kill with `lsm/bprm_check_security` etc. to close the exec race (kernel ≥5.7, `CONFIG_BPF_LSM`) |
| Memory-injection **prevention** | ⏳🧪 | mmap/memfd/ptrace are detected; LSM-based blocking planned |

---

## 4. Self-protection & transport

| Capability | Status |
|------------|--------|
| Anti-ptrace (userspace poll + eBPF `ptrace`) | ✅ |
| Binary integrity (SHA-256 + optional Ed25519) | ✅ |
| Watchdog (survives SIGKILL, re-execs) | ✅ |
| Kernel-hardening audit (sysctl posture) | ✅ |
| TLS with **fail-closed CA pinning** + optional mTLS | ✅ |
| Durable disk-backed spool (offline queue, replay) | ✅ |
| Signed, monotonic config delivery | ✅ |
| **Sigma + anomaly + SIEM + vuln config over signed channel** | ✅ |
| mTLS certificate rotation | ⏳ |

---

## 4b. Telemetry loss transparency (`agent/src/telemetry/`) — ✅ NEW

The pipeline does not promise that no event is ever lost — under a burst that
would mean blocking a kernel ring-buffer consumer, which merely hides the loss.
It promises that **nothing is lost silently**: every accepted event is either
acknowledged, still queued, or dropped with a named, counted reason.

| Capability | Status | Notes |
|------------|--------|-------|
| Stable `event_id` across retry / recovery / restart | ✅ | assigned once; backend dedupes idempotently (at-least-once) |
| Provenance (`boot_id`, `sequence_number`, monotonic clock) | ✅ | a sequence gap is direct evidence of loss; ordering survives NTP steps |
| PID-reuse-safe process identity | ✅ | `(boot_id, pid, start_time)`; the `/proc` poller reports a recycled PID as terminate+create instead of missing both |
| Checksummed, crash-safe persistent queue | ✅ | CRC-32 per record, length validated before allocation, `0600`/`0700`, atomic compaction |
| Torn tail vs. corruption distinguished | ✅ | interrupted append is expected; a checksum mismatch escalates to `recovery_required` |
| Partial / duplicate / out-of-order acknowledgement | ✅ | unconfirmed events stay queued — silence is not consent |
| Exponential backoff with full jitter | ✅ | per-record and per-batch; attempt count persists across restarts |
| Bounded queue (events **and** bytes) with counted eviction | ✅ | `TRAPD_SPOOL_MAX`, `TRAPD_SPOOL_MAX_BYTES` |
| Partial enrichment (never discards the kernel record) | ✅ | `enrichment_status` / `enrichment_errors` per field |
| Explicit truncation markers | ✅ | original vs. captured length, cut on a UTF-8 boundary |
| 11 distinct drop reasons, all counted | ✅ | the sum is asserted against the total; a mismatch is `recovery_required` |
| Derived health state (8 states) | ✅ | pure function of the metrics, so it cannot drift from them |
| `trapd-agent diagnostics telemetry` | ✅ | collector mode, drops by reason, queue, retries, latency percentiles |
| Parser fuzzing (journal framing + bounded reader) | ✅ | seeded, ~45 k iterations in the unit suite |
| Load profiles (100 / 1 000 / 5 000 eps) | ✅ | `--test telemetry_load -- --ignored`; 1 000 eps × 60 s verified lossless |
| Prometheus/OTEL metric export | ⏳ | counters exist; only the JSON report is exposed today |
| Multi-day soak profile in CI | ⏳ | bounded load tests gate PRs; long profiles need a reference host |

---

## 5. Inventory, vulnerability & compliance (`agent/src/inventory/`)

| Capability | Status | Notes |
|------------|--------|-------|
| Asset + security-posture baseline | ✅ | SUID/SGID (+SHA-256), file caps, listening ports, kernel modules + signature |
| **CycloneDX SBOM** | ✅ **NEW** | `inventory/compliance.rs`, per-package purls |
| **CVE correlation** | ✅ **NEW** | installed packages vs `<config>/cve_feed.json`, epoch-aware version compare |
| **CIS-style hardening checks** | ✅ **NEW** | ASLR, suid_dumpable, IP-forward, SSH root/password auth, `/etc/passwd|shadow` perms |
| STIX/TAXII / live NVD sync | ⏳ | feed file today; remote sync planned |

Snapshot schema is **v4** (`compliance` block added); gated by `vuln_scan_enabled`
/ `cis_benchmark_enabled`.

---

## 6. SIEM & logging integration (`agent/src/output/siem.rs`) — ✅ NEW

Every event (and detection) can be forwarded, best-effort and non-blocking, in
parallel with native backend ingest:

- **Formats:** CEF (ArcSight), LEEF 2.0 (QRadar), JSON.
- **Transports:** syslog RFC 5424 (`unix:///dev/log` or `udp://host:port`),
  Splunk HEC (HTTP POST).
- **Config:** `siem_enabled`, `siem_format`, `siem_syslog_address`,
  `siem_hec_url`, `siem_hec_token` (off by default).

**Planned:** ⏳ Kafka producer · ⏳ Elastic/OpenSearch bulk · ⏳ OpenTelemetry exporter.

---

## 6b. Generic log collector (`agent/src/collectors/linux/logs/`) — ✅ NEW

Linux security collector: one pipeline, many sources — never a per-product
hard-coded tailer.

```text
LogSource → Reader → Framing / Multiline → Parser → Normalizer → Canonical Event
```

| Capability | Status | Notes |
|------------|--------|-------|
| File tail (plain, JSON, glob) | ✅ | inode + fingerprint; copytruncate; logrotate rename follow |
| systemd journal | ✅ | `journalctl --output=json --follow` + persisted `__CURSOR` |
| Syslog listener | ✅ | UDP / unix datagram; does not steal `:514`/`/dev/log` |
| Multiline | ✅ | start-regex + timeout + max lines/bytes; dedicated auditd event-id grouping |
| Parsers | ✅ | syslog RFC3164/5424, json, nginx/apache access+error, postgres, mysql, docker, sshd, sudo, auditd, kv, cef, auto |
| Persisted offsets | ✅ | `<state>/log_offsets.json` (`0600`); at-least-once across restarts |
| Backpressure | ✅ | log reader `send().await`s (pauses, does not drop into a kernel buffer) |
| Rate limits | ✅ | per-source token bucket; excess counted `rate_limit_applied` |
| Max line size | ✅ | default 64 KiB, UTF-8 cut, `truncated_fields` marker |
| Sigma + detection | ✅ | log events project into Sigma; sudo COMMAND / src_addr feed the engine |
| Built-in catalogue | ✅ | auto-discovers auth, auditd, nginx, apache, postgres, mysql, docker, cron |

Config: `logs_enabled` (default on), `logs: [LogSourceConfig]`, `logs_include_builtins`.
Empty `logs` discovers builtins; an explicit list is exclusive.

---

## 7. Configuration reference (selected)

All fields are delivered over the **signed, monotonic** config channel and
mirrored in the backend signer (`services/web/lib/api/config/sign.ts`).

| Field | Default | Purpose |
|-------|---------|---------|
| `prevention_enabled` | `true` | master switch for active response |
| `auto_response_enabled` / `_action` / `_min_severity` / `_min_confidence` | off / alert / critical / 90 | detection auto-response |
| `sigma_enabled` / `sigma_rules` | true / `[]` | Sigma engine + inline rules |
| `anomaly_detection_enabled` | `true` | statistical baseline |
| `vuln_scan_enabled` / `cis_benchmark_enabled` | true / true | SBOM+CVE / CIS checks |
| `siem_enabled` / `siem_format` / `siem_syslog_address` / `siem_hec_url` / `siem_hec_token` | off / cef / "" / "" / "" | SIEM forwarding |
| `logs_enabled` / `logs` / `logs_include_builtins` | true / `[]` / false | generic log collector + catalogue |
| `rtr_enabled` / `rtr_max_artifact_bytes` | false / 32768 | real-time response |
| `honeytoken_*` | — | deception lifecycle + escalation |

Provisioned files under `<config>` (default `/etc/trapd`): `ca.crt`, `agent.crt`/
`agent.key` (mTLS), `command_signing.pub`, `policy.json`, `iocs.json`,
`cve_feed.json`, `sigma/*.yml`.

---

## 8. Roadmap (prioritised)

**P0 — close detect→prevent gaps**
- ⏳ Real BPF-LSM enforcement (exec/ptrace/mmap), kernel SHA-256→inode blocking.
- ⏳ Memory-injection prevention (block, not just detect).

**P1 — detection breadth/fidelity**
- ✅ Generic Linux log collector (file / journal / syslog, parsers, rotation).
- ⏳ YARA over process memory.
- ⏳ Threat-intel: SQLite IOC store + STIX/TAXII consumer + IP/domain reputation.

**P2 — enterprise ops**
- ⏳ SIEM: Kafka / Elastic / OTEL sinks.
- ⏳ Group/policy templating (per-device today), mTLS cert rotation.
- ⏳ Forensics timeline export (JSONL) as an RTR command.

**P3 — coverage polish**
- ⏳ live `dlopen`/CRI lifecycle events, JA3S, multi-segment TLS reassembly.
- ⏳ Rootkit: cross-view detection of **hidden files** (kernel-layer inode gate
  to catch `getdents` filtering, the one concealment class §2b does not cover).

> Items marked 🧪 are kernel- or feature-gated and validated in a kernel/CI
> environment rather than in unit tests.

---

_Last updated: 2026-09-08 — adds the generic Linux log collector
(§6b: file/journal/syslog pipeline, inode-aware rotation, parsers for
nginx/apache/postgres/mysql/docker/ssh/sudo/auditd, persisted offsets)
and cross-view rootkit and manipulation detection (§2b: hidden
processes/sockets/files/mounts/logins, kernel modules, package-verified
binary integrity, `diagnostics rootkit`). Previous revision covered the
loss-transparent telemetry pipeline._

