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
| **Sigma + anomaly + SIEM + vuln config over signed channel** | ✅ **NEW** |
| mTLS certificate rotation | ⏳ |

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
- ⏳ YARA over process memory.
- ⏳ Threat-intel: SQLite IOC store + STIX/TAXII consumer + IP/domain reputation.

**P2 — enterprise ops**
- ⏳ SIEM: Kafka / Elastic / OTEL sinks.
- ⏳ Group/policy templating (per-device today), mTLS cert rotation.
- ⏳ Forensics timeline export (JSONL) as an RTR command.

**P3 — coverage polish**
- ⏳ live `dlopen`/CRI lifecycle events, JA3S, multi-segment TLS reassembly.

> Items marked 🧪 are kernel- or feature-gated and validated in a kernel/CI
> environment rather than in unit tests.

---

_Last updated: 2026-06-03 — reflects the Sigma engine, anomaly baseline, inline
network IoC enforcement, SBOM/CVE/CIS, and SIEM forwarding work._
