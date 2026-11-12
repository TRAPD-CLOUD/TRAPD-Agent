# Telemetry coverage gaps (after moving detection to the backend)

Status: 2026-11-04. The agent no longer evaluates detection rules; the backend
receives raw telemetry in the canonical schema and detects there. This file
lists what the agent still does not capture, and what the move itself costs.
Every item was checked against the code of this branch; "not found" means a
search of `agent/src` returned nothing, not that it is impossible.

## A. Regressions caused by removing agent-side rules

The 80 removed rules are preserved in `docs/legacy-agent-rules/rule-catalog.json`
(rule id, MITRE mapping, severity, window).

**Ported** (TRAPD-CLOUD/TRAPD#265, 41 Sigma rules with fixtures; 30 enabled,
11 draft): Windows process/LOLBin/credential/impact/persistence rules, Office
and web-server child shells (the agent now sends `parent_exe`), PowerShell
script blocks, service/WMI audit records, registry autostart, and the Linux
command-line and persistence-path rules that can be expressed in Sigma. The
Linux rules are approximations: the old engine parsed shell pipelines, Sigma
matches the raw command line.

**Also in the pack** (drafts, replay before enabling): port scan and admin-port
sweep (windowed `value_count`), IMDS access, DNS encoded-label and DNS query
burst, two attack chains as ordered per-host sequences, DLL side-loading (see
B1), and IOC template rules (hash / IP / domain; the list lives in the rule
because the backend has no IOC store).

**Covered by what the backend already had:** baseline anomaly (the
`baseline_deviation` stage: process novelty, active hours, event volume, per
host) and volume-based beaconing (the starter correlation rule).

**Not covered anywhere:**

| Area | Why |
|---|---|
| Beaconing by cadence (regular intervals / low jitter) | needs interval statistics per destination; the correlation engine only counts |
| Per-domain DNS tunnel rate | the engine cannot group by registrable domain; only the host-level burst rule exists |
| Privilege-escalation chain (unprivileged, then setuid 0, then action) | setuid events have no Sigma class in the backend |
| IOC feeds (STIX/TAXII, auto-sync) | no IOC store; indicators are edited into the template rules |
| Process-tree bound chains | the agent bound chains to one process tree; the backend binds to a host, so the two chain rules are coarser |
| Remaining Linux command-line rules | account manipulation, timestomp, tunnelling/MitM tools, container abuse, exploit command lines, masquerading by daemon name |
| Registry persistence beyond autostart keys | services ImagePath, IFEO, COM hijack, WMI |
| Sysmon event 10 (LSASS access) | forwarded raw as a `log` event; the backend maps only 4104/7045/4697/4698/4702/5861 |

Still produced on the host because they need host access, not rule matching:
honeytoken access/tamper, rootkit cross-view findings, memory-injection scan
findings, agent self-protection (tamper, ETW session stopped, audit policy
changed, unclean shutdown), ransomware *indicators* (entropy / mass-write
measurements).

## B. Collection gaps (not found in `agent/src`)

| # | Platform | Gap | Why it matters |
|---|---|---|---|
| B1 | Windows: **closed for side-loading**; Linux open | Windows now ships DLL-load *candidates* only (protected process loads a `.dll` from a user-writable folder) as `kernel/module_load` with `path` and `process_exe`; the backend rule re-checks them. Not every load: that would be far too frequent. Signed state and injected modules are not covered. Linux `dlopen` is still planned | A full image-load stream stays out of scope for the 1 % budget |
| B2 | Windows | File events carry no acting process (`actor: None`) | Backend cannot say who wrote a file; ransomware and tamper attribution rely on a host-side guess (`accessor_correlation`) |
| B3 | Windows | DNS events lack client/server address and transaction id (the ETW source does not provide them) | Weaker DNS tunnelling / C2 correlation |
| B4 | Windows | No LSASS handle-access telemetry of its own; the only source is Sysmon event 10 | Without Sysmon there is no credential-dumping signal |
| B5 | Windows | No named-pipe events (nothing in `agent/src`) | Lateral movement / C2 pipes (PsExec, Cobalt Strike defaults) |
| B6 | Windows | No AMSI telemetry (only a quarantine reference) | Script content before execution; obfuscated PowerShell |
| B7 | Windows | Driver loads only as periodic inventory, no load event stream | Vulnerable/malicious driver loading (BYOVD) is seen late |
| B8 | Windows | Network telemetry has no byte/packet/RTT depth, no TLS SNI/JA3 (Linux has both) | Exfiltration volume, TLS fingerprinting |
| B9 | Windows, Linux | No removable-media / device-attach events (no `usb`/`udev` in `agent/src`) | Physical exfiltration and rubber-ducky style attacks |
| B10 | Linux | No container lifecycle stream (CRI/containerd planned), no multi-segment TLS reassembly, no JA3S | Container escape/start visibility; weaker TLS fingerprints |
| B11 | Linux | Agent tamper collector watches only `$HOME/.trapd`; state dir not watched | Tampering with agent state is not reported |
| B12 | Windows | Rootkit cross-view detection not available (depends on `/proc`, `getdents`, `sock_diag`) | No hidden process/socket/file detection on Windows |
| B13 | Windows | No kernel-side exec blocking (post-creation kill only) | Short-lived malware executes before it is killed |
| B14 | both | Heartbeat `coverage` / `shadow_hits` fields are stripped by the backend web schema | Sensor health is partly invisible to operators. `shadow_hits` is now meaningless |

## C. Decision taken without the user: script-block text

PowerShell script text can contain credentials. Before this change it never
left the host. Backend detection needs the text, so it can now be forwarded,
but only when the operator sets `script_block_capture_enabled` in the signed
config (default off). Until someone enables it, there is no script-block
detection at all. This needs an explicit product/privacy decision (data
protection impact, works-council consent in Germany).

## D. Performance changes in this branch

1. Detection engine removed from the consumer: no per-event process-tree
   lookup, global mutexes, regex/Sigma matching or finding gate.
2. The consumer works on batches (up to 256 queued events): one task switch,
   one spool lock and one local-output write per batch instead of per event.
3. The local OCSF mirror is no longer computed unless used. Default output is
   `off` for non-interactive runs (was `stdout`, i.e. the journal). The
   Windows service still defaults to `file` because `test-msi.ps1` and the
   Windows README rely on `events.ndjson`; set `TRAPD_OUTPUT=off` to skip it.
4. Collector channel capacity 1,000 -> 4,096 events, so bursts (builds,
   installs) are absorbed instead of dropped.

Not yet done: per-component profiling of the collectors on the Windows test
host. The earlier measurement (about a third of one core at idle on the
installed 0.7.x service) came from collectors, not from the rule engine, so
the engine removal alone will not reach the target; see PRs #138-#140.

## E. Channel burst measurement (GAP-MATRIX L1)

Harness: `agent/src/pipeline/burst.rs` (test module of the agent crate).
It drives the real `try_emit` -> `next_batch` -> `consume_batch` -> durable
`Spool` (journal in a temp dir, `OutputMode::Off`, SIEM disabled) with a
producer OS thread, as the ring-buffer consumers do. No network, no
collectors. Drops are counted from `try_emit`'s return value.

```text
cargo test --release -p trapd-agent --bin trapd-agent burst_measurement_table -- --ignored --nocapture
```

Host: Linux dev box (QEMU virtual CPU, `nproc` = 4), `--release` profile,
rustc 1.98.1, single run per cell (no repeats; timing-dependent cells vary by
tens of percent between runs). Event sizes: about 400 B exec event (process),
about 250 B file-open event.

| scenario | capacity | sent | dropped (userspace_channel_full) | peak occupancy | drain ms |
|---|---|---|---|---|---|
| max 1k | 1024 | 1000 | 0 | 804 | 42 |
| max 1k | 4096 | 1000 | 0 | 763 | 41 |
| max 1k | 16384 | 1000 | 0 | 709 | 40 |
| max 5k | 1024 | 1510 | 3490 | 1024 | 53 |
| max 5k | 4096 | 4639 | 361 | 4096 | 181 |
| max 5k | 16384 | 5000 | 0 | 4478 | 230 |
| max 20k | 1024 | 2084 | 17916 | 1024 | 44 |
| max 20k | 4096 | 5393 | 14607 | 4096 | 226 |
| max 20k | 16384 | 17948 | 2052 | 16384 | 1100 |
| max 50k | 1024 | 2570 | 47430 | 1024 | 93 |
| max 50k | 4096 | 5641 | 44359 | 4096 | 366 |
| max 50k | 16384 | 17677 | 32323 | 16384 | 1390 |
| process storm 2k/s x5s | 1024 | 10000 | 0 | 65 | 100 |
| process storm 2k/s x5s | 4096 | 10000 | 0 | 123 | 89 |
| process storm 2k/s x5s | 16384 | 10000 | 0 | 72 | 72 |
| file storm 10k/s x2s | 1024 | 20000 | 0 | 839 | 144 |
| file storm 10k/s x2s | 4096 | 20000 | 0 | 1644 | 164 |
| file storm 10k/s x2s | 16384 | 20000 | 0 | 901 | 113 |

Findings:

- The consumer sustains roughly 20-40k events/s here (batching plus journal
  append with fsync every 50 records). The realistic storms (2k/s and 10k/s)
  are well below that: no drops at any tested capacity, peak occupancy 65-1644.
- Drops appear only for instantaneous bursts of more than about the capacity
  plus what the consumer drains meanwhile (5k at 1024, 20k at 4096). Those are
  synthetic worst cases: a real producer is rate-limited by the kernel ring
  buffer drain and `/proc` enrichment, so a 20k-event spike with zero spacing
  does not occur. Whether it does on a real host stays unmeasured.
- 4,096 gives 2.5x headroom over the observed peak of the 10k/s file storm
  (1,644); 1,024 gave 839 in that run, i.e. little margin. The capacity change
  to 4,096 is justified; raising it further only moves the cliff (16,384 still
  drops at 20k instantaneous) at about 4 MiB more worst-case memory per 10k
  slots. No code change to the capacity or to backpressure was made.

Not covered: the second tee channel to prevention (capacity 1,024, drops
counted as `userspace_channel_full` too) with a real prevention engine behind
it; collector-side cost (`/proc` enrichment, ring-buffer reads); the Windows
ETW path; the network stage; a slower disk than this box's.

Regression tests (fast, no clocks): a burst of exactly `CHANNEL_CAPACITY`
events with a stalled consumer is not dropped and fully reaches the spool;
overflow beyond capacity is counted exactly.
