# Telemetry coverage gaps (after moving detection to the backend)

Status: 2026-11-04. The agent no longer evaluates detection rules; the backend
receives raw telemetry in the canonical schema and detects there. This file
lists what the agent still does not capture, and what the move itself costs.
Every item was checked against the code of this branch; "not found" means a
search of `agent/src` returned nothing, not that it is impossible.

## A. Regressions caused by removing agent-side rules (backend work required)

The 80 removed rules are preserved in `docs/legacy-agent-rules/rule-catalog.json`
(rule id, MITRE mapping, severity, window). Until the backend has equivalent
Sigma / sequence rules, these detections are gone:

| Area | Needs in the backend |
|---|---|
| Command-line rules (LOLBins, reverse shells, defence evasion, credential access) | stateless Sigma over `process_create` / `process_exec` |
| Process-tree chains (IOA) | sequence rules; the backend must keep lineage (ppid chain from process events) |
| IOC hash / IP / domain match | IOC set matched in the pipeline (hash is on every exec event) |
| Beaconing, DNS tunnelling, port scan, lateral movement | windowed correlation over network/DNS events |
| Baseline anomaly (binary novelty, exec rate) | `baseline_deviation` stage already exists in `stream-processor` |
| Windows registry persistence | Sigma over `registry` events |
| Windows 4688 / 7045 / 4698 / WMI 5861 | Sigma over `log` events (`EventID` in `fields`) |
| Sysmon 10 (LSASS memory access) | Sigma over the raw Sysmon `log` event (the agent forwards it; no local verdict) |
| PowerShell 4104 script blocks | **opt-in only** (`script_block_capture_enabled`), see C |
| DLL side-loading | no event exists (gap B1) |

Still produced on the host because they need host access, not rule matching:
honeytoken access/tamper, rootkit cross-view findings, memory-injection scan
findings, agent self-protection (tamper, ETW session stopped, audit policy
changed, unclean shutdown), ransomware *indicators* (entropy / mass-write
measurements).

## B. Collection gaps (not found in `agent/src`)

| # | Platform | Gap | Why it matters |
|---|---|---|---|
| B1 | Windows, Linux | No image/library load event. Windows ETW image loads were only turned into a verdict (now removed); Linux `dlopen` is listed as planned | DLL side-loading, injected modules, `LD_PRELOAD`-style abuse cannot be detected in the backend. Needs a filtered event (path class, signed state), not every load |
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
