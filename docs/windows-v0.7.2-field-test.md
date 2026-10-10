# Windows agent v0.7.2 field test (2026-10-10)

Manual end-to-end test of agent 0.7.2 on a Windows 11 host (`CLT-MBL`, service
`trapd-agent`, paired to the local dev stack). Events were verified in
ClickHouse (`trapd_events`). Frontend visibility was checked by the tester per
test and is **not** recorded here unless stated.

Status legend: PASS = works as expected, PARTIAL = arrives but defective,
FAIL = expected telemetry or detection missing.

## Results

| # | Area | Action | Status | Summary |
|---|------|--------|--------|---------|
| 0 | Install / start | 0.7.2 binary copied over the old install | FAIL, then PASS | Service refused to start (see Finding F1). Passed after the baseline was reset. |
| 1 | Process, short-lived | `cmd /c echo ...`, `powershell -Command ...` | PARTIAL | `process.create`/`terminate` arrive, but `cmdline` is empty (`enrichment_errors.cmdline = io_error`, `enrichment_status = partial`). |
| 2 | Process, long-lived | `powershell ... Start-Sleep 20` | PASS (with bug) | Full command line, create + terminate. `exe_sha256` is malformed (F2). |
| 3 | Network / DNS | `Resolve-DnsName`, `Invoke-WebRequest`, `Test-NetConnection` | PARTIAL | DNS and connection events arrive. No process attribution, raw `ERROR87` rcode, NXDOMAIN reported as NOERROR (F4, F5). |
| 4 | File, Temp | create/modify/rename/delete in `%TEMP%` | n/a | No events. Expected: generic FIM only watches `drivers\etc`; ransomware heuristics ignore Temp. Test design error, not a bug. |
| 4b | File, hosts | append and remove a comment in `drivers\etc\hosts` | PARTIAL | `filesystem.modify` arrives (3 events). No actor/process, no hash (`integrity: not_checked`), no alert (F6). |
| 5 | Authentication | `runas /user:<nonexistent>` | PARTIAL | `user.logon_failed` plus raw 4776/4625 as `log.log`. Spurious `user.logon` `SYSTEM` success event recurs (F7). Failure reason unresolved (`%%2313`). |
| 6 | Persistence | `reg add/delete HKCU\...\Run` | FAIL | No registry event and no detection. `reg.exe` events have an empty command line (F3). |
| 7 | Ransomware | 30 files renamed to `*.docx.locked` | PASS | 30 `filesystem.ransomware_indicator` (high) folded into one alert (`ransomware.suspicious_extension`, medium). Severity arguably too low. |
| 8 | Honeytoken | read, copy and open the decoy `bitlocker-recovery-key.txt` | PARTIAL | `detection.honeytoken_access` arrives (~15-25 s after access, polling) but with `accessor: unknown`, confidence 30, severity low (F12). |
| 9 | Restart / offline buffer | firewall block to gateway, activity, service restart, unblock | PASS (with bug) | No ingest 09:18:44-09:21:02 UTC, then replay bursts (100 + 69 events) with original timestamps. Heartbeats are not buffered. Uptime/restart fields are never populated (F13). Zero loss not provable (F14). |

## Findings

| ID | Severity | Finding |
|----|----------|---------|
| F1 | high | After replacing the binary the service crash-loops with `BINARY INTEGRITY VIOLATION`. The baseline (`config\binary.sha256`) is only reset by the MSI (`deploy/windows/Package.wxs`). Any non-MSI update path leaves a stale baseline. Also: the log asks for `config\signing.pub`, but the shipped keys are `release_signing.pub` and `command_signing.pub`, so binary signature verification is skipped. |
| F2 | high | `exe_sha256` is hex-encoded twice (135 chars instead of 71, `sha256:` + 128 hex). Decoding the payload yields the real hash. Breaks hash lookups, allowlists and probably per-binary alert folding. Seen on every `process.create` checked. |
| F3 | high | Command line missing for short-lived processes (race between process start and the handle-based read). Defeats every cmdline-based rule (`windows_rules.rs`) for one-liners such as `reg add`, `schtasks`, `certutil`. Also `username: unknown` for these processes. |
| F4 | medium | DNS events carry no PID/process, no client/server address, `transaction_id` always 0. |
| F5 | medium | DNS rcode leaks a raw Windows error (`ERROR87`). Non-existent domain reported as `NOERROR` with the authoritative nameserver in `cnames` (suspected authority-section misparse, unverified). |
| F6 | medium | File events have no actor and no content/hash check. Hosts-file tampering raises no alert. |
| F7 | medium | `user.logon` with `success: true, username: SYSTEM` is emitted repeatedly (and on every failed-logon batch). Failure reason and logon type are only in the raw `log.log`, not in `user.logon_failed`. |
| F8 | high | No registry change monitoring. `collectors/windows/registry.rs` only contains read helpers; there is no watcher, so Run keys, services, IFEO, WMI and similar persistence are blind spots. |
| F9 | high | Alert noise. In 2 h: 237 `anomaly.rare_binary_for_user` (180 distinct dedup keys, ~85 % of all alerts) and 22 `memory.anon_exec` on benign Microsoft/third-party processes (explorer, RuntimeBroker, SystemSettings, WARP, LockApp, Copilot). The 0.7.2 per-binary folding does not hold on this host. Real attack signals are buried. |
| F10 | low | Honeytoken `windows_last_access` raised a `timestamp_only` alert (confidence 30, accessor unknown) right after service start. Probable restart artifact. |
| F11 | low | Ransomware burst of 30 renames maps to medium severity. |
| F12 | high | Honeytoken access has no accessor (`comm: unknown`, pid -1) and only `timestamp_only` evidence (confidence 30, severity low), although the opening process (`Notepad.exe`, decoy path in its command line) is known from `process.create`. A decoy nobody should touch is a near-certain signal and should be correlated with process events and rated high. Detection latency is ~15-25 s (polling). |
| F13 | medium | `agent_uptime_seconds` is always 0 and `agent_last_restart` always empty in every heartbeat, also after a service restart. A stop/restart of the agent is not visible in telemetry. |
| F14 | low | No sent/received event counters between agent spool, gateway and ClickHouse, so lossless replay after an outage cannot be verified. Heartbeats are not buffered (acceptable) but the backend must alert on a missing heartbeat (not verified). |

## TODO

Ordered by value. "Done when" is the acceptance test, ideally an automated
regression test plus a repeat of the field test above.

### P0: correctness of what we already collect
- [ ] F2: fix double hex encoding of `exe_sha256`. Done when: unit test asserts 64 hex chars, and the hash equals `Get-FileHash` for the same file.
- [ ] F3: capture the command line at process start (ETW process-start payload or event-time read) instead of a later handle read. Done when: `reg add ... trapdtest` and `cmd /c echo x` report the full command line and a user in 100 % of 100 runs.
- [ ] F1: make every update path (not only the MSI) refresh or atomically replace the baseline; fix the `signing.pub` vs `release_signing.pub` mismatch. Done when: replacing the binary via signed self-update and via manual copy both start cleanly, and a tampered binary still refuses to start.
- [ ] F9: reduce noise before adding more rules. Verify dedup key stability after F2, suppress/downgrade `memory.anon_exec` for signed vendor binaries at low confidence, review `rare_binary_for_user` learning window. Done when: an idle workstation produces fewer than ~10 alerts per day and the Test 7 alert is still raised.

### P1: detection coverage gaps (what an attacker does first)
- [ ] F8: registry watcher for Run/RunOnce, Services, IFEO/debugger, Winlogon, AppInit, Defender exclusions, COM hijack keys (HKLM and per-user hives). Done when: Test 6 yields an event and a detection.
- [ ] Scheduled tasks and new services (Windows events 4698, 7045), WMI event subscriptions, startup folder.
- [ ] F7: normalize logon events (type, status/sub-status text, source, process); drop the spurious `SYSTEM` success event. Add brute-force (N failures per source/user in a window), password spray, and success-after-failures detections.
- [ ] F6: attach actor (process/user) to file events on watched paths; hash or diff critical files; alert on hosts-file and agent-config changes.
- [ ] Defense evasion: Defender disable/exclusion changes, event-log clearing (1102/104), `wevtutil cl`, `vssadmin delete shadows`, `bcdedit` recovery tampering.
- [ ] Credential access: LSASS access (Sysmon-style handle access or ETW), SAM/SECURITY hive export, DPAPI/browser store reads.
- [ ] Execution: encoded PowerShell (script block logging 4104), LOLBins (certutil, mshta, regsvr32, rundll32 with remote args), Office spawning shells.
- [ ] F11: score ransomware by burst size and entropy/rename rate (not by a single extension); consider shadow-copy deletion as a correlated signal.
- [ ] F4/F5: DNS enrichment with PID/process, proper rcode mapping, NXDOMAIN handling.

### P1: self-protection and resilience
- [ ] F12: correlate honeytoken access with process events (decoy path in cmdline, open handles) to fill the accessor, rate real accessor hits high, and reduce latency below ~5 s (change notification instead of polling). Done when: Test 8 yields a high alert naming `Notepad.exe` and the user.
- [ ] F13: populate `agent_uptime_seconds` and `agent_last_restart`. Done when: a service restart is visible in the next heartbeat.
- [ ] F14: add per-sensor sent/received counters and a replay check; test spool size limits and long outages (hours). Backend: alert on missing heartbeat.
- [ ] Agent tamper tests: stop/kill the service as admin, delete files in `config`, modify `agent.env`; confirm a tamper event reaches the backend before shutdown, and that the backend alerts on a missing heartbeat.
- [ ] F10: suppress last-access honeytoken alerts during the first scan after start unless an accessor is known.

### P2: validation
- [ ] Turn this manual field test into a repeatable script (`deploy/windows/field-test.ps1`) that runs the tests above and checks ClickHouse via a documented query set.
- [ ] Map detections to MITRE ATT&CK and track coverage per technique; run an adversary-emulation set (for example Atomic Red Team, with owner approval) against a test VM and record what is detected, what is only logged and what is missed.
- [ ] Measure false-positive rate on at least one week of idle/normal use per host profile before claiming coverage.
- [ ] Frontend verification column: for each test record whether event, alert and entity page show the data correctly.

## Fix status (branch `integ/windows-field-test-fixes`)

The integration fixes are tracked in [agent PR 135](https://github.com/TRAPD-CLOUD/TRAPD-Agent/pull/135). Linux tests and Windows cross-compilation validate the code; native Windows/MSI checks run in CI. **The original field test has not been repeated on `CLT-MBL`.** A field finding is only closed after that host test is repeated.

| Finding | State | What changed | Still open |
|---------|-------|--------------|------------|
| F1 | fixed, untested on Windows | `release_signing.pub` used consistently; manual copy refreshes the baseline only with a verifying `binary.sig`; capped backoff (30 s to 15 min) instead of a restart loop | Release publishes no standalone `binary.sig`; downgrade of an older signed binary is accepted; `BINARY_SIGNING_KEY` removed, the release key now also signs the binary digest (one trust anchor instead of two: owner decision) |
| F2 | fixed | single hex encoding, unit test with a known digest | none |
| F3 | mitigated with persisted sources | ETW event-time enrichment plus recorded Security 4688 / optional Sysmon 1 command line and account; historical PIDs never borrow current process context | Security auditing and command-line policy or existing Sysmon are required; acceptance test (100 runs) not repeated |
| F4/F5 | partly fixed | SOA no longer parsed as CNAME; rcode mapping; PID/process added | no client/server address or transaction id in the source event; NXDOMAIN-as-NOERROR unconfirmed on a real host |
| F6 | partly fixed | hosts-file hash and diff alert; optional `actor`/`change_summary` | actor is a command-line lead only; agent-config changes have no hash/actor |
| F7 | fixed, untested on Windows | spurious SYSTEM logons dropped; failure reason/type/source structured; brute force, spray, success-after-failures rules | 4776 on domain controllers not counted |
| F8 | implemented, field validation pending | bounded persistent snapshot baseline, unloaded-hive/read-failure retention, durable event handoff; Security 4657 / optional Sysmon 12–14 supplement polling | snapshot misses changes between polls; native registry auditing requires policy and key SACLs or configured Sysmon; host test pending |
| F9 | partly fixed | rare-binary baseline cap 64 to 512 (root cause of endless "novel" alerts); admin install paths learned silently; anon-exec thread start in protected images downgraded | downgrade is path-based, no Authenticode check; idle alert rate not measured |
| F10 | fixed | 30 s warm-up suppression for unattributed last-access hits | none |
| F11 | fixed | single event medium; `rename_burst` high at 10 and critical at 30 files in 10 s | backend alert severity not checked |
| F12 | partly fixed | accessor from `process.create` command lines, high/90 when attributed; 2 s poll | processes that do not name the decoy (Explorer copy) are not found; no true change notification |
| F13 | fixed | `agent_uptime_seconds`, `agent_last_restart`, `previous_shutdown` in the heartbeat | none |
| F14 | agent side fixed | `pipeline` counters in the heartbeat; oldest-first spool eviction with priority-loss counters | backend must alert on missing heartbeat, `previous_shutdown=unclean`, `dropped_total` and `durability_lost`; no `agent.stopping` event on shutdown |

### Backend work required (not done in this repo)
- Registry normalization and the missing Windows runtime catalog policies are prepared in the companion platform branch `fix/agent-registry-normalization`; they require platform release and migration deployment.
- ClickHouse payload schema: registry fields, new heartbeat fields (`pipeline.*`), logon fields, filesystem `actor`/`change_summary`, DNS `pid`/`process`.
- Missing-heartbeat and unclean-shutdown alerting.

### Not covered by any fix yet
- Tamper detection for deleted `config` files or edited `agent.env`. Journal checkpoint now performs a checked final fsync; durability failure is visible in diagnostics, health and heartbeat.
- Scheduled-task subfolders, WMI subscriptions and startup folder.
- LSASS access without an existing configured Sysmon process-access source; script block logging 4104. Sysmon 10 memory-capable LSASS access is a low-severity signal, not a confirmed dump.
- Repeatable field-test script and ATT&CK coverage measurement (P2).

## Honest scope statement

"Reports every attack" is not achievable for any agent. The realistic goal is
broad coverage of the common attack chain (initial execution, persistence,
credential access, defense evasion, ransomware impact), with a measured
detection and false-positive rate per technique and clear gaps documented.
Until the P0 items are fixed, existing rules operate on incomplete or wrong
data.

## How the results were obtained

ClickHouse queries against `trapd_events` (`ts`, `event_type`, `payload_json`)
filtered by marker strings (`trapdtest*`), PIDs and time windows; agent logs
from `C:\ProgramData\TRAPD\logs`. Findings F4/F5 (cause) and F2 (effect on
folding) are hypotheses and have not been confirmed in the agent code.

Runtime coverage prerequisites and failure behavior are documented in [Persisted Windows event coverage](windows-native-event-coverage.md). Historical test results above remain unchanged; code fixes do not substitute for repeating the host test.
