# Adversarial test kit (Phase 09)

Each script refuses to run unless `TRAPD_ADVERSARIAL_OK=1` and cleans up what it creates.

| Threat | Script | Command | Expected event / finding | How to verify |
|---|---|---|---|---|
| T1 copied `credentials.json` / cloned VM image | `t1_credentials_copy.sh` | `TRAPD_ADVERSARIAL_OK=1 TRAPD_BACKEND_URL=https://... ./t1_credentials_copy.sh` on a bound agent | file has no `agent_secret`; a leftover secret is rejected with HTTP 401 | script prints `PASS`; console shows the agent with `protection: tpm\|software` |
| T1b second key bound for the same agent | manual (WP1): copy `credentials.json` incl. secret to a host before the first bind, bind on both | second `identity/bind` answers 409 | finding `agent.identity_bind_conflict` (high) | agent logs `identity: backend reports a DIFFERENT key`, stops; finding in console |
| T1c identity key export (Windows, TPM) | `t1_tpm_key_export.ps1` | `$env:TRAPD_ADVERSARIAL_OK=1; .\t1_tpm_key_export.ps1` elevated on a bound Windows agent | no event; every export route fails: `certutil -csp "Microsoft Platform Crypto Provider" -key` / `-exportPFX`, `CngKey.Export(EccPrivateBlob)`; credentials.json has no secret | script prints `RESULT: PASS`; a `FAIL` line means the key is exportable (software provider keys must also refuse: export policy 0) |
| T13 delete or restore the local tamper journal | `t13_journal_delete.sh` / `t13_journal_delete.ps1` | `TRAPD_ADVERSARIAL_OK=1 ./t13_journal_delete.sh` (root) / `$env:TRAPD_ADVERSARIAL_OK=1; .\t13_journal_delete.ps1` (elevated) on a bound test agent with some acknowledged journal entries | the agent restarts its chain at seq 1; backend answers 409 and records `selfprotect.journal_gap` (high, reason `fork` or `regression`); a restored old file is detected the same way (backend ahead of the file) | finding in console; agent log `backend rejected the tamper journal`; the script restores the original file afterwards. Unit-level equivalents: `agent_journal_smoke.sql` steps 5-6 and `test-agent-journal-route.mts` T13 rows |
# Adversarial test kit

Each row: a tamper technique, the command that performs it, the expected event
or finding, and how to verify. Scripts refuse to run unless
`TRAPD_ADVERSARIAL_OK=1`, are safe (they create nothing persistent and restore
what they change) and need an installed, running agent on a disposable host.

| Threat | Command | Expected | Verify |
|---|---|---|---|
| T2 kill the agent or the guard | Linux: `sudo -E ./T2_T3_guard_pair.sh kill agent` (or `guard`). Windows (as SYSTEM): `.\T2_T3_guard_pair.ps1 -Mode kill -Target agent` | The peer restarts the killed service within seconds; event `selfprotect.peer_lost` with `peer`, `reason: died`, `announced_stop: false`, `maintenance_authorized: false` | The script waits for the new pid and greps `events.ndjson`; in the console look for the finding on the host. A planned stop (`systemctl stop`, MSI upgrade/uninstall, maintenance token) must produce no restart and no `peer_lost`. |
| T3 suspend the agent or the guard (alive but mute) | Linux: `sudo -E ./T2_T3_guard_pair.sh suspend agent`. Windows (as SYSTEM): `.\T2_T3_guard_pair.ps1 -Mode suspend -Target agent` (`NtSuspendProcess`) | After about 10 s of silence the peer terminates the hung process, restarts the service and emits `selfprotect.peer_lost` with `reason: hung` | Same; the script resumes a suspended process on exit. As an administrator without SeDebugPrivilege the process DACL refuses the suspend (reported as BLOCKED, expected). |

Not covered by a script (needs a window of two kills within about 10 s, which
is the stated custom-tooling bar of the guard pair): killing agent and guard
together. The expected outcome there is the backend's heartbeat gap, not a
local event.
# Adversarial test kit

Every script tampers with the local agent on purpose and refuses to run unless
`TRAPD_ADVERSARIAL_OK=1`. Run on a test host only. Scripts create their test
artefacts in a temp dir and remove them.

| Row | Threat | Script | Command | Expected event | How to verify |
|---|---|---|---|---|---|
| T6 | Debugger / DLL injection into the agent | `T6_T7_linux.sh` | `TRAPD_ADVERSARIAL_OK=1 ./T6_T7_linux.sh` | `selfprotect.debugger_attached` (tracer pid, comm, exe) within ~60 s; also the 10 s `AgentTamper` ptrace event | agent log `process integrity finding`, console alert |
| T7 | Memory implant (Linux) | `T6_T7_linux.sh` | same run (gdb maps an rwx page) | `selfprotect.module_injected`, reason `anonymous_rwx` | as above |
| T6 | Remote DLL load (Windows) | `T6_T7_windows.ps1` | `$env:TRAPD_ADVERSARIAL_OK=1; .\T6_T7_windows.ps1` (elevated) | `selfprotect.module_injected` (path outside System32/install dir, sha256), `selfprotect.handle_access` (the PowerShell process with VM_WRITE/CREATE_THREAD) within ~60 s | console alert; agent log |
| T7 | ETW patch (Windows) | `T6_T7_windows.ps1` | same run (writes `ret` over `EtwEventWrite`, restores it) | `selfprotect.code_patched`, subject `ntdll.dll!EtwEventWrite`, expected vs actual bytes | console alert |

False-positive switches: `TRAPD_SELFPROTECT_CHECK_{CODE,MODULES,THREADS,DEBUGGER,HANDLES}=off`,
`TRAPD_SELFPROTECT_MODULE_ALLOW`, `TRAPD_SELFPROTECT_HANDLE_ALLOW`.
# Adversarial test kit

Every script refuses to run unless `TRAPD_ADVERSARIAL_OK=1` and restores what it changes.

| Threat | Script | Action | Expected | Verify |
|---|---|---|---|---|
| T4 WFP block (Windows) | `T4-wfp-block-windows.ps1` | `New-NetFirewallRule -Direction Outbound -Action Block -Program <agent exe>` (EDRSilencer-style app-id block filter), removed after 75 s | `selfprotect.network_silenced`, high, evidence `filter_name`, `provider` ("Microsoft Windows Firewall"), `layer`, `reason=app_id`, within ~65 s (change notification) | Detections list; events queued during the block arrive after removal |
| T4 iptables owner DROP (Linux) | `T4-iptables-uid-linux.sh` | `iptables -A OUTPUT -m owner --uid-owner <uid> -j DROP` | `selfprotect.network_silenced`, high, `source=iptables`, `reason=uid` | as above; `nft` rules are parsed the same way |
| T5 hosts redirect (Windows) | `T5-hosts-redirect-windows.ps1 -BackendHost <host>` | hosts entry `203.0.113.66 <backend host>`, restored | `selfprotect.backend_redirected`, high, `vector=hosts` | Detections list |
| T5 hosts redirect (Linux) | `T5-hosts-redirect-linux.sh` | same on `/etc/hosts` | same | same |
| T5 TLS interception (MANUAL) | none | set `TRAPD_BACKEND_SPKI_PINS` to a wrong pin, restart the agent; or front the backend with a proxy whose CA is in `ca.crt` | handshake refused, `selfprotect.tls_pin_mismatch`, high, `observed_spki_sha256` lists the presented chain; delivered after the correct pin is restored | agent log; unset the variable and restart to recover. Report-only mode (no pins) writes `observed_spki_pins.json` to the state dir |
| T5 proxy / NRPT (MANUAL) | none | `netsh winhttp set proxy 127.0.0.1:3128`, or `Add-DnsClientNrptRule -Namespace .<backend domain> -NameServers 203.0.113.53`. Revert: `netsh winhttp reset proxy`, `Get-DnsClientNrptRule \| Remove-DnsClientNrptRule` | `selfprotect.backend_redirected`, vector `proxy_winhttp` (medium) / `nrpt` (high) | Detections list |
| T4 selective block (MANUAL) | none | set `TRAPD_NETWORK_PROBE_URL=https://<neutral EU endpoint>`, then block only the backend address | after 3 scans (~3 min) `selfprotect.backend_unreachable_selective`, medium | delivered once the block is removed |

Hosts-file and proxy findings that are legitimate (on-prem backend, corporate proxy) are silenced with `TRAPD_NETWORK_GUARD_ALLOW` (for example `203.0.113.66` or the proxy `host:port`).
