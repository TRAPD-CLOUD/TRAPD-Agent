# Adversarial test kit (Phase 09)

Every script tampers with the local agent on purpose. It refuses to run unless
`TRAPD_ADVERSARIAL_OK=1`, must run on a disposable test host with an installed agent,
and restores everything it changes. Rows marked MANUAL have no script (reboot or
environment change needed).

| Threat | Script | Command / action | Expected event or finding | How to verify |
|---|---|---|---|---|
| T1 copied `credentials.json` / cloned VM image | `t1_credentials_copy.sh` | `TRAPD_ADVERSARIAL_OK=1 TRAPD_BACKEND_URL=https://... ./t1_credentials_copy.sh` on a bound agent | file has no `agent_secret`; a leftover secret is rejected with HTTP 401 | script prints `PASS`; console shows the agent with `protection: tpm\|software` |
| T1b second key bound for the same agent | manual (WP1): copy `credentials.json` incl. secret to a host before the first bind, bind on both | second `identity/bind` answers 409 | finding `agent.identity_bind_conflict` (high) | agent logs `identity: backend reports a DIFFERENT key`, stops; finding in console |
| T1c identity key export (Windows, TPM) | `t1_tpm_key_export.ps1` | `$env:TRAPD_ADVERSARIAL_OK=1; .\t1_tpm_key_export.ps1` elevated on a bound Windows agent | no event; every export route fails: `certutil -csp "Microsoft Platform Crypto Provider" -key` / `-exportPFX`, `CngKey.Export(EccPrivateBlob)`; credentials.json has no secret | script prints `RESULT: PASS`; a `FAIL` line means the key is exportable (software provider keys must also refuse: export policy 0) |
| T2 kill the agent or the guard | see command | Linux: `sudo -E ./T2_T3_guard_pair.sh kill agent` (or `guard`). Windows (as SYSTEM): `.\T2_T3_guard_pair.ps1 -Mode kill -Target agent` | The peer restarts the killed service within seconds; event `selfprotect.peer_lost` with `peer`, `reason: died`, `announced_stop: false`, `maintenance_authorized: false` | The script waits for the new pid and greps `events.ndjson`; in the console look for the finding on the host. A planned stop (`systemctl stop`, MSI upgrade/uninstall, maintenance token) must produce no restart and no `peer_lost`. |
| T3 suspend the agent or the guard (alive but mute) | see command | Linux: `sudo -E ./T2_T3_guard_pair.sh suspend agent`. Windows (as SYSTEM): `.\T2_T3_guard_pair.ps1 -Mode suspend -Target agent` (`NtSuspendProcess`) | After about 10 s of silence the peer terminates the hung process, restarts the service and emits `selfprotect.peer_lost` with `reason: hung` | Same; the script resumes a suspended process on exit. As an administrator without SeDebugPrivilege the process DACL refuses the suspend (reported as BLOCKED, expected). |
| T4 WFP block (Windows) | `T4-wfp-block-windows.ps1` | `New-NetFirewallRule -Direction Outbound -Action Block -Program <agent exe>` (EDRSilencer-style app-id block filter), removed after 75 s | `selfprotect.network_silenced`, high, evidence `filter_name`, `provider` ("Microsoft Windows Firewall"), `layer`, `reason=app_id`, within ~65 s (change notification) | Detections list; events queued during the block arrive after removal |
| T4 iptables owner DROP (Linux) | `T4-iptables-uid-linux.sh` | `iptables -A OUTPUT -m owner --uid-owner <uid> -j DROP` | `selfprotect.network_silenced`, high, `source=iptables`, `reason=uid` | as above; `nft` rules are parsed the same way |
| T4 selective block (MANUAL) | none | set `TRAPD_NETWORK_PROBE_URL=https://<neutral EU endpoint>`, then block only the backend address | after 3 scans (~3 min) `selfprotect.backend_unreachable_selective`, medium | delivered once the block is removed |
| T5 hosts redirect (Windows) | `T5-hosts-redirect-windows.ps1 -BackendHost <host>` | hosts entry `203.0.113.66 <backend host>`, restored | `selfprotect.backend_redirected`, high, `vector=hosts` | Detections list |
| T5 hosts redirect (Linux) | `T5-hosts-redirect-linux.sh` | same on `/etc/hosts` | same | same |
| T5 TLS interception (MANUAL) | none | set `TRAPD_BACKEND_SPKI_PINS` to a wrong pin, restart the agent; or front the backend with a proxy whose CA is in `ca.crt` | handshake refused, `selfprotect.tls_pin_mismatch`, high, `observed_spki_sha256` lists the presented chain; delivered after the correct pin is restored | agent log; unset the variable and restart to recover. Report-only mode (no pins) writes `observed_spki_pins.json` to the state dir |
| T5 proxy / NRPT (MANUAL) | none | `netsh winhttp set proxy 127.0.0.1:3128`, or `Add-DnsClientNrptRule -Namespace .<backend domain> -NameServers 203.0.113.53`. Revert: `netsh winhttp reset proxy`, `Get-DnsClientNrptRule \| Remove-DnsClientNrptRule` | `selfprotect.backend_redirected`, vector `proxy_winhttp` (medium) / `nrpt` (high) | Detections list |
| T6 Debugger / DLL injection into the agent | `T6_T7_linux.sh` | `TRAPD_ADVERSARIAL_OK=1 ./T6_T7_linux.sh` | `selfprotect.debugger_attached` (tracer pid, comm, exe) within ~60 s; also the 10 s `AgentTamper` ptrace event | agent log `process integrity finding`, console alert |
| T6 Remote DLL load (Windows) | `T6_T7_windows.ps1` | `$env:TRAPD_ADVERSARIAL_OK=1; .\T6_T7_windows.ps1` (elevated) | `selfprotect.module_injected` (path outside System32/install dir, sha256), `selfprotect.handle_access` (the PowerShell process with VM_WRITE/CREATE_THREAD) within ~60 s | console alert; agent log |
| T7 Memory implant (Linux) | `T6_T7_linux.sh` | same run (gdb maps an rwx page) | `selfprotect.module_injected`, reason `anonymous_rwx` | as above |
| T7 ETW patch (Windows) | `T6_T7_windows.ps1` | same run (writes `ret` over `EtwEventWrite`, restores it) | `selfprotect.code_patched`, subject `ntdll.dll!EtwEventWrite`, expected vs actual bytes | console alert |
| T10 posture (Linux) | `T10-posture-linux.sh` | `ptrace_scope` 1 -> 0 | `selfprotect.platform_posture_changed`, high, key `yama_ptrace_scope`, before=1 after=0; info after restore | Detections list, or agent log "platform posture changed" |
| T10 posture (Windows) | `T10-posture-windows.ps1` | `VulnerableDriverBlocklistEnable` 1 -> 0, service restarts | same rule, high, key `driver_blocklist` | same |
| T10 test-signing (Windows, MANUAL) | none (needs reboot) | `bcdedit /set testsigning on`, reboot. Revert: `bcdedit /set testsigning off`, reboot | high `platform_posture_changed` key `test_signing` off -> on; measured-boot round may add a medium `measured_boot` finding | Revert and confirm the info/strengthened event. Do not do this on a production host; Secure Boot blocks the command when enabled |
| T10 kernel debugger (Windows, MANUAL) | none | `bcdedit /debug on`, reboot. Revert: `bcdedit /debug off`, reboot | high, key `kernel_debugger` | as above |
| T11 clock jump | `T11-clock-jump.sh` / `.ps1` | wall clock -1 h for 70 s, restored | `selfprotect.time_jump`, medium, direction backward (and forward on restore) | Detections list; `evidence.skew_secs` about -3600 |
| T13 delete or restore the local tamper journal | `t13_journal_delete.sh` / `t13_journal_delete.ps1` | `TRAPD_ADVERSARIAL_OK=1 ./t13_journal_delete.sh` (root) / `$env:TRAPD_ADVERSARIAL_OK=1; .\t13_journal_delete.ps1` (elevated) on a bound test agent with some acknowledged journal entries | the agent restarts its chain at seq 1; backend answers 409 and records `selfprotect.journal_gap` (high, reason `fork` or `regression`); a restored old file is detected the same way (backend ahead of the file) | finding in console; agent log `backend rejected the tamper journal`; the script restores the original file afterwards. Unit-level equivalents: `agent_journal_smoke.sql` steps 5-6 and `test-agent-journal-route.mts` T13 rows |

## Notes

Not covered by a script (needs a window of two kills within about 10 s, which
is the stated custom-tooling bar of the guard pair): killing agent and guard
together. The expected outcome there is the backend's heartbeat gap, not a
local event.

False-positive switches: `TRAPD_SELFPROTECT_CHECK_{CODE,MODULES,THREADS,DEBUGGER,HANDLES}=off`,
`TRAPD_SELFPROTECT_MODULE_ALLOW`, `TRAPD_SELFPROTECT_HANDLE_ALLOW`.

Hosts-file and proxy findings that are legitimate (on-prem backend, corporate proxy) are silenced with `TRAPD_NETWORK_GUARD_ALLOW` (for example `203.0.113.66` or the proxy `host:port`).

Not covered by scripts: clock change while the agent is stopped (stop agent, `date -s`, start agent; the persisted anchor reports it at start, `across_reboot=false` on the same boot).
