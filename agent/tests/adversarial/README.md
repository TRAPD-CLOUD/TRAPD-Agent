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
