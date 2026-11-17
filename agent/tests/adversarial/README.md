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
