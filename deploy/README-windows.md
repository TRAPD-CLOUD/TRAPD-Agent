# TRAPD Agent on Windows

The Windows agent is the same `trapd-agent` binary cross-compiled for
`x86_64-pc-windows-gnu` (release asset: `trapd-agent-windows-x86_64.exe`).
It reuses the Linux agent's enrollment, heartbeat, config and ingest
channels and emits the identical OCSF-based NDJSON event schema.

## Install (run from an elevated prompt)

```bat
trapd-agent.exe install
```

Registers and starts the **trapd-agent** Windows Service (auto-start at
boot, runs as LocalSystem). The binary is registered at its current
location, so copy it somewhere permanent first, e.g.
`C:\Program Files\trapd\trapd-agent.exe`.

## Configure

Filesystem layout (override with `TRAPD_STATE_DIR` / `TRAPD_CONFIG_DIR` /
`TRAPD_LOG_DIR`):

| Kind   | Default                       | Contents                          |
|--------|-------------------------------|-----------------------------------|
| state  | `C:\ProgramData\trapd\state`  | `device_id`, `credentials.json`   |
| config | `C:\ProgramData\trapd\config` | `agent.env`, `ca.crt`, certs      |
| logs   | `C:\ProgramData\trapd\logs`   | `events.ndjson`, `agent.log`      |

Backend connection goes in `C:\ProgramData\trapd\config\agent.env`
(same `KEY=VALUE` format the systemd unit consumes on Linux):

```
TRAPD_BACKEND_URL=https://backend.example.com
TRAPD_ENROLL_TOKEN=<enrollment token>
```

Without a backend URL the agent runs in offline mode and only writes
local telemetry. TLS pinning is fail-closed exactly as on Linux: provision
`config\ca.crt` or explicitly set `TRAPD_TLS_ALLOW_SYSTEM_ROOTS=1`.

## Run in the foreground (debugging)

```bat
trapd-agent.exe run
```

Logs go to stderr; in service mode they go to
`C:\ProgramData\trapd\logs\agent.log`.

## Uninstall (elevated)

```bat
trapd-agent.exe uninstall
```

Stops the service, deletes the registration, then schedules removal of the
binary itself. Enrollment state under `C:\ProgramData\trapd` is left in
place so a reinstall keeps the same agent identity; delete that directory
to fully deregister the host.

## Telemetry collected (MVP)

- `system/snapshot` — CPU count/usage, memory, uptime, OS + build version
- `process/create`, `process/terminate` — process table diff (pid, ppid,
  exe, cmdline, user)
- `user/session_open`, `user/session_close` — logged-on users via `quser`
- Heartbeat every 30 s with live resource metrics (same payload as Linux)
