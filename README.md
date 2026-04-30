# TRAPD Agent

TRAPD Agent is a lightweight Linux security telemetry agent written in Rust. It continuously monitors process activity, network connections, filesystem changes, and system health, streaming structured NDJSON events to a TRAPD backend or local log file.

## Installation

```sh
curl -sSL https://raw.githubusercontent.com/trapd-cloud/trapd-agent/main/deploy/install.sh | sudo bash
```

The installer fetches the latest release binary from GitHub, installs it to `/usr/local/bin/trapd-agent`, registers a systemd service, and sets up a daily auto-update timer.

## Configuration

Edit `/etc/trapd/agent.env` after installation:

```sh
nano /etc/trapd/agent.env
```

```ini
# Required: URL of your TRAPD backend
TRAPD_BACKEND_URL=https://your-backend.com

# Optional: pre-shared agent token (obtained automatically via enrollment if omitted)
TRAPD_TOKEN=your-token

# Optional: output destination — "file" writes to /var/log/trapd/events.ndjson
TRAPD_OUTPUT=file

# Optional: log verbosity (default: info)
RUST_LOG=info
```

Apply changes:

```sh
systemctl restart trapd-agent
```

## Collected Telemetry

| Event class  | Event type         | Data collected                                              | Frequency         |
|--------------|--------------------|-------------------------------------------------------------|-------------------|
| `process`    | `create`           | PID, name, exe path, cmdline, UID, username, PPID           | Every 3 s         |
| `process`    | `terminate`        | PID, name                                                   | Every 3 s         |
| `network`    | `connection`       | Protocol, src/dst address+port, state, PID, process name    | Every 5 s         |
| `system`     | `snapshot`         | CPU %, memory used/total, uptime, load avg, OS, kernel      | Startup + 60 s    |
| `filesystem` | `create/delete/modify` | File path under `/etc`, `/bin`, `/tmp`                  | On change (inotify) |
| `user`       | `logon`            | Username, source IP, auth method, success/failure           | On auth.log entry |
| `user`       | `session_open/close` | Username                                                  | On auth.log entry |

All events share a common envelope:

```json
{
  "event_id":  "uuid-v4",
  "agent_id":  "uuid-v4",
  "hostname":  "myserver",
  "timestamp": "2025-04-30T14:32:01.123Z",
  "class":     "process",
  "action":    "create",
  "severity":  "info",
  "data":      {}
}
```

## Manual Update

Run the updater at any time:

```sh
sudo trapd-update
```

The updater compares the installed version against the latest GitHub release and replaces the binary atomically if a newer version is available. A systemd timer also runs `trapd-update` automatically every day at 03:00.

## Building from Source

```sh
# Requires Rust 1.75+ and a Linux x86_64 host
cargo build --release --manifest-path agent/Cargo.toml
cp target/release/trapd-agent /usr/local/bin/trapd-agent
```

## Releasing a New Version

```sh
git tag v0.2.0
git push origin v0.2.0
```

The `release` GitHub Actions workflow triggers on tag push, builds the release binary, and publishes it to GitHub Releases. The auto-updater on installed agents will pick it up within 24 hours.
