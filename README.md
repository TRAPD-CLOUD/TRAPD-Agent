# TRAPD-Agent

A lightweight, open-source Linux cybersecurity telemetry agent written in Rust.

Collects process, network, and system events and emits them as NDJSON to stdout or a log file for consumption by a frontend or SIEM.

## Features

- **Process monitoring** — detects new and terminated processes every 3 seconds
- **Network monitoring** — tracks established TCP connections every 5 seconds with PID resolution
- **System snapshots** — emits OS/CPU/memory/uptime data at startup and every 60 seconds
- **NDJSON output** — one JSON object per line, stable snake_case field names
- **Persistent agent identity** — UUID stored in `~/.trapd/agent_id`

## Requirements

- Linux (x86_64)
- Rust 1.75+
- Run as root or with `CAP_NET_ADMIN` for full network + PID resolution

## Build

```sh
cargo build --release
```

## Run

```sh
# Output to stdout (default)
./target/release/trapd-agent

# Output to /var/log/trapd/events.ndjson
TRAPD_OUTPUT=file ./target/release/trapd-agent

# Enable debug logging
RUST_LOG=debug ./target/release/trapd-agent 2>/dev/null | jq .
```

## Event Schema

Every event is a single JSON line:

```json
{
  "event_id":  "uuid-v4",
  "agent_id":  "uuid-v4",
  "hostname":  "myserver",
  "timestamp": "2025-04-30T14:32:01.123Z",
  "class":     "process|network|system",
  "action":    "create|terminate|connection|snapshot",
  "severity":  "info|low|medium|high",
  "data":      {}
}
```

## Output Modes

| `TRAPD_OUTPUT` | Destination |
|---|---|
| `stdout` (default) | stdout, one line per event |
| `file` | `/var/log/trapd/events.ndjson` (directory created automatically) |

All log/diagnostic output goes to stderr.
