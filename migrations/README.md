# Backend migrations

Schema for the **TRAPD backend** datastores that receive the agent's events.
The agent itself is stateless on the wire — it POSTs `AgentEvent` JSON to
`/api/v1/ingest/events`. These migrations give the backend first-class storage
for the **IOA (Indicator-of-Attack) findings** the agent now emits: completed
attack chains (`class=detection`, `rule_id` prefixed `ioa.`), each carrying its
full stage trail and the acting process's lineage.

Two stores, mirroring the production split:

| Directory     | Store                         | Apply with                                  |
|---------------|-------------------------------|---------------------------------------------|
| `postgres/`   | Supabase Postgres (control)   | Supabase MCP / `supabase db push` / `psql`  |
| `clickhouse/` | ClickHouse (event analytics)  | `clickhouse-client < file.sql`              |

> **Note:** the ClickHouse migration is laid down here but **not applied** from
> this environment (no ClickHouse connectivity yet). Apply it on the analytics
> tier when reachable. The Supabase migration can be applied via the Supabase
> MCP/CLI.

Migrations are ordered by filename prefix and are idempotent
(`create table if not exists`), so re-running is safe.

## IOA finding shape

A finding's `evidence` JSON looks like:

```json
{
  "chain": ["interactive shell", "network downloader spawned", "executes dropped payload"],
  "stages": [
    {"stage": 0, "label": "interactive shell",          "pid": 200, "offset_ms": 0},
    {"stage": 1, "label": "network downloader spawned",  "pid": 300, "offset_ms": 1200},
    {"stage": 2, "label": "executes dropped payload",    "pid": 301, "offset_ms": 2400}
  ],
  "anchor_pid": 200,
  "final_pid": 301,
  "duration_ms": 2400,
  "process_lineage": [
    {"pid": 301, "comm": "x",    "exe": "/tmp/x",        "exe_sha256": "…"},
    {"pid": 200, "comm": "bash", "exe": "/bin/bash",     "exe_sha256": "…"},
    {"pid": 100, "comm": "sshd", "exe": "/usr/sbin/sshd"}
  ]
}
```
