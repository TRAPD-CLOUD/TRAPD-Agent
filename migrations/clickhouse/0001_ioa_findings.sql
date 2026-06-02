-- IOA (Indicator-of-Attack) findings — ClickHouse analytics projection.
--
-- Mirrors migrations/postgres/0001_ioa_findings.sql for the high-volume event
-- analytics tier. JSON blobs are stored as String (parse with JSONExtract* at
-- query time) to stay schema-flexible as chains evolve. Idempotent.
--
-- NOTE: laid down but not applied from CI — apply on the ClickHouse tier when
-- reachable.

create table if not exists ioa_findings
(
    event_id         UUID,
    agent_id         String,
    hostname         String,
    detected_at      DateTime64(3, 'UTC'),

    rule_id          LowCardinality(String),
    title            String,
    category         LowCardinality(String),
    mitre_tactic     LowCardinality(String),
    mitre_technique  LowCardinality(String),
    confidence       UInt8,
    severity         LowCardinality(String),

    anchor_pid       Int32,
    final_pid        Int32,
    duration_ms      UInt64,

    stages           String,   -- JSON array
    process_lineage  String,   -- JSON array
    evidence         String,   -- JSON object

    ingested_at      DateTime64(3, 'UTC') default now64(3)
)
engine = MergeTree
partition by toYYYYMM(detected_at)
order by (agent_id, detected_at, rule_id)
ttl toDateTime(detected_at) + interval 180 day;
