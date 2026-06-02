-- IOA (Indicator-of-Attack) findings — completed attack chains correlated by
-- the agent across the process tree and time.  Supabase / Postgres.
--
-- These arrive in the normal event stream as detections with rule_id prefixed
-- `ioa.`; this table is the queryable, normalised projection the SOC UI and
-- alerting build on.  Idempotent: safe to re-run.

create table if not exists public.ioa_findings (
    id               uuid        primary key default gen_random_uuid(),
    -- Correlates back to the raw AgentEvent.event_id.
    event_id         uuid        not null,
    agent_id         text        not null,
    hostname         text        not null,
    detected_at      timestamptz not null default now(),

    rule_id          text        not null,   -- e.g. ioa.download_and_execute
    title            text        not null,
    category         text        not null,   -- ioa.execution / ioa.privilege_escalation / ...
    mitre_tactic     text,
    mitre_technique  text,
    confidence       smallint    not null check (confidence between 0 and 100),
    severity         text        not null,   -- info|low|medium|high|critical

    -- Chain shape.
    anchor_pid       integer,                -- process that opened the chain
    final_pid        integer,                -- process that completed it
    duration_ms      bigint,                 -- start → completion span

    -- Full structured detail (see migrations/README.md for the shape).
    stages           jsonb       not null default '[]'::jsonb,
    process_lineage  jsonb,
    evidence         jsonb,

    created_at       timestamptz not null default now()
);

-- Per-agent timeline (the dominant query: "show this host's recent IOAs").
create index if not exists ioa_findings_agent_time_idx
    on public.ioa_findings (agent_id, detected_at desc);

-- Hunting by rule and by ATT&CK technique.
create index if not exists ioa_findings_rule_idx
    on public.ioa_findings (rule_id);
create index if not exists ioa_findings_technique_idx
    on public.ioa_findings (mitre_technique)
    where mitre_technique is not null;

-- De-duplicate retries of the same emitted finding.
create unique index if not exists ioa_findings_event_id_uidx
    on public.ioa_findings (event_id);

comment on table public.ioa_findings is
    'Completed IOA attack chains correlated by the TRAPD agent (stateful, multi-event).';

-- Row-level security: enable and let the backend service role manage access.
-- Tenant-scoped policies are defined alongside the existing events tables; this
-- migration only turns RLS on so the table is not world-readable by default.
alter table public.ioa_findings enable row level security;
