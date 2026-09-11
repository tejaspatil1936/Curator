-- Curator schema — system_design.md §5.
--
-- Runs once, on first boot of an empty pgdata volume (docker-entrypoint-initdb.d,
-- executed with ON_ERROR_STOP). For schema changes during the build, add a numbered
-- file (002_*.sql) and run `make reset`.
--
-- Tables match §5 exactly, with one ordering change: events.incident_id references
-- incidents, but §5 defines events first. events is created with the incident_id
-- column and no constraint; the FK is added by ALTER TABLE once incidents exists,
-- under the name Postgres would have generated for the inline form.

BEGIN;

CREATE EXTENSION IF NOT EXISTS vector;

-- §5.1 events — the atoms ----------------------------------------------------

CREATE TABLE events (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL,          -- event time, NOT ingest time
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    source          TEXT NOT NULL,                 -- 'sysmon' | 'winsec' | 'powershell'
                                                   -- | 'winevt' | 'auditd'
    host            TEXT,
    user_name       TEXT,
    process_name    TEXT,
    process_id      INTEGER,
    parent_process  TEXT,
    src_ip          INET,
    dst_ip          INET,
    file_path       TEXT,
    command_line    TEXT,
    event_code      TEXT,                          -- e.g. Sysmon '1', '10'
    ocsf            JSONB NOT NULL,                -- full normalized event
    raw             JSON NOT NULL,                 -- original, byte-identical (json, not jsonb:
                                                   -- jsonb re-serializes and reorders keys)
    dedup_key       TEXT,
    is_duplicate    BOOLEAN NOT NULL DEFAULT false,
    canonical_id    BIGINT REFERENCES events(id),  -- set if is_duplicate
    incident_id     BIGINT,                        -- FK to incidents(id), added below
    is_planted      BOOLEAN NOT NULL DEFAULT false -- the demo's false alert
);

CREATE INDEX idx_events_ts        ON events (ts);
CREATE INDEX idx_events_host      ON events (host);
CREATE INDEX idx_events_incident  ON events (incident_id);
CREATE INDEX idx_events_ocsf_gin  ON events USING GIN (ocsf);
CREATE INDEX idx_events_dedup     ON events (dedup_key);

-- Ingest idempotency: exactly one row per source record. The parser sets
-- ocsf.metadata.uid to "<dataset>/<file>:<line>". Deliberately not a content hash:
-- byte-identical records in the source are distinct events that Step 3 dedup must see.
CREATE UNIQUE INDEX idx_events_source_uid ON events ((ocsf #>> '{metadata,uid}'));

-- §5.2 incidents -------------------------------------------------------------

CREATE TABLE incidents (
    id              BIGSERIAL PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    title           TEXT,                    -- LLM-generated
    first_seen      TIMESTAMPTZ NOT NULL,    -- deterministic
    last_seen       TIMESTAMPTZ NOT NULL,    -- deterministic
    event_count     INTEGER NOT NULL,
    raw_alert_count INTEGER NOT NULL,        -- before dedup — for the "500 → 6" reveal
    hosts           TEXT[],
    users           TEXT[],
    priority        INTEGER NOT NULL,        -- 0-100, deterministic
    priority_reason JSONB,                   -- which factors contributed
    confidence      NUMERIC(4,3),            -- updated by challenge cycle
    status          TEXT NOT NULL DEFAULT 'open'
);

-- Closes the events <-> incidents cycle.
ALTER TABLE events
    ADD CONSTRAINT events_incident_id_fkey
    FOREIGN KEY (incident_id) REFERENCES incidents(id);

-- §5.1b alerts (Step 3 detection stage) --------------------------------------

CREATE TABLE alerts (
    id            BIGSERIAL PRIMARY KEY,
    event_id      BIGINT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    rule_id       TEXT NOT NULL,
    rule_name     TEXT NOT NULL,
    severity      TEXT NOT NULL,           -- low|medium|high|critical
    technique_ids TEXT[],                  -- rule author's hint. NEVER used for scoring.
    ts            TIMESTAMPTZ NOT NULL,
    host          TEXT,                    -- normalized endpoint (Hostname, not collector)
    user_norm     TEXT,
    process_uid   TEXT,
    dedup_key     TEXT,
    is_duplicate  BOOLEAN NOT NULL DEFAULT false,
    canonical_id  BIGINT REFERENCES alerts(id),
    incident_id   BIGINT REFERENCES incidents(id) ON DELETE SET NULL,
    is_planted    BOOLEAN NOT NULL DEFAULT false
);

COMMENT ON COLUMN alerts.technique_ids IS 'alerts.technique_ids must never reach the accuracy harness. Scoring against labels a rule author wrote would make the evaluation circular.';

CREATE INDEX idx_alerts_ts        ON alerts (ts);
CREATE INDEX idx_alerts_host      ON alerts (host);
CREATE INDEX idx_alerts_incident  ON alerts (incident_id);
CREATE INDEX idx_alerts_dedup     ON alerts (dedup_key);
CREATE INDEX idx_alerts_event     ON alerts (event_id);

-- §5.3 entities and entity_edges ---------------------------------------------

CREATE TABLE entities (
    id           BIGSERIAL PRIMARY KEY,
    incident_id  BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,   -- host|user|ip|process|file|hash
    value        TEXT NOT NULL,
    first_seen   TIMESTAMPTZ,
    last_seen    TIMESTAMPTZ,
    event_ids    BIGINT[] NOT NULL,
    enrichment   JSONB,           -- IOC lookup results, if any
    UNIQUE (incident_id, kind, value)
);

CREATE TABLE entity_edges (
    id           BIGSERIAL PRIMARY KEY,
    incident_id  BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    src_id       BIGINT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    dst_id       BIGINT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relation     TEXT NOT NULL,   -- executed|connected_to|authenticated_as|wrote|spawned
    event_ids    BIGINT[] NOT NULL
);

-- §5.4 narrative_sentences — the most important table ------------------------

CREATE TABLE narrative_sentences (
    id                 BIGSERIAL PRIMARY KEY,
    incident_id        BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    seq                INTEGER NOT NULL,          -- display order
    text               TEXT NOT NULL,
    evidence_event_ids BIGINT[] NOT NULL DEFAULT '{}',
    technique_id       TEXT,                      -- e.g. 'T1059.001'
    technique_name     TEXT,
    technique_conf     NUMERIC(4,3),
    generated_by       TEXT NOT NULL,             -- model id
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (incident_id, seq)
);

-- §5.5 verifications ---------------------------------------------------------

CREATE TABLE verifications (
    id           BIGSERIAL PRIMARY KEY,
    sentence_id  BIGINT NOT NULL REFERENCES narrative_sentences(id) ON DELETE CASCADE,
    supported    BOOLEAN NOT NULL,
    reason       TEXT,
    checked_ids  BIGINT[],
    model        TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- §5.6 techniques — ATT&CK, with embeddings ----------------------------------

CREATE TABLE techniques (
    id           TEXT PRIMARY KEY,        -- 'T1059.001'
    name         TEXT NOT NULL,
    tactic       TEXT[],
    description  TEXT,
    embedding    vector(384),             -- BAAI/bge-small-en-v1.5 (fastembed, local)
    search_tsv   tsvector GENERATED ALWAYS AS (
        to_tsvector('english', name || ' ' || coalesce(description, ''))
    ) STORED                              -- keyword half of hybrid retrieval
);

CREATE INDEX idx_tech_embedding ON techniques
    USING hnsw (embedding vector_cosine_ops);
CREATE INDEX idx_tech_search_tsv ON techniques USING GIN (search_tsv);

-- §5.7 audit_chain — tamper evidence -----------------------------------------

CREATE TABLE audit_chain (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT NOT NULL,          -- 'pipeline' | 'ai:<model>' | 'analyst'
    action      TEXT NOT NULL,
    detail      JSONB,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);

-- §5.8 ground_truth — for the accuracy reveal --------------------------------

CREATE TABLE ground_truth (
    id           BIGSERIAL PRIMARY KEY,
    dataset      TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    ts           TIMESTAMPTZ,
    note         TEXT
);

COMMIT;
