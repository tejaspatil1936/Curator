# Curator — System Design

> **Every conclusion, traced to its evidence.**

AI-assisted security investigation system for SOC analysts. Correlates alerts and
logs, reconstructs attack timelines, maps to MITRE ATT&CK, and proposes
evidence-backed next steps — where *every* generated sentence is linked to the raw
log line that supports it.

Built for hackathon problem statement PS05 (Advanced).

---

## 0. How to use this document

This is the **reference specification**, not a build order. Claude Code should keep
this open and consult it for schema, contracts, naming, and conventions.

Work proceeds in **numbered steps** (Section 12). Each step is requested separately.
**Do not build ahead.** If a step's prompt conflicts with this document, the prompt wins
for that step — but flag the conflict.

### Companion document

`DESIGN.md` in this directory is the **complete interface specification** — colour,
type, layout, components, motion, copy, accessibility. It is authoritative for anything
visual.

**Precedence, in order:**

1. The current step's prompt
2. `DESIGN.md` — for anything visual
3. This document — for everything else

Read `DESIGN.md` before writing any frontend code. Do not infer visual decisions from
this document; Section 9 here is a pointer, not a specification.

---

## 1. The core principle (read this first)

**The deterministic layer decides what happened. The AI layer only describes it.**

| Decided by Python (never by an LLM) | Decided by an LLM |
| --- | --- |
| Which events are duplicates | How to narrate the incident in English |
| Which events belong to one incident | Which ATT&CK technique a step matches |
| The order of events in the timeline | What to recommend next, and why |
| Which entities are linked to which | Whether a sentence is supported by evidence |
| Incident priority score | Alternative hypotheses / what's missing |

This separation is the project's answer to the evaluation criteria "evidence grounding"
and "hallucination resistance." It is an architectural guarantee, not a prompt
instruction.

**Consequences that must hold everywhere in the code:**

1. An LLM never reorders, invents, or infers a timestamp. Timestamps are data.
2. An LLM never decides two events are related. Correlation is code.
3. Every generated sentence carries `evidence_event_ids`. A sentence with an empty
   evidence list is rendered struck-through, never silently dropped.
4. The LLM receives only already-correlated facts as input. It never sees the raw
   unfiltered log firehose and is never asked "what happened here?"

---

## 2. Non-negotiables (the four demo moments)

Everything else in this system is negotiable. These four are not. If time runs short,
cut features in the order given in Section 12.4 — never these.

1. **Click-to-evidence.** Click any sentence in the narrative → the exact raw log
   line(s) behind it appear. This is the single highest-value interaction.
2. **Strike-out.** A planted false alert produces an unsupported sentence; the verifier
   flags it; the UI renders it struck through. Live proof of hallucination resistance.
3. **Accuracy reveal.** Curator's reconstructed technique list vs. the dataset's
   ground-truth technique list, side by side, with real numbers:
   `N executed / M recovered / K invented`.
4. **Challenge.** A button that makes the system argue against its own conclusion,
   name the missing evidence, run a query to check, and update its confidence.

---

## 3. Architecture

### 3.1 Local (Steps 1–6 — the entire build happens here)

```
┌──────────────────────────────────────────────────────────────┐
│  DEV MACHINE (Kali Linux) — docker compose up                 │
│                                                               │
│  ┌──────────────┐   ┌───────────────┐   ┌─────────────────┐  │
│  │ curator-web  │   │ curator-api   │   │ curator-db      │  │
│  │ React + Vite │──▶│ FastAPI       │──▶│ Postgres 16     │  │
│  │ :5173        │   │ :8000         │   │ + pgvector      │  │
│  └──────────────┘   │               │   │ :5432           │  │
│                     │ + pipeline    │   │ volume: pgdata  │  │
│                     │   (APScheduler)│  └─────────────────┘  │
│                     └───────┬───────┘                        │
│                             │                                │
│  datasets/ ────mounted─────▶│                                │
│  (Security-Datasets JSON)   │                                │
└─────────────────────────────┼────────────────────────────────┘
                              ▼
                      Anthropic API (key from api/.env)
```

Three containers. One command: `make up`.

### 3.2 AWS (Step 7 only — a deploy target, not a dependency)

```
Terraform-provisioned, ap-south-1:

  VPC ─ public subnet ─ SG (SSH from my IP only, 443 from anywhere)
    └─ EC2 t3.medium (Ubuntu 24.04)
         ├─ curator-db   (Postgres container, EBS-backed volume)
         ├─ curator-api  (FastAPI container)
         └─ Caddy        (automatic HTTPS reverse proxy)

  Frontend → Vercel (separate, points at the EC2 HTTPS endpoint)
```

Identical containers to local. Nothing rearchitects between local and cloud.

### 3.3 Drawn but not built (the "production shape" slide)

S3 log ingestion → Lambda parsers → DynamoDB audit chain → Step Functions
orchestration. These appear on the architecture slide as the production decomposition.
**Do not build them.** They add zero evaluated value and cost the whole weekend.

---

## 4. Repository layout

```
curator/
├── docker-compose.yml
├── Makefile
├── README.md
├── system_design.md            # this file — architecture, data, contracts
├── DESIGN.md                   # interface spec — authoritative for all UI
├── .env.example                # template; real .env is gitignored
│
├── api/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── .env                    # GITIGNORED — never commit
│   └── curator/
│       ├── main.py             # FastAPI app + routes
│       ├── config.py           # env loading, model IDs
│       ├── db.py               # connection pool, session
│       ├── models.py           # SQLAlchemy / pydantic models
│       │
│       ├── ingest/
│       │   ├── ocsf.py         # OCSF event schema + validators
│       │   ├── sysmon.py       # Sysmon/Windows Security → OCSF
│       │   ├── auditd.py       # Linux auditd → OCSF
│       │   └── seed.py         # dataset loader
│       │
│       ├── pipeline/           # ★ DETERMINISTIC — NO LLM CALLS IN HERE
│       │   ├── dedup.py
│       │   ├── correlate.py
│       │   ├── timeline.py
│       │   ├── entities.py
│       │   ├── priority.py
│       │   └── runner.py       # the scheduled loop
│       │
│       ├── ai/                 # ★ ALL LLM CALLS LIVE HERE, NOWHERE ELSE
│       │   ├── client.py       # Anthropic client, caching, retry/backoff
│       │   ├── narrative.py    # Sonnet — story generation
│       │   ├── mapping.py      # Sonnet — ATT&CK mapping
│       │   ├── recommend.py    # Sonnet — next steps
│       │   ├── challenge.py    # Sonnet — adversarial critique
│       │   ├── verify.py       # Haiku — per-sentence grounding check
│       │   └── extract.py      # Haiku — IOC extraction
│       │
│       ├── attack/
│       │   ├── load_attack.py  # ATT&CK STIX → techniques table
│       │   └── retrieve.py     # pgvector similarity search
│       │
│       ├── audit.py            # hash-chained audit log
│       └── eval/
│           └── harness.py      # accuracy scoring vs ground truth
│
├── db/
│   └── init/
│       └── 001_schema.sql      # auto-runs on first container boot
│
├── web/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── App.jsx
│       ├── api.js              # fetch wrappers
│       └── components/
│           ├── IncidentList.jsx
│           ├── Timeline.jsx
│           ├── Narrative.jsx       # ★ click-to-evidence lives here
│           ├── EvidencePanel.jsx   # ★ raw log display
│           ├── AttackGrid.jsx
│           ├── ChallengePanel.jsx
│           └── Scoreboard.jsx      # ★ accuracy reveal
│
├── datasets/                   # gitignored — downloaded, not committed
│   └── apt29/
│
└── infra/                      # Step 7 only
    ├── main.tf
    ├── variables.tf
    └── outputs.tf
```

**Hard rule:** no file in `pipeline/` may import from `ai/`. The dependency arrow points
one way only: `ai/` may read pipeline output; `pipeline/` never calls an LLM. Enforce
this in review.

---

## 5. Data model

Postgres 16 + pgvector. Full DDL lives in `db/init/001_schema.sql`.

### 5.1 `events` — the atoms

Every normalized log line. Everything else references these by ID.

```sql
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
    raw             JSON NOT NULL,                 -- original, byte-identical
    dedup_key       TEXT,
    is_duplicate    BOOLEAN NOT NULL DEFAULT false,
    canonical_id    BIGINT REFERENCES events(id),  -- set if is_duplicate
    incident_id     BIGINT REFERENCES incidents(id),
    is_planted      BOOLEAN NOT NULL DEFAULT false -- the demo's false alert
);

CREATE INDEX idx_events_ts        ON events (ts);
CREATE INDEX idx_events_host      ON events (host);
CREATE INDEX idx_events_incident  ON events (incident_id);
CREATE INDEX idx_events_ocsf_gin  ON events USING GIN (ocsf);
CREATE INDEX idx_events_dedup     ON events (dedup_key);
CREATE UNIQUE INDEX idx_events_source_uid ON events ((ocsf #>> '{metadata,uid}'));
```

`raw` is never modified. It is what click-to-evidence displays. It is `json`, not
`jsonb`: `json` stores the exact source text, while `jsonb` re-serializes (reorders keys,
drops whitespace), which would break the byte-identical guarantee. Read it back as
`raw::text`, never through a JSON decoder.

`idx_events_source_uid` makes ingest idempotent: the parser sets `ocsf.metadata.uid` to
`<dataset>/<file>:<line>`. It is deliberately not a content hash — identical records in
the source are distinct events, and dedup (§6.1) must see them.

### 5.2 `incidents`

```sql
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
```

### 5.3 `entities` and `entity_edges`

Built deterministically. Powers the (optional) graph; also feeds LLM context.

```sql
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
```

### 5.4 `narrative_sentences` — ★ the most important table

This is what makes click-to-evidence work. A sentence is not text; it is text **plus its
evidence**.

```sql
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
```

The LLM is required to return evidence IDs alongside each sentence. Any returned ID that
does not exist in `events` for that incident is **dropped at parse time, in Python**,
before it is written. A sentence left with an empty array is exactly what the verifier
should catch.

### 5.5 `verifications`

```sql
CREATE TABLE verifications (
    id           BIGSERIAL PRIMARY KEY,
    sentence_id  BIGINT NOT NULL REFERENCES narrative_sentences(id) ON DELETE CASCADE,
    supported    BOOLEAN NOT NULL,
    reason       TEXT,
    checked_ids  BIGINT[],
    model        TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 5.6 `techniques` — ATT&CK, with embeddings

```sql
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE techniques (
    id           TEXT PRIMARY KEY,        -- 'T1059.001'
    name         TEXT NOT NULL,
    tactic       TEXT[],
    description  TEXT,
    embedding    vector(384),             -- BAAI/bge-small-en-v1.5 via fastembed, local
    search_tsv   tsvector GENERATED ALWAYS AS (
        to_tsvector('english', name || ' ' || coalesce(description, ''))
    ) STORED
);

CREATE INDEX idx_tech_embedding ON techniques
    USING hnsw (embedding vector_cosine_ops);
CREATE INDEX idx_tech_search_tsv ON techniques USING GIN (search_tsv);
```

Loaded once from the ATT&CK Enterprise STIX bundle. Embeddings are computed locally with
fastembed (`BAAI/bge-small-en-v1.5`, 384 dimensions); the model is baked into the API
image at build time, so nothing is downloaded at runtime.

Technique mapping is **retrieval-grounded**: hybrid retrieval — vector similarity over
`embedding` fused with a keyword match over `search_tsv` — returns top-k candidates, then
Sonnet chooses among them. The model never emits a technique ID from memory.

### 5.7 `audit_chain` — tamper evidence

```sql
CREATE TABLE audit_chain (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT NOT NULL,          -- 'pipeline' | 'ai:<model>' | 'analyst'
    action      TEXT NOT NULL,
    detail      JSONB,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);
```

`hash = sha256(prev_hash || ts || actor || action || canonical_json(detail))`.
Genesis row uses `prev_hash = '0' * 64`. A `verify_chain()` function walks the table and
returns `(valid: bool, broken_at: id | None)`.

### 5.8 `ground_truth` — for the accuracy reveal

```sql
CREATE TABLE ground_truth (
    id           BIGSERIAL PRIMARY KEY,
    dataset      TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    ts           TIMESTAMPTZ,
    note         TEXT
);
```

---

## 6. The deterministic pipeline

Runs on a loop (default every 10s, configurable). Idempotent: safe to run repeatedly
over the same data.

### 6.1 Stages

**1. Parse** (`ingest/`) — source-specific → OCSF. Unknown fields go to `ocsf.unmapped`
rather than being discarded. Original always preserved in `raw`.

**2. Detect** (`pipeline/detect.py`) — deterministic Python predicates over the OCSF
shape and event fields. Emits candidate security alerts into the `alerts` table.
Derives 15–25 rules from confirmed event types in `SCHEMA_NOTES.md`.

**3. Dedup** (`pipeline/dedup.py`) — deduplication over alerts:
- `dedup_key = sha256(rule_id | host | user_norm | process_uid | floor(ts, 60s))`
- Exact key match → mark `is_duplicate`, point `canonical_id` at the first occurrence.
- Near-match: MinHash/Jaccard over the token set of `command_line` + `process_name`;
  threshold 0.9 within a 5-minute window.
- **Duplicates are never deleted.** They are marked. `raw_alert_count` on the incident
  counts them — that number is the "500" in "500 alerts → 6 incidents."

**4. Correlate** (`pipeline/correlate.py`) — union-find over unique alerts using normalized entities:
Two non-duplicate alerts join the same incident if they share any of:
- same `host` within 30 min
- same normalized `user_norm` within 30 min (machine accounts excluded)
- process lineage via process GUIDs (`process_uid`) within 15 min
- a shared IP (`src_ip`/`dst_ip` in either direction, non-loopback) within 30 min
- a shared `file_path` or hash

Windows are config constants, not magic numbers in the code. Tune them against the
dataset; document what you tuned.

**5. Timeline** (`pipeline/timeline.py`) — `ORDER BY ts`. That is the entire algorithm.
Ties broken by `event_code`, then `id`. **No model involvement, ever.**

**6. Entities** (`pipeline/entities.py`) — extract hosts/users/IPs/processes/files, build
edges from co-occurrence within an event.

**7. Priority** (`pipeline/priority.py`) — transparent additive score, 0–100. Every
contributing factor is written to `priority_reason` so the UI can explain the ranking:
```
+30  credential-access indicators present
+25  more than one host involved
+20  lateral-movement pattern (auth from host A to host B)
+15  outbound connection to external IP
+10  persistence mechanism touched
+ 5  per additional distinct ATT&CK tactic
```
Explainable prioritization is an explicit evaluation criterion. Do not replace this with
an LLM score.

---

## 7. The AI layer

### 7.1 Model assignment

| Component | Model | Notes |
| --- | --- | --- |
| IOC extraction | `claude-haiku-4-5-20251001` | high volume |
| Sentence verification | `claude-haiku-4-5-20251001` | batch 5 sentences/call |
| Narrative generation | `claude-sonnet-5` | streams to UI |
| ATT&CK mapping | `claude-sonnet-5` | retrieval-grounded |
| Recommendations | `claude-sonnet-5` | |
| Challenge agent | `claude-sonnet-5` | |

Model IDs live in `config.py` as constants — **never hardcoded at call sites**, so a
swap is one line. Opus 5 stays available behind a config flag as a *diagnostic* (see
Section 10.2), not a dependency. Fable is not used: its safeguards route cybersecurity
content to Opus unpredictably, which adds cost and variance for no gain.

### 7.2 Prompt structure — caching matters

Every call is built as: **stable prefix first, volatile content last.**

```
[cacheable]  system prompt + rules
[cacheable]  retrieved ATT&CK context
[cacheable]  the incident's event corpus (id + ts + key fields)
[volatile]   the specific task instruction
```

Mark the cacheable block with `cache_control: ephemeral`. This cuts Sonnet's billable
input by roughly 60% across the multi-call sequence. Do not cache Haiku's verifier
prompt — it is below the minimum cacheable size and the write premium makes it a loss.

### 7.3 Contracts

Every AI module returns strict JSON. Parse it in Python; never regex it; never trust it.

**Narrative** (`ai/narrative.py`):
```json
{
  "title": "string",
  "sentences": [
    {"seq": 1, "text": "...", "evidence_event_ids": [12, 15]}
  ]
}
```
Post-parse validation in Python, mandatory:
- every `evidence_event_ids` entry must exist in `events` for this incident → else drop
  the ID
- a sentence left with zero valid IDs is kept, written with an empty array, and will be
  caught by the verifier

**Mapping** (`ai/mapping.py`): chooses only from the retrieved candidate list.
```json
{"mappings": [{"seq": 1, "technique_id": "T1059.001", "confidence": 0.9}]}
```
A technique ID not in the candidate list is rejected in Python.

**Verify** (`ai/verify.py`):
```json
{"results": [{"seq": 1, "supported": true, "reason": "..."}]}
```

**Challenge** (`ai/challenge.py`):
```json
{
  "alternative_hypotheses": ["..."],
  "missing_evidence": ["..."],
  "proposed_query": {
    "kind": "event_search",
    "filters": {"host": "...", "process_name": "...", "after": "..."}
  },
  "confidence_delta": -0.15,
  "reasoning": "..."
}
```
`proposed_query` is a **structured filter object, not SQL**. Python translates it into a
parameterized query. The model never emits executable SQL.

### 7.4 Client discipline (`ai/client.py`)

- Exponential backoff with jitter on 429/529. A rate limit must degrade gracefully, not
  blank the timeline mid-demo.
- `max_tokens` explicitly set on every call — output is 5× the input price.
- Every call logged to `audit_chain` with model, token counts, latency.
- A `DRY_RUN=true` env flag returns canned fixtures without calling the API — use this
  while developing everything else so you don't burn tokens on UI iteration.

---

## 8. API contracts

```
GET  /health
     → {"status":"ok","db":true,"version":"..."}

POST /ingest
     body: {"source":"sysmon","events":[...]}
     → {"accepted":N,"duplicates":M}

POST /seed
     body: {"dataset":"apt29"}
     → {"events":N}

GET  /incidents
     → [{id,title,priority,priority_reason,event_count,raw_alert_count,
         first_seen,last_seen,hosts,confidence,status}]
     sorted by priority DESC

GET  /incidents/{id}
     → {incident, timeline[], narrative[], verifications[],
        techniques[], entities[], edges[], recommendations[]}

GET  /evidence?event_ids=1,2,3            ★ powers click-to-evidence
     → [{id, ts, source, host, raw}]

POST /incidents/{id}/challenge             ★ the adversarial pass
     → {alternative_hypotheses[], missing_evidence[],
        query_run{}, query_results[], old_confidence, new_confidence, reasoning}

GET  /incidents/{id}/accuracy              ★ the reveal
     → {ground_truth[], recovered[], missed[], invented[],
        precision, recall, time_to_narrative_seconds}

GET  /audit/verify
     → {"valid":true,"rows":N,"broken_at":null}
```

Frontend polls `GET /incidents` every 2s. No WebSockets — fewer moving parts on stage.

---

## 9. Frontend

**See `DESIGN.md`. It is authoritative for every visual decision.** An earlier draft of
this section specified a dark theme; that is superseded. The interface is **light**.

Only the facts the backend needs to know are repeated here:

**Stack:** React 18 + Vite + Tailwind. Tailwind's theme extends the CSS custom
properties defined in `DESIGN.md` §3 — no arbitrary hex values in components.

**Data dependencies the API must satisfy:**

| Component | Needs from the API |
| --- | --- |
| `IncidentList` | `GET /incidents` — including `priority_reason` for the score breakdown, and `raw_alert_count` for the "1,247 alerts → 6 incidents" header |
| `Narrative` | `narrative_sentences` with `evidence_event_ids` populated, joined to `verifications.supported` |
| `EvidencePanel` | `GET /evidence?event_ids=` — must return the untouched `raw` JSON |
| `Timeline` | ordered events, plus which event IDs are cited by some sentence |
| `AttackGrid` | observed technique IDs, binary — no confidence gradient is rendered |
| `ChallengePanel` | `old_confidence` and `new_confidence` as separate fields, so the change can be animated |
| `Scoreboard` | `GET /incidents/{id}/accuracy` — `invented` count and `time_to_narrative_seconds` |
| Chain status | `GET /audit/verify` |

**Polling:** `GET /incidents` every 2s. No WebSockets.

**The narrative must never render as a blank panel while generating** — the API should
expose enough state (`status`, `event_count`) for the UI to show a determinate
progress line. See `DESIGN.md` §7 for the exact copy.

**Build order for the UI** is in `DESIGN.md` §10. The narrative and evidence drawer come
before the timeline, grid, challenge, and scoreboard — they are the product.

---

## 10. Evaluation harness

### 10.1 Scoring

`eval/harness.py` compares Curator's recovered technique set against `ground_truth`:
- **recovered** = in both
- **missed** = in ground truth, not recovered
- **invented** = recovered, not in ground truth ← *the number that must be zero*
- precision, recall, and `time_to_narrative_seconds`

Runnable as `make eval`. Output is what `Scoreboard.jsx` renders.

### 10.2 The Opus diagnostic

If recall is low, flip `CHALLENGE_MODEL` / `NARRATIVE_MODEL` to `claude-opus-5` and
re-run ~20 incidents (≈$8). If the score barely moves, the bottleneck is correlation or
retrieval — fix that, not the model. If it jumps, the reasoning is the constraint. This
is a one-evening diagnostic, not a production dependency.

### 10.3 The planted false alert

A fixture event with `is_planted = true`, plausible but unsupported by any other
evidence. It must survive correlation (so it reaches the narrative) and be caught by the
verifier. Seeded via `POST /seed` with `{"plant_false_alert": true}`. Test this path
early — it is demo moment #2 and it must be reliable.

---

## 11. Conventions

- **Python 3.11+**, `ruff` + `black`, type hints on public functions.
- **Timestamps:** always timezone-aware UTC. Convert at parse time, never later.
- **No secrets in code.** Everything via `api/.env`, which is gitignored. `.env.example`
  documents the keys with dummy values.
- **No `print()`** — structured logging only.
- **Migrations:** `db/init/` runs only on an empty volume. For schema changes during the
  build, add a numbered file and document that `make reset` is required.
- **Every LLM call** is wrapped, logged, and has a `DRY_RUN` path.
- **Tests:** pytest for `pipeline/` at minimum. The deterministic layer is the part that
  must be provably correct — it is also the only part that is cheap to test.

### Make targets

```
make up        # docker compose up --build
make down
make reset     # down + drop volume + up  (wipes DB)
make seed      # load the dataset
make eval      # run the accuracy harness
make logs
make shell-api
make psql
```

---

## 12. Build sequence

Each step is requested as a separate prompt. **Do not build ahead.**

### 12.1 Steps

| # | Deliverable | Done when |
| --- | --- | --- |
| 1 | Skeleton: compose, 3 containers, schema, `/health` | `make up` → `/health` green, web shows "connected" |
| 2 | Ingest: dataset download, parsers, OCSF, `/seed` | events queryable in psql, counts sane |
| 3 | Detection & deterministic pipeline: detect, dedup, correlate, timeline, entities, priority | `/incidents` returns a ranked list; alert→incident reduction visible |
| 4 | Narrative + ATT&CK mapping + **click-to-evidence** | click a sentence → raw log appears |
| 5 | Verifier + **strike-out** + planted alert | planted alert produces a struck-through sentence |
| 6 | Accuracy harness + **Challenge** | `make eval` prints numbers; Challenge button works |
| 7 | Polish, then Terraform deploy to EC2 + Vercel | public URL serving the demo |

Steps 1–3 are backend only. **From Step 4 onward, `DESIGN.md` governs** — re-read it at
the start of each of those steps rather than working from memory of this file.

### 12.2 Step 1 scope (explicit — nothing more)

- `docker-compose.yml` with `curator-db`, `curator-api`, `curator-web`
- `db/init/001_schema.sql` with all tables from Section 5
- FastAPI with `/health` only
- `web/` — Vite + React + Tailwind scaffold. **Placeholder UI only**: one page polling
  `/health` and showing connection status. Wire the `DESIGN.md` §3 tokens into
  `tailwind.config.js` and load IBM Plex Sans + IBM Plex Mono now, so Step 4 doesn't
  retrofit them — but build no real components. This page is thrown away.
- `Makefile`, `.env.example`, `.gitignore`, `README.md`
- **No** parsers, no pipeline, no AI, no Anthropic calls

### 12.3 Tier 2 (optional, only if Steps 1–6 are done)

One EC2 Windows box, Sysmon installed, Atomic Red Team executing a small chain, logs
shipped to `/ingest`. Same pipeline, live data. Skip entirely if behind — Tier 1 carries
the demo.

### 12.4 Cut order under time pressure

Cut in this order, from the top:
1. Entity graph visualization (data model stays; only the viz goes)
2. Tier 2 live attack
3. Audit chain UI panel (keep the table and the hashing)
4. IOC enrichment lookups
5. Recommendations panel

**Never cut:** click-to-evidence, strike-out, accuracy reveal, Challenge.

Also never cut, even under pressure: the `DESIGN.md` §9 checklist and §8 quality floor
(focus states, contrast, keyboard paths). A half-finished interface that is disciplined
reads as deliberate; a complete one that trips the §9 checklist reads as generated. Ship
fewer views, finished.

---

## 13. Out of scope

Explicitly not built, to protect the schedule:

- Lambda / S3 / DynamoDB / Step Functions (architecture slide only)
- RDS (Postgres runs as a container with a persistent volume)
- Bedrock (Anthropic API used directly)
- Real C2, real malware, internet-exposed attack infrastructure
- Multi-tenant auth, RBAC, user management
- Any containment action that actually touches a live system — the "isolate host" button
  is simulated and clearly labelled as such

---

## 14. Security notes

- `api/.env` is gitignored. If a key is ever committed, rotate it immediately.
- Claude Code receives **no AWS credentials** during Steps 1–6 — nothing in those steps
  touches AWS.
- Step 7 uses Terraform, run by the operator with a scoped IAM user. The agent writes
  the Terraform; the human holds the credentials and runs `apply`.
- Security groups: SSH restricted to the operator's IP. Never `0.0.0.0/0` on anything
  but 443.
- `terraform destroy` after the hackathon. Release the Elastic IP — an unattached EIP
  bills silently.
