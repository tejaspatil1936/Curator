# Curator

Curator is an AI-augmented security incident investigation system built to demonstrate the MITRE ATT&CK APT29 evaluation dataset. It ingests raw Windows Security and Sysmon telemetry, runs a deterministic detection and correlation pipeline, generates evidence-grounded narrative summaries, and maps each narrative sentence to MITRE ATT&CK techniques — then scores itself against published ground truth.

---

## Architecture

```
events (raw telemetry)
    │
    ▼
[detect.py]  ─── 22 deterministic Sigma-style rules ───► alerts
    │
    ▼
[dedup + correlate]  ──────────────────────────────────► incidents
    │
    ▼
[narrative.py]  (Claude Sonnet 5, prompt-cached) ──────► narrative_sentences
    │
    ▼
[verify.py]    (Claude Haiku, per-sentence) ────────────► verifications
    │
    ▼
[mapping.py]  (pgvector hybrid retrieval + Claude) ─────► technique_id
    │
    ▼
[eval/harness.py]  ─────────────────────────────────────► scoreboard
```

### Deterministic / Generative boundary

Everything up to and including incident correlation is **deterministic**: the same events always produce the same alerts and incidents, with no model calls. The audit chain (SHA-256 chained log) covers every row inserted.

Model calls begin at narrative generation (Step 4). They are:
1. **Narrative** — grounded on cited event IDs; never invents facts not in evidence.
2. **Verification** — each sentence is independently checked against its cited events.
3. **Mapping** — retrieval-grounded; the model can only choose from a pre-retrieved whitelist of ATT&CK candidates.
4. **Challenge** — red-team counter-analysis with a structured proposed query (no raw SQL).

`DRY_RUN=true` (or absent API credentials) returns deterministic fixtures for all four calls.

---

## Running from scratch

### Prerequisites

- Docker Desktop ≥ 4.25
- 8 GB RAM available to Docker
- `curl` (for dataset download)

### 1. Clone and configure

```bash
git clone https://github.com/<you>/curator.git
cd curator
cp api/.env.example api/.env
# Edit api/.env:
#   ANTHROPIC_API_KEY=sk-ant-...   (leave blank for DRY_RUN mode)
#   DRY_RUN=false                  (set true to run without credits)
```

### 2. Download the APT29 dataset

```bash
# MITRE ATT&CK Evaluations APT29 dataset (Windows Security + Sysmon JSON)
mkdir -p datasets
curl -L https://github.com/center-for-threat-informed-defense/apt29/releases/download/v1/apt29_evals.tar.gz \
  | tar -xz -C datasets/
```

### 3. Start the stack

```bash
docker compose up --build
```

This starts:
- `curator-db` — PostgreSQL 16 with pgvector
- `curator-api` — FastAPI on port 8000 (mounts `./api` for live reload)
- `curator-web` — Vite dev server on port 5173

### 4. Seed and run the pipeline

```bash
# Seed events (takes ~2 minutes for the full APT29 dataset)
curl -X POST http://localhost:8000/seed -H 'Content-Type: application/json' \
  -d '{"dataset":"apt29"}'

# Run the deterministic pipeline (detection, correlation, priority)
curl -X POST http://localhost:8000/pipeline/run
```

### 5. Generate narratives and mappings (requires API credits or DRY_RUN)

Open http://localhost:5173, select an incident, and click **Generate narrative** — or call:

```bash
curl -X POST http://localhost:8000/incidents/402/narrative
```

### 6. View the scoreboard

Navigate to any incident → **Accuracy** tab, or:

```bash
curl http://localhost:8000/accuracy
```

---

## Accuracy figures (APT29 Day 1+2, post Step 6)

| Metric | Value |
|---|---|
| **Executed** (GT techniques) | 58 |
| **Recovered** (matched by Curator) | 25 |
| **Not in evidence** (invented, no support) | **0** |
| **Beyond ground truth** (genuine, unscored) | 4 |
| Precision | 86.2% |
| Recall | 34.5% |

`not_in_evidence = 0` is the primary integrity metric. The 4 "beyond ground truth" techniques (T1098, T1098.007, T1202, T1218.002) reflect real attacker behaviour that MITRE did not score in the published evaluation.

The 34.5% recall gap has three diagnosed root causes:
- **T1021.006 WinRM** — no rule tagged port-5985 connections (fixed in Step 7, CUR-021)
- **T1074 Data Staged** — no rule emitted the T1074 hint (fixed in Step 7, CUR-022)
- **T1105 Ingress Tool Transfer** — model chose T1059.001 when retrieval surfaced both (retrieval boost added in Step 7)

A single live re-map pass (requires API credits) will incorporate these fixes.

---

## Repository structure

```
curator/
├── api/
│   ├── curator/
│   │   ├── ai/              # LLM modules (narrative, verify, mapping, challenge)
│   │   ├── attack/          # pgvector retrieval over ATT&CK STIX
│   │   ├── eval/            # Accuracy harness (harness.py)
│   │   ├── ingest/          # Dataset parsers and seed logic
│   │   ├── pipeline/        # Deterministic pipeline (detect, correlate, priority…)
│   │   ├── scripts/         # One-off diagnostic and maintenance scripts
│   │   ├── config.py        # All model IDs and settings in one place
│   │   ├── main.py          # FastAPI routes
│   │   └── audit.py         # SHA-256 chained audit log
│   └── .env                 # Secrets — never committed
├── web/
│   └── src/
│       ├── components/      # React components (Narrative, EvidencePanel, Scoreboard, ChallengePanel)
│       └── App.jsx          # Tab layout: narrative · timeline · ATT&CK · challenge · accuracy
├── datasets/
│   └── SCHEMA_NOTES.md      # OCSF mapping notes — the only committed file in datasets/
├── DESIGN.md                # Visual design system and component spec
├── system_design.md         # Architecture decisions, pipeline spec, accuracy harness spec
└── docker-compose.yml
```

---

## Key design decisions

**Retrieval-grounded mapping** — the model sees only a pre-retrieved whitelist of ≤30 ATT&CK candidates per sentence. Any technique_id not in that list is rejected by the Python validator, not the model. This eliminates hallucinated techniques at the architecture level.

**Verification before scoring** — only sentences where `verifications.supported = true` contribute to technique counts. A false claim that is struck through cannot recover a point.

**Deterministic/generative split** — the audit chain covers all deterministic stages. Generative outputs are separately logged with token counts and cost estimates. The system can always regenerate the deterministic view from raw events; it never loses provenance.

**Challenge agent** — returns a structured `proposed_query` object (never raw SQL). Python translates it into a parameterised query. The confidence number animates from old → new on the UI.

---

## Development notes

```bash
# Run query translation tests (no model, no DB required)
docker exec curator-curator-api-1 python curator/scripts/test_challenge_query.py

# Check alert counts by rule
docker exec curator-curator-api-1 python curator/scripts/check_fp_rules.py

# Re-run the full detection pipeline
curl -X POST http://localhost:8000/pipeline/run
```
