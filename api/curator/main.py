"""Curator API. Step 2: health, dataset seeding, audit chain verification."""

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from curator import __version__, audit, db
from curator.config import configure_logging, settings
from curator.ingest import seed as seeding

configure_logging()

app = FastAPI(title="Curator", version=__version__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class Health(BaseModel):
    status: str
    db: bool
    version: str


@app.get("/health")
def health() -> Health:
    # Sync on purpose: the DB round-trip blocks, so FastAPI runs this in its threadpool.
    return Health(status="ok", db=db.ping(), version=__version__)


class SeedRequest(BaseModel):
    dataset: str


class SeedResult(BaseModel):
    events: int  # rows inserted by this call
    skipped: (
        int  # records already present (idempotent re-run) or rejected by the parser
    )
    sources: dict[str, int]  # inserted rows per events.source


@app.post("/seed")
def seed(req: SeedRequest) -> SeedResult:
    # Sync: a full load takes minutes and runs in the threadpool.
    if req.dataset not in seeding.DATASETS:
        raise HTTPException(
            404, f"unknown dataset {req.dataset!r}; known: {sorted(seeding.DATASETS)}"
        )
    return SeedResult(**seeding.seed(req.dataset))


class ChainStatus(BaseModel):
    valid: bool
    rows: int
    broken_at: int | None


@app.get("/audit/verify")
def audit_verify() -> ChainStatus:
    valid, broken_at = audit.verify_chain()
    return ChainStatus(valid=valid, rows=audit.row_count(), broken_at=broken_at)


@app.post("/pipeline/run")
def trigger_pipeline(session: Session = Depends(db.get_session)) -> dict:
    """Trigger execution of the deterministic pipeline."""
    from curator.pipeline.runner import run_pipeline

    return run_pipeline(session)


@app.get("/incidents")
def list_incidents(session: Session = Depends(db.get_session)) -> list[dict]:
    """List all incidents ordered by priority descending (system_design.md §8)."""
    q = text("""
        SELECT id, title, priority, priority_reason, event_count, raw_alert_count,
               first_seen, last_seen, hosts, confidence, status
        FROM incidents
        ORDER BY priority DESC, id ASC
    """)
    rows = session.execute(q).fetchall()
    return [
        {
            "id": r.id,
            "title": r.title or f"Incident #{r.id} ({', '.join(r.hosts or ['Unknown'])})",
            "priority": r.priority,
            "priority_reason": r.priority_reason,
            "event_count": r.event_count,
            "raw_alert_count": r.raw_alert_count,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "hosts": r.hosts or [],
            "confidence": float(r.confidence) if r.confidence is not None else None,
            "status": r.status,
        }
        for r in rows
    ]


@app.get("/incidents/{incident_id}")
def get_incident(
    incident_id: int, session: Session = Depends(db.get_session)
) -> dict:
    """Get full incident case file details including timeline and entity graph (system_design.md §8)."""
    from curator.pipeline.timeline import build_timeline

    q_inc = text("""
        SELECT id, title, priority, priority_reason, event_count, raw_alert_count,
               first_seen, last_seen, hosts, users, confidence, status
        FROM incidents
        WHERE id = :id
    """)
    inc_row = session.execute(q_inc, {"id": incident_id}).fetchone()
    if not inc_row:
        raise HTTPException(404, f"Incident {incident_id} not found")

    incident = {
        "id": inc_row.id,
        "title": inc_row.title or f"Incident #{inc_row.id} ({', '.join(inc_row.hosts or ['Unknown'])})",
        "priority": inc_row.priority,
        "priority_reason": inc_row.priority_reason,
        "event_count": inc_row.event_count,
        "raw_alert_count": inc_row.raw_alert_count,
        "first_seen": inc_row.first_seen.isoformat() if inc_row.first_seen else None,
        "last_seen": inc_row.last_seen.isoformat() if inc_row.last_seen else None,
        "hosts": inc_row.hosts or [],
        "users": inc_row.users or [],
        "confidence": float(inc_row.confidence) if inc_row.confidence is not None else None,
        "status": inc_row.status,
    }

    # Timeline: events associated with this incident
    q_events = text("""
        SELECT id, ts, source, host, user_name, process_name, process_id,
               parent_process, src_ip, dst_ip, file_path, command_line, event_code
        FROM events
        WHERE incident_id = :id
        ORDER BY ts ASC, event_code ASC, id ASC
    """)
    ev_rows = [dict(r._mapping) for r in session.execute(q_events, {"id": incident_id})]
    timeline = build_timeline(ev_rows)

    # Entities
    q_ent = text("""
        SELECT id, kind, value, first_seen, last_seen, event_ids, enrichment
        FROM entities
        WHERE incident_id = :id
        ORDER BY id ASC
    """)
    entities = [
        {
            "id": r.id,
            "kind": r.kind,
            "value": r.value,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "event_ids": r.event_ids,
            "enrichment": r.enrichment,
        }
        for r in session.execute(q_ent, {"id": incident_id})
    ]

    # Edges
    q_edge = text("""
        SELECT id, src_id, dst_id, relation, event_ids
        FROM entity_edges
        WHERE incident_id = :id
        ORDER BY id ASC
    """)
    edges = [
        {
            "id": r.id,
            "src_id": r.src_id,
            "dst_id": r.dst_id,
            "relation": r.relation,
            "event_ids": r.event_ids,
        }
        for r in session.execute(q_edge, {"id": incident_id})
    ]

    return {
        "incident": incident,
        "timeline": timeline,
        "narrative": [],
        "verifications": [],
        "techniques": [],
        "entities": entities,
        "edges": edges,
        "recommendations": [],
    }

