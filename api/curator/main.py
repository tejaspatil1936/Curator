"""Curator API. Step 2: health, dataset seeding, audit chain verification."""

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import text
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
def list_incidents(
    include_suppressed: bool = False,
    session: Session = Depends(db.get_session),
) -> list[dict]:
    """List surfaced incidents ordered by priority descending, first_seen ascending (system_design.md §8).

    3.1c: Suppressed clusters stay in the database and are reachable by direct ID, but
    only surface in the ranked list when meeting INCIDENT_MIN_ALERTS or containing high/critical alerts.
    3.1e: Break priority ties on first_seen ASC.
    """
    where_clause = "" if include_suppressed else "WHERE status != 'suppressed'"
    q = text(f"""
        SELECT id, title, priority, priority_reason, event_count, raw_alert_count,
               first_seen, last_seen, hosts, confidence, status
        FROM incidents
        {where_clause}
        ORDER BY priority DESC, first_seen ASC, id ASC
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

    # Narrative sentences & verifications (Step 4c, 4d, 5a, 5c)
    q_narr = text("""
        SELECT n.id, n.seq, n.text, n.evidence_event_ids, n.technique_id, n.technique_name,
               n.technique_conf, n.generated_by,
               v.supported, v.reason AS verification_reason, v.model AS verifier_model
        FROM narrative_sentences n
        LEFT JOIN LATERAL (
            SELECT supported, reason, model
            FROM verifications
            WHERE sentence_id = n.id
            ORDER BY created_at DESC
            LIMIT 1
        ) v ON true
        WHERE n.incident_id = :id
        ORDER BY n.seq ASC
    """)
    narr_rows = session.execute(q_narr, {"id": incident_id}).fetchall()

    narrative = []
    verifications = []
    for r in narr_rows:
        has_ev = bool(r.evidence_event_ids and len(r.evidence_event_ids) > 0)
        is_supp = r.supported if r.supported is not None else (True if has_ev else False)

        narrative.append({
            "id": r.id,
            "seq": r.seq,
            "text": r.text,
            "evidence_event_ids": r.evidence_event_ids or [],
            "technique_id": r.technique_id,
            "technique_name": r.technique_name,
            "technique_conf": float(r.technique_conf) if r.technique_conf is not None else None,
            "generated_by": r.generated_by,
            "supported": is_supp,
            "verification_reason": r.verification_reason,
            "verification": {
                "supported": is_supp,
                "reason": r.verification_reason or ("No cited evidence events." if not has_ev else None),
                "model": r.verifier_model,
            } if r.supported is not None or not has_ev else None,
        })
        if r.supported is not None:
            verifications.append({
                "sentence_id": r.id,
                "seq": r.seq,
                "supported": r.supported,
                "reason": r.verification_reason,
                "model": r.verifier_model,
            })

    return {
        "incident": incident,
        "timeline": timeline,
        "narrative": narrative,
        "verifications": verifications,
        "techniques": [],
        "entities": entities,
        "edges": edges,
        "recommendations": [],
    }


@app.post("/incidents/{incident_id}/verify")
def verify_incident_endpoint(
    incident_id: int,
    session: Session = Depends(db.get_session),
) -> dict:
    """Run forensic claim verification for an incident's narrative (Step 5a)."""
    from curator.ai.verify import verify_incident
    return verify_incident(incident_id, session=session)


@app.post("/verify/all")
def verify_all_endpoint(
    session: Session = Depends(db.get_session),
) -> dict:
    """Run forensic claim verification across all incidents (Step 5a)."""
    from curator.ai.verify import verify_all_incidents
    return verify_all_incidents(session=session)


@app.get("/evidence")
def get_evidence(
    event_ids: str,
    incident_id: int | None = None,
    session: Session = Depends(db.get_session),
) -> list[dict]:
    """Fetch raw telemetry events for click-to-evidence (Step 4e).

    Returns raw::text directly without decoding and re-serializing JSON,
    strictly preserving byte-identity.
    """
    if not event_ids:
        return []
    try:
        ids = [int(i.strip()) for i in event_ids.split(",") if i.strip()]
    except ValueError:
        raise HTTPException(400, "event_ids must be a comma-separated list of integers")

    if not ids:
        return []

    q = text("""
        SELECT id, ts, source, host, event_code, raw::text AS raw_text
        FROM events
        WHERE id = ANY(:ids)
        ORDER BY ts ASC, event_code ASC, id ASC
    """)
    rows = session.execute(q, {"ids": ids}).fetchall()

    # Pre-fetch evidence_selection_reason if incident_id is given
    reason_lookup = {}
    if incident_id:
        from curator.pipeline.evidence import fetch_incident_evidence
        q_alert_ids = text("SELECT event_id FROM alerts WHERE incident_id = :inc_id")
        a_ids = [r[0] for r in session.execute(q_alert_ids, {"inc_id": incident_id}).fetchall()]
        ev_items = fetch_incident_evidence(session, a_ids)
        for e in ev_items:
            reason_lookup[e["id"]] = e.get("evidence_selection_reason", "context")

    result = []
    for r in rows:
        reason = reason_lookup.get(r.id)
        if not reason:
            # Check if event triggered an alert directly
            is_alert = session.execute(
                text("SELECT EXISTS(SELECT 1 FROM alerts WHERE event_id = :eid)"),
                {"eid": r.id},
            ).scalar()
            reason = "alerting" if is_alert else "context"

        result.append(
            {
                "id": r.id,
                "ts": r.ts.isoformat() if r.ts else None,
                "source": r.source,
                "host": r.host,
                "event_code": r.event_code,
                "raw": r.raw_text,
                "evidence_selection_reason": reason,
            }
        )
    return result


@app.post("/incidents/{incident_id}/narrative")
def generate_narrative_endpoint(
    incident_id: int, session: Session = Depends(db.get_session)
) -> dict:
    """Generate evidence-grounded narrative and ATT&CK mappings for an incident (Step 4c & 4d)."""
    from curator.ai.mapping import map_incident_techniques
    from curator.ai.narrative import generate_incident_narrative

    narr_result = generate_incident_narrative(incident_id, session)
    map_result = map_incident_techniques(incident_id, session)

    return {
        "narrative": narr_result,
        "attack_mapping": map_result,
    }


@app.get("/accuracy")
def get_accuracy(session: Session = Depends(db.get_session)) -> dict:
    """Accuracy reveal harness endpoint (system_design.md §8, §10 & Step 6d)."""
    from curator.eval.harness import evaluate_accuracy

    return evaluate_accuracy(session)


@app.get("/incidents/{incident_id}/accuracy")
def get_incident_accuracy(
    incident_id: int, session: Session = Depends(db.get_session)
) -> dict:
    """Accuracy reveal harness endpoint for a specific incident or global (system_design.md §8)."""
    from curator.eval.harness import evaluate_accuracy

    return evaluate_accuracy(session)


@app.post("/incidents/{incident_id}/challenge")
def challenge_incident_endpoint(
    incident_id: int, session: Session = Depends(db.get_session)
) -> dict:
    """Run the Challenge agent for an incident (system_design.md §7.3).

    Returns structured counter-analysis with alternative hypotheses, missing evidence,
    a proposed query result, and updated confidence (old_confidence, new_confidence).
    In DRY_RUN mode returns the grounded fixture immediately with no API call.
    """
    from curator.ai.challenge import challenge_incident

    return challenge_incident(incident_id, session=session)
