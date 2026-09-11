"""Pipeline fixtures, including the planted false alert (Step 5b & system_design.md §10.3)."""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from curator.config import settings

logger = logging.getLogger(__name__)

PLANTED_ALERT_EVENT_ID = 42145  # conhost.exe helper on SCRANTON (benign telemetry)
PLANTED_RULE_ID = "CUR-005"
PLANTED_RULE_NAME = "LSASS Process Memory Access"
PLANTED_SEVERITY = "critical"
PLANTED_TECHNIQUE_IDS = ["T1003.001"]
PLANTED_HOST = "SCRANTON"
PLANTED_USER = "pbeesly"
PLANTED_TS = "2020-05-02 03:01:42.054000+00:00"


def inject_planted_alert(session: Session) -> dict[str, Any] | None:
    """Inject a plausible but unsupported planted false alert into alerts table.

    The alert survives correlation and reaches the narrative because it is on
    host SCRANTON under user pbeesly during incident #402's time window, but
    its underlying event (42145) is a benign conhost.exe execution with zero LSASS
    access or memory dumping telemetry.
    """
    if not settings.plant_false_alert:
        logger.info("PLANT_FALSE_ALERT is disabled; skipping planted alert injection")
        return None

    # Check if already injected
    q_check = text("SELECT id, incident_id FROM alerts WHERE is_planted = true LIMIT 1")
    existing = session.execute(q_check).fetchone()
    if existing:
        logger.info("Planted alert already present: alert_id=%d in incident_id=%s", existing[0], existing[1])
        return {"alert_id": existing[0], "incident_id": existing[1], "already_existed": True}

    # Find the target incident on SCRANTON (Day 1 pbeesly campaign, #402)
    q_inc = text("""
        SELECT id FROM incidents
        WHERE 'SCRANTON' = ANY(hosts) AND 'pbeesly' = ANY(users)
        ORDER BY priority DESC, id ASC
        LIMIT 1
    """)
    inc_row = session.execute(q_inc).fetchone()
    target_incident_id = inc_row[0] if inc_row else 402

    q_insert = text("""
        INSERT INTO alerts (
            event_id, rule_id, rule_name, severity, technique_ids,
            ts, host, user_norm, process_uid, is_planted, detail, incident_id
        ) VALUES (
            :event_id, :rule_id, :rule_name, :severity, :technique_ids,
            :ts, :host, :user_norm, :process_uid, :is_planted, :detail, :incident_id
        ) RETURNING id
    """)

    alert_id = session.execute(
        q_insert,
        {
            "event_id": PLANTED_ALERT_EVENT_ID,
            "rule_id": PLANTED_RULE_ID,
            "rule_name": PLANTED_RULE_NAME,
            "severity": PLANTED_SEVERITY,
            "technique_ids": PLANTED_TECHNIQUE_IDS,
            "ts": PLANTED_TS,
            "host": PLANTED_HOST,
            "user_norm": PLANTED_USER,
            "process_uid": f"proc_{PLANTED_ALERT_EVENT_ID}",
            "is_planted": True,
            "detail": json.dumps({"planted": True, "note": "Step 5b demo false alert"}),
            "incident_id": target_incident_id,
        },
    ).scalar_one()

    session.commit()
    logger.info(
        "Injected planted false alert: alert_id=%d (event_id=%d, rule=%s, incident_id=%d)",
        alert_id,
        PLANTED_ALERT_EVENT_ID,
        PLANTED_RULE_ID,
        target_incident_id,
    )

    return {
        "alert_id": alert_id,
        "event_id": PLANTED_ALERT_EVENT_ID,
        "incident_id": target_incident_id,
        "rule_id": PLANTED_RULE_ID,
        "is_planted": True,
    }
