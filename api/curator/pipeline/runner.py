"""Deterministic pipeline runner (system_design.md §6.1).

Orchestrates the deterministic stages:
1. Parse (ingest)
2. Detect (pipeline/detect.py) -> alerts
3. Dedup (pipeline/dedup.py) -> mark duplicates
4. Correlate (pipeline/correlate.py) -> incident clusters
5. Timeline (pipeline/timeline.py) -> sorted event & alert sequences
6. Entities & Edges (pipeline/entities.py) -> graph nodes & relationships
7. Priority (pipeline/priority.py) -> explainable additive score (0-100)

Bounded evidence set is attached to each incident (pipeline/evidence.py).
Idempotent and safe for scheduled execution.
"""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Any


from sqlalchemy import text
from sqlalchemy.orm import Session

from curator import audit
from curator.config import (
    BEACON_BUCKET_SECONDS,
    CORRELATE_FILE_WINDOW_SECONDS,
    CORRELATE_HOST_WINDOW_SECONDS,
    CORRELATE_IP_WINDOW_SECONDS,
    CORRELATE_PROCESS_WINDOW_SECONDS,
    CORRELATE_USER_WINDOW_SECONDS,
    INCIDENT_MIN_ALERTS,
)
from curator.db import SessionLocal
from curator.pipeline.correlate import AlertItem, correlate_alerts
from curator.pipeline.dedup import AlertRecord, deduplicate_alerts
from curator.pipeline.detect import evaluate_event
from curator.pipeline.entities import extract_entities_and_edges
from curator.pipeline.evidence import fetch_incident_evidence
from curator.pipeline.priority import calculate_priority

logger = logging.getLogger(__name__)

CANDIDATE_EVENT_CODES = [
    "1",
    "2",
    "3",
    "7",
    "10",
    "11",
    "12",
    "13",
    "23",
    "4688",
    "4624",
    "4697",
    "4698",
    "4702",
    "4720",
    "4722",
    "4724",
    "4728",
    "4732",
    "4769",
    "5140",
    "5145",
    "7045",
    "4104",
    "5857",
    "5858",
    "5861",
    "1149",
]


def run_pipeline(session: Session | None = None) -> dict[str, Any]:
    """Execute the full deterministic pipeline from start to finish."""
    if session is None:
        with SessionLocal() as sess:
            return _execute_pipeline(sess)
    return _execute_pipeline(session)


def _execute_pipeline(session: Session) -> dict[str, Any]:
    start_time = datetime.now(UTC)
    logger.info("Starting deterministic pipeline execution")

    # --------------------------------------------------------------------------
    # Stage 2: Detection
    # --------------------------------------------------------------------------
    logger.info("Stage 2: Evaluating detection rules over candidate telemetry")
    q_events = text("""
        SELECT id, ts, source, host, user_name, process_name, process_id,
               parent_process, src_ip, dst_ip, file_path, command_line,
               event_code, ocsf, is_planted
        FROM events
        WHERE event_code = ANY(:codes)
        ORDER BY ts ASC, id ASC
    """).execution_options(yield_per=10000)

    raw_alerts: list[dict[str, Any]] = []

    for r in session.execute(q_events, {"codes": CANDIDATE_EVENT_CODES}):
        ev = dict(r._mapping)
        cand_alerts = evaluate_event(ev)
        for c in cand_alerts:
            raw_alerts.append(
                {
                    "event_id": c.event_id,
                    "rule_id": c.rule_id,
                    "rule_name": c.rule_name,
                    "severity": c.severity,
                    "technique_ids": c.technique_ids,
                    "ts": c.ts,
                    "host": c.host,
                    "user_norm": c.user_norm,
                    "process_uid": c.process_uid,
                    "command_line": c.command_line,
                    "is_planted": c.is_planted,
                    "detail": c.detail,
                    "dst_ip": str(ev.get("dst_ip") or ""),
                    "dst_port": (ev.get("ocsf") or {}).get("dst_endpoint", {}).get("port"),
                }
            )

    # 3.2a: Session aggregation for CUR-013 (BEACON_BUCKET_SECONDS = 300)
    # Collapse Sysmon 3 connections into sessions keyed on (host, process_uid, dst_ip, dst_port)
    cur013_alerts = [a for a in raw_alerts if a["rule_id"] == "CUR-013"]
    other_alerts = [a for a in raw_alerts if a["rule_id"] != "CUR-013"]

    cur013_sessions: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for a in cur013_alerts:
        b_id = int(a["ts"].timestamp() // BEACON_BUCKET_SECONDS)
        key = (a["host"], a["process_uid"], a["dst_ip"], a["dst_port"], b_id)
        cur013_sessions[key].append(a)

    aggregated_cur013: list[dict[str, Any]] = []
    for key, items in cur013_sessions.items():
        items.sort(key=lambda x: x["ts"])
        conn_count = len(items)
        first_s = items[0]["ts"]
        last_s = items[-1]["ts"]

        # Calculate inter-arrival gaps
        if conn_count > 1:
            gaps = [
                (items[i + 1]["ts"] - items[i]["ts"]).total_seconds()
                for i in range(conn_count - 1)
            ]
            mean_gap = sum(gaps) / len(gaps)
            # Regularity metric: standard deviation of gaps
            variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
            std_gap = variance ** 0.5
            is_regular = std_gap < (mean_gap * 0.5 + 2.0)
        else:
            mean_gap = 0.0
            is_regular = False

        # Raise severity to high where connection count is high and inter-arrival timing is regular
        severity = "high" if (conn_count >= 10 and is_regular) or conn_count >= 20 else "medium"

        rep = items[0]
        detail = {
            "connection_count": conn_count,
            "first_seen": first_s.isoformat(),
            "last_seen": last_s.isoformat(),
            "mean_gap_seconds": round(mean_gap, 2),
            "is_beaconing": bool(conn_count >= 10 and is_regular),
            "dst_ip": rep["dst_ip"],
            "dst_port": rep["dst_port"],
        }
        aggregated_cur013.append(
            {
                "event_id": rep["event_id"],
                "rule_id": "CUR-013",
                "rule_name": "Scripting Process Initiated Outbound Network Connection",
                "severity": severity,
                "technique_ids": rep["technique_ids"],
                "ts": rep["ts"],
                "host": rep["host"],
                "user_norm": rep["user_norm"],
                "process_uid": rep["process_uid"],
                "command_line": rep["command_line"],
                "is_planted": rep["is_planted"],
                "detail": detail,
            }
        )

    all_alerts: list[dict[str, Any]] = other_alerts + aggregated_cur013

    # Step 5b: Planted false alert demo fixture
    if settings.plant_false_alert:
        from datetime import datetime
        from curator.pipeline.fixtures import (
            PLANTED_ALERT_EVENT_ID,
            PLANTED_HOST,
            PLANTED_RULE_ID,
            PLANTED_RULE_NAME,
            PLANTED_SEVERITY,
            PLANTED_TECHNIQUE_IDS,
            PLANTED_TS,
            PLANTED_USER,
        )
        all_alerts.append(
            {
                "event_id": PLANTED_ALERT_EVENT_ID,
                "rule_id": PLANTED_RULE_ID,
                "rule_name": PLANTED_RULE_NAME,
                "severity": PLANTED_SEVERITY,
                "technique_ids": PLANTED_TECHNIQUE_IDS,
                "ts": datetime.fromisoformat(PLANTED_TS),
                "host": PLANTED_HOST,
                "user_norm": PLANTED_USER,
                "process_uid": f"proc_{PLANTED_ALERT_EVENT_ID}",
                "command_line": r"\??\C:\windows\system32\conhost.exe 0xffffffff -ForceV1",
                "is_planted": True,
                "detail": {"planted": True, "note": "Step 5b demo false alert"},
                "dst_ip": "",
                "dst_port": None,
            }
        )

    all_alerts.sort(key=lambda x: (x["ts"], x["rule_id"]))

    rule_counts: Counter[str] = Counter(a["rule_id"] for a in all_alerts)
    total_alerts_fired = len(all_alerts)
    logger.info(
        "Detection complete: %d alerts fired across %d rules (CUR-013 aggregated to %d sessions)",
        total_alerts_fired,
        len(rule_counts),
        len(aggregated_cur013),
    )

    # Clean up old alerts & incidents for fresh idempotent pipeline run
    session.execute(text("DELETE FROM entity_edges;"))
    session.execute(text("DELETE FROM entities;"))
    session.execute(text("UPDATE events SET incident_id = NULL;"))
    session.execute(text("DELETE FROM alerts;"))
    session.execute(text("DELETE FROM incidents;"))

    if all_alerts:
        q_insert_alert = text("""
            INSERT INTO alerts (
                event_id, rule_id, rule_name, severity, technique_ids,
                ts, host, user_norm, process_uid, is_planted, detail
            ) VALUES (
                :event_id, :rule_id, :rule_name, :severity, :technique_ids,
                :ts, :host, :user_norm, :process_uid, :is_planted, :detail
            ) RETURNING id
        """)
        for a in all_alerts:
            a["id"] = session.execute(
                q_insert_alert,
                {
                    "event_id": a["event_id"],
                    "rule_id": a["rule_id"],
                    "rule_name": a["rule_name"],
                    "severity": a["severity"],
                    "technique_ids": a["technique_ids"],
                    "ts": a["ts"],
                    "host": a["host"],
                    "user_norm": a["user_norm"],
                    "process_uid": a["process_uid"],
                    "is_planted": a["is_planted"],
                    "detail": json.dumps(a.get("detail")) if a.get("detail") else None,
                },
            ).scalar_one()


    # --------------------------------------------------------------------------
    # Stage 3: Deduplication
    # --------------------------------------------------------------------------
    logger.info("Stage 3: Running alert deduplication (exact + MinHash)")
    alert_records = [
        AlertRecord(
            id=a["id"],
            rule_id=a["rule_id"],
            host=a["host"],
            user_norm=a["user_norm"],
            process_uid=a["process_uid"],
            ts=a["ts"],
            command_line=a.get("command_line"),
        )
        for a in all_alerts
    ]

    deduped_alerts, dup_count = deduplicate_alerts(alert_records)
    unique_alert_count = len(deduped_alerts) - dup_count
    logger.info(
        "Dedup complete: %d unique alerts, %d duplicates marked",
        unique_alert_count,
        dup_count,
    )

    if deduped_alerts:
        q_update_dedup = text("""
            UPDATE alerts
            SET dedup_key = :dedup_key,
                is_duplicate = :is_duplicate,
                canonical_id = :canonical_id
            WHERE id = :id
        """)
        session.execute(
            q_update_dedup,
            [
                {
                    "id": d.id,
                    "dedup_key": d.dedup_key,
                    "is_duplicate": d.is_duplicate,
                    "canonical_id": d.canonical_id,
                }
                for d in deduped_alerts
            ],
        )

    # --------------------------------------------------------------------------
    # Stage 4: Correlation
    # --------------------------------------------------------------------------
    logger.info("Stage 4: Running Union-Find correlation across alerts")
    alert_event_ids = list({a["event_id"] for a in all_alerts})
    ev_lookup = {}
    if alert_event_ids:
        q_ev_look = text("""
            SELECT id, file_path, src_ip, dst_ip
            FROM events
            WHERE id = ANY(:ids)
        """)
        for er in session.execute(q_ev_look, {"ids": alert_event_ids}):
            ev_lookup[er.id] = er

    alert_items = []
    for a in all_alerts:
        ev = ev_lookup.get(a["event_id"])
        alert_items.append(
            AlertItem(
                id=a["id"],
                rule_id=a["rule_id"],
                severity=a["severity"],
                ts=a["ts"],
                host=a["host"],
                user_norm=a["user_norm"],
                process_uid=a["process_uid"],
                file_path=ev.file_path if ev else None,
                src_ip=str(ev.src_ip) if ev and ev.src_ip else None,
                dst_ip=str(ev.dst_ip) if ev and ev.dst_ip else None,
                is_duplicate=a.get("is_duplicate", False),
                canonical_id=a.get("canonical_id"),
                command_line=a.get("command_line"),
            )
        )

    for it, da in zip(alert_items, deduped_alerts, strict=True):
        it.is_duplicate = da.is_duplicate
        it.canonical_id = da.canonical_id

    clusters = correlate_alerts(
        alert_items,
        host_window_s=CORRELATE_HOST_WINDOW_SECONDS,
        user_window_s=CORRELATE_USER_WINDOW_SECONDS,
        process_window_s=CORRELATE_PROCESS_WINDOW_SECONDS,
        ip_window_s=CORRELATE_IP_WINDOW_SECONDS,
        file_window_s=CORRELATE_FILE_WINDOW_SECONDS,
    )
    logger.info("Correlation complete: %d incident clusters formed", len(clusters))

    # --------------------------------------------------------------------------
    # Stages 5, 6, 7: Incidents, Priority, Evidence, Entities
    # --------------------------------------------------------------------------
    incidents_output: list[dict[str, Any]] = []

    for cluster in clusters:
        priority_score, priority_reason = calculate_priority(
            cluster.alerts, cluster.hosts
        )

        # 4a: Require priority > 0 AND (raw_alert_count >= INCIDENT_MIN_ALERTS or has_high_crit)
        # to surface as 'open'. Incidents with priority == 0 are suppressed noise.
        has_high_crit = any(
            a.severity in ("high", "critical") for a in cluster.alerts
        )
        status = (
            "open"
            if (
                priority_score > 0
                and (cluster.raw_alert_count >= INCIDENT_MIN_ALERTS or has_high_crit)
            )
            else "suppressed"
        )



        q_create_inc = text("""
            INSERT INTO incidents (
                first_seen, last_seen, event_count, raw_alert_count,
                hosts, users, priority, priority_reason, status
            ) VALUES (
                :first_seen, :last_seen, :event_count, :raw_alert_count,
                :hosts, :users, :priority, :priority_reason, :status
            ) RETURNING id
        """)
        inc_res = session.execute(
            q_create_inc,
            {
                "first_seen": cluster.first_seen,
                "last_seen": cluster.last_seen,
                "event_count": cluster.raw_alert_count,
                "raw_alert_count": cluster.raw_alert_count,
                "hosts": cluster.hosts,
                "users": cluster.users,
                "priority": priority_score,
                "priority_reason": json.dumps(priority_reason),
                "status": status,
            },
        )
        inc_id = inc_res.scalar_one()
        cluster.incident_id = inc_id

        # Link alerts
        session.execute(
            text(
                "UPDATE alerts SET incident_id = :inc_id WHERE id = ANY(:aids)"
            ),
            {"inc_id": inc_id, "aids": cluster.alert_ids},
        )

        alert_ev_ids = [
            a["event_id"]
            for a in all_alerts
            if a["id"] in cluster.alert_ids
        ]

        # Link alerting events
        session.execute(
            text(
                "UPDATE events SET incident_id = :inc_id WHERE id = ANY(:eids)"
            ),
            {"inc_id": inc_id, "eids": alert_ev_ids},
        )

        # Evidence bounding
        evidence_events = fetch_incident_evidence(session, alert_ev_ids)
        event_count = len(evidence_events)
        cluster.event_count = event_count

        session.execute(
            text(
                "UPDATE incidents SET event_count = :ev_count WHERE id = :inc_id"
            ),
            {"ev_count": event_count, "inc_id": inc_id},
        )

        # Entities and Edges
        entities, edges = extract_entities_and_edges(inc_id, evidence_events)
        if entities:
            q_ins_ent = text("""
                INSERT INTO entities (
                    incident_id, kind, value, first_seen, last_seen, event_ids, enrichment
                ) VALUES (
                    :incident_id, :kind, :value, :first_seen, :last_seen, :event_ids, :enrichment
                ) ON CONFLICT (incident_id, kind, value) DO UPDATE
                SET last_seen = EXCLUDED.last_seen,
                    event_ids = EXCLUDED.event_ids
            """)
            session.execute(q_ins_ent, entities)
            q_get_ent = text(
                "SELECT id, kind, value FROM entities WHERE incident_id = :inc_id"
            )
            ent_rows = [
                dict(r._mapping)
                for r in session.execute(q_get_ent, {"inc_id": inc_id})
            ]
            ent_key_to_id = {
                (r["kind"], r["value"]): r["id"] for r in ent_rows
            }

            valid_edges = []
            for ed in edges:
                src_key = (ed["src_kind"], ed["src_value"])
                dst_key = (ed["dst_kind"], ed["dst_value"])
                if src_key in ent_key_to_id and dst_key in ent_key_to_id:
                    valid_edges.append(
                        {
                            "incident_id": inc_id,
                            "src_id": ent_key_to_id[src_key],
                            "dst_id": ent_key_to_id[dst_key],
                            "relation": ed["relation"],
                            "event_ids": ed["event_ids"],
                        }
                    )
            if valid_edges:
                q_ins_edge = text("""
                    INSERT INTO entity_edges (
                        incident_id, src_id, dst_id, relation, event_ids
                    ) VALUES (
                        :incident_id, :src_id, :dst_id, :relation, :event_ids
                    )
                """)
                session.execute(q_ins_edge, valid_edges)

        incidents_output.append(
            {
                "id": inc_id,
                "priority": priority_score,
                "priority_reason": priority_reason,
                "status": status,
                "hosts": cluster.hosts,
                "users": cluster.users,
                "raw_alert_count": cluster.raw_alert_count,
                "event_count": event_count,
                "first_seen": cluster.first_seen.isoformat(),
                "last_seen": cluster.last_seen.isoformat(),
            }
        )

    # Log to audit chain
    audit.append(
        session.connection(),
        actor="pipeline",
        action="deterministic_pipeline_run",
        detail={
            "alerts_fired": total_alerts_fired,
            "unique_alerts": unique_alert_count,
            "duplicates": dup_count,
            "incidents": len(clusters),
            "rule_counts": dict(rule_counts),
        },
    )

    session.commit()

    # 3.1e: Tie-break priority on first_seen ASC so ordering is deterministic
    incidents_output.sort(key=lambda i: (-i["priority"], i["first_seen"]))

    surfaced_count = sum(1 for i in incidents_output if i["status"] == "open")
    suppressed_count = sum(1 for i in incidents_output if i["status"] == "suppressed")

    summary = {
        "total_alerts_fired": total_alerts_fired,
        "unique_alerts": unique_alert_count,
        "duplicate_alerts": dup_count,
        "incident_count": len(clusters),
        "surfaced_incidents": surfaced_count,
        "suppressed_incidents": suppressed_count,
        "rule_counts": dict(rule_counts),
        "incidents": incidents_output,
        "duration_ms": int(
            (datetime.now(UTC) - start_time).total_seconds() * 1000
        ),
    }
    return summary


if __name__ == "__main__":
    import json
    from curator.config import configure_logging

    configure_logging()
    result = run_pipeline()
    print(json.dumps(result, indent=2, default=str))
