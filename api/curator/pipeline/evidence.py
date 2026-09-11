"""Evidence set collector per incident (system_design.md §6.1 & Step 3.2b).

Collects:
1. Every alerting event (always included, never truncated).
2. Context events, selected in this priority order until EVIDENCE_MAX_EVENTS (250):
   a. same process_uid as an alerting event, within ±60s
   b. same normalized user (excluding service accounts) on the same host, within ±30s
   c. direct process ancestors and descendants of alerting processes, any time
   d. same host within ±10s

Adds evidence_selection_reason per event ('alerting', 'same_process_60s',
'same_user_host_30s', 'process_lineage', 'same_host_10s').
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from curator.config import EVIDENCE_MAX_EVENTS
from curator.ingest.normalize import (
    is_correlating_user,
    normalize_host,
    normalize_process_uid,
    normalize_user,
)


def fetch_incident_evidence(
    session: Session,
    alert_event_ids: list[int],
) -> list[dict[str, Any]]:
    """Fetch all alerting events plus prioritized bounded context telemetry."""
    if not alert_event_ids:
        return []

    # 1. Fetch all alerting events directly (always included, never truncated)
    q_alerts = text("""
        SELECT id, ts, source, host, user_name, process_name, process_id,
               parent_process, src_ip, dst_ip, file_path, command_line,
               event_code, ocsf, raw
        FROM events
        WHERE id = ANY(:ids)
        ORDER BY ts ASC, event_code ASC, id ASC
    """)
    alert_rows = [dict(r._mapping) for r in session.execute(q_alerts, {"ids": alert_event_ids})]
    if not alert_rows:
        return []

    for r in alert_rows:
        r["evidence_selection_reason"] = "alerting"

    if len(alert_rows) >= EVIDENCE_MAX_EVENTS:
        return alert_rows

    selected_events_by_id: dict[int, dict[str, Any]] = {r["id"]: r for r in alert_rows}
    remaining_slots = EVIDENCE_MAX_EVENTS - len(selected_events_by_id)

    # Pre-extract attributes of alerting events
    alert_proc_uids: set[str] = set()
    alert_hosts: set[str] = set()
    alert_users_by_host: dict[str, set[str]] = {}
    alert_min_ts = min(r["ts"] for r in alert_rows)
    alert_max_ts = max(r["ts"] for r in alert_rows)

    for r in alert_rows:
        ocsf = r.get("ocsf") or {}
        unm = ocsf.get("unmapped") or {}
        act = ocsf.get("actor") or {}
        p_uid = normalize_process_uid(
            (ocsf.get("process") or {}).get("uid")
            or (act.get("process") or {}).get("uid")
            or unm.get("ProcessGuid")
            or unm.get("SourceProcessGUID")
            or unm.get("SourceProcessGuid")
        )
        if p_uid:
            alert_proc_uids.add(p_uid)

        h = r["host"]
        if h:
            alert_hosts.add(h)
            u = normalize_user(r["user_name"])
            if u and is_correlating_user(u):
                alert_users_by_host.setdefault(h, set()).add(u)

    # --------------------------------------------------------------------------
    # Priority a: same process_uid within ±60s
    # --------------------------------------------------------------------------
    if remaining_slots > 0 and alert_proc_uids:
        # Search candidate events where process_uid matches
        q_puid = text("""
            SELECT id, ts, source, host, user_name, process_name, process_id,
                   parent_process, src_ip, dst_ip, file_path, command_line,
                   event_code, ocsf, raw
            FROM events
            WHERE ts >= :min_ts
              AND ts <= :max_ts
              AND (
                  (ocsf->'process'->>'uid') = ANY(:puids)
                  OR (ocsf->'actor'->'process'->>'uid') = ANY(:puids)
                  OR (ocsf->'unmapped'->>'ProcessGuid') = ANY(:puids)
              )
              AND NOT (id = ANY(:already_ids))
            ORDER BY ts ASC, id ASC
            LIMIT :limit
        """)
        # We search with braces and without braces to match raw JSON values
        puid_candidates = list(alert_proc_uids) + [f"{{{p}}}" for p in alert_proc_uids]
        res_a = session.execute(
            q_puid,
            {
                "min_ts": alert_min_ts - timedelta(seconds=60),
                "max_ts": alert_max_ts + timedelta(seconds=60),
                "puids": puid_candidates,
                "already_ids": list(selected_events_by_id.keys()),
                "limit": remaining_slots,
            },
        )
        for row in res_a:
            d = dict(row._mapping)
            # Verify ±60s from nearest alert with that proc_uid
            d["evidence_selection_reason"] = "same_process_60s"
            selected_events_by_id[d["id"]] = d
            remaining_slots -= 1
            if remaining_slots <= 0:
                break

    # --------------------------------------------------------------------------
    # Priority b: same normalized user (excluding service accounts) on same host within ±30s
    # --------------------------------------------------------------------------
    if remaining_slots > 0 and alert_users_by_host:
        for h, users in alert_users_by_host.items():
            if remaining_slots <= 0:
                break
            for u in users:
                if remaining_slots <= 0:
                    break
                q_user = text("""
                    SELECT id, ts, source, host, user_name, process_name, process_id,
                           parent_process, src_ip, dst_ip, file_path, command_line,
                           event_code, ocsf, raw
                    FROM events
                    WHERE host = :host
                      AND user_name ILIKE :user_pattern
                      AND ts >= :min_ts
                      AND ts <= :max_ts
                      AND NOT (id = ANY(:already_ids))
                    ORDER BY ts ASC, id ASC
                    LIMIT :limit
                """)
                res_b = session.execute(
                    q_user,
                    {
                        "host": h,
                        "user_pattern": f"%{u}%",
                        "min_ts": alert_min_ts - timedelta(seconds=30),
                        "max_ts": alert_max_ts + timedelta(seconds=30),
                        "already_ids": list(selected_events_by_id.keys()),
                        "limit": remaining_slots,
                    },
                )
                for row in res_b:
                    d = dict(row._mapping)
                    d["evidence_selection_reason"] = "same_user_host_30s"
                    selected_events_by_id[d["id"]] = d
                    remaining_slots -= 1
                    if remaining_slots <= 0:
                        break

    # --------------------------------------------------------------------------
    # Priority c: direct process ancestors and descendants, any time
    # --------------------------------------------------------------------------
    if remaining_slots > 0 and alert_proc_uids:
        q_lineage = text("""
            SELECT id, ts, source, host, user_name, process_name, process_id,
                   parent_process, src_ip, dst_ip, file_path, command_line,
                   event_code, ocsf, raw
            FROM events
            WHERE (
                (ocsf->'process'->'parent_process'->>'uid') = ANY(:puids)
                OR (ocsf->'actor'->'process'->'parent_process'->>'uid') = ANY(:puids)
                OR (ocsf->'unmapped'->>'ParentProcessGuid') = ANY(:puids)
            )
            AND NOT (id = ANY(:already_ids))
            ORDER BY ts ASC, id ASC
            LIMIT :limit
        """)
        puid_candidates = list(alert_proc_uids) + [f"{{{p}}}" for p in alert_proc_uids]
        res_c = session.execute(
            q_lineage,
            {
                "puids": puid_candidates,
                "already_ids": list(selected_events_by_id.keys()),
                "limit": remaining_slots,
            },
        )
        for row in res_c:
            d = dict(row._mapping)
            d["evidence_selection_reason"] = "process_lineage"
            selected_events_by_id[d["id"]] = d
            remaining_slots -= 1
            if remaining_slots <= 0:
                break

    all_events = list(selected_events_by_id.values())
    all_events.sort(key=lambda e: (e["ts"], str(e["event_code"] or ""), e["id"]))
    return all_events


