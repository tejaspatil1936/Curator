"""Evidence set collector per incident (system_design.md §6.1).

Collects:
- All alerting events for the incident.
- Surrounding events on the same host and process within ±EVIDENCE_SURROUNDING_SECONDS (60s).
- Bounded and capped to at most EVIDENCE_MAX_EVENTS (250) so Step 4 model context stays bounded.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from curator.config import EVIDENCE_MAX_EVENTS, EVIDENCE_SURROUNDING_SECONDS


def fetch_incident_evidence(
    session: Session,
    alert_event_ids: list[int],
) -> list[dict[str, Any]]:
    """Fetch all alerting events plus bounded surrounding telemetry."""
    if not alert_event_ids:
        return []

    # 1. Fetch all alerting events directly
    q_alerts = text("""
        SELECT id, ts, source, host, user_name, process_name, process_id,
               parent_process, src_ip, dst_ip, file_path, command_line,
               event_code, ocsf, raw
        FROM events
        WHERE id = ANY(:ids)
        ORDER BY ts ASC, event_code ASC, id ASC
    """)
    res = session.execute(q_alerts, {"ids": alert_event_ids})
    alert_rows = [dict(r._mapping) for r in res]

    if not alert_rows:
        return []

    if len(alert_rows) >= EVIDENCE_MAX_EVENTS:
        return alert_rows[:EVIDENCE_MAX_EVENTS]

    # 2. Gather surrounding time windows per host
    host_windows: dict[str, list[tuple[datetime, datetime, int | None]]] = {}
    for r in alert_rows:
        h = r["host"]
        ts = r["ts"]
        pid = r["process_id"]
        if not h:
            continue
        start = ts - timedelta(seconds=EVIDENCE_SURROUNDING_SECONDS)
        end = ts + timedelta(seconds=EVIDENCE_SURROUNDING_SECONDS)
        host_windows.setdefault(h, []).append((start, end, pid))

    alert_id_set = set(alert_event_ids)
    remaining_slots = EVIDENCE_MAX_EVENTS - len(alert_rows)
    surrounding_rows: list[dict[str, Any]] = []

    for h, windows in host_windows.items():
        if remaining_slots <= 0:
            break
        windows.sort(key=lambda w: w[0])
        merged: list[tuple[datetime, datetime]] = []
        for w_start, w_end, _ in windows:
            if not merged:
                merged.append((w_start, w_end))
            else:
                last_start, last_end = merged[-1]
                if w_start <= last_end:
                    merged[-1] = (last_start, max(last_end, w_end))
                else:
                    merged.append((w_start, w_end))

        for m_start, m_end in merged:
            if remaining_slots <= 0:
                break
            q_surr = text("""
                SELECT id, ts, source, host, user_name, process_name, process_id,
                       parent_process, src_ip, dst_ip, file_path, command_line,
                       event_code, ocsf, raw
                FROM events
                WHERE host = :host
                  AND ts >= :m_start
                  AND ts <= :m_end
                  AND NOT (id = ANY(:alert_ids))
                ORDER BY ts ASC, event_code ASC, id ASC
                LIMIT :limit
            """)
            s_res = session.execute(
                q_surr,
                {
                    "host": h,
                    "m_start": m_start,
                    "m_end": m_end,
                    "alert_ids": list(alert_id_set),
                    "limit": remaining_slots,
                },
            )
            found = [dict(r._mapping) for r in s_res]
            surrounding_rows.extend(found)
            remaining_slots -= len(found)

    all_events = alert_rows + surrounding_rows
    all_events.sort(
        key=lambda e: (e["ts"], str(e["event_code"] or ""), e["id"])
    )
    return all_events[:EVIDENCE_MAX_EVENTS]
