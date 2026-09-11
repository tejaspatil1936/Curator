from curator.db import SessionLocal
from sqlalchemy import text
import json

db = SessionLocal()
q = text("""
    SELECT n.id, n.incident_id, n.seq, n.text, n.technique_id, n.technique_name, n.evidence_event_ids, v.supported, v.reason
    FROM narrative_sentences n
    LEFT JOIN verifications v ON v.sentence_id = n.id
    WHERE n.technique_id IN ('T1021.001', 'T1053.005')
""")
rows = db.execute(q).fetchall()
print(f"Found {len(rows)} sentences for T1021.001 and T1053.005:")
for r in rows:
    print("=" * 60)
    print(f"Sentence ID: {r.id} | Incident #{r.incident_id} | Seq {r.seq}")
    print(f"Technique: {r.technique_id} - {r.technique_name}")
    print(f"Supported: {r.supported}")
    print(f"Text: {r.text}")
    print(f"Verifier Reason: {r.reason}")
    print(f"Evidence Event IDs: {r.evidence_event_ids}")
    
    if r.evidence_event_ids:
        eq = text("""
            SELECT e.id, e.ts, e.host, e.user_name, e.process_name, e.command_line, e.event_code, e.raw, e.ocsf
            FROM events e
            WHERE e.id = ANY(:eids)
        """)
        evs = db.execute(eq, {"eids": r.evidence_event_ids}).fetchall()
        for ev in evs:
            print(f"  Event #{ev.id} | TS: {ev.ts} | Host: {ev.host} | User: {ev.user_name} | Code: {ev.event_code}")
            print(f"  Process: {ev.process_name}")
            print(f"  Cmd: {ev.command_line}")
            print(f"  Raw: {str(ev.raw)[:300]}")
            if ev.ocsf:
                unmapped = ev.ocsf.get('unmapped', {}) if isinstance(ev.ocsf, dict) else {}
                print(f"  Unmapped: {unmapped}")
db.close()
