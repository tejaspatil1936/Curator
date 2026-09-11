from curator.db import SessionLocal
from sqlalchemy import text

db = SessionLocal()
rows = db.execute(text("""
    SELECT e.id, e.ts, e.host, e.user_name, e.process_name, e.command_line, a.rule_id, a.rule_name,
           e.dst_ip, e.file_path, e.event_code,
           e.ocsf->'dst_endpoint'->>'port' as port,
           e.ocsf->'unmapped'->>'ShareName' as share_name
    FROM alerts a
    JOIN events e ON a.event_id = e.id
    WHERE a.incident_id = 803
    ORDER BY e.ts ASC
""")).fetchall()

print(f"Incident 803 has {len(rows)} alerts.")
by_rule_events = {}
for r in rows:
    by_rule_events.setdefault(r.rule_id, []).append(r)

for r_id, evs in by_rule_events.items():
    print(f"\nRule {r_id} ({evs[0].rule_name}): {len(evs)} alerts")
    hosts = set(e.host for e in evs)
    eids = [e.id for e in evs]
    print(f"  Hosts: {hosts}")
    print(f"  Sample event IDs: {eids[:8]}")
    for sample in evs[:2]:
        print(f"    ts={sample.ts} proc={sample.process_name} cmd={(sample.command_line or '')[:60]} dst={sample.dst_ip}:{sample.port} share={sample.share_name}")

db.close()
