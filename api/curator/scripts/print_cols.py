from curator.db import SessionLocal
from sqlalchemy import text

db = SessionLocal()
row = db.execute(text("SELECT * FROM events LIMIT 1")).fetchone()
if row:
    print("Columns in events:", list(row._mapping.keys()))

inc402_alerts = db.execute(text("""
    SELECT a.id, a.rule_id, a.rule_name, e.id as ev_id, e.host, e.process_name, e.command_line, e.dst_ip, e.ts
    FROM alerts a
    JOIN events e ON a.event_id = e.id
    WHERE a.incident_id = 402
    ORDER BY e.ts ASC
""")).fetchall()

print(f"Total alerts for 402: {len(inc402_alerts)}")
by_rule = {}
for a in inc402_alerts:
    by_rule.setdefault(a.rule_id, []).append(a)

for r, alist in by_rule.items():
    print(f"Rule: {r} ({alist[0].rule_name}) - Count: {len(alist)}")
    for x in alist[:3]:
        cmd = (x.command_line or "")[:70].replace("\n", " ")
        print(f"   [ev_id={x.ev_id}] host={x.host} proc={x.process_name} cmd={cmd}")

db.close()
