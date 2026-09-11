from curator.db import SessionLocal
from sqlalchemy import text

with SessionLocal() as s:
    rows = s.execute(text(
        "SELECT rule_id, count(*) as n FROM alerts GROUP BY rule_id ORDER BY rule_id"
    )).fetchall()
    total = sum(r[1] for r in rows)
    print(f"Total alerts: {total}")
    for r in rows:
        print(f"  {r[0]}: {r[1]}")
    
    inc = s.execute(text(
        "SELECT status, count(*) FROM incidents GROUP BY status ORDER BY status"
    )).fetchall()
    print("Incidents:")
    for r in inc:
        print(f"  {r[0]}: {r[1]}")
