import json
from curator.db import SessionLocal
from sqlalchemy import text

db = SessionLocal()

with open('/tmp/mappings_402_455.json') as f:
    data = json.load(f)

# Lookup techniques
q_techs = text("SELECT id, name FROM techniques")
tech_names = {r[0]: r[1] for r in db.execute(q_techs).fetchall()}

for inc_id_str, items in data.items():
    inc_id = int(inc_id_str)
    for m in items:
        seq = m["seq"]
        tid = m["technique_id"]
        conf = m["confidence"]
        tname = tech_names.get(tid, tid)
        db.execute(text("""
            UPDATE narrative_sentences
            SET technique_id = :tid,
                technique_name = :tname,
                technique_conf = :conf
            WHERE incident_id = :inc_id AND seq = :seq
        """), {"tid": tid, "tname": tname, "conf": conf, "inc_id": inc_id, "seq": seq})

db.commit()

# Check count now
print("Updated sentences with technique_id per incident:")
for r in db.execute(text("SELECT incident_id, count(*), count(technique_id) FROM narrative_sentences GROUP BY incident_id ORDER BY incident_id")).fetchall():
    print(f"  Incident #{r[0]}: total={r[1]}, with_technique={r[2]}")

db.close()
