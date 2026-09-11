from sqlalchemy import text
from curator.db import SessionLocal

db = SessionLocal()
q = text("""
    SELECT n.incident_id, n.seq, n.text, n.evidence_event_ids, v.reason
    FROM narrative_sentences n
    JOIN verifications v ON v.sentence_id = n.id
    WHERE v.supported = false
    ORDER BY n.incident_id ASC, n.seq ASC
""")
rows = db.execute(q).fetchall()
print(f"Total unsupported sentences: {len(rows)}")
for r in rows:
    print(f"--- [Incident #{r[0]} | Seq {r[1]}] ---")
    print(f"Text: {r[2]}")
    print(f"Citations: {r[3]}")
    print(f"Reason: {r[4]}\n")
