from curator.db import SessionLocal
from sqlalchemy import text

db = SessionLocal()
q = text("SELECT id, technique_id, note FROM ground_truth WHERE note ILIKE '%step 20%' OR note ILIKE '%group%' OR note ILIKE '%task%' OR note ILIKE '%schedule%'")
for r in db.execute(q).fetchall():
    print(r)
db.close()
