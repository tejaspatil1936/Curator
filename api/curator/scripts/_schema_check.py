from curator.db import SessionLocal
from sqlalchemy import text
with SessionLocal() as s:
    r = s.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='alerts' ORDER BY ordinal_position")).fetchall()
    print([x[0] for x in r])
