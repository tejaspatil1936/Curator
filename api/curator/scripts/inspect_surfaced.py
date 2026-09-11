from curator.db import SessionLocal
from sqlalchemy import text

db = SessionLocal()

incidents = db.execute(text("""
    SELECT id, priority, raw_alert_count, hosts, users
    FROM incidents
    WHERE status != 'suppressed'
    ORDER BY priority DESC, first_seen ASC, id ASC
""")).fetchall()

print(f"Total surfaced incidents: {len(incidents)}")
for inc in incidents:
    ev_count = db.execute(
        text("SELECT COUNT(*) FROM events WHERE incident_id = :id"),
        {"id": inc.id}
    ).scalar()
    al_count = db.execute(
        text("SELECT COUNT(*) FROM alerts WHERE incident_id = :id"),
        {"id": inc.id}
    ).scalar()
    print(f"Incident #{inc.id}: priority={inc.priority}, raw_alerts={inc.raw_alert_count}, db_alerts={al_count}, events={ev_count}, hosts={inc.hosts}, users={inc.users}")

db.close()
