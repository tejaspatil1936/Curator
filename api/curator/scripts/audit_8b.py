"""8b audit: verify priority fix, CUR-022 tightening, planted alert, campaign IDs."""
from curator.db import SessionLocal
from sqlalchemy import text

with SessionLocal() as s:

    # ── Planted alert ─────────────────────────────────────────────────────────
    print("=== PLANTED ALERT ===")
    rows = s.execute(text("""
        SELECT a.id, a.event_id, a.rule_id, a.incident_id, a.is_planted,
               i.status, i.priority
        FROM alerts a
        JOIN incidents i ON i.id = a.incident_id
        WHERE a.is_planted = true
    """)).fetchall()
    for r in rows:
        print(f"  alert_id={r.id} event_id={r.event_id} rule_id={r.rule_id} "
              f"incident_id={r.incident_id} planted={r.is_planted} "
              f"status={r.status} priority={r.priority}")

    # ── Day 1 and Day 2 campaigns (priority-90, multi-host) ───────────────────
    print("\n=== PRIORITY-90 OPEN INCIDENTS (Day 1 & Day 2 campaigns) ===")
    camps = s.execute(text("""
        SELECT id, priority, raw_alert_count, hosts, first_seen, last_seen, status
        FROM incidents
        WHERE priority = 90 AND status = 'open'
        ORDER BY first_seen
    """)).fetchall()
    for r in camps:
        tag = "Day 1" if r.id == min(c.id for c in camps) else "Day 2"
        print(f"  [{tag}] #{r.id}: priority={r.priority} alerts={r.raw_alert_count} "
              f"hosts={r.hosts} status={r.status} "
              f"{str(r.first_seen)[:16]}–{str(r.last_seen)[:16]}")

    # ── All open incidents ─────────────────────────────────────────────────────
    print("\n=== ALL OPEN INCIDENTS ===")
    open_rows = s.execute(text("""
        SELECT id, priority, raw_alert_count, hosts, first_seen, last_seen
        FROM incidents WHERE status = 'open'
        ORDER BY priority DESC, first_seen
    """)).fetchall()
    for r in open_rows:
        print(f"  #{r.id}: priority={r.priority} alerts={r.raw_alert_count} "
              f"hosts={r.hosts} {str(r.first_seen)[:16]}–{str(r.last_seen)[:16]}")
    print(f"  TOTAL OPEN: {len(open_rows)}")

    # ── CUR-021 incidents (WinRM — was #745, should now surface) ──────────────
    print("\n=== CUR-021 (WinRM) INCIDENTS ===")
    winrm = s.execute(text("""
        SELECT i.id, i.status, i.priority, i.hosts,
               array_agg(DISTINCT a.rule_id ORDER BY a.rule_id) AS rules
        FROM incidents i
        JOIN alerts a ON a.incident_id = i.id
        WHERE a.rule_id = 'CUR-021'
        GROUP BY i.id, i.status, i.priority, i.hosts
        ORDER BY i.status, i.priority DESC
    """)).fetchall()
    for r in winrm:
        print(f"  #{r.id}: status={r.status} priority={r.priority} "
              f"hosts={r.hosts} rules={r.rules}")

    # ── CUR-022 total alert count ──────────────────────────────────────────────
    print("\n=== CUR-022 (Data Staging) ALERT COUNT ===")
    n022 = s.execute(text("SELECT COUNT(*) FROM alerts WHERE rule_id='CUR-022'")).scalar()
    print(f"  CUR-022 alerts: {n022}")
    # Show what they fired on
    staging_events = s.execute(text("""
        SELECT e.file_path, COUNT(*) as n
        FROM alerts a
        JOIN events e ON e.id = a.event_id
        WHERE a.rule_id = 'CUR-022'
        GROUP BY e.file_path
        ORDER BY n DESC
        LIMIT 10
    """)).fetchall()
    for r in staging_events:
        print(f"    {r.n}x  {r.file_path}")

    # ── Total alerts by rule ───────────────────────────────────────────────────
    print("\n=== ALERT COUNTS BY RULE ===")
    rule_rows = s.execute(text("""
        SELECT rule_id, COUNT(*) as n
        FROM alerts GROUP BY rule_id ORDER BY rule_id
    """)).fetchall()
    total = sum(r.n for r in rule_rows)
    for r in rule_rows:
        print(f"  {r.rule_id}: {r.n}")
    print(f"  TOTAL: {total}")

    # ── Suppressed count ───────────────────────────────────────────────────────
    supp_n = s.execute(text("SELECT COUNT(*) FROM incidents WHERE status='suppressed'")).scalar()
    print(f"\n=== SUPPRESSED: {supp_n} ===")
