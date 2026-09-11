"""Incident change audit — no API calls."""
from curator.db import SessionLocal
from sqlalchemy import text

with SessionLocal() as s:

    # ── 1. Planted alert ─────────────────────────────────────────────────────
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

    # ── 2. #402 and #455 ─────────────────────────────────────────────────────
    print("\n=== INCIDENTS #402 AND #455 ===")
    for iid in [402, 455]:
        row = s.execute(text(
            "SELECT id, status, priority, hosts, first_seen, last_seen, raw_alert_count "
            "FROM incidents WHERE id = :id"
        ), {"id": iid}).fetchone()
        if row:
            print(f"  #{iid}: status={row.status} priority={row.priority} "
                  f"alerts={row.raw_alert_count} hosts={row.hosts} "
                  f"{str(row.first_seen)[:16]} – {str(row.last_seen)[:16]}")
        else:
            print(f"  #{iid}: NOT FOUND")

    # ── 3. All currently-open incidents ──────────────────────────────────────
    print("\n=== OPEN INCIDENTS ===")
    open_rows = s.execute(text("""
        SELECT id, priority, raw_alert_count, hosts, first_seen, last_seen
        FROM incidents WHERE status = 'open'
        ORDER BY priority DESC, id
    """)).fetchall()
    for r in open_rows:
        print(f"  #{r.id}: priority={r.priority} alerts={r.raw_alert_count} "
              f"hosts={r.hosts} {str(r.first_seen)[:16]}–{str(r.last_seen)[:16]}")

    # ── 4. Suppressed incidents — which rules fired? ──────────────────────────
    print("\n=== SUPPRESSED INCIDENTS (with rules) ===")
    supp = s.execute(text("""
        SELECT i.id, i.priority, i.raw_alert_count, i.hosts,
               i.first_seen, i.last_seen,
               array_agg(DISTINCT a.rule_id ORDER BY a.rule_id) AS rules
        FROM incidents i
        JOIN alerts a ON a.incident_id = i.id
        WHERE i.status = 'suppressed'
        GROUP BY i.id, i.priority, i.raw_alert_count, i.hosts, i.first_seen, i.last_seen
        ORDER BY i.raw_alert_count DESC, i.id
        LIMIT 40
    """)).fetchall()
    for r in supp:
        print(f"  #{r.id}: priority={r.priority} alerts={r.raw_alert_count} "
              f"hosts={r.hosts} {str(r.first_seen)[:16]}–{str(r.last_seen)[:16]} "
              f"rules={r.rules}")

    # ── 5. Orphaned narrative sentences ───────────────────────────────────────
    print("\n=== ORPHANED NARRATIVE SENTENCES ===")
    orphan = s.execute(text("""
        SELECT COUNT(*) FROM narrative_sentences n
        JOIN incidents i ON i.id = n.incident_id
        WHERE i.status != 'open'
    """)).scalar()
    total = s.execute(text("SELECT COUNT(*) FROM narrative_sentences")).scalar()
    open_sent = s.execute(text("""
        SELECT COUNT(*) FROM narrative_sentences n
        JOIN incidents i ON i.id = n.incident_id
        WHERE i.status = 'open'
    """)).scalar()
    print(f"  Total sentences: {total}")
    print(f"  Belonging to open incidents: {open_sent}")
    print(f"  Orphaned (non-open incident): {orphan}")

    # ── 6. Harness scoreboard — verify it filters on open only ────────────────
    print("\n=== SCOREBOARD (harness) ===")
    from curator.eval.harness import evaluate_accuracy
    score = evaluate_accuracy(s)
    keys = ["executed", "recovered", "not_in_evidence", "invented_beyond_gt",
            "precision", "recall", "f1"]
    for k in keys:
        print(f"  {k}: {score.get(k)}")
