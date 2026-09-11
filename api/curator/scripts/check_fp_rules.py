"""Diagnostic: FP technique sentences and rule alert counts (6.1a)."""
from curator.db import SessionLocal
from sqlalchemy import text

def main():
    with SessionLocal() as s:
        # 1. Sentences still mapped to FP techniques
        rows = s.execute(text("""
            SELECT n.id, n.incident_id, n.technique_id, n.text, n.evidence_event_ids
            FROM narrative_sentences n
            WHERE n.technique_id IN ('T1021.001','T1053.005')
            ORDER BY n.technique_id, n.incident_id
        """)).fetchall()

        print("=== Sentences mapped to T1021.001 / T1053.005 ===")
        if not rows:
            print("  (none found)")
        for r in rows:
            print(f"\n  technique={r.technique_id} sentence_id={r.id} incident={r.incident_id}")
            print(f"  TEXT: {r.text[:300]}")
            if r.evidence_event_ids:
                evs = s.execute(
                    text("SELECT id, event_code, source, command_line, raw FROM events WHERE id = ANY(:eids)"),
                    {"eids": r.evidence_event_ids}
                ).fetchall()
                for ev in evs:
                    raw = ev.raw or {}
                    cmd = ev.command_line or raw.get("CommandLine") or str(raw.get("Message", ""))[:200]
                    task = raw.get("TaskName", "")
                    logon_type = raw.get("LogonType", "")
                    src_addr = raw.get("IpAddress", "") or raw.get("WorkstationName", "")
                    print(f"    EVENT {ev.id} code={ev.event_code} src={ev.source}")
                    print(f"      cmd={cmd!r}")
                    print(f"      TaskName={task!r}  LogonType={logon_type!r}  SrcAddr={src_addr!r}")

        # 2. Alert counts by rule
        print("\n=== Alert counts by rule ===")
        rows2 = s.execute(text(
            "SELECT rule_id, COUNT(*) cnt FROM alerts GROUP BY rule_id ORDER BY rule_id"
        )).fetchall()
        total = 0
        for r in rows2:
            flag = " *** FP RULES" if r.rule_id in ("CUR-008", "CUR-017") else ""
            print(f"  {r.rule_id}: {r.cnt}{flag}")
            total += r.cnt
        print(f"  TOTAL: {total}")

        # 3. Incident counts
        print("\n=== Incident counts by status ===")
        rows3 = s.execute(text(
            "SELECT status, COUNT(*) cnt FROM incidents GROUP BY status ORDER BY status"
        )).fetchall()
        for r in rows3:
            print(f"  {r.status}: {r.cnt}")

if __name__ == "__main__":
    main()
