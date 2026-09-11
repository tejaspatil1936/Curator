"""
6.1c — Mapping gap diagnosis for 5 missed techniques.

For each missed technique, find the narrative sentence that should have captured it,
retrieve the mapping candidate list that the model actually saw, and determine whether
the correct technique was present in candidates but the model chose differently,
or whether retrieval never surfaced it.

Run with: docker exec curator-curator-api-1 python curator/scripts/diagnose_mapping_gaps.py
"""
from __future__ import annotations

import json
from curator.db import SessionLocal
from sqlalchemy import text

# The 5 mapping gaps to diagnose
GAPS = {
    "T1021.006": {
        "name": "WinRM",
        "note": "5 steps; tagged T1059.001 instead",
        "keywords": ["winrm", "winrs", "wsmprovhost", "wsman"],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "note": "6 steps; tagged as download/execution",
        "keywords": ["downloadstring", "downloadfile", "invoke-webrequest", "certutil", "bits"],
    },
    "T1543.003": {
        "name": "Windows Service",
        "note": "1 step; tagged T1569",
        "keywords": ["sc create", "sc config", "new-service", "installutil"],
    },
    "T1074": {
        "name": "Data Staged",
        "note": "3 steps; grouped into collection sentences",
        "keywords": ["stage", "compress", "archive", "zip", "rar", "collected"],
    },
    "T1136": {
        "name": "Create Account",
        "note": "1 step; mapped to T1098 instead",
        "keywords": ["net user /add", "useradd", "new-localuser", "dsadd user"],
    },
}


def main():
    with SessionLocal() as s:
        for tid, info in GAPS.items():
            print(f"\n{'='*70}")
            print(f"TARGET: {tid} — {info['name']}")
            print(f"NOTE:   {info['note']}")

            # 1. Find sentences that SHOULD map to this technique
            #    Look for sentences whose text contains related keywords
            keyword_conditions = " OR ".join(
                f"LOWER(n.text) LIKE '%{kw}%'" for kw in info["keywords"]
            )
            rows = s.execute(text(f"""
                SELECT n.id, n.incident_id, n.seq, n.technique_id, n.technique_name,
                       n.text, n.evidence_event_ids
                FROM narrative_sentences n
                WHERE {keyword_conditions}
                ORDER BY n.incident_id, n.seq
                LIMIT 5
            """)).fetchall()

            if not rows:
                # Broader fallback: search alerts for the technique hint
                rows = s.execute(text("""
                    SELECT n.id, n.incident_id, n.seq, n.technique_id, n.technique_name,
                           n.text, n.evidence_event_ids
                    FROM narrative_sentences n
                    JOIN alerts al ON al.id = ANY(
                        SELECT a.id FROM alerts a
                        WHERE :tid = ANY(a.technique_ids)
                    )
                    ORDER BY n.incident_id, n.seq
                    LIMIT 5
                """), {"tid": tid}).fetchall()

            print(f"\n  Candidate sentences (keyword match):")
            if not rows:
                print("    (none found by keyword — checking by actual mapped technique_id)")
                # As last resort, show sentences with nearby incident events
                rows = s.execute(text("""
                    SELECT n.id, n.incident_id, n.seq, n.technique_id, n.technique_name,
                           n.text, n.evidence_event_ids
                    FROM narrative_sentences n
                    JOIN incidents i ON i.id = n.incident_id
                    WHERE i.status != 'suppressed'
                    ORDER BY n.incident_id, n.seq
                    LIMIT 3
                """)).fetchall()

            for r in rows:
                print(f"\n    [Inc #{r.incident_id} Seq {r.seq}] mapped_to={r.technique_id} ({r.technique_name})")
                print(f"    TEXT: {r.text[:250]}")

                # Show the actual evidence events for this sentence
                if r.evidence_event_ids:
                    evs = s.execute(text("""
                        SELECT id, event_code, source, command_line, raw
                        FROM events WHERE id = ANY(:eids)
                    """), {"eids": r.evidence_event_ids}).fetchall()
                    for ev in evs[:3]:
                        raw = ev.raw or {}
                        cmd = (
                            ev.command_line
                            or raw.get("CommandLine")
                            or raw.get("ScriptBlockText", "")[:150]
                        )
                        print(f"      EVENT {ev.id} code={ev.event_code}  cmd={cmd!r}")

            # 2. Check mapping_candidates table if it exists
            has_candidates = s.execute(text("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'mapping_candidates'
                )
            """)).scalar()

            if has_candidates:
                cand_rows = s.execute(text("""
                    SELECT sentence_id, candidates_json, chosen_id
                    FROM mapping_candidates
                    WHERE :tid = ANY(
                        SELECT jsonb_array_elements_text(candidates_json::jsonb -> 'ids')
                    )
                    OR chosen_id = :tid
                    LIMIT 5
                """), {"tid": tid}).fetchall()
                print(f"\n  Mapping candidate records (target in list OR chosen):")
                if not cand_rows:
                    print("    (none)")
                for cr in cand_rows:
                    print(f"    sentence_id={cr.sentence_id} chosen={cr.chosen_id}")
                    print(f"    candidates={cr.candidates_json}")
            else:
                print("\n  [no mapping_candidates table — checking narrative_sentences for mapping metadata]")

            # 3. Check alerts whose technique_ids include this technique  
            alert_rows = s.execute(text("""
                SELECT a.id, a.rule_id, a.rule_name, a.incident_id,
                       a.technique_ids, e.command_line
                FROM alerts a
                JOIN events e ON e.id = a.event_id
                WHERE :tid = ANY(a.technique_ids)
                LIMIT 5
            """), {"tid": tid}).fetchall()

            print(f"\n  Alerts whose technique_ids includes {tid}:")
            if not alert_rows:
                print("    (none — retrieval never surfaced this technique as a candidate)")
            for ar in alert_rows:
                print(f"    alert={ar.id} rule={ar.rule_id} inc={ar.incident_id}")
                print(f"    technique_ids={ar.technique_ids}  cmd={str(ar.command_line or '')[:120]!r}")


if __name__ == "__main__":
    main()
