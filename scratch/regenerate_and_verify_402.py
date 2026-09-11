import json
from sqlalchemy import text
from curator.db import SessionLocal
from curator.pipeline.fixtures import inject_planted_alert
from curator.ai.narrative import generate_incident_narrative
from curator.ai.mapping import map_incident_techniques
from curator.ai.verify import verify_incident

def main():
    db = SessionLocal()
    
    print("1. Injecting synthetic planted alert...")
    res = inject_planted_alert(db)
    print(f"Planted alert injection result: {res}")
    
    print("\n2. Generating narrative for Incident #402 (Sonnet 5)...")
    narr = generate_incident_narrative(402, session=db)
    print(f"Narrative generated: {len(narr['sentences'])} sentences.")
    
    print("\n3. Mapping techniques for Incident #402 (Sonnet 5)...")
    mapping = map_incident_techniques(402, session=db)
    print(f"Mapped {len(mapping['mappings'])} techniques.")
    
    print("\n4. Verifying narrative sentences for Incident #402 (Haiku 4.5)...")
    verif = verify_incident(402, session=db, batch_size=5)
    print(f"Verification: {verif['checked']} checked | {verif['supported']} supported | {verif['unsupported']} unsupported")
    
    print("\n5. Searching for sentence derived from planted event 999999:")
    q_planted_sent = text("""
        SELECT n.seq, n.text, n.evidence_event_ids, v.supported, v.reason
        FROM narrative_sentences n
        LEFT JOIN verifications v ON v.sentence_id = n.id
        WHERE n.incident_id = 402 AND (999999 = ANY(n.evidence_event_ids) OR n.text ILIKE '%198.51.100.66%')
    """)
    rows = db.execute(q_planted_sent).fetchall()
    if rows:
        for r in rows:
            print(f"Seq: {r[0]}")
            print(f"Text: \"{r[1]}\"")
            print(f"Citations: {r[2]}")
            print(f"Supported: {r[3]}")
            print(f"Verifier Reason: \"{r[4]}\"")
    else:
        print("WARNING: No sentence cited event 999999 or mentioned 198.51.100.66!")
        print("\nAll sentences in #402:")
        all_s = db.execute(text("SELECT seq, text, evidence_event_ids FROM narrative_sentences WHERE incident_id = 402 ORDER BY seq")).fetchall()
        for s in all_s:
            print(f"[{s[0]}] {s[1]} ({s[2]})")

    db.close()

if __name__ == '__main__':
    main()
