from curator.db import SessionLocal
from sqlalchemy import text
from curator.attack.retrieve import retrieve

db = SessionLocal()

sentences = db.execute(text("""
    SELECT seq, text, evidence_event_ids
    FROM narrative_sentences
    WHERE incident_id = 402 AND seq IN (3, 4, 5)
    ORDER BY seq ASC
""")).fetchall()

for s in sentences:
    seq = s.seq
    txt = s.text
    eids = s.evidence_event_ids or []
    
    context_terms = []
    if eids:
        q_ctx = text("""
            SELECT process_name, command_line, file_path, dst_ip,
                   ocsf->'dst_endpoint'->>'port' as port, event_code,
                   ocsf->'unmapped'->>'ShareName' as share_name
            FROM events
            WHERE id = ANY(:eids)
            LIMIT 10
        """)
        ctx_rows = db.execute(q_ctx, {"eids": eids}).fetchall()
        for cr in ctx_rows:
            if cr[0]: context_terms.append(str(cr[0]))
            if cr[1]: context_terms.append(str(cr[1]))
            if cr[2]: context_terms.append(str(cr[2]))
            if cr[3]: context_terms.append(str(cr[3]))
            if cr[4]: context_terms.append(f"port {cr[4]}")
            if cr[5]: context_terms.append(f"event {cr[5]}")
            if cr[6]: context_terms.append(f"share {cr[6]}")

    enriched_query = f"{txt} {' '.join(context_terms[:15])}".strip()
    print(f"\n=======================================================")
    print(f"Sentence {seq}: \"{txt}\"")
    print(f"Cited Event IDs: {eids}")
    print(f"Context terms from DB ({len(context_terms)}): {context_terms[:15]}")
    print(f"Enriched query: \"{enriched_query}\"")
    
    cands = retrieve(enriched_query, k=20, conn=db.connection())
    has_t1071_001 = any(c.id == "T1071.001" for c in cands)
    has_t1071 = any(c.id == "T1071" for c in cands)
    has_t1105 = any(c.id == "T1105" for c in cands)
    print(f"T1071.001 in top-20?: {has_t1071_001} | T1071 in top-20?: {has_t1071} | T1105 in top-20?: {has_t1105}")
    print("Top Candidates:")
    for idx, c in enumerate(cands, 1):
        target_mark = " ***" if c.id in ("T1071.001", "T1071", "T1105", "T1205", "T1546.002") else ""
        print(f"  {idx:2d}. {c.id:10s} {c.name[:38]:38s} score={c.score:.5f}{target_mark}")

db.close()
