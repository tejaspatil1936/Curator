import json
import time
from sqlalchemy import text
from curator.db import SessionLocal
from curator.ai.narrative import generate_incident_narrative
from curator.ai.mapping import map_incident_techniques
from curator.ai.verify import verify_incident
from curator.pipeline.fixtures import inject_planted_alert

def main():
    db = SessionLocal()
    
    # 1. Ensure planted false alert is in place
    inject_planted_alert(db)
    
    # 2. Get baseline audit_chain ID
    start_audit_id = db.execute(text("SELECT coalesce(max(id), 0) FROM audit_chain")).scalar_one()
    print(f"Starting complete regeneration and verification at audit_chain ID: {start_audit_id}")
    
    # 3. Get all surfaced incidents
    q_surfaced = text("""
        SELECT id FROM incidents
        WHERE priority > 0 AND (raw_alert_count >= 3 OR priority >= 80)
        ORDER BY id ASC
    """)
    surfaced_ids = [r[0] for r in db.execute(q_surfaced).fetchall()]
    print(f"Surfaced incidents to regenerate ({len(surfaced_ids)}): {surfaced_ids}")
    
    start_time = time.time()
    
    # 4. Process each incident
    for idx, inc_id in enumerate(surfaced_ids, start=1):
        print(f"\n[{idx}/{len(surfaced_ids)}] Processing Incident #{inc_id}...")
        t0 = time.time()
        
        # a. Narrative (Sonnet 5)
        narr = generate_incident_narrative(inc_id, session=db)
        print(f"  Narrative: {len(narr['sentences'])} sentences generated")
        
        # b. Mapping (Sonnet 5)
        m = map_incident_techniques(inc_id, session=db)
        print(f"  Mapping: {len(m['mappings'])} techniques mapped")
        
        # c. Verification (Haiku 4.5, 5 per batch)
        v = verify_incident(inc_id, session=db, batch_size=5)
        print(f"  Verification: {v['checked']} checked | {v['supported']} supported | {v['unsupported']} unsupported ({time.time()-t0:.1f}s)")
        
    elapsed = time.time() - start_time
    print(f"\nAll 20 incidents regenerated and verified in {elapsed:.1f}s")
    
    # 5. Database aggregation
    q_agg = text("""
        SELECT 
            count(v.id) as checked,
            count(v.id) FILTER (WHERE v.supported = true) as supported,
            count(v.id) FILTER (WHERE v.supported = false) as unsupported
        FROM verifications v
    """)
    agg = db.execute(q_agg).fetchone()
    total_checked, total_supp, total_unsupp = agg[0], agg[1], agg[2]
    unsupp_pct = (total_unsupp / total_checked * 100.0) if total_checked else 0.0
    
    # 6. Audit chain metrics
    q_audit = text("""
        SELECT 
            detail->>'task' as task,
            detail->>'model' as model,
            count(id) as calls,
            sum((detail->>'input_tokens')::int) as in_tok,
            sum((detail->>'output_tokens')::int) as out_tok,
            sum((detail->>'cache_read_tokens')::int) as cache_read,
            sum((detail->>'cache_creation_tokens')::int) as cache_write,
            sum((detail->>'cost_micro_usd')::numeric)/1000000.0 as cost_usd
        FROM audit_chain
        WHERE id > :start_id AND action = 'anthropic_api_call'
        GROUP BY detail->>'task', detail->>'model'
        ORDER BY task ASC
    """)
    audit_rows = db.execute(q_audit, {"start_id": start_audit_id}).fetchall()
    
    total_run_cost = db.execute(
        text("SELECT sum((detail->>'cost_micro_usd')::numeric)/1000000.0 FROM audit_chain WHERE id > :start_id AND action = 'anthropic_api_call'"),
        {"start_id": start_audit_id}
    ).scalar_one() or 0.0
    
    print("\n" + "="*80)
    print("STEP 5.1 FINAL VERIFICATION REPORT")
    print("="*80)
    print(f"Total Sentences Checked: {total_checked}")
    print(f"Total Supported: {total_supp} ({total_supp/total_checked*100:.1f}%)")
    print(f"Total Unsupported: {total_unsupp} ({unsupp_pct:.1f}%)")
    print(f"Target Window: 10% - 15% unsupported")
    print(f"Total Run Cost: ${float(total_run_cost):.4f} USD")
    
    print("\nAudit Chain Breakdown:")
    for a in audit_rows:
        print(f"  Task: {a[0]:<22} | Model: {a[1]} | Calls: {a[2]:<2} | InTok: {a[3] or 0:,} | OutTok: {a[4] or 0:,} | Cost: ${float(a[7] or 0):.4f}")
        
    print("\n" + "="*80)
    print("PER-INCIDENT BREAKDOWN")
    print("="*80)
    q_inc_breakdown = text("""
        SELECT n.incident_id,
               count(v.id) as checked,
               count(v.id) FILTER (WHERE v.supported = true) as supported,
               count(v.id) FILTER (WHERE v.supported = false) as unsupported
        FROM narrative_sentences n
        JOIN verifications v ON v.sentence_id = n.id
        GROUP BY n.incident_id
        ORDER BY n.incident_id ASC
    """)
    for r in db.execute(q_inc_breakdown).fetchall():
        pct = (r[3] / r[1] * 100.0) if r[1] else 0.0
        print(f"Incident #{r[0]:<4} | Checked: {r[1]:<2} | Supported: {r[2]:<2} | Unsupported: {r[3]:<2} ({pct:.1f}%)")
        
    print("\n" + "="*80)
    print("ALL REMAINING UNSUPPORTED SENTENCES IN FULL WITH VERIFIER REASONS")
    print("="*80)
    q_unsupp = text("""
        SELECT n.incident_id, n.seq, n.text, n.evidence_event_ids, v.reason
        FROM narrative_sentences n
        JOIN verifications v ON v.sentence_id = n.id
        WHERE v.supported = false
        ORDER BY n.incident_id ASC, n.seq ASC
    """)
    unsupp_rows = db.execute(q_unsupp).fetchall()
    for u in unsupp_rows:
        print(f"\n[Incident #{u[0]} | Seq {u[1]}]")
        print(f"Sentence: \"{u[2]}\"")
        print(f"Citations: {u[3]}")
        print(f"Verifier Reason: {u[4]}")

if __name__ == '__main__':
    main()
