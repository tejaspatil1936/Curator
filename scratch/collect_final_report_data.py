import json
from sqlalchemy import text
from curator.db import SessionLocal

db = SessionLocal()

print("=== 1. AGGREGATE VERIFICATION METRICS ===")
q_agg = text("""
    SELECT 
        count(v.id) as checked,
        count(v.id) FILTER (WHERE v.supported = true) as supported,
        count(v.id) FILTER (WHERE v.supported = false) as unsupported
    FROM verifications v
    JOIN narrative_sentences n ON n.id = v.sentence_id
    JOIN incidents i ON i.id = n.incident_id
    WHERE i.status != 'suppressed'
""")
agg = db.execute(q_agg).fetchone()
checked, supp, unsupp = agg[0], agg[1], agg[2]
pct = (unsupp / checked * 100.0) if checked else 0.0
print(f"Total sentences: {checked}")
print(f"Supported: {supp} ({supp/checked*100:.2f}%)")
print(f"Unsupported: {unsupp} ({pct:.2f}%)")

print("\n=== 2. PER-INCIDENT BREAKDOWN ===")
q_inc = text("""
    SELECT n.incident_id,
           count(v.id) as checked,
           count(v.id) FILTER (WHERE v.supported = true) as supported,
           count(v.id) FILTER (WHERE v.supported = false) as unsupported
    FROM narrative_sentences n
    JOIN verifications v ON v.sentence_id = n.id
    JOIN incidents i ON i.id = n.incident_id
    WHERE i.status != 'suppressed'
    GROUP BY n.incident_id
    ORDER BY n.incident_id ASC
""")
inc_rows = db.execute(q_inc).fetchall()
for r in inc_rows:
    inc_pct = (r[3] / r[1] * 100.0) if r[1] else 0.0
    print(f"Incident #{r[0]:<4} | Checked: {r[1]:<2} | Supported: {r[2]:<2} | Unsupported: {r[3]:<2} ({inc_pct:5.1f}%)")

print("\n=== 3. SPECIFIC 5 INCIDENTS COMPARISON (5.1a) ===")
# #418, #477, #430, #490, #504
for inc_id in [418, 477, 430, 490, 504]:
    r = db.execute(text("""
        SELECT count(v.id), 
               count(v.id) FILTER (WHERE v.supported = true),
               count(v.id) FILTER (WHERE v.supported = false)
        FROM narrative_sentences n
        JOIN verifications v ON v.sentence_id = n.id
        WHERE n.incident_id = :id
    """), {"id": inc_id}).fetchone()
    print(f"Incident #{inc_id}: Checked={r[0]}, Supported={r[1]}, Unsupported={r[2]}")

print("\n=== 4. PLANTED ALERT IN INCIDENT #402 ===")
planted_rows = db.execute(text("""
    SELECT n.seq, n.text, n.evidence_event_ids, v.supported, v.reason
    FROM narrative_sentences n
    JOIN verifications v ON v.sentence_id = n.id
    WHERE n.incident_id = 402 AND (42145 = ANY(n.evidence_event_ids) OR n.text ILIKE '%pbeesly%lsass%' OR n.text ILIKE '%0xffffffff%')
""")).fetchall()
for p in planted_rows:
    print(f"Seq: {p[0]}")
    print(f"Text: {p[1]}")
    print(f"Citations: {p[2]}")
    print(f"Supported: {p[3]}")
    print(f"Verifier Reason: {p[4]}")

print("\n=== 5. EVERY REMAINING UNSUPPORTED SENTENCE WITH VERIFIER REASON ===")
q_unsupp = text("""
    SELECT n.incident_id, n.seq, n.text, n.evidence_event_ids, v.reason
    FROM narrative_sentences n
    JOIN verifications v ON v.sentence_id = n.id
    JOIN incidents i ON i.id = n.incident_id
    WHERE i.status != 'suppressed' AND v.supported = false
    ORDER BY n.incident_id ASC, n.seq ASC
""")
unsupp_rows = db.execute(q_unsupp).fetchall()
print(f"Total unsupported sentences found: {len(unsupp_rows)}")
for idx, u in enumerate(unsupp_rows, 1):
    print(f"\n--- [{idx}/{len(unsupp_rows)}] Incident #{u[0]} | Seq {u[1]} ---")
    print(f"Text: \"{u[2]}\"")
    print(f"Citations: {u[3]}")
    print(f"Reason: \"{u[4]}\"")

print("\n=== 6. AUDIT CHAIN METRICS & REAL COST ===")
# Get total cost for the current day / session
q_audit_summary = text("""
    SELECT 
        detail->>'task' as task,
        detail->>'model' as model,
        count(id) as calls,
        sum((detail->>'input_tokens')::int) as in_tok,
        sum((detail->>'output_tokens')::int) as out_tok,
        sum(coalesce((detail->>'cache_read_tokens')::int, 0)) as cache_read,
        sum(coalesce((detail->>'cache_creation_tokens')::int, 0)) as cache_write,
        sum((detail->>'cost_micro_usd')::numeric)/1000000.0 as cost_usd
    FROM audit_chain
    WHERE action = 'anthropic_api_call' AND (detail->>'dry_run')::boolean = false
    GROUP BY detail->>'task', detail->>'model'
    ORDER BY task ASC
""")
for a in db.execute(q_audit_summary).fetchall():
    print(f"Task: {a[0]:<25} | Model: {a[1]:<25} | Calls: {a[2]:<3} | InTok: {a[3] or 0:,} | OutTok: {a[4] or 0:,} | Cost: ${float(a[7] or 0):.4f}")

total_cost = db.execute(text("""
    SELECT sum((detail->>'cost_micro_usd')::numeric)/1000000.0
    FROM audit_chain
    WHERE action = 'anthropic_api_call' AND (detail->>'dry_run')::boolean = false
""")).scalar() or 0.0
print(f"\nTotal Live API Cost Recorded in audit_chain: ${float(total_cost):.4f} USD")

db.close()
