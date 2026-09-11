from curator.db import SessionLocal
from sqlalchemy import text

db = SessionLocal()

q = text("""
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
    WHERE action = 'anthropic_api_call'
    GROUP BY detail->>'task', detail->>'model'
    ORDER BY task ASC
""")
rows = db.execute(q).fetchall()
print("=== AUDIT CHAIN BREAKDOWN BY TASK AND MODEL ===")
for r in rows:
    print(f"Task: {r[0]:<25} | Model: {r[1]:<25} | Calls: {r[2]:<3} | InTok: {r[3] or 0:,} | OutTok: {r[4] or 0:,} | CacheRead: {r[5] or 0:,} | CacheWrite: {r[6] or 0:,} | Cost: ${float(r[7] or 0):.4f} USD")

total_cost = db.execute(text("SELECT sum((detail->>'cost_micro_usd')::numeric)/1000000.0 FROM audit_chain WHERE action = 'anthropic_api_call'")).scalar() or 0.0
print(f"\nTotal Real Cumulative Cost in audit_chain: ${float(total_cost):.4f} USD")

# Also get the cost of the Step 5.1 runs (after the previous Step 5 report)
# Let's see max id around start of Step 5.1
q_recent = text("""
    SELECT 
        detail->>'task' as task,
        detail->>'model' as model,
        count(id) as calls,
        sum((detail->>'input_tokens')::int) as in_tok,
        sum((detail->>'output_tokens')::int) as out_tok,
        sum((detail->>'cost_micro_usd')::numeric)/1000000.0 as cost_usd
    FROM audit_chain
    WHERE action = 'anthropic_api_call' AND id >= 180
    GROUP BY detail->>'task', detail->>'model'
    ORDER BY task ASC
""")
print("\n=== STEP 5.1 RUN COST BREAKDOWN (SINCE STEP 5.1 LAUNCH) ===")
for r in db.execute(q_recent).fetchall():
    print(f"Task: {r[0]:<25} | Model: {r[1]:<25} | Calls: {r[2]:<3} | InTok: {r[3] or 0:,} | OutTok: {r[4] or 0:,} | Cost: ${float(r[5] or 0):.4f} USD")

recent_cost = db.execute(text("SELECT sum((detail->>'cost_micro_usd')::numeric)/1000000.0 FROM audit_chain WHERE action = 'anthropic_api_call' AND id >= 180")).scalar() or 0.0
print(f"Step 5.1 Run Cost: ${float(recent_cost):.4f} USD")

db.close()
