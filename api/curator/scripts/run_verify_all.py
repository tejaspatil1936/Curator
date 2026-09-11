import json
from sqlalchemy import text
from curator.db import SessionLocal
from curator.ai.verify import verify_all_incidents

def main():
    db = SessionLocal()
    
    # Get audit chain start ID
    start_audit_id = db.execute(text("SELECT coalesce(max(id), 0) FROM audit_chain")).scalar_one()
    print(f"Starting verify_all_incidents at audit_chain ID {start_audit_id}...")
    
    summary = verify_all_incidents(session=db, batch_size=5)
    
    # Query audit chain for calls made during this run
    q_audit = text("""
        SELECT id, ts, actor, action, detail
        FROM audit_chain
        WHERE id > :start_id AND action = 'anthropic_api_call'
        ORDER BY id ASC
    """)
    audit_rows = db.execute(q_audit, {"start_id": start_audit_id}).fetchall()
    
    total_cost_usd = 0.0
    total_in_tok = 0
    total_out_tok = 0
    total_calls = len(audit_rows)
    
    for r in audit_rows:
        d = r.detail or {}
        in_tok = d.get("input_tokens", 0)
        out_tok = d.get("output_tokens", 0)
        cost_micro = d.get("cost_micro_usd", 0) or 0
        total_in_tok += in_tok
        total_out_tok += out_tok
        total_cost_usd += cost_micro / 1_000_000.0
    
    print("\n" + "="*80)
    print("VERIFICATION COMPREHENSIVE REPORT")
    print("="*80)
    print(f"Total Incidents Processed: {summary['incidents_count']}")
    print(f"Total Sentences Checked: {summary['total_checked']}")
    print(f"Total Supported: {summary['total_supported']}")
    print(f"Total Unsupported: {summary['total_unsupported']}")
    print(f"Verifier LLM Calls (Haiku 4.5): {total_calls}")
    print(f"Verifier Input Tokens: {total_in_tok:,}")
    print(f"Verifier Output Tokens: {total_out_tok:,}")
    print(f"Verifier Total Cost: ${total_cost_usd:.4f} USD")
    
    print("\n" + "="*80)
    print("PER-INCIDENT BREAKDOWN")
    print("="*80)
    for inc in summary['incidents']:
        print(f"Incident #{inc['incident_id']:<4} | Checked: {inc['checked']:<2} | Supported: {inc['supported']:<2} | Unsupported: {inc['unsupported']:<2}")
        
    print("\n" + "="*80)
    print("UNSUPPORTED SENTENCES IN FULL WITH VERIFIER REASONS")
    print("="*80)
    for u in summary['unsupported_sentences']:
        print(f"\n[Incident #{u['incident_id']} | Seq {u['seq']}]")
        print(f"Sentence: \"{u['text']}\"")
        print(f"Cited Event IDs: {u['evidence_event_ids']}")
        print(f"Verifier Reason: {u['reason']}")

if __name__ == '__main__':
    main()
