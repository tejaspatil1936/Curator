import json
import numpy as np
from sqlalchemy import text
from curator.db import SessionLocal
from curator.ai.narrative import generate_incident_narrative
from curator.ai.mapping import map_incident_techniques

def run_live():
    db = SessionLocal()

    # Get baseline audit_chain max ID before running
    start_audit_id = db.execute(text("SELECT coalesce(max(id), 0) FROM audit_chain")).scalar_one()
    print(f"Starting live run at audit_chain ID: {start_audit_id}")

    incidents_to_run = [803, 855]
    results = {}

    for inc_id in incidents_to_run:
        print(f"\n=======================================================")
        print(f"Executing LIVE generation for Incident #{inc_id}...")
        
        # 1. Narrative
        print(f"Calling Sonnet 5 for narrative (#{inc_id})...")
        narr_res = generate_incident_narrative(inc_id, session=db)
        
        # 2. Mapping
        print(f"Calling Sonnet 5 for technique mapping (#{inc_id})...")
        map_res = map_incident_techniques(inc_id, session=db, k_candidates=20)
        
        results[inc_id] = {
            "narrative": narr_res,
            "mapping": map_res,
        }

    # Fetch audit chain rows produced during this run
    q_audit = text("""
        SELECT id, ts, actor, action, detail
        FROM audit_chain
        WHERE id > :start_id AND action = 'anthropic_api_call'
        ORDER BY id ASC
    """)
    audit_rows = db.execute(q_audit, {"start_id": start_audit_id}).fetchall()

    print("\n" + "="*80)
    print("RAW AUDIT_CHAIN CALL LOGS (Live Calls Only)")
    print("="*80)
    total_cost_usd = 0.0
    total_in_tokens = 0
    total_out_tokens = 0
    total_cache_read = 0
    total_cache_write = 0

    for r in audit_rows:
        d = r.detail or {}
        model = d.get("model")
        task = d.get("task")
        inc = d.get("incident_id")
        in_tok = d.get("input_tokens", 0)
        out_tok = d.get("output_tokens", 0)
        c_read = d.get("cache_read_tokens", 0)
        c_write = d.get("cache_creation_tokens", 0)
        lat = d.get("latency_ms", 0)
        dry = d.get("dry_run", False)
        cost_usd = (d.get("cost_micro_usd", 0) or 0) / 1_000_000.0

        total_in_tokens += in_tok
        total_out_tokens += out_tok
        total_cache_read += c_read
        total_cache_write += c_write
        total_cost_usd += cost_usd

        print(f"\n[Audit ID {r.id}] Timestamp: {r.ts.isoformat()}")
        print(f"  Incident: #{inc} | Task: {task} | Model: {model}")
        print(f"  Input Tokens: {in_tok} | Output Tokens: {out_tok}")
        print(f"  Cache Read: {c_read} | Cache Write: {c_write}")
        print(f"  Latency: {lat}ms | Cost: ${cost_usd:.6f} | dry_run: {dry}")

    # Compute sentence metrics
    all_sentence_eids_lens = []
    dropped_details = []
    zero_valid_count = 0
    total_mapped = 0
    total_declined = 0
    total_rejected = 0
    distinct_tech_ids = set()

    print("\n" + "="*80)
    print("PER-INCIDENT SENTENCE & VALIDATION REPORT")
    print("="*80)

    for inc_id in incidents_to_run:
        n_data = results[inc_id]["narrative"]
        m_data = results[inc_id]["mapping"]
        s_list = n_data["sentences"]
        
        ev_lens = [len(s["evidence_event_ids"]) for s in s_list]
        all_sentence_eids_lens.extend(ev_lens)
        
        for s in s_list:
            if len(s["evidence_event_ids"]) == 0:
                zero_valid_count += 1

        total_mapped += m_data["mapped_count"]
        total_declined += m_data["declined_count"]
        total_rejected += m_data["rejected_out_of_candidates_count"]

        for m in m_data["mappings"]:
            if m.get("technique_id"):
                distinct_tech_ids.add(m["technique_id"])

        print(f"\nIncident #{inc_id}:")
        print(f"  Title: {n_data['title']}")
        print(f"  Sentence count: {len(s_list)}")
        print(f"  Mean EIDs/sentence:   {n_data['mean_evidence_ids_per_sentence']:.2f}")
        print(f"  Median EIDs/sentence: {n_data['median_evidence_ids_per_sentence']:.2f}")
        print(f"  Dropped IDs: {n_data['dropped_ids_count']} / Total Claimed: {n_data['total_claimed_ids']}")
        if n_data.get("dropped_details"):
            for dd in n_data["dropped_details"]:
                print(f"    -> Sentence {dd['seq']}: invalid IDs {dd['invalid_ids']} ('{dd['text']}...')")
        else:
            print(f"    -> Zero invalid IDs dropped (100% of cited IDs exist in database)")
        print(f"  Mapping: {m_data['mapped_count']} mapped, {m_data['declined_count']} declined, {m_data['rejected_out_of_candidates_count']} rejected")

    overall_mean = float(np.mean(all_sentence_eids_lens)) if all_sentence_eids_lens else 0.0
    overall_median = float(np.median(all_sentence_eids_lens)) if all_sentence_eids_lens else 0.0

    total_prompt_toks = total_in_tokens + total_cache_read
    cache_hit_rate = (total_cache_read / total_prompt_toks * 100.0) if total_prompt_toks > 0 else 0.0

    print("\n" + "="*80)
    print("OVERALL SUMMARY FOR LIVE RUN (#803 & #855)")
    print("="*80)
    print(f"Total Sentences Produced:      {len(all_sentence_eids_lens)}")
    print(f"Mean Evidence IDs / sentence:  {overall_mean:.2f}")
    print(f"Median Evidence IDs / sentence:{overall_median:.2f}")
    print(f"Total Dropped Invalid IDs:     {sum(results[i]['narrative']['dropped_ids_count'] for i in incidents_to_run)}")
    print(f"Sentences with 0 valid IDs:    {zero_valid_count}")
    print(f"ATT&CK Mapped:                 {total_mapped}")
    print(f"ATT&CK Declined:               {total_declined}")
    print(f"ATT&CK Rejected (out-of-cand): {total_rejected}")
    print(f"Total Real Cost (USD):         ${total_cost_usd:.6f}")
    print(f"Cache Hit Rate:                {cache_hit_rate:.1f}% (Read: {total_cache_read}, Write: {total_cache_write}, Input: {total_in_tokens})")

    # Read technique names directly from database
    print("\n" + "="*80)
    print("DISTINCT TECHNIQUES RECOVERED (Read from techniques table)")
    print("="*80)
    for tid in sorted(distinct_tech_ids):
        t_row = db.execute(text("SELECT id, name FROM techniques WHERE id = :id"), {"id": tid}).fetchone()
        t_name = t_row[1] if t_row else "UNKNOWN"
        print(f"  {tid:12s} : {t_name}")

    # Full narrative for #803
    print("\n" + "="*80)
    print("FULL LIVE NARRATIVE FOR INCIDENT #803")
    print("="*80)
    q_402 = text("""
        SELECT ns.seq, ns.text, ns.evidence_event_ids, ns.technique_id, ns.technique_name, ns.technique_conf
        FROM narrative_sentences ns
        WHERE ns.incident_id = 803
        ORDER BY ns.seq ASC
    """)
    rows_402 = db.execute(q_402).fetchall()
    for r in rows_402:
        t_str = f"[{r.technique_id} - {r.technique_name} (conf={r.technique_conf})]" if r.technique_id else "[DECLINED]"
        print(f"\n[Sentence {r.seq}] {r.text}")
        print(f"  Evidence Event IDs ({len(r.evidence_event_ids)}): {r.evidence_event_ids}")
        print(f"  Technique: {t_str}")

    db.close()

if __name__ == "__main__":
    run_live()
