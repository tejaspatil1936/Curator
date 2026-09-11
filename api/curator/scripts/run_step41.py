import json
import numpy as np
from sqlalchemy import text
from curator.db import SessionLocal
from curator.ai.narrative import generate_incident_narrative
from curator.ai.mapping import map_incident_techniques

def run_evaluation():
    db = SessionLocal()

    # 1. Fetch the 20 surfaced incidents
    q_inc = text("""
        SELECT id, title, priority, raw_alert_count, hosts, users
        FROM incidents
        WHERE status != 'suppressed'
        ORDER BY priority DESC, first_seen ASC, id ASC
    """)
    incidents = db.execute(q_inc).fetchall()
    print(f"Loaded {len(incidents)} surfaced incidents for Step 4.1 re-run.")

    per_incident_stats = []
    all_sentence_ev_counts = []
    total_dropped_ids = 0
    total_zero_id_sentences = 0
    total_sentences = 0

    total_mapped = 0
    total_declined = 0
    total_rejected = 0
    all_distinct_techniques = set()

    total_in_tokens = 0
    total_out_tokens = 0
    total_cache_read = 0
    total_cache_write = 0
    total_cost_usd = 0.0

    narrative_402_details = None

    for idx, inc in enumerate(incidents, 1):
        inc_id = inc.id
        print(f"[{idx}/{len(incidents)}] Processing Incident #{inc_id} (priority={inc.priority}, raw_alerts={inc.raw_alert_count})...")

        # Generate Narrative
        narr_res = generate_incident_narrative(inc_id, session=db)
        # Map ATT&CK Techniques
        map_res = map_incident_techniques(inc_id, session=db)

        s_count = len(narr_res["sentences"])
        total_sentences += s_count
        total_dropped_ids += narr_res["dropped_ids_count"]

        ev_lens = [len(s["evidence_event_ids"]) for s in narr_res["sentences"]]
        all_sentence_ev_counts.extend(ev_lens)
        zero_cnt = sum(1 for c in ev_lens if c == 0)
        total_zero_id_sentences += zero_cnt

        total_mapped += map_res["mapped_count"]
        total_declined += map_res["declined_count"]
        total_rejected += map_res["rejected_out_of_candidates_count"]

        for m in map_res["mappings"]:
            t_id = m.get("technique_id")
            if t_id:
                all_distinct_techniques.add(t_id)

        # Track usage
        total_in_tokens += narr_res["usage"]["input_tokens"] + map_res["usage"]["input_tokens"]
        total_out_tokens += narr_res["usage"]["output_tokens"] + map_res["usage"]["output_tokens"]
        total_cache_read += narr_res["usage"]["cache_read_tokens"] + map_res["usage"]["cache_read_tokens"]
        total_cache_write += narr_res["usage"]["cache_creation_tokens"] + map_res["usage"]["cache_creation_tokens"]
        total_cost_usd += narr_res["usage"]["cost_usd"] + map_res["usage"]["cost_usd"]

        mean_ev = float(np.mean(ev_lens)) if ev_lens else 0.0
        med_ev = float(np.median(ev_lens)) if ev_lens else 0.0

        per_incident_stats.append({
            "incident_id": inc_id,
            "priority": inc.priority,
            "sentences_count": s_count,
            "mean_ev_per_sent": mean_ev,
            "median_ev_per_sent": med_ev,
            "dropped_ids": narr_res["dropped_ids_count"],
            "zero_id_sentences": zero_cnt,
            "mapped": map_res["mapped_count"],
            "declined": map_res["declined_count"],
            "rejected": map_res["rejected_out_of_candidates_count"],
        })

        if inc_id == 402:
            # Query full narrative sentences and their mapped techniques from DB
            q_detail = text("""
                SELECT ns.seq, ns.text, ns.evidence_event_ids, ns.technique_id, ns.technique_conf as confidence, t.name as tech_name
                FROM narrative_sentences ns
                LEFT JOIN techniques t ON t.id = ns.technique_id
                WHERE ns.incident_id = 402
                ORDER BY ns.seq ASC
            """)
            narrative_402_details = db.execute(q_detail).fetchall()

    overall_mean_ev = float(np.mean(all_sentence_ev_counts)) if all_sentence_ev_counts else 0.0
    overall_median_ev = float(np.median(all_sentence_ev_counts)) if all_sentence_ev_counts else 0.0

    total_prompt_tokens = total_in_tokens + total_cache_read
    cache_hit_rate = (total_cache_read / total_prompt_tokens * 100.0) if total_prompt_tokens > 0 else 0.0

    print("\n" + "="*80)
    print("STEP 4.1 RE-RUN RESULTS REPORT")
    print("="*80)
    print("\n1. SENTENCES PER INCIDENT:")
    for s in per_incident_stats:
        print(f"  Incident #{s['incident_id']:3d} (Priority {s['priority']:2d}): {s['sentences_count']:2d} sentences | Mean EIDs/sent: {s['mean_ev_per_sent']:.2f} | Med: {s['median_ev_per_sent']:.1f} | Dropped: {s['dropped_ids']} | Mapped: {s['mapped']} | Declined: {s['declined']}")
    print(f"\nTotal Sentences across all 20 incidents: {total_sentences}")

    print("\n2. EVIDENCE IDS PER SENTENCE:")
    print(f"  Mean Evidence IDs per sentence:   {overall_mean_ev:.2f}")
    print(f"  Median Evidence IDs per sentence: {overall_median_ev:.2f}")
    print(f"  Dropped invalid IDs:              {total_dropped_ids}")
    print(f"  Sentences with zero valid IDs:    {total_zero_id_sentences}")

    print("\n3. ATT&CK MAPPING STATS:")
    print(f"  Mapped techniques:    {total_mapped}")
    print(f"  Declined (null):      {total_declined}")
    print(f"  Rejected out-of-cand: {total_rejected}")
    print(f"  Distinct techniques:  {len(all_distinct_techniques)} -> {sorted(list(all_distinct_techniques))}")

    print("\n4. COST AND CACHE:")
    print(f"  Total Cost (USD):     ${total_cost_usd:.4f}")
    print(f"  Input Tokens:         {total_in_tokens}")
    print(f"  Cache Read Tokens:    {total_cache_read}")
    print(f"  Output Tokens:        {total_out_tokens}")
    print(f"  Cache Hit Rate:       {cache_hit_rate:.1f}%")

    print("\n5. FULL NARRATIVE FOR INCIDENT #402:")
    if narrative_402_details:
        for row in narrative_402_details:
            tech_str = f"[{row.technique_id} - {row.tech_name} (conf={row.confidence})]" if row.technique_id else "[DECLINED / NO TECHNIQUE]"
            print(f"\n[Sentence {row.seq}] {row.text}")
            print(f"  Evidence Event IDs ({len(row.evidence_event_ids)}): {row.evidence_event_ids}")
            print(f"  ATT&CK Mapping: {tech_str}")

    db.close()

if __name__ == "__main__":
    run_evaluation()
