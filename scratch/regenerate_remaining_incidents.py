import time
from sqlalchemy import text
from curator.db import SessionLocal
from curator.ai.narrative import generate_incident_narrative
from curator.ai.mapping import map_incident_techniques
from curator.ai.verify import verify_incident

def main():
    db = SessionLocal()
    
    # All surfaced incident IDs
    all_surfaced = [r[0] for r in db.execute(text("SELECT id FROM incidents WHERE status != 'suppressed' ORDER BY id ASC")).fetchall()]
    
    # The 10 that task-2305 is running
    first_10 = [402, 418, 421, 444, 455, 477, 504, 505, 521, 524]
    
    # The remaining 10
    remaining_10 = [inc_id for inc_id in all_surfaced if inc_id not in first_10]
    print(f"Remaining {len(remaining_10)} incidents to process: {remaining_10}")
    
    start_time = time.time()
    for idx, inc_id in enumerate(remaining_10, start=1):
        print(f"\n[{idx}/{len(remaining_10)}] Processing Incident #{inc_id}...")
        t0 = time.time()
        
        # Narrative (Sonnet 5)
        narr = generate_incident_narrative(inc_id, session=db)
        print(f"  Narrative: {len(narr['sentences'])} sentences generated")
        
        # Verification (Haiku 4.5)
        v = verify_incident(inc_id, session=db, batch_size=5)
        print(f"  Verification: {v['checked']} checked | {v['supported']} supported | {v['unsupported']} unsupported ({time.time()-t0:.1f}s)")
        
        # Mapping (Sonnet 5)
        m = map_incident_techniques(inc_id, session=db)
        print(f"  Mapping: {len(m['mappings'])} techniques mapped")

    print(f"\nRemaining {len(remaining_10)} incidents processed in {time.time()-start_time:.1f}s")
    db.close()

if __name__ == '__main__':
    main()
