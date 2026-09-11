from curator.db import SessionLocal
from curator.ai.narrative import generate_incident_narrative
from curator.ai.mapping import map_incident_techniques
from sqlalchemy import text
import json

with SessionLocal() as session:
    print('=== RE-RUNNING INCIDENT #402 NARRATIVE ===')
    n_res = generate_incident_narrative(402, session)
    print('Narrative result summary:')
    print('  Title:', n_res.get('title'))
    print('  Sentence count:', n_res.get('sentence_count'))
    print('  Total claimed IDs:', n_res.get('total_claimed_event_ids'))
    print('  Dropped IDs:', n_res.get('dropped_ids_count'))
    print('  Dropped details:', n_res.get('dropped_details'))

    print('\n=== RE-RUNNING INCIDENT #402 MAPPING ===')
    m_res = map_incident_techniques(402, session)
    print('Mapping result summary:')
    print('  Mapped count:', m_res.get('mapped_count'))
    print('  Declined count:', m_res.get('declined_count'))
    print('  Unique techniques:', m_res.get('unique_techniques'))

    print('\n=== FETCHING ALL SENTENCES FROM DB ===')
    rows = session.execute(text('SELECT seq, text, evidence_event_ids, technique_id, technique_name, technique_conf FROM narrative_sentences WHERE incident_id = 402 ORDER BY seq ASC')).fetchall()
    for r in rows:
        print(f'[{r[0]}] {r[1]}')
        print(f'    IDs ({len(r[2])}): {r[2][:8]}... | Tech: {r[3]} - {r[4]} (conf={r[5]})')

    print('\n=== AUDIT LOG ENTRY FOR THIS RUN ===')
    audit_rows = session.execute(text("SELECT id, ts, detail FROM audit_chain WHERE action = 'anthropic_api_call' AND detail->>'incident_id' = '402' ORDER BY id DESC LIMIT 2")).fetchall()
    for ar in reversed(audit_rows):
        print(f'ID: {ar[0]} | TS: {ar[1]} | Detail: {ar[2]}')
