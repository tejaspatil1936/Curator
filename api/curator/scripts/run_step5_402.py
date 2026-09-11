from curator.db import SessionLocal
from curator.ai.narrative import generate_incident_narrative
from curator.ai.mapping import map_incident_techniques
from curator.pipeline.fixtures import inject_planted_alert

def main():
    db = SessionLocal()
    inject_planted_alert(db)
    print("Re-generating narrative for #402 with planted alert...")
    narr = generate_incident_narrative(402, session=db)
    print(f"Generated {len(narr['sentences'])} sentences")
    for s in narr['sentences']:
        if 42145 in s['evidence_event_ids'] or 'lsass' in s['text'].lower():
            print(f"Planted alert sentence: seq={s['seq']}\n  text={s['text']}\n  citations={s['evidence_event_ids']}")

    print("Mapping techniques for #402...")
    map_res = map_incident_techniques(402, session=db)
    print(f"Mapped {len(map_res['mappings'])} techniques")

if __name__ == '__main__':
    main()
