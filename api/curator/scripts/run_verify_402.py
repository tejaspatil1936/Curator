from curator.db import SessionLocal
from curator.ai.verify import verify_incident

def main():
    db = SessionLocal()
    print("Running verifier on Incident #402 with Claude Haiku 4.5...")
    res = verify_incident(402, session=db)
    print(f"Incident #402 Verification Summary:")
    print(f"  Total Checked: {res['checked']}")
    print(f"  Supported: {res['supported']}")
    print(f"  Unsupported: {res['unsupported']}")
    print("\nUnsupported sentences:")
    for r in res['results']:
        if not r['supported']:
            print(f"- Seq {r['seq']}: {r['text']}")
            print(f"  Reason: {r['reason']}")
            print(f"  Citations: {r['evidence_event_ids']}\n")

if __name__ == '__main__':
    main()
