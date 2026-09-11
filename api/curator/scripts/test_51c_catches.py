from curator.db import SessionLocal
from curator.ai.verify import verify_incident

def main():
    db = SessionLocal()
    print("Testing 5 good catches on existing sentences:")
    r803 = verify_incident(803, session=db)
    r444 = verify_incident(444, session=db)
    r855 = verify_incident(855, session=db)

    def check_seq(results, seq, name):
        item = next((r for r in results if r['seq'] == seq), None)
        if item:
            supp = item['supported']
            reason = item['reason']
            print(f"{name} (Seq {seq}): supported={supp}")
            print(f"  Reason: {reason}\n")

    check_seq(r803['results'], 3, '#803 Seq 3 (malformed timestamp)')
    check_seq(r803['results'], 7, '#803 Seq 7 (planted false alert)')
    check_seq(r444['results'], 1, '#444 Seq 1 (miscount 18 vs 14)')
    check_seq(r855['results'], 10, '#855 Seq 10 (port 443 / encryption)')
    check_seq(r855['results'], 18, '#855 Seq 18 (direction error)')

if __name__ == '__main__':
    main()
