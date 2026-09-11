from curator.db import SessionLocal
from curator.ai.verify import verify_incident

def main():
    db = SessionLocal()
    print("Testing 5 good catches on existing sentences:")
    r402 = verify_incident(402, session=db)
    r444 = verify_incident(444, session=db)
    r455 = verify_incident(455, session=db)

    def check_seq(results, seq, name):
        item = next((r for r in results if r['seq'] == seq), None)
        if item:
            supp = item['supported']
            reason = item['reason']
            print(f"{name} (Seq {seq}): supported={supp}")
            print(f"  Reason: {reason}\n")

    check_seq(r402['results'], 3, '#402 Seq 3 (malformed timestamp)')
    check_seq(r402['results'], 7, '#402 Seq 7 (planted false alert)')
    check_seq(r444['results'], 1, '#444 Seq 1 (miscount 18 vs 14)')
    check_seq(r455['results'], 10, '#455 Seq 10 (port 443 / encryption)')
    check_seq(r455['results'], 18, '#455 Seq 18 (direction error)')

if __name__ == '__main__':
    main()
