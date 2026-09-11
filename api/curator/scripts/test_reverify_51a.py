from curator.db import SessionLocal
from curator.ai.verify import verify_incident

def main():
    db = SessionLocal()
    target_incidents = [418, 477, 430, 490, 504]
    print("=== RE-VERIFYING 418, 477, 430, 490, 504 WITH RICH SERIALIZATION ===")
    for inc_id in target_incidents:
        res = verify_incident(inc_id, session=db)
        print(f"Incident #{inc_id}: checked={res['checked']}, supported={res['supported']}, unsupported={res['unsupported']}")

if __name__ == '__main__':
    main()
