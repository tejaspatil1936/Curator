from curator.db import SessionLocal
from sqlalchemy import text
from curator.attack.retrieve import retrieve

db = SessionLocal()

items = [
    ('T1021.006 WinRM', 455, 37),
    ('T1105 Ingress Tool Transfer', 504, 1),
    ('T1543.003 Windows Service', 402, 18),
    ('T1074 Data Staged', 455, 26),
    ('T1136 Create Account', 524, 14),
]

for t_name, inc, seq in items:
    s = db.execute(text('SELECT seq, text, technique_id, technique_name FROM narrative_sentences WHERE incident_id = :inc AND seq = :seq'), {'inc': inc, 'seq': seq}).fetchone()
    cands = retrieve(s.text, k=30, conn=db.connection())
    cand_ids = [c.id for c in cands]
    prefix = t_name.split()[0]
    matched_cand = [c for c in cand_ids if c == prefix or c.startswith(prefix + '.')]
    print('='*70)
    print(f'Technique: {t_name}')
    print(f'Sentence [Inc #{inc} Seq {seq}]: "{s.text}"')
    print(f'Currently Mapped: {s.technique_id} ({s.technique_name})')
    print(f'Target Candidate in Retrieved List? {bool(matched_cand)}')
    if matched_cand:
        print(f'   Surfaced target candidate: {matched_cand}')
    else:
        print(f'   Surfaced top-5 candidates: {cand_ids[:5]}')

db.close()
