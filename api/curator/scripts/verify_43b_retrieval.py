from curator.db import SessionLocal
from curator.attack.retrieve import retrieve
from curator.ai.mapping import _clean_query_text, _PORT_TRANSLATIONS, _EVENT_CODE_TRANSLATIONS
from sqlalchemy import text

db = SessionLocal()

test_cases = [
    ('C2 Beaconing (Sentence 3 #402)', 'PowerShell on SCRANTON established initial outbound command-and-control network connections to 192.168.0.5 over port 443 at 02:58:45.', [7665, 69383], 'T1071.001'),
    ('HTTPS Staging / Transfer (Sentence 4 #402)', 'PowerShell on SCRANTON initiated repeated outbound HTTPS staging connections to 23.4.15.75:443 between 03:08:04 and 03:08:14.', [69385, 88468, 89587], 'T1071.001'),
    ('Admin Share Access (Sentence 6 #402)', 'Initial SMB sessions connected to administrative share \\\\*\\IPC$ on domain controller NEWYORK.dmevals.local at 03:04:04.', [50798, 50799], 'T1021.002'),
    ('LSASS Access (Day 2 event)', 'LSASS process memory was accessed to extract credentials and forge authentication tickets.', [301294], 'T1003.001'),
]

for label, sent, eids, target in test_cases:
    context_terms = []
    q_ctx = text("""
        SELECT process_name, command_line, file_path, dst_ip,
               ocsf->'dst_endpoint'->>'port' as port, event_code,
               ocsf->'unmapped'->>'ShareName' as share_name
        FROM events
        WHERE id = ANY(:eids)
        LIMIT 10
    """)
    ctx_rows = db.execute(q_ctx, {"eids": eids}).fetchall()
    for cr in ctx_rows:
        p_name, cmd, f_path, dst_ip, raw_p, e_code, share = cr
        if p_name: context_terms.append(_clean_query_text(str(p_name)))
        if cmd: context_terms.append(_clean_query_text(str(cmd)[:120]))
        if f_path: context_terms.append(_clean_query_text(str(f_path)))
        if share: context_terms.append(_clean_query_text(str(share)))
        p_val = int(raw_p) if raw_p and str(raw_p).isdigit() else None
        if p_val and p_val in _PORT_TRANSLATIONS:
            context_terms.append(_PORT_TRANSLATIONS[p_val])
        if e_code and str(e_code) in _EVENT_CODE_TRANSLATIONS:
            context_terms.append(_EVENT_CODE_TRANSLATIONS[str(e_code)])

    cleaned_txt = _clean_query_text(sent)
    unique_context = list(dict.fromkeys(context_terms))
    enriched_query = f"{cleaned_txt} {' '.join(unique_context[:20])}".strip()
    cands = retrieve(enriched_query, k=20, conn=db.connection())

    print(f"\n=======================================================")
    print(f"{label} (Target: {target})")
    print(f"Enriched query: \"{enriched_query}\"")
    
    target_rank = None
    for idx, c in enumerate(cands, 1):
        if c.id == target or (target == "T1071.001" and c.id in ("T1071.001", "T1071", "T1105")):
            target_rank = idx
            break
    print(f"Target {target} rank: {target_rank} (in top 20: {target_rank is not None})")
    for idx, c in enumerate(cands[:10], 1):
        is_t = " *** TARGET ***" if c.id == target or c.id.startswith(target.split(".")[0]) or c.id == "T1105" else ""
        print(f"  {idx:2d}. {c.id:10s} {c.name[:45]:45s} score={c.score:.5f}{is_t}")

db.close()
