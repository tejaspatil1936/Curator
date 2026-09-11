"""Verify T1021.006, T1074, and T1105 appear in top-20 retrieval candidates for
representative sentences. No model call required — retrieval only."""
from curator.db import SessionLocal
from curator.attack.retrieve import retrieve
from sqlalchemy import text

TEST_CASES = [
    # (description, query_text, expected_technique_ids)
    (
        "WinRM lateral movement",
        "wsmprovhost.exe spawned on remote host windows remote management 5985",
        ["T1021.006", "T1021"],
    ),
    (
        "Data staged — archive in temp",
        "zip archive created in AppData Temp staging collection prior to exfil",
        ["T1074", "T1074.001", "T1560"],
    ),
    (
        "Ingress tool transfer via PowerShell DownloadFile",
        "PowerShell DownloadFile DownloadString net.webclient remote host download payload",
        ["T1105"],
    ),
]

with SessionLocal() as s:
    conn = s.connection()
    for desc, query, expected in TEST_CASES:
        cands = retrieve(query, k=20, conn=conn)
        ids = [c.id for c in cands]
        hit = any(e in ids for e in expected)
        rank = None
        for e in expected:
            if e in ids:
                rank = ids.index(e) + 1
                break
        print(f"\n{'PASS' if hit else 'FAIL'}: {desc}")
        print(f"  Looking for: {expected}")
        if hit:
            print(f"  Found at rank {rank}")
        else:
            print(f"  Top-5 returned: {ids[:5]}")
