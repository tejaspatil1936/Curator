from curator.attack.retrieve import retrieve
from curator.db import engine

sentences = [
    ("Beaconing", "The process established an outbound TLS command-and-control connection to 192.168.0.4 over port 443.", "T1071.001"),
    ("LSASS access", "LSASS process memory was accessed to extract credentials and forge authentication tickets.", "T1003.001"),
    ("WMI lateral movement", "Administrative shares and WMI execution providers were leveraged to move laterally to domain controller NEWYORK.", "T1047"),
    ("Admin share access", "Administrative network shares were accessed across systems to perform discovery and stage lateral movement.", "T1021.002")
]

with engine.connect() as conn:
    for label, sent, target in sentences:
        print(f"\n==========================================")
        print(f"DIAGNOSTIC: {label} (Target: {target})")
        print(f"Query: \"{sent}\"")
        candidates = retrieve(sent, k=10, conn=conn)
        target_found = False
        for idx, c in enumerate(candidates, 1):
            is_target = " *** TARGET ***" if c.id == target or c.id.startswith(target) else ""
            print(f"  {idx:2d}. {c.id:10s} {c.name[:45]:45s} score={c.score:.5f} vec_rnk={c.vector_rank} kw_rnk={c.keyword_rank}{is_target}")
            if c.id == target or c.id.startswith(target):
                target_found = True
        print(f"Target {target} in top-10 candidates: {target_found}")

