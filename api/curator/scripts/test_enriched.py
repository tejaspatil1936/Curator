from curator.attack.retrieve import retrieve
from curator.db import engine

with engine.connect() as conn:
    print("\n--- ENRICHED QUERY FOR BEACONING ---")
    # Adding process name, dst_ip, port 443, https, web traffic
    q_beacon = "The process established an outbound TLS command-and-control connection to 192.168.0.4 over port 443. powershell.exe port 443 destination 192.168.0.4 https web traffic application layer protocol"
    cands_b = retrieve(q_beacon, k=20, conn=conn)
    for idx, c in enumerate(cands_b, 1):
        is_target = " *** TARGET ***" if "T1071" in c.id else ""
        print(f"  {idx:2d}. {c.id:10s} {c.name[:45]:45s} score={c.score:.5f}{is_target}")

    print("\n--- ENRICHED QUERY FOR ADMIN SHARES ---")
    # Adding share names C$, ADMIN$, IPC$, SMB, EventID 5140, 5145, remote services
    q_share = "Administrative network shares were accessed across systems to stage lateral movement. IPC$ ADMIN$ C$ smb windows admin shares remote services 5140 5145"
    cands_s = retrieve(q_share, k=20, conn=conn)
    for idx, c in enumerate(cands_s, 1):
        is_target = " *** TARGET ***" if "T1021" in c.id else ""
        print(f"  {idx:2d}. {c.id:10s} {c.name[:45]:45s} score={c.score:.5f}{is_target}")
