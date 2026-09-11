from curator.db import SessionLocal
from sqlalchemy import text
import json
from curator.ai.verify import format_forensic_event

db = SessionLocal()

# Fetch event 53267
row = db.execute(text("""
    SELECT id, ts, host, user_name, process_name, parent_process, command_line, event_code, src_ip, dst_ip, raw, ocsf
    FROM events
    WHERE id = 53267
""")).mappings().fetchone()

if row:
    print("=== EVENT 53267 DETAILS ===")
    print(f"ID: {row['id']}")
    print(f"Event Code: {row['event_code']}")
    print(f"Host: {row['host']}")
    print(f"Process Name: {row['process_name']}")
    print(f"Parent Process: {row['parent_process']}")
    print(f"Command Line: {row['command_line']}")
    print(f"Raw: {row['raw']}")
    
    print("\n=== FULL OCSF OBJECT ===")
    print(json.dumps(row['ocsf'], indent=2))
    
    print("\n=== OLD SERIALIZATION (WHAT VERIFIER WAS SHOWN INITIALLY) ===")
    old_str = f"Event {row['id']}: {row['ts']} | Host={row['host']} | User={row['user_name'] or 'N/A'} | Proc={row['process_name']} | Parent={row['parent_process']} | Code={row['event_code']} | Cmd={row['command_line'] or 'N/A'}"
    print(old_str)
    
    print("\n=== NEW FORENSIC SERIALIZATION (WITH 5.1a FIX) ===")
    new_str = format_forensic_event(dict(row))
    print(new_str)
else:
    print("Event 53267 not found!")

db.close()
