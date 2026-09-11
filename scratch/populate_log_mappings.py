import re
import sys
import os
sys.path.insert(0, os.path.abspath('api'))
from curator.db import SessionLocal
from sqlalchemy import text

db = SessionLocal()

# Read task-2305.log
log_path = r'C:\Users\baodh\.gemini\antigravity-ide\brain\2fef093e-535a-4df5-baea-dc40442176f4\.system_generated\tasks\task-2305.log'
with open(log_path, encoding='utf-8') as f:
    text_content = f.read()

# Lookup techniques
q_techs = text("SELECT id, name FROM techniques")
tech_names = {r[0]: r[1] for r in db.execute(q_techs).fetchall()}

# Find mapping blocks for 402 and 455
matches = [m.start() for m in re.finditer(r'Failed to parse ATT&CK mapping JSON', text_content)]

# 1. First block is #402
block_402_start = text_content.find('Content: ', matches[0])
block_402_end = text_content.find('\n  Mapping:', block_402_start)
block_402 = text_content[block_402_start:block_402_end]

# Extract items via regex: {"seq": X, "technique_id": "...", "confidence": Y}
pattern = re.compile(r'["\']seq["\']:\s*(\d+).*?["\']technique_id["\']:\s*["\']([^"\']+)["\'].*?["\']confidence["\']:\s*([0-9.]+)', re.DOTALL)

items_402 = pattern.findall(block_402)
print(f"Recovered {len(items_402)} mappings for Incident #402")
for seq, tid, conf in items_402:
    tid = tid.strip()
    tname = tech_names.get(tid, tid)
    db.execute(text("""
        UPDATE narrative_sentences
        SET technique_id = :tid,
            technique_name = :tname,
            technique_conf = :conf
        WHERE incident_id = 402 AND seq = :seq
    """), {"tid": tid, "tname": tname, "conf": float(conf), "seq": int(seq)})

# 2. Second block is #455
block_455_start = text_content.find('Content: ', matches[1])
block_455_end = text_content.find('\n  Mapping:', block_455_start)
if block_455_end == -1:
    block_455_end = text_content.find('\n  Verification:', block_455_start)
block_455 = text_content[block_455_start:block_455_end]

items_455 = pattern.findall(block_455)
print(f"Recovered {len(items_455)} mappings for Incident #455")
for seq, tid, conf in items_455:
    tid = tid.strip()
    tname = tech_names.get(tid, tid)
    db.execute(text("""
        UPDATE narrative_sentences
        SET technique_id = :tid,
            technique_name = :tname,
            technique_conf = :conf
        WHERE incident_id = 455 AND seq = :seq
    """), {"tid": tid, "tname": tname, "conf": float(conf), "seq": int(seq)})

db.commit()

# Check count now
print("\nUpdated sentences with technique_id per incident:")
for r in db.execute(text("SELECT incident_id, count(*), count(technique_id) FROM narrative_sentences GROUP BY incident_id ORDER BY incident_id")).fetchall():
    print(f"  Incident #{r[0]}: total={r[1]}, with_technique={r[2]}")

db.close()
