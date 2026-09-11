import json
from curator.db import SessionLocal
from sqlalchemy import text
from curator.fetch import ensure
from curator.attack.load_attack import BUNDLE

db = SessionLocal()

# 1. Build 6a mapping from STIX bundle
bundle_path = ensure(BUNDLE)
bundle = json.loads(bundle_path.read_bytes())
objects_by_id = {o['id']: o for o in bundle['objects'] if 'id' in o}
ap_by_ext_id = {}
for o in bundle['objects']:
    if o.get('type') == 'attack-pattern':
        for r in o.get('external_references', []):
            if r.get('source_name') == 'mitre-attack' and 'external_id' in r:
                ap_by_ext_id[r['external_id']] = o

revoked_by = {}
for o in bundle['objects']:
    if o.get('type') == 'relationship' and o.get('relationship_type') == 'revoked-by':
        src = o.get('source_ref')
        tgt = o.get('target_ref')
        if src and tgt:
            revoked_by[src] = tgt

def resolve_technique_id(tid: str):
    obj = ap_by_ext_id.get(tid)
    if not obj:
        return tid, "unknown", tid
    if obj.get('revoked'):
        repl_stix = revoked_by.get(obj['id'])
        repl_obj = objects_by_id.get(repl_stix) if repl_stix else None
        if repl_obj:
            for r in repl_obj.get('external_references', []):
                if r.get('source_name') == 'mitre-attack' and 'external_id' in r:
                    return r['external_id'], 'revoked', repl_obj.get('name', '')
        return tid, 'revoked', obj.get('name', '')
    if obj.get('x_mitre_deprecated'):
        return tid, 'deprecated', obj.get('name', '')
    return tid, 'current', obj.get('name', '')

# 2. Fetch ground truth
q_gt = text("SELECT id, technique_id, note FROM ground_truth ORDER BY id")
gt_rows = db.execute(q_gt).fetchall()

# Map all ground truth items
gt_items = []
for r in gt_rows:
    orig_id = r[1]
    mapped_id, status, mapped_name = resolve_technique_id(orig_id)
    gt_items.append({
        "gt_id": r[0],
        "orig_id": orig_id,
        "mapped_id": mapped_id,
        "status": status,
        "name": mapped_name,
        "note": r[2]
    })

# 3. Fetch recovered techniques from supported sentences only
q_rec = text("""
    SELECT DISTINCT n.technique_id, n.technique_name
    FROM narrative_sentences n
    JOIN verifications v ON v.sentence_id = n.id
    JOIN incidents i ON i.id = n.incident_id
    WHERE i.status != 'suppressed'
      AND v.supported = true
      AND n.technique_id IS NOT NULL
""")
recovered_rows = db.execute(q_rec).fetchall()
recovered_set = {r[0]: r[1] for r in recovered_rows}

print(f"Total Ground Truth Entries: {len(gt_items)}")
distinct_orig_gt = sorted({item["orig_id"] for item in gt_items})
print(f"Distinct Shipped GT IDs: {len(distinct_orig_gt)}")
distinct_mapped_gt = sorted({item["mapped_id"] for item in gt_items})
print(f"Distinct Mapped GT IDs: {len(distinct_mapped_gt)}")

print(f"Total Recovered Techniques (Supported sentences only): {len(recovered_set)}")

# 4. Matching logic:
# A recovered technique matches ground truth if:
# - Exact match: rec_id == mapped_id (or rec_id == orig_id)
# - Parent/Child match:
#   - ground truth is parent (e.g. T1059) and recovered is sub-technique (e.g. T1059.001 or T1059.003)
#   - OR ground truth is sub-technique and recovered is parent (e.g. GT has T1021.002 and recovered has T1021)

exact_matches = set()
parent_child_matches = {}  # rec_id -> matching gt_ids

for rec_id in recovered_set:
    matched = False
    # Check exact match
    for item in gt_items:
        if rec_id == item["mapped_id"] or rec_id == item["orig_id"]:
            exact_matches.add(rec_id)
            matched = True
            break
    if not matched:
        # Check parent/child
        # e.g. rec_id is T1036.002, GT mapped has T1036
        for item in gt_items:
            gt_m = item["mapped_id"]
            gt_o = item["orig_id"]
            if rec_id.startswith(gt_m + ".") or gt_m.startswith(rec_id + ".") or \
               rec_id.startswith(gt_o + ".") or gt_o.startswith(rec_id + "."):
                parent_child_matches[rec_id] = gt_m
                matched = True
                break

all_recovered_matched = exact_matches | set(parent_child_matches.keys())
invented = set(recovered_set.keys()) - all_recovered_matched

print(f"\nExact matches ({len(exact_matches)}): {sorted(exact_matches)}")
print(f"Parent/Child matches ({len(parent_child_matches)}): {parent_child_matches}")
print(f"Invented ({len(invented)}): {sorted(invented)}")

# Check Ground Truth coverage
# Which GT techniques were recovered (either exact or parent/child)?
gt_recovered = set()
gt_parent_child = set()
gt_missed = set()

for item in gt_items:
    mid = item["mapped_id"]
    oid = item["orig_id"]
    if mid in exact_matches or oid in exact_matches:
        gt_recovered.add(mid)
    elif any(rec.startswith(mid + ".") or mid.startswith(rec + ".") for rec in recovered_set):
        gt_parent_child.add(mid)
    else:
        gt_missed.add(mid)

print(f"\nGT Distinct Mapped Recovered exact: {len(gt_recovered)}")
print(f"GT Distinct Mapped Parent/Child: {len(gt_parent_child)}")
print(f"GT Distinct Mapped Missed: {len(gt_missed)}")

db.close()
