import json
from curator.db import SessionLocal
from sqlalchemy import text
from curator.fetch import ensure
from curator.attack.load_attack import BUNDLE

db = SessionLocal()
gt_ids = sorted({r[0] for r in db.execute(text('SELECT technique_id FROM ground_truth')).fetchall()})
print(f"Distinct ground truth IDs ({len(gt_ids)}): {gt_ids}")

bundle_path = ensure(BUNDLE)
bundle = json.loads(bundle_path.read_bytes())

# Index all objects by id
objects_by_id = {o['id']: o for o in bundle['objects'] if 'id' in o}

# Index attack-patterns by external_id (mitre-attack)
ap_by_ext_id = {}
for o in bundle['objects']:
    if o.get('type') == 'attack-pattern':
        for r in o.get('external_references', []):
            if r.get('source_name') == 'mitre-attack' and 'external_id' in r:
                ap_by_ext_id[r['external_id']] = o

# Index revoked-by relationships
revoked_by = {}
for o in bundle['objects']:
    if o.get('type') == 'relationship' and o.get('relationship_type') == 'revoked-by':
        src = o.get('source_ref')
        tgt = o.get('target_ref')
        if src and tgt:
            revoked_by[src] = tgt

# Check each ground truth ID
mapping = {}
for tid in gt_ids:
    obj = ap_by_ext_id.get(tid)
    if not obj:
        print(f"{tid}: NOT FOUND IN BUNDLE!")
        continue
    is_revoked = obj.get('revoked', False)
    is_deprecated = obj.get('x_mitre_deprecated', False)
    stix_id = obj['id']
    name = obj.get('name', '')
    
    if is_revoked:
        repl_stix_id = revoked_by.get(stix_id)
        repl_obj = objects_by_id.get(repl_stix_id) if repl_stix_id else None
        repl_ext_id = None
        repl_name = ''
        if repl_obj:
            repl_name = repl_obj.get('name', '')
            for r in repl_obj.get('external_references', []):
                if r.get('source_name') == 'mitre-attack' and 'external_id' in r:
                    repl_ext_id = r['external_id']
                    break
        mapping[tid] = {'status': 'revoked', 'name': name, 'replacement_id': repl_ext_id, 'replacement_name': repl_name}
    elif is_deprecated:
        mapping[tid] = {'status': 'deprecated', 'name': name, 'replacement_id': None, 'replacement_name': None}
    else:
        mapping[tid] = {'status': 'current', 'name': name, 'replacement_id': tid, 'replacement_name': name}

current = [k for k, v in mapping.items() if v['status'] == 'current']
revoked = [k for k, v in mapping.items() if v['status'] == 'revoked']
deprecated = [k for k, v in mapping.items() if v['status'] == 'deprecated']

print(f"\nTotal: {len(gt_ids)} | Current: {len(current)} | Revoked: {len(revoked)} | Deprecated: {len(deprecated)}")

print("\n--- REVOKED MAPPING TABLE (OLD -> NEW) ---")
print(f"{'Old ID':<8} | {'Old Name':<35} | {'New ID':<10} | {'New Name':<35}")
print("-" * 95)
for k in sorted(revoked):
    v = mapping[k]
    print(f"{k:<8} | {v['name']:<35} | {v['replacement_id'] or 'None':<10} | {v['replacement_name'] or 'None':<35}")

print("\n--- DEPRECATED TECHNIQUE ---")
for k in deprecated:
    print(f"{k:<8} | {mapping[k]['name']:<35} | Deprecated (No replacement)")

db.close()
