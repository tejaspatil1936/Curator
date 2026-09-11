import re
import json

log_path = r'C:\Users\baodh\.gemini\antigravity-ide\brain\2fef093e-535a-4df5-baea-dc40442176f4\.system_generated\tasks\task-2305.log'
with open(log_path, encoding='utf-8') as f:
    text_content = f.read()

matches = [m.start() for m in re.finditer(r'Failed to parse ATT&CK mapping JSON', text_content)]

pattern = re.compile(r'["\']seq["\']:\s*(\d+).*?["\']technique_id["\']:\s*["\']([^"\']+)["\'].*?["\']confidence["\']:\s*([0-9.]+)', re.DOTALL)

# Block 1: #402
b1_start = text_content.find('Content: ', matches[0])
b1_end = text_content.find('\n  Mapping:', b1_start)
items_402 = [{"seq": int(s), "technique_id": t.strip(), "confidence": float(c)} for s, t, c in pattern.findall(text_content[b1_start:b1_end])]

# Block 2: #455
b2_start = text_content.find('Content: ', matches[1])
b2_end = text_content.find('\n  Mapping:', b2_start)
if b2_end == -1:
    b2_end = text_content.find('\n  Verification:', b2_start)
items_455 = [{"seq": int(s), "technique_id": t.strip(), "confidence": float(c)} for s, t, c in pattern.findall(text_content[b2_start:b2_end])]

out = {"402": items_402, "455": items_455}
with open(r'scratch\mappings_402_455.json', 'w', encoding='utf-8') as f:
    json.dump(out, f, indent=2)

print(f"Extracted {len(items_402)} mappings for #402, {len(items_455)} mappings for #455")
