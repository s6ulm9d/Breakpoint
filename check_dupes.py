import yaml
import os

path = r"c:\Users\soulmad\projects\break-point\breakpoint\breakpoint\omni_attack_all.yaml"
with open(path, 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f)

print(f"Total items in YAML: {len(data)}")

seen = {}
duplicates = []
for item in data:
    # Use a tuple as a key for deduplication
    key = (item.get('type'), item.get('target'), item.get('method'), str(item.get('config', {})))
    if key in seen:
        duplicates.append((item.get('id'), seen[key]))
    else:
        seen[key] = item.get('id')

print(f"Unique scenarios: {len(seen)}")
print(f"Duplicate scenarios found: {len(duplicates)}")
for d in duplicates[:10]:
    print(f"  {d[0]} is a duplicate of {d[1]}")
