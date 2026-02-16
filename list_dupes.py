import yaml
import os

path = r"c:\Users\soulmad\projects\break-point\breakpoint\breakpoint\omni_attack_all.yaml"
with open(path, 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f)

seen = {}
duplicates = []
for item in data:
    key = (item.get('type'), item.get('target'), item.get('method'), str(item.get('config', {})))
    if key in seen:
        duplicates.append((item.get('id'), seen[key]))
    else:
        seen[key] = item.get('id')

print(f"Duplicates list:")
for d in duplicates:
    print(f"- {d[0]} (is same as {d[1]})")
