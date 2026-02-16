import yaml
import os

path = r"c:\Users\soulmad\projects\break-point\breakpoint\breakpoint\omni_attack_all.yaml"
with open(path, 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f)

seen = {}
for item in data:
    key = (item.get('type'), item.get('target'), item.get('method'), str(item.get('config', {})))
    if key in seen:
        print(f"DUPE: {item.get('id')} is same as {seen[key]}")
    else:
        seen[key] = item.get('id')
