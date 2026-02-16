import yaml
import os

path = r"c:\Users\soulmad\projects\break-point\breakpoint\breakpoint\omni_attack_all.yaml"
with open(path, 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f)

seen = {}
for item in data:
    # Normalize config
    config = item.get('config', {})
    if not config: config = {}
    
    key = (item.get('type'), item.get('target'), item.get('method'), str(sorted(config.items())))
    if key in seen:
        print(f"ID: {item.get('id')} IS DUPLICATE OF {seen[key]}")
    else:
        seen[key] = item.get('id')
