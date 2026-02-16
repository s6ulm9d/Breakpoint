import yaml
from collections import Counter

path = r"c:\Users\soulmad\projects\break-point\breakpoint\breakpoint\omni_attack_all.yaml"
with open(path, 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f)

types = [item.get('type') for item in data]
counts = Counter(types)

for t, count in counts.most_common():
    print(f"{t}: {count}")
