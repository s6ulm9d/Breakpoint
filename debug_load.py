from breakpoint.scenarios import load_scenarios
import os

path = r"c:\Users\soulmad\projects\break-point\breakpoint\breakpoint\omni_attack_all.yaml"
scenarios = load_scenarios(path)
print(f"Total scenarios: {len(scenarios)}")
unique_types = sorted(list(set([getattr(s, 'attack_type', s.type) for s in scenarios])))
print(f"Total unique types: {len(unique_types)}")
print(f"Unique types: {unique_types}")

for s in scenarios:
    if "clickjacking" in s.id or "clickjacking" == getattr(s, 'attack_type', ''):
        print(f"Found: {s.id} ({getattr(s, 'attack_type', 'N/A')})")
