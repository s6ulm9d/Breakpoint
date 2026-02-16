from breakpoint.scenarios import load_scenarios
import os

path = r"c:\Users\soulmad\projects\break-point\breakpoint\breakpoint\omni_attack_all.yaml"
scenarios = load_scenarios(path)
available_module_ids = sorted(list(set([getattr(s, 'attack_type', s.type) for s in scenarios])))
print(available_module_ids)
