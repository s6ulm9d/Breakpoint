from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import yaml
import sys

@dataclass
class ScenarioBase:
    id: str
    type: str # 'simple' or 'flow'
    description: str = ""

@dataclass
class SimpleScenario(ScenarioBase):
    method: str = "GET"
    target: str = "/"
    attack_type: str = "unknown" # e.g. sql_injection, password_length
    config: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FlowScenario(ScenarioBase):
    steps: List[Dict[str, Any]] = field(default_factory=list)

def load_scenarios(path: str) -> List[ScenarioBase]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or []
    except Exception as e:
        print(f"Error loading scenarios file {path}: {e}")
        return []

    scenarios: List[ScenarioBase] = []
    
    for idx, item in enumerate(data):
        s_id = str(item.get("id", f"scenario_{idx}"))
        
        # Check if Flow
        if item.get("flow") is True:
            scenarios.append(FlowScenario(
                id=s_id,
                type="flow",
                description=item.get("description", ""),
                steps=item.get("steps", [])
            ))
        else:
            # Simple Scenario
            # 'type' in YAML maps to attack_type in our object model
            # But the user requires 'type' field in the base.
            # Let's map YAML 'type' to 'attack_type' and set internal type to 'simple'
            attack_type = item.get("type", "generic")
            scenarios.append(SimpleScenario(
                id=s_id,
                type="simple",
                description=item.get("description", ""),
                attack_type=attack_type,
                method=item.get("method", "GET"),
                target=item.get("target", "/"),
                config=item.get("config", {})
            ))

    return scenarios
