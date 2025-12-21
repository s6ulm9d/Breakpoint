from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario
import json

def run_malformed_json(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # Send garbage JSON, truncated JSON, wrong types
    
    cases = [
        ("truncated", '{"username": "test", "pass"'),
        ("wrong_types", json.dumps({"username": 123, "password": ["wrong"]})),
        ("extra_fields", json.dumps({"username": "user", "password": "pw", "admin": True, "garbage": "data"})),
        ("empty", "{}")
    ]
    
    issues = []
    
    for name, body in cases:
        # Use simple string body passing to client to avoid it auto-json encoding
        resp = client.send(scenario.method, scenario.target, form_body=body, headers={"Content-Type": "application/json"})
        
        if resp.status_code >= 500:
            issues.append(f"Case {name} caused 500 Internal Server Error")
        
        if "traceback" in resp.text.lower():
            issues.append(f"Case {name} leaked stack trace")

    return {
        "scenario_id": scenario.id,
        "attack_type": "malformed_json",
        "passed": len(issues) == 0,
        "details": {
            "issues": issues,
            "attempts": len(cases)
        }
    }
