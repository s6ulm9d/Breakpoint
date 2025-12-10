from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_idor_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Insecure Direct Object Reference / Broken Object Level Authorization
    """
    param = scenario.config.get("param_name", "id")
    # Where does the param go? Path or Query? 
    # Current limitation: SimpleScenario target is static string?
    # We can iterate if target has {{param}} or assume suffix if not specified.
    # Let's support formatting the target string directly in the config loop.
    
    target_template = scenario.target # e.g. /invoices/{{id}}
    
    # We need a range of IDs to test
    id_range = scenario.config.get("test_ids", ["1", "2", "3", "100", "101"])
    
    # We assume we are "attacker" (maybe authenticated as user A).
    # If we can access resources that seemingly distinct IDs, we flag it for manual review 
    # OR if we know which ones are ours vs others.
    
    # For this simulation:
    # 1. Access a "known good" ID (optional, if owned_id provided)
    # 2. Iterate others. If 200 OK and content differs -> Potential IDOR.
    
    results = []
    
    for val in id_range:
        # Simple substitution
        actual_path = target_template.replace(f"{{{{{param}}}}}", str(val))
        # If no template found, append (fallback)
        if actual_path == target_template:
            actual_path = f"{target_template.rstrip('/')}/{val}"
            
        resp = client.send(scenario.method, actual_path)
        
        results.append({
            "id": val,
            "status": resp.status_code,
            "len": len(resp.text)
        })
        
    # Analysis
    # If we get 200 OKs for multiple distinct IDs, it's NOT secure by default (unless public data).
    # Engine goal: "Prove It". If I got data for ID 101 and ID 100, and they differ, I have access.
    
    successful_accesses = [r for r in results if r["status"] == 200]
    
    # Heuristic: If we accessed more than 1 distinct object, report IDOR risk.
    # (In real prod, public endpoints exist, but for 'BREAKPOINT' typically we target private stuff)
    
    risk = len(successful_accesses) > 1
    
    details = []
    if risk:
        ids = [r['id'] for r in successful_accesses]
        details.append(f"Accessible IDs found: {ids}. Ensure these are not sensitive/private.")

    return {
        "scenario_id": scenario.id,
        "attack_type": "idor",
        "passed": not risk,
        "details": {
            "issues": details,
            "probed_ids": [r['id'] for r in results]
        }
    }
