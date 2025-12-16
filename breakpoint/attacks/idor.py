from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_idor_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
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
    
    # Aggressive Mode: Use a wider, more dangerous range of IDs
    aggressive = scenario.config.get('aggressive', False)
    if aggressive:
        # Fuzz boundary conditions and known admin IDs
        extras = ["0", "-1", "9999", "999999", "admin", "root", "test"]
        # Basic numeric iteration around the target param if it looks numeric
        # Assuming we don't know the exact current ID, we just spray.
        id_range.extend(extras)
        
    results = []
    for val in id_range:
        actual_path = target_template.replace(f"{{{{{param}}}}}", str(val))
        if actual_path == target_template:
            actual_path = f"{target_template.rstrip('/')}/{val}"
            
        resp = client.send(scenario.method, actual_path)
        
        snippet = resp.text[:100].replace("\n", " ")
        results.append({
            "id": val,
            "status": resp.status_code,
            "len": len(resp.text),
            "snippet": snippet
        })
        
    # HEURISTIC IDOR VERIFICATION
    # 1. Reject if response is HTML but we expect API data (SPA Fallback)
    #    (Simple check: if starts with <!DOCTYPE html> or <html)
    successful_accesses = [
        r for r in results 
        if r["status"] == 200 
        and "error" not in r["snippet"].lower() 
        and "<!doctype html>" not in r["snippet"].lower()
    ]

    # 2. Reject if all responses are identical length (Static Page/Error)
    #    Real IDOR returns different user data => different lengths.
    if successful_accesses:
        lengths = [r["len"] for r in successful_accesses]
        # Calculate variance or just check if they are all within 5 bytes?
        # If max(len) - min(len) < 5, probably static content.
        if max(lengths) - min(lengths) < 5 and len(successful_accesses) > 1:
            successful_accesses = [] # Mark as false positive

    risk = len(successful_accesses) > 0 # Was > 1, but > 0 is correct if we filtered carefully
    
    details = []
    leaked_data = []
    
    if risk:
        ids = [r['id'] for r in successful_accesses]
        details.append(f"Accessible IDs found: {ids}. Ensure these are not sensitive/private.")
        # Populate leaked data
        for r in successful_accesses[:3]: # Limit to first 3
             leaked_data.append(f"ID {r['id']} Data: {r['snippet']}...")

    return {
        "scenario_id": scenario.id,
        "attack_type": "idor",
        "passed": not risk,
        "details": {
            "issues": details,
            "leaked_data": leaked_data,
            "probed_ids": [r['id'] for r in results]
        }
    }
