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
    
    successful_accesses = [r for r in results if r["status"] == 200]
    
    # Heuristic: If we accessed more than 1 distinct object, report IDOR risk.
    # (In real prod, public endpoints exist, but for 'BREAKPOINT' typically we target private stuff)
    
    risk = len(successful_accesses) > 1
    
    details = []
    leaked_data = [] # Capture what we saw
    
    if risk:
        ids = [r['id'] for r in successful_accesses]
        details.append(f"Accessible IDs found: {ids}. Ensure these are not sensitive/private.")
        
        # Grab snippet from first couple of successes to prove data access
        # We need to re-fetch or if we stored it? We only stored len.
        # Let's just trust that re-fetching is fine or we should have stored it. 
        # Modifying the loop above to store snippet would be better, but let's just 
        # add a targeted fetch here or just instruct user. 
        # actually, let's modify the loop above to store snippet!
        # wait, I can't modify the loop above in this chunk easily without expanding scope.
        # Let's just say "Data length: X" is the leak for now, OR better, let's just 
        # assume we can't easily get the body retrospectively without storing it.
        # Let's change the strategy: Update the loop to store 'snippet'.
        pass 
        
    # Re-writing the previous loop block to store snippet
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
        
    successful_accesses = [r for r in results if r["status"] == 200]
    risk = len(successful_accesses) > 1
    
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
