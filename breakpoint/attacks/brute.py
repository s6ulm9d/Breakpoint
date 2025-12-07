from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_brute_force(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Simple Brute Force / Credential Stuffing Simulation.
    Checks if rate limiting is absent.
    """
    username = scenario.config.get("user", "admin")
    count = int(scenario.config.get("count", 20))
    
    # We send 20 bad passwords. 
    # If all return 401/200 OK (fast) without 429 Too Many Requests -> Logic Flaw.
    
    responses = []
    for i in range(count):
        body = {"username": username, "password": f"pass_{i}"}
        resp = client.send(scenario.method, scenario.target, json_body=body)
        responses.append(resp.status_code)
        
    # Analysis
    rate_limited = 429 in responses
    # Or if server started blocking (403/Connection Reset)
    
    passed = rate_limited
    details = f"Sent {count} requests. No 429 received."
    
    if rate_limited:
        details = "Rate Limit (429) detected."
    elif 403 in responses:
        details = "Soft Block (403) detected."
        passed = True
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "brute_force",
        "passed": passed,
        "details": details
    }
