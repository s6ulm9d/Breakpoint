from typing import Any, Dict, List
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_password_length(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    lengths = scenario.config.get("lengths", [0, 100, 1000, 5000, 10000])
    target_field = scenario.config.get("password_field", "password")
    
    results = []
    issues = []
    
    for length in lengths:
        val = "A" * length
        body = {"username": "test", target_field: val}
        
        resp = client.send(scenario.method, scenario.target, json_body=body)
        
        failed = resp.status_code >= 500 or resp.elapsed_ms > 2000 # 2s arbitrary hard limit for MVP
        
        if failed:
            issues.append(f"Length {length} caused failure: status={resp.status_code}, time={resp.elapsed_ms:.2f}ms")
            
        results.append({
            "length": length,
            "status": resp.status_code,
            "elapsed_ms": resp.elapsed_ms
        })

    return {
        "scenario_id": scenario.id,
        "attack_type": "password_length",
        "passed": len(issues) == 0,
        "details": {
            "issues": issues,
            "results": results
        }
    }

def run_replay_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # Simple replay: repeat N times, check for consistency
    repeats = int(scenario.config.get("repeats", 5))
    body = scenario.config.get("body", {"action": "test"})
    
    responses = []
    statuses = set()
    
    for i in range(repeats):
        resp = client.send(scenario.method, scenario.target, json_body=body)
        responses.append({
            "iter": i,
            "status": resp.status_code
        })
        statuses.add(resp.status_code)
        
    # Naive check: if we get different status codes, might be interesting
    passed = len(statuses) == 1
    
    return {
        "scenario_id": scenario.id,
        "attack_type": "replay_simple",
        "passed": passed,
        "details": {
            "distinct_statuses": list(statuses),
            "responses": responses
        }
    }
