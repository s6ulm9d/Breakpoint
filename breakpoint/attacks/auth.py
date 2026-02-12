from typing import Any, Dict, List
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_password_length(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    lengths = scenario.config.get("lengths", [0, 100, 1000, 5000, 10000])
    target_field = scenario.config.get("password_field", "password")
    
    results = []
    issues = []
    
    for i, length in enumerate(lengths):
        val = "A" * length
        body = {"username": "test", target_field: val}
        
        resp = client.send(scenario.method, scenario.target, json_body=body, is_canary=(i > 0))
        
        # Abort if endpoint is missing
        if resp.status_code in [404, 405]:
            return {
                "scenario_id": scenario.id,
                "attack_type": "password_length",
                "passed": True,
                "details": {"skipped": True, "reason": "Endpoint 404. Skipping length test."}
            }
            
        baseline_time = baseline.elapsed_ms if i > 0 else 500 # Default if first
        is_5xx = resp.status_code >= 500
        is_timeout = resp.elapsed_ms > 5000 and resp.elapsed_ms > (baseline_time * 4)
        
        if is_5xx or is_timeout:
            reason = "Server Error 5xx" if is_5xx else f"Significant Latency ({resp.elapsed_ms:.0f}ms vs baseline {baseline_time:.0f}ms)"
            issues.append(f"Length {length} caused failure: {reason}")
            
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
        resp = client.send(scenario.method, scenario.target, json_body=body, is_canary=(i > 0))
        
        # Abort if endpoint is missing or blocked persistently
        if resp.status_code in [404, 405, 410]:
            return {
                "scenario_id": scenario.id,
                "attack_type": "replay_simple",
                "passed": True,
                "details": {"skipped": True, "reason": f"Endpoint returned {resp.status_code}. Aborting replay loop."}
            }
            
        responses.append({
            "iter": i,
            "status": resp.status_code
        })
        statuses.add(resp.status_code)
        
        # Optimization: If we already have multiple statuses, we can stop early
        if len(statuses) > 1:
            break
        
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
