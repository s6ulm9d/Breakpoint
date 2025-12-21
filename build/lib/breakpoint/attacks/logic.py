from typing import Any, Dict
import time
import threading
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_race_condition(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    True Race Condition: Sending requests with EXACT timing.
    Differs from traffic spike (just load).
    Requires 'Barrier' synchronization.
    """
    concurrency = 10
    barrier = threading.Barrier(concurrency)
    
    results = []
    
    def worker():
        try:
            barrier.wait() # Wait for all threads to be ready
            # FIRE EXACTLY AT ONCE
            resp = client.send(scenario.method, scenario.target, json_body=scenario.config.get("body"))
            results.append(resp.status_code)
        except:
            pass
            
    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    for t in threads: t.start()
    for t in threads: t.join()
    
    # Analyze - if we got multiple 200 OKs where logic says 1 allowed?
    # User must define what counts as 'failure'.
    # Default: if all 200, assume race succeeded (unsafe default, but informative).
    
    success_count = results.count(200)
    passed = success_count <= 1
    
    return {
        "scenario_id": scenario.id,
        "attack_type": "race_condition",
        "passed": passed,
        "details": {"success_count": success_count, "total": len(results)}
    }

def run_otp_reuse(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    OTP Reuse / Rate Limit test on sensitive endpoint.
    """
    otp = scenario.config.get("otp", "123456")
    body = {"otp": otp}
    
    # Send once (Consume)
    r1 = client.send("POST", scenario.target, json_body=body)
    
    # Send again (Reuse)
    r2 = client.send("POST", scenario.target, json_body=body)
    
    passed = r1.status_code == 200 and r2.status_code != 200
    if r1.status_code != 200: passed = True # Attack invalid if first failed
    
    return {
        "scenario_id": scenario.id,
        "attack_type": "otp_reuse",
        "passed": passed,
        "details": {"first": r1.status_code, "second": r2.status_code}
    }
