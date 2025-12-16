from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_performance_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Checks if the application performance degrades under load.
    Replaces checks/performance.py using HttpClient.
    """
    base_req = scenario.config.get("baseline_requests", 5)
    load_req = scenario.config.get("load_requests", 20)
    
    # 1. Baseline
    latencies = []
    for _ in range(base_req):
        resp = client.send("GET", scenario.target)
        if resp.status_code != 0:
            latencies.append(resp.elapsed_ms / 1000.0) # Convert back to seconds for consistency with old logic if needed, but ms is better. keeping seconds as logic used seconds
            
    if not latencies:
         return {
            "scenario_id": scenario.id,
            "attack_type": "performance",
            "passed": False,
            "details": "Baseline requests failed completely."
        }
        
    avg_base = sum(latencies) / len(latencies)
    
    # 2. Load
    # HttpClient is synchronous, but Engine runs checks in parallel. 
    # However, 'performance' check itself runs concurrent requests internally in the old one.
    # To mimic that, we need parallelism here.
    
    import concurrent.futures
    
    load_latencies = []
    
    def send_one():
        r = client.send("GET", scenario.target)
        return r.elapsed_ms / 1000.0 if r.status_code != 0 else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(send_one) for _ in range(load_req)]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: load_latencies.append(res)
            
    if not load_latencies:
         return {
            "scenario_id": scenario.id, 
            "attack_type": "performance",
            "passed": True, # Technically "Secure" from vulnerability stand point, but broken? 
            # Old logic said VULNERABLE if dropped.
            "passed": False,
            "details": "Server dropped all requests under simplified load."
        }

    avg_load = sum(load_latencies) / len(load_latencies)
    
    # Logic: 2x slower and > 500ms
    if avg_load > (avg_base * 2) and avg_load > 0.5:
        return {
            "scenario_id": scenario.id,
            "attack_type": "performance",
            "passed": False,
            "details": f"Latency doubled under load ({avg_base*1000:.0f}ms -> {avg_load*1000:.0f}ms)"
        }
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "performance",
        "passed": True,
        "details": f"Performance stable ({avg_base*1000:.0f}ms -> {avg_load*1000:.0f}ms)"
    }
