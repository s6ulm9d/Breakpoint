import requests
import time
import concurrent.futures
from ..models import CheckResult

def check(base_url, scenario, logger):
    url = f"{base_url}{scenario.target}"
    base_req = scenario.config.get("baseline_requests", 5)
    load_req = scenario.config.get("load_requests", 20)
    
    def send_one():
        try:
            return requests.get(url, timeout=5).elapsed.total_seconds()
        except: return None
        
    # Baseline
    latencies = []
    for _ in range(base_req):
        l = send_one()
        if l: latencies.append(l)
    
    if not latencies:
        return CheckResult(scenario.id, scenario.type, "ERROR", None, "Baseline requests failed")
        
    avg_base = sum(latencies) / len(latencies)
    
    # Load
    load_latencies = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(send_one) for _ in range(load_req)]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: load_latencies.append(res)
            
    if not load_latencies:
        return CheckResult(scenario.id, scenario.type, "VULNERABLE", "LOW", "Server dropped all requests under simplified load.")
        
    avg_load = sum(load_latencies) / len(load_latencies)
    
    if avg_load > (avg_base * 2) and avg_load > 0.5: # 2x slower and at least 500ms
        return CheckResult(scenario.id, scenario.type, "VULNERABLE", "LOW", f"Latency doubled under load ({avg_base*1000:.0f}ms -> {avg_load*1000:.0f}ms)")
        
    return CheckResult(scenario.id, scenario.type, "SECURE", None, f"Performance stable ({avg_base*1000:.0f}ms -> {avg_load*1000:.0f}ms)")
