from typing import Any, Dict, List
import threading
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_traffic_spike(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # Base count
    count = int(scenario.config.get("requests", 50))
    concurrency = int(scenario.config.get("concurrency", 5))

    # AGGRESSIVE SCALING (User Request: Triple/Increase counts)
    if scenario.config.get("aggressive"):
        # If user didn't manually set a huge number in YAML, we force a massive spike
        if count < 1500: 
            count = 1500 # 30x standard, or "Tripled" if they had a heavier config
        if concurrency < 50:
            concurrency = 50
            
    # If still too low for a "DDoS", bump it
    # But let's respect the logic: "Triple the requests count"
    # If standard was 500, we make it 1500. So the logic above holds mostly.
    
    errors = 0
    latencies = []
    lock = threading.Lock()
    
    def worker():
        nonlocal errors
        # Create a new session per thread ideally, but client has one. 
        # For true concurrency we should probably spawn new HttpClients or ignore session locking issues for now.
        # Let's use the provided client - requests Session is thread-safe.
        
        # We need to distribute work. Naive approach:
        while True:
            # This is not perfect batching, but good enough for simulation
            # We'll just run N times total.
            # Ideally: loop range(count // concurrency)
            pass 
        
    # Better structure
    results = []
    
    def task(n):
        for _ in range(n):
            resp = client.send(scenario.method, scenario.target)
            with lock:
                results.append(resp)

    threads = []
    reqs_per_thread = count // concurrency
    
    for i in range(concurrency):
        t = threading.Thread(target=task, args=(reqs_per_thread,))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    # Analyze
    total = len(results)
    if total == 0:
        return {"scenario_id": scenario.id, "passed": False, "details": {"error": "No requests run"}}

    failures = [r for r in results if r.status_code >= 500 or r.status_code == 0]
    latencies = sorted([r.elapsed_ms for r in results])
    
    p50 = latencies[int(total * 0.5)]
    p95 = latencies[int(total * 0.95)] if total > 20 else latencies[-1]
    
    # Degraded Criteria
    max_p95 = scenario.config.get("max_p95_ms", 1000)
    failed = len(failures) > 0 or p95 > max_p95
    
    return {
        "scenario_id": scenario.id,
        "attack_type": "traffic_spike",
        "passed": not failed,
        "details": {
            "total": total,
            "failed_count": len(failures),
            "p50_ms": p50,
            "p95_ms": p95,
            "threshold_ms": max_p95
        }
    }
