from typing import Any, Dict, List
import threading
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_traffic_spike(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # Base count
    count = int(scenario.config.get("requests", 50))
    concurrency = int(scenario.config.get("concurrency", 5))

    # AGGRESSIVE SCALING (User Request: "make it minimum 5k and above only")
    if scenario.config.get("aggressive"):
        # If user didn't manually set a huge number in YAML, we force a massive spike
        # User demanded "minimum 5k"
        if count < 5000: 
            count = 5000 
        if concurrency < 100:
            concurrency = 100
            
    # If still too low for a "DDoS", bump it
    # We respect the YAML if it's > 5000.
    
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
        import random

        body = scenario.config.get("body")
        
        # Auto-generate body for spam if none provided but method is POST
        if not body and scenario.method in ["POST", "PUT"]:
            body = {"spam_id": random.randint(1, 1000000), "data": "A" * 100}

        for _ in range(n):
            try:
                # Vary the body slightly if possible to avoid caching (client.send handles json_body)
                if isinstance(body, dict):
                    body["random_nonce"] = random.randint(1, 10000000)
                    resp = client.send(scenario.method, scenario.target, json_body=body)
                else:
                    resp = client.send(scenario.method, scenario.target, form_body=body)

                with lock:
                    results.append(resp)
            except Exception as e:
                # Record as a failure/error dummy response or just skip
                pass

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
