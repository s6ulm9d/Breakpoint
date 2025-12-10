from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_debug_exposure(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Checks for exposed debug endpoints, admin panels, and stack traces.
    """
    targets = [
        "/admin", "/admin/dashboard", "/debug", "/info", "/status", 
        "/actuator", "/actuator/health", "/metrics", "/.env", "/config.json"
    ]
    
    issues = []
    
    # 1. Endpoint Scanning
    for t in targets:
        resp = client.send("GET", t)
        if resp.status_code == 200:
            # Check content - don't alert on custom 200 error pages
            if "login" not in resp.text.lower() and len(resp.text) > 20: 
                issues.append(f"Exposed Sensitive Endpoint: {t} (Status 200)")
                
    return {
        "scenario_id": scenario.id,
        "attack_type": "debug_exposure",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }

def run_secret_leak(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Scans responses for leaked API keys, tokens, ENV vars.
    """
    # Baseline
    resp = client.send(scenario.method, scenario.target)
    
    sigs = [
        "AWS_ACCESS_KEY_ID", "BEGIN RSA PRIVATE KEY", "AIzaSy", 
        "sk_live_", "xoxb-", "DB_PASSWORD"
    ]
    
    issues = []
    text = resp.text
    for s in sigs:
        if s in text:
            issues.append(f"Secret Leak Detected: Found pattern '{s}'")
            
    return {
        "scenario_id": scenario.id,
        "attack_type": "secret_leak",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }
