from typing import Any, Dict
import time
import random
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_cache_deception(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Web Cache Deception / Poisoning Attack.
    Attempts to trick the cache into storing sensitive data or malicious payloads.
    """
    issues = []
    leaked_data = []
    
    # 1. Web Cache Deception (Path Confusion)
    # Target: /api/user -> Try /api/user/nonexistent.css
    # If server returns the USER DATA (JSON/HTML) but with a 200 OK and Cache Headers, 
    # a proxy might cache it as a CSS file.
    
    target_clean = scenario.target.split('?')[0].rstrip('/')
    deception_path = f"{target_clean}/test_wcd_{random.randint(1000,9999)}.css"
    
    resp_deco = client.send("GET", deception_path)
    
    # Check if we got the sensitive content from the base endpoint
    # (We assume base endpoint returns something specific, or checking if it ignores the suffix)
    # A simple heuristic: If response is 200 OK, has specific caching headers, and looks like dynamic content (not real CSS).
    
    cache_headers = ["X-Cache", "CF-Cache-Status", "Age", "X-Proxy-Cache"]
    is_cached = any(h in resp_deco.headers for h in cache_headers) or "public" in resp_deco.headers.get("Cache-Control", "")
    
    if resp_deco.status_code == 200 and is_cached:
        # Check if content looks like what we expect from the main endpoint (e.g. JSON or specific HTML)
        # If it returns "user_id" or similar, but we asked for .css
        if "application/json" in resp_deco.headers.get("Content-Type", "") or "text/html" in resp_deco.headers.get("Content-Type", ""):
            issues.append(f"Web Cache Deception: {deception_path} returned 200 OK with caching headers but dynamic Content-Type.")
            leaked_data.append(f"Header Dump: {resp_deco.headers}")

    # 2. Host Header Poisoning (Cache Poisoning) - DANGEROUS
    # Inject X-Forwarded-Host: evil.com and see if it's reflected in absolute links.
    # If successful, this ruins the cache for other users.
    
    if scenario.config.get("aggressive"):
        print("    [!] AGGRESSIVE: Attempting Host Header Poisoning...")
        canary = f"attacker-{random.randint(1000,9999)}.com"
        resp_poison = client.send("GET", scenario.target, headers={"X-Forwarded-Host": canary, "X-Host": canary})
        
        if canary in resp_poison.text:
            # Reflected! Now check if it's potentially cacheable.
            if is_cached or "public" in resp_poison.headers.get("Cache-Control", ""):
                issues.append(f"Cache Poisoning: Injected Host '{canary}' reflected in response and potentially cacheable.")
                leaked_data.append(f"Reflected: ...{resp_poison.text[:100]}...")
            else:
                # Just reflection, maybe not cached, but still risky
                pass
    else:
        # In non-aggressive mode, we skip the poisoning attempt
        pass

    return {
        "scenario_id": scenario.id,
        "attack_type": "cache_poisoning",
        "passed": len(issues) == 0,
        "details": {
            "issues": issues,
            "leaked_data": leaked_data
        }
    }
