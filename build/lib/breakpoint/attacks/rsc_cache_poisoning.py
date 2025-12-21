from typing import Any, Dict
import time
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_cache_poisoning(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    RSC Flight Cache Poisoning Audit.
    
    Target: CDNs and Intermediary Caches handling Flight (text/x-component) responses.
    
    Mechanism:
    - Sends requests with varying 'Key' headers (User-Identity, Permissions) that *should* be part of the cache key.
    - If the server/CDN returns the SAME cached Flight blob for different identity contexts, it's a poisoning/transparency risk.
    """
    
    issues = []
    evidence = []
    
    target = scenario.target
    path = f"{target.rstrip('/')}/"
    
    # 1. Baseline Request (User A)
    headers_a = {
        "RSC": "1",
        "X-User-ID": "1001", # Simulated identity header
        "Cookie": "session=user_a_token"
    }
    resp_a = client.send("GET", path, headers=headers_a)
    
    if "text/x-component" not in resp_a.headers.get("Content-Type", ""):
        # Not a flight endpoint?
        pass

    # 2. Victim Request (User B) - Same URL, Different Identity
    headers_b = {
        "RSC": "1",
        "X-User-ID": "2002",
        "Cookie": "session=user_b_token"
    }
    resp_b = client.send("GET", path, headers=headers_b)
    
    # 3. Cache Poisoning Check
    # If the response bodies are IDENTICAL but should contain user-specific data, 
    # OR if we see cache headers (CF-Cache-Status: HIT) when we changed ID.
    
    cache_header = resp_b.headers.get("CF-Cache-Status") or resp_b.headers.get("X-Cache") or "MISS"
    
    if resp_a.text and resp_a.text == resp_b.text:
         # Simpler check: Did we get a cache HIT on the second request despite changing cookies/identity?
         if "HIT" in str(cache_header).upper():
             issues.append(f"Cache Key Failure: Received Cached Response ({cache_header}) despite changing User Identity.")
             evidence.append(f"Poisoned Cache Response for User B: {resp_b.text[:100]}...")

    # 4. "Opaque Blob" Analysis
    # Flight blobs are hard for CDNs to parse. Check if Vary headers are missing.
    vary = resp_a.headers.get("Vary", "")
    if "Cookie" not in vary and "RSC" in resp_a.headers.get("Content-Type", ""):
         issues.append("Cache Config Error: RSC response missing 'Vary: Cookie' header. High risk of PII leakage.")

    # Forensic Narrative
    narrative = []
    if issues:
        narrative.append("Forensic Analysis: Flight Cache Desync Detected.")
        narrative.append("Observation: CDN/Cache treated user-specific Flight requests as identical static resources.")
        narrative.append("Impact: PII Leakage (GDPR Violation). One user's data served to another.")

    return {
        "scenario_id": scenario.id,
        "attack_type": "rsc_cache_poisoning",
        "passed": len(issues) == 0,
        "details": {
             "title": "RSC Flight Cache Poisoning",
             "issues": issues,
             "forensic_narrative": narrative,
             "evidence": evidence
        }
    }
