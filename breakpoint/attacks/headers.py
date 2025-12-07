from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_header_security_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Checks for missing security headers (Clickjacking, MIME, CORS).
    """
    # Baseline GET
    resp = client.send(scenario.method, scenario.target)
    headers = {k.lower(): v for k, v in resp.headers.items()}
    
    issues = []
    
    # 1. Clickjacking (X-Frame-Options / CSP)
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        issues.append("Missing Clickjacking Protection (X-Frame-Options / CSP)")
        
    # 2. MIME Sniffing
    if "x-content-type-options" not in headers:
        issues.append("Missing X-Content-Type-Options: nosniff")
        
    # 3. CORS Misconfig (Wildcard)
    acao = headers.get("access-control-allow-origin")
    if acao == "*":
        issues.append("CORS Misconfiguration: Access-Control-Allow-Origin: *")
        
    # 4. HSTS
    if "strict-transport-security" not in headers and scenario.target.startswith("https"):
        issues.append("Missing HSTS Header")

    return {
        "scenario_id": scenario.id,
        "attack_type": "header_security",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }
