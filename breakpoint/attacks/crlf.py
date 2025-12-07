from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_crlf_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    HTTP Response Splitting / CRLF Injection.
    Injects %0d%0a to see if we can set arbitrary headers.
    """
    payload = "valid\r\nX-Injected: true"
    encoded_payload = "valid%0d%0aX-Injected: true"
    
    fields = scenario.config.get("fields", ["url", "redirect", "lang"])
    issues = []
    
    for field in fields:
        for p in [payload, encoded_payload]:
            params = {field: p}
            resp = client.send(scenario.method, scenario.target, params=params)
            
            # Check if header was set
            if "X-Injected" in resp.headers or "X-Injected" in resp.text: # Sometimes reflected in body
                # If in headers, it's critical. If in body, it's just reflection/XSS risk.
                # For engine simplicity we flag both but distinguish logic if possible.
                # requests header parsing might be strict, so we check raw if possible, but here we check parsed.
                if resp.headers.get("X-Injected") == "true":
                    issues.append(f"[CRITICAL] CRLF Injection in '{field}' (Header Injection)")
                else:
                    issues.append(f"[MEDIUM] Reflected CRLF in '{field}'")
                    
    return {
        "scenario_id": scenario.id,
        "attack_type": "crlf_injection",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }
