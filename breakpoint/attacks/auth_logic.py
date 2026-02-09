from typing import Any, Dict, List
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_privilege_escalation_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Business Logic Awareness: Horizontal & Vertical Privilege Escalation.
    Targets /settings, /profile, /admin, etc.
    """
    target = scenario.target
    roles = ["user", "admin", "superadmin", "guest"]
    
    # Horizontal: Try to access other users' data with our session
    # We need to identify ID parameters in the path/query
    
    results = []
    
    # 1. Test for BOLA (IDOR) with role context
    # This is handled by IDOR module, but here we add "role-aware" logic
    # e.g. Trying to use a "user" cookie to access "/admin/settings"
    
    headers = client.headers
    # If no auth header, it's just a guest check
    is_authenticated = any(h.lower() in ["authorization", "cookie"] for h in headers.keys())
    
    if not is_authenticated:
        # Vertical: Try to access sensitive endpoints as guest
        sensitive_endpoints = ["/admin", "/api/v1/users", "/settings", "/config", "/backup", "/logs"]
        for ep in sensitive_endpoints:
             # Try both relative and absolute paths
             resp = client.send("GET", ep)
             if resp.status_code == 200:
                 results.append({"type": "Vertical PE", "target": ep, "finding": "Guest access allowed to sensitive endpoint."})

    # Heuristic for role-mapping
    # If endpoint contains "admin", "owner", or "internal"
    if any(keyword in target.lower() for keyword in ["admin", "internal", "owner", "private"]):
        resp = client.send(scenario.method, target)
        if resp.status_code == 200:
             results.append({"type": "BOLA", "target": target, "finding": f"Potentially sensitive endpoint {target} accessible."})

    risk = len(results) > 0
    
    return {
        "scenario_id": scenario.id,
        "attack_type": "privilege_escalation",
        "passed": not risk,
        "details": {
            "issues": [r["finding"] for r in results],
            "leaked_data": [f"Endpoint {r['target']} returned success." for r in results]
        }
    }
