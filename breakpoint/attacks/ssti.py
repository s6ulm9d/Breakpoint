from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_ssti_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Server-Side Template Injection (SSTI)
    Injects template syntax to execute code on the server.
    """
    payloads = [
        "{{7*7}}", # Jinja2 / Twig
        "${7*7}", # Spring / EL
        "<%= 7*7 %>", # ERB
        "{{config}}", # Jinja2 info leak
        "{{self}}",
        "#{7*7}", # Velocity
    ]
    
    fields = scenario.config.get("fields", ["q", "name", "template"])
    issues = []
    
    for field in fields:
        for p in payloads:
            # Try both Params and JSON
            body = {field: p}
            resp = client.send(scenario.method, scenario.target, json_body=body)
            
            suspicious = False
            reasons = []
            
            # Math check
            if "49" in resp.text and "7*7" not in resp.text:
                suspicious = True
                reasons.append("Expression Evaluated (7*7 -> 49)")
                
            # Class/Config leak
            if "<class" in resp.text and "config" in p:
                suspicious = True
                reasons.append("Internal Config Object Leaked")
                
            if suspicious:
                issues.append(f"[CRITICAL] SSTI in '{field}': {', '.join(reasons)}")

    return {
        "scenario_id": scenario.id,
        "attack_type": "ssti",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }
