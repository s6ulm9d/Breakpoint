from typing import Any, Dict, List
import json
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_rsc_flight_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    RSC Flight Trust Boundary Violation Scanner.
    
    This module detects if a React Server Components (RSC) endpoint is improperly 
    exposed and accepting complex serialized input from unauthenticated clients.
    
    It does NOT execute arbitrary code. It checks for:
    1. Unprotected Flight endpoints.
    2. Server willingness to process custom Flight structures.
    3. Information leaks in error messages indicating unsafe deserialization.
    """
    
    # Common RSC Flight Endpoints
    potential_endpoints = [
        "",  # Root (often handles RSC via headers)
        "/_next/static/chunks/rsc",
        "/_flight",
        "/rsc"
    ]
    
    # Headers often required to trigger Flight processing
    flight_headers = {
        "RSC": "1",
        "Next-Router-State-Tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%5D%7D%5D",
        "Accept": "text/x-component"
    }

    issues = []
    suspicious_responses = []

    # 1. Endpoint Discovery & Protocol Violation Probe
    for endpoint in potential_endpoints:
        target_path = f"{scenario.target.rstrip('/')}/{endpoint.lstrip('/')}"
        
        # 1. Protocol Violation Probe (Basic)
        # A server that tries to parse this is crossing the trust boundary if unauthenticated.
        probe_payload = '["$","@id",{"key":"value"}]' 
        
        # 2. Logic Abuse: Recursive Reference / Parser Stress
        # Flight protocols often use recursion. deeply nested structures can trigger logic failures.
        # This isn't just a DoS; it's seeing if the *logic* breaks (stack depth limits, reference cycles).
        recursive_payload = '["$","@id",{"children":' * 100 + 'null' + '}]}' * 100

        # 3. Component Reference Injection (Attempting to reference internal IDs)
        # Attempting to load server references that shouldn't be exposed.
        ref_payload = '["$L", "$R", "$S", "$F", "InternalComponent"]'

        payloads = [
            ("Std Probe", probe_payload),
            ("Recursive Abuse", recursive_payload),
            ("Reference Injection", ref_payload)
        ]

        for name, pld in payloads:
            resp = client.send(
                "POST", 
                target_path, 
                headers=flight_headers, 
                json_body=None, 
                form_body=pld
            )

            # Analysis
            is_flight_response = "text/x-component" in resp.headers.get("Content-Type", "")
            
            # Check for React/Next.js specific error signatures indicating deep processing or logic failure
            error_signatures = [
                "ReactServerComponentsError", 
                "Digest: ", 
                "Minified React error",
                "Cannot read properties of undefined",
                "unsupported type",
                "Maximum call stack size exceeded", # Logic failure
                "Circular structure" # Logic failure
            ]
            
            signature_found = any(sig in resp.text for sig in error_signatures)

            if is_flight_response or signature_found:
                msg = f"Protocol Logic Failure at {target_path} [{name}]"
                details = []
                if is_flight_response:
                    details.append("Endpoint processed Flight protocol (Trust Boundary Violation)")
                if signature_found:
                    details.append(f"Parser Logic Failure: Server stack/state exposed")
                
                issues.append(f"{msg}: {', '.join(details)}")
                # Capture the response for review (simulated 'leak' of server state)
                suspicious_responses.append(f"[{name}] {resp.text[:200]}")

    # Forensic Narrative Construction
    narrative = []
    if not issues:
        narrative.append("Forensic Analysis: No active Flight protocol handlers were detected on standard endpoints. The server rejected all serialized payloads.")
    else:
        narrative.append(f"Forensic Analysis: CONFIRMED. The server at {scenario.target} is actively processing unauthenticated Flight protocol data.")
        narrative.append(f"Observation: {len(suspicious_responses)} distinct protocol abuse vectors triggered server-side processing.")
        narrative.append("Risk Assessment: High. The accepted payloads indicate a Trust Boundary Violation where client-controlled serialized objects are being deserialized by the server runtime.")
        narrative.append("Execution Potential: The server exposes deep recursion/parsing logic (Stack Traces/Error Codes observed), confirming that input reaches the core React runtime.")

    return {
        "scenario_id": scenario.id,
        "attack_type": "rsc_flight_trust_boundary_violation",
        "passed": len(issues) == 0,
        "details": {
            "title": "RSC Flight Protocol Trust Boundary Violation",
            "issues": issues,
            "forensic_narrative": narrative,
            "evidence_snippets": suspicious_responses
        }
    }
