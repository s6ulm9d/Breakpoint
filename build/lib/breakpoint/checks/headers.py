import requests
from ..models import CheckResult

def check(base_url, scenario, logger):
    url = f"{base_url}{scenario.target}"
    
    try:
        resp = requests.get(url, timeout=5)
        logger.log_request("GET", url, None, None, resp)
    except Exception as e:
        return CheckResult(scenario.id, scenario.type, "ERROR", None, str(e))
        
    headers = {k.lower(): v for k, v in resp.headers.items()}
    missing = []
    
    # 1. Clickjacking
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        missing.append("X-Frame-Options/CSP")
        
    # 2. MIMESniff
    if "x-content-type-options" not in headers:
        missing.append("X-Content-Type-Options")
        
    if missing:
        return CheckResult(scenario.id, scenario.type, "VULNERABLE", "MEDIUM", f"Missing headers: {', '.join(missing)}")
    
    return CheckResult(scenario.id, scenario.type, "SECURE", None, "All critical headers present.")
