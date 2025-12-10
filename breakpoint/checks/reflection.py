import requests
import random
from ..models import CheckResult

def check(base_url, scenario, logger):
    url = f"{base_url}{scenario.target}"
    param = scenario.config.get("param", "q")
    marker = f"BP_TEST_{random.randint(1000,9999)}"
    
    try:
        resp = requests.get(url, params={param: marker}, timeout=5)
        logger.log_request("GET", url, None, {param: marker}, resp)
    except Exception as e:
        return CheckResult(scenario.id, scenario.type, "ERROR", None, str(e))
        
    if resp.status_code in [404, 405]:
        return CheckResult(scenario.id, scenario.type, "INCONCLUSIVE", None, f"Endpoint returned {resp.status_code}")
        
    # Check for reflection
    if marker in resp.text:
        return CheckResult(scenario.id, scenario.type, "VULNERABLE", "MEDIUM", f"Parameter '{param}' reflected in response body without obvious escaping.")
        
    return CheckResult(scenario.id, scenario.type, "SECURE", None, "Marker not found in response.")
