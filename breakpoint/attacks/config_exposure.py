from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_debug_exposure(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Checks for exposed debug endpoints, admin panels, and stack traces.
    """
    targets = [
        "/admin", "/admin/dashboard", "/debug", "/info", "/status", 
        "/actuator", "/actuator/health", "/metrics", "/.env", "/config.json",
        "/server-status", "/console", "/web-console", "/dashboard",
        "/phpmyadmin", "/wp-admin", "/test.php", "/db_backup.sql"
    ]
    
    issues = []
    
    # 1. Endpoint Scanning
    for t in targets:
        resp = client.send("GET", t)
        if resp.status_code == 200 and not client.is_soft_404(resp):
            # Check content - don't alert on custom 200 error pages
            if "login" not in resp.text.lower() and len(resp.text) > 20: 
                issues.append(f"Exposed Sensitive Endpoint: {t} (Status 200)")
                
    return {
        "scenario_id": scenario.id,
        "attack_type": "debug_exposure",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }

def run_secret_leak(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Scans responses for leaked API keys, tokens, ENV vars.
    """
    # Baseline
    resp = client.send(scenario.method, scenario.target)
    if client.is_soft_404(resp):
        return {
            "scenario_id": scenario.id,
            "attack_type": "secret_leak",
            "passed": True,
            "details": "Target returned Soft-404. Skipping secret scanning."
        }
    
    sigs = [
        "AWS_ACCESS_KEY_ID", "BEGIN RSA PRIVATE KEY", "AIzaSy", 
        "sk_live_", "xoxb-", "DB_PASSWORD"
    ]
    
    issues = []
    leaked_data = []
    text = resp.text
    for s in sigs:
        if s in text:
            issues.append(f"Secret Leak Detected: Found pattern '{s}'")
            # Extract context (e.g., 50 chars around the match)
            idx = text.find(s)
            start_idx = max(0, idx - 20)
            end_idx = min(len(text), idx + len(s) + 50)
            snippet = text[start_idx:end_idx].replace("\n", " ")
            leaked_data.append(f"Match: ...{snippet}...")
            
    return {
        "scenario_id": scenario.id,
        "attack_type": "secret_leak",
        "passed": len(issues) == 0,
        "details": {"issues": issues, "leaked_data": leaked_data}
    }

def run_ds_store(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Checks for .DS_Store file exposure"""
    resp = client.send("GET", "/.DS_Store")
    issues = []
    if resp.status_code == 200 and "Mac OS X" in resp.text: # Header often contains this or binary soup
        issues.append("Exposed .DS_Store file found.")
    return {"scenario_id": scenario.id, "attack_type": "ds_store_exposure", "passed": not issues, "details": issues}

def run_git_exposure(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Checks for .git/HEAD exposure"""
    resp = client.send("GET", "/.git/HEAD")
    issues = []
    if resp.status_code == 200 and "refs/heads" in resp.text:
        issues.append("Exposed .git repository found (HEAD accessible).")
    return {"scenario_id": scenario.id, "attack_type": "git_exposure", "passed": not issues, "details": issues}

def run_env_exposure(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Checks for .env file exposure"""
    resp = client.send("GET", "/.env")
    issues = []
    if resp.status_code == 200 and ("DB_PASSWORD" in resp.text or "API_KEY" in resp.text):
        issues.append("Exposed .env file found with sensitive keys.")
    return {"scenario_id": scenario.id, "attack_type": "env_exposure", "passed": not issues, "details": issues}

def run_phpinfo(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Checks for phpinfo() pages"""
    resp = client.send("GET", "/phpinfo.php")
    issues = []
    if resp.status_code == 200 and "PHP Version" in resp.text:
        issues.append("Exposed phpinfo() page found.")
    return {"scenario_id": scenario.id, "attack_type": "phpinfo", "passed": not issues, "details": issues}

def run_swagger_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Checks for Swagger UI / Open API docs"""
    targets = ["/v2/api-docs", "/swagger-ui.html", "/api/docs"]
    issues = []
    for t in targets:
         resp = client.send("GET", t)
         if resp.status_code == 200 and ("swagger" in resp.text.lower() or "openapi" in resp.text.lower()):
             issues.append(f"Swagger/OpenAPI Documentation exposed at {t}")
             break
    return {"scenario_id": scenario.id, "attack_type": "swagger_exposure", "passed": not issues, "details": issues}
