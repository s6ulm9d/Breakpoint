import requests
import time
from ..models import CheckResult

def check(base_url, scenario, logger):
    url = f"{base_url}{scenario.target}"
    user = scenario.config.get("user", "test")
    attempts = scenario.config.get("attempts", 15)
    
    status_codes = []
    
    # Real-World Priority Password List (Top 100 from RockYou + Common Defaults)
    real_passwords = [
        "123456", "password", "123456789", "12345", "12345678", "qwerty", "1234567", "111111", "123123", "987654321",
        "iloveyou", "admin", "1234567890", "123", "michael", "555555", "welcome", "toor", "root", "666666",
        "1234", "12345678901", "princess", "dragon", "1234567890", "monkey", "charke", "changeme", "sunshine", "letmein",
        "football", "master", "orange", "baseball", "jennifer", "jessica", "password123", "superman", "mustang", "shadow",
        "fuckyou", "login", "trustno1", "harley", "pussy", "access", "hunter2", "simon", "joshua", "cisco", 
        "matrix", "1q2w3e4r", "qwertyuiop", "cool", "stars", "cookie", "chocolate", "baby", "love", "secret",
        "1234567890", "wanker", "buster", "freedom", "ginger", "pokemon", "liverpool", "arsenal", "chelsea", "manchester"
    ]
    
    # Combo Stuffing (User:Password pairs)
    combo_list = [
        ("admin", "admin"),      # 1
        ("admin", "password"),   # 2
        ("Soulmad", "soulmad"),  # 3 (Custom Request)
        ("admin", "123456"),
        ("root", "root"), ("root", "toor"), ("root", "admin"),
        ("user", "user"), ("test", "test"), ("guest", "guest"),
        ("postgres", "postgres"), ("oracle", "oracle"), ("tomcat", "s3cret")
    ]
    
    # 2. Attack Loop (Parallelized for Speed)
    # Combine lists
    max_requests = min(len(real_passwords) + len(combo_list), scenario.config.get("attempts", 20))
    
    # Merge targets: (user_from_config, pwd) AND (specific_user, specific_pwd)
    targets = []
    
    # Dictionary Attack against Configured User
    for p in real_passwords:
        targets.append((user, p))
        
    # Combo Stuffing (Try different usernames too)
    for u, p in combo_list:
        if u != user: # Avoid duplicates if user is 'admin'
             targets.append((u, p))
             
    final_targets = targets[:max_requests]
    
    import concurrent.futures
    
    def attempt_login(creds):
        u, p = creds
        payload = {"username": u, "password": p}
        try:
            resp = requests.post(url, json=payload, timeout=2)
            logger.log_request("POST", url, None, payload, resp)
            return resp.status_code
        except:
            return None

    print(f"    [BRUTE] Launching {len(final_targets)} requests concurrently (Dictionary + Stuffing)...")
    
    start_time = time.time()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(attempt_login, creds) for creds in final_targets]
            for f in concurrent.futures.as_completed(futures):
                # TIMEOUT GUARD
                if time.time() - start_time > 45: 
                    executor.shutdown(wait=False)
                    return CheckResult(scenario.id, scenario.type, "INCONCLUSIVE", None, "Brute force timed out (>45s).")
                    
                code = f.result()
                if code:
                    status_codes.append(code)
    except KeyboardInterrupt:
        print(f"\n    [!] Brute Force Interrupted. Stopping 100 threads...")
        # Executor context manager handles shutdown automatically on exit, 
        # but we re-raise to stop the main engine too.
        raise
        
    # 3. Analyze
    if 429 in status_codes:
        return CheckResult(scenario.id, scenario.type, "SECURE", None, "Received 429 Rate Limit response.")
        
    if all(c in [200, 401, 403] for c in status_codes):
        return CheckResult(scenario.id, scenario.type, "VULNERABLE", "MEDIUM", f"Sent {attempts} requests, no rate limiting (all {status_codes[0]}).")
        
    return CheckResult(scenario.id, scenario.type, "INCONCLUSIVE", None, f"Mixed/Unknown responses: {list(set(status_codes))}")
