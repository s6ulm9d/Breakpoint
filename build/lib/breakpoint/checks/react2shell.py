import requests
from ..models import CheckResult

def check(base_url, scenario, logger):
    url = f"{base_url}{scenario.target}"
    
    
    # 1. Deserialization (Node)
    # Payload simulating a node-serialize RCE attempt (Benign)
    node_payload = {"tracker": "_$$ND_FUNC$$_function (){ return 'BP_SAFE_PROBE'; }()"}
    
    # 2. OS Command Injection
    # Common separators and commands
    cmd_payloads = [
        "; echo BP_RCE_TEST",
        "| echo BP_RCE_TEST",
        "|| echo BP_RCE_TEST",
        "$(echo BP_RCE_TEST)",
        "`echo BP_RCE_TEST`",
        "; cat /etc/passwd",
        "| type C:\\Windows\\win.ini" # Windows specific
    ]

    try:
        # Check 1: Node Deserialization
        resp = requests.post(url, json=node_payload, timeout=5)
        logger.log_request("POST", url, None, node_payload, resp)

        # OPTIMIZATION: Fail fast if endpoint doesn't exist
        if resp.status_code == 404:
            return CheckResult(scenario.id, scenario.type, "SECURE", "INFO", "Endpoint not found (404). Skipping RCE checks.")

        if "BP_SAFE_PROBE" in resp.text:
             return CheckResult(scenario.id, scenario.type, "VULNERABLE", "HIGH", "Server executed serialized function payload (Node Deserialization RCE).")
             
        # Check 2: OS Command Injection (Blind/Reflected)
        import concurrent.futures
        
        def check_cmd(cmd):
            try:
                payload = {"tracker": cmd}
                resp = requests.post(url, json=payload, timeout=3)
                logger.log_request("POST", url, None, payload, resp)
                
                if "BP_RCE_TEST" in resp.text or "root:x:0:0" in resp.text or "[extensions]" in resp.text:
                     return CheckResult(scenario.id, scenario.type, "VULNERABLE", "CRITICAL", f"Command Injection confirmed with payload: {cmd}")
            except: pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_cmd, c) for c in cmd_payloads]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res: return res
                 
        # Probe 2: Debug Endpoint Check (if configured)
        debug_path = "/json/list" # Common for Node Inspector
        debug_url = f"{base_url}{debug_path}"
        try:
            d_resp = requests.get(debug_url, timeout=2)
            if d_resp.status_code == 200 and "devtoolsFrontendUrl" in d_resp.text:
                return CheckResult(scenario.id, scenario.type, "VULNERABLE", "HIGH", f"Node Inspector exposed at {debug_path}")
        except: pass

    except Exception as e:
        return CheckResult(scenario.id, scenario.type, "ERROR", None, str(e))
        
    return CheckResult(scenario.id, scenario.type, "SECURE", None, "No RCE indicators found.")
