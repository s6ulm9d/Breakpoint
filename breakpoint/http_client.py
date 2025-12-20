import time
import requests
import random
import threading
import os
from typing import Optional, Dict, Any, Union, List
from dataclasses import dataclass, field
from colorama import Fore, Style
import uuid

# Suppress SSL warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

@dataclass
class ResponseWrapper:
    status_code: int
    headers: Dict[str, str]
    text: str
    elapsed_ms: float
    url: str
    json_data: Optional[Any] = None
    
    @property
    def is_error(self):
        return self.status_code >= 500

    @property
    def is_client_error(self):
        return 400 <= self.status_code < 500

# Modern User Agents to bypass basic bot filters
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
]

class HttpClient:
    _proxies: List[str] = []
    _proxy_lock = threading.Lock()
    _proxies_loaded = False

    def __init__(self, base_url: str, timeout: float = 30.0, verbose: bool = False, headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verbose = verbose
        self.global_headers = headers or {}
        self.session = requests.Session()
        
        # High-Concurrency Adapter
        adapter = requests.adapters.HTTPAdapter(pool_connections=1000, pool_maxsize=1000)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Unique Canary for Log Verification
        self.canary_id = str(uuid.uuid4())[:8]
        self._dead_proxies = set()
        
        # Load proxies once
        if not HttpClient._proxies_loaded:
            self._load_proxies()

        if self.verbose:
            mode = "ELITE PROXY" if HttpClient._proxies else "DIRECT"
            print(f"[*] HttpClient initialized ({mode} MODE). Traffic Tag ID: {self.canary_id}")

    def _load_proxies(self):
        with HttpClient._proxy_lock:
            if HttpClient._proxies_loaded: return
            
            # Search in common locations
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            paths = [
                "proxies.txt", 
                "proxies.txt.bak",
                os.path.join(root, "proxies.txt"),
                "breakpoint/proxies.txt", 
                "data/proxies.txt",
                "C:\\Users\\soulmad\\projects\\break-point\\breakpoint\\proxies.txt"
            ]

            for path in paths:
                if os.path.exists(path):
                    try:
                        with open(path, "r") as f:
                            lines = [line.strip() for line in f if line.strip()]
                            HttpClient._proxies = lines
                            if self.verbose: print(f"[+] Loaded {len(HttpClient._proxies)} proxies from {path}")
                            break
                    except Exception as e:
                        if self.verbose: print(f"[!] Error loading proxies: {e}")
            
            HttpClient._proxies_loaded = True

    def _get_bypass_headers(self) -> Dict[str, str]:
        """Generates evasive and WAF bypass headers."""
        ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        
        # Extensive IP Spoofing pool
        spoof_headers = {
            "X-Forwarded-For": f"{ip}, {random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "X-Real-IP": ip,
            "Client-IP": ip,
            "CF-Connecting-IP": ip,
            "True-Client-IP": ip,
            "X-Client-IP": ip,
            "X-Remote-IP": ip,
            "X-Remote-Addr": ip,
            "X-Originating-IP": ip,
            "Forwarded": f"for={ip};proto=https",
            "X-ProxyUser-Ip": ip,
            "Via": f"1.1 {random.choice(['google', 'bing', 'chrome-compression-proxy'])}",
            # "From": "googlebot@google.com",  # Removed - Do not claim to be googlebot if we aren't, some WAFs verify this via RDNS
        }
        
        # Randomize which ones we send to avoid static fingerprint
        subset = dict(random.sample(list(spoof_headers.items()), k=random.randint(3, 7)))
        
        # Core Evasion - LOOK LIKE A REAL BROWSER
        subset.update({
            "User-Agent": random.choice(USER_AGENTS),
            # REMOVED X-Breakpoint-Tag (Dead giveaway)
            # REMOVED X-Request-Id (Too API-like)
            "DNT": "1",
            "Sec-Ch-Ua-Mobile": "?0",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Accept-Encoding": "gzip, deflate, br", # Vital for looking like a browser
        })
        
        return subset

    def send(self, method: str, target: str, *, 
             headers: Optional[Dict[str, str]] = None, 
             params: Optional[Dict[str, Any]] = None, 
             json_body: Optional[Any] = None, 
             form_body: Optional[Dict[str, Any]] = None,
             timeout: Optional[float] = None) -> ResponseWrapper:
        
        url = target if target.startswith("http") else f"{self.base_url}/{target.lstrip('/')}"
        
        # Cache Busting (Shuffled query param name)
        cb_key = random.choice(["_v", "cache", "ref", "ts", "rnd", "id"])
        cb_val = random.randint(1000000, 9999999)
        # Avoid appending if it looks like a static asset to avoid 404s
        if not any(url.endswith(ext) for ext in [".js", ".css", ".png", ".jpg"]):
             if "?" in url: url += f"&{cb_key}={cb_val}"
             else: url += f"?{cb_key}={cb_val}"

        # Standard headers
        base_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,en;q=0.8",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        # Referers - Extended
        REFERERS = [
            "https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/", 
            "https://twitter.com/", "https://www.reddit.com/", "https://t.co/",
            "https://www.linkedin.com/", "https://www.facebook.com/", "https://instagram.com/",
            self.base_url
        ]

        # Retry Loop
        max_retries = 10 # INCREASED: WAF Bypass Strategy - Persistence
        errors = []
        
        for attempt in range(max_retries):
            # 1. Build Headers
            req_headers = base_headers.copy()
            req_headers.update(self._get_bypass_headers())
            
            if "Referer" not in (headers or {}):
                req_headers["Referer"] = random.choice(REFERERS)
            
            if self.global_headers: req_headers.update(self.global_headers)
            if headers: req_headers.update(headers)
            
            # 2. Smart Proxy Rotation (Real IP Usage)
            proxy_url = None
            # Bypass proxies for localhost to avoid 403s from public proxies trying to hit local addresses
            if "localhost" in self.base_url or "127.0.0.1" in self.base_url:
                 if self.verbose and attempt == 0: 
                     print(f"{Fore.CYAN}[*] Localhost detected. Bypassing proxies for direct connection.{Style.RESET_ALL}")
                 proxies = None
            elif HttpClient._proxies:
                # Filter out known dead proxies for this session
                valid_proxies = [p for p in HttpClient._proxies if p not in self._dead_proxies]
                
                # If we exhausted valid proxies, reset the pool (maybe transient network issues)
                if not valid_proxies:
                    if self.verbose: print(f"{Fore.MAGENTA}[*] Proxy pool exhausted/cleaned. Recycling all {len(HttpClient._proxies)} proxies.{Style.RESET_ALL}")
                    self._dead_proxies.clear()
                    valid_proxies = list(HttpClient._proxies)

                if valid_proxies:
                    proxy_url = random.choice(valid_proxies)
                    proxies = {"http": proxy_url, "https": proxy_url}

            # 3. Request
            try:
                # Dynamic Read Timeout - Fail Fast on Connect (3s), Wait for Read (15s)
                # If using a proxy, give it slightly more connect time but still fail fast to rotate
                connect_timeout = 4.0 if proxy_url else 3.0
                req_timeout = timeout if timeout is not None else (connect_timeout, 15.0) 
                
                resp = self.session.request(
                    method=method.upper(),
                    url=url,
                    headers=req_headers,
                    params=params,
                    json=json_body,
                    data=form_body,
                    timeout=req_timeout,
                    proxies=proxies,
                    verify=False,
                    allow_redirects=True
                )
                
                # Check for rate limiting or WAF block
                if resp.status_code in [403, 429]:
                    if self.verbose: 
                        reason = "WAF Block" if resp.status_code == 403 else "Rate Limit"
                        if attempt % 5 == 0:
                            print(f"{Fore.YELLOW}[!] {reason} ({resp.status_code}). Retry {attempt+1}/{max_retries}...{Style.RESET_ALL}")
                    
                    # Minimal Backoff for Speed but Randomized to avoid Pattern Detection
                    time.sleep(random.uniform(0.5, 1.5))
                    continue

                # Parse Success
                json_data = None
                try: json_data = resp.json()
                except: pass

                if self.verbose:
                    sc = resp.status_code
                    color = Fore.GREEN if sc < 400 else Fore.YELLOW if sc < 500 else Fore.RED
                    print(f"{color}[<] {sc} {resp.reason} ({resp.elapsed.total_seconds()*1000:.0f}ms) | {url.split('?')[0]}{Style.RESET_ALL}")

                return ResponseWrapper(
                    status_code=resp.status_code, 
                    headers=dict(resp.headers),
                    text=resp.text,
                    elapsed_ms=resp.elapsed.total_seconds()*1000,
                    url=str(resp.url),
                    json_data=json_data
                )

            except Exception as e:
                # Mark proxy as dead if it failed connection
                if proxy_url:
                    self._dead_proxies.add(proxy_url)
                    # if self.verbose: print(f"{Fore.MAGENTA}[!] Proxy dead: {proxy_url}{Style.RESET_ALL}")

                errors.append(str(e))
                if attempt < max_retries - 1:
                    continue # No sleep, just retry
        
        raise ConnectionError(f"Network Blocked: Max retries exited. Firewall or ISP blocking traffic. Last error: {errors[-1] if errors else 'Unknown'}")
