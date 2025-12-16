import time
import requests
import random
import threading
from typing import Optional, Dict, Any, Union, List
from dataclasses import dataclass, field
from colorama import Fore, Style
import uuid

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
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
]

class HttpClient:
    def __init__(self, base_url: str, timeout: float = 30.0, verbose: bool = False, proxies: Optional[List[str]] = None, headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verbose = verbose
        self.global_headers = headers or {}
        self.session = requests.Session()
        
        # PROXY MANAGEMENT
        self.proxies = proxies or []
        self.proxy_lock = threading.Lock()
        
        # OPTIMIZATION: High-Concurrency but Frequent Rotation
        # Reduced pool size significantly to prevent socket choking on unstable proxies
        adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Unique Canary for Log Verification
        self.canary_id = str(uuid.uuid4())[:8]
        
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
            "X-Breakpoint-ID": self.canary_id
        })
        
        if self.verbose:
            proxy_msg = f" | Proxies: {len(self.proxies)} loaded" if self.proxies else " | No Proxies (Direct)"
            print(f"[*] HttpClient initialized. Traffic Tag: X-Breakpoint-ID: {self.canary_id}{proxy_msg}")


    def _jitter(self):
        """Adds a tiny random delay to avoid machine-like timing fingerprints"""
        # Reduced for aggressive speed requirements
        time.sleep(random.uniform(0.01, 0.05))

    def _ip_spoof(self) -> Dict[str, str]:
        """Generates random fake IP headers to bypass simple rate limiters."""
        fake_ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        
        # WEAPONIZED HEADER LIST: Try every known IP forwarding header
        return {
            "X-Forwarded-For": fake_ip,
            "X-Real-IP": fake_ip,
            "Client-IP": fake_ip,
            "X-Originating-IP": fake_ip,
            "X-Remote-IP": fake_ip,
            "X-Client-IP": fake_ip,
            "True-Client-IP": fake_ip,
            "X-Forwarded-Host": fake_ip,
            "X-Host": fake_ip,
            "X-Custom-IP-Authorization": fake_ip,
            "Forwarded": f"for={fake_ip};proto=http",
            "Via": f"1.1 {fake_ip}",
            # Rotate User-Agent for identity protection
            "User-Agent": random.choice(USER_AGENTS)
        }

    def send(self, method: str, target: str, *, 
             headers: Optional[Dict[str, str]] = None, 
             params: Optional[Dict[str, Any]] = None, 
             json_body: Optional[Any] = None, 
             form_body: Optional[Dict[str, Any]] = None,
             timeout: Optional[float] = None) -> ResponseWrapper:
        
        url = target if target.startswith("http") else f"{self.base_url}/{target.lstrip('/')}"
        
        # 1. CACHE BUSTING (Critical for logging)
        if "?" in url:
            url += f"&_cb={random.randint(100000, 999999)}"
        else:
            url += f"?_cb={random.randint(100000, 999999)}"

        # REALISTIC REFERER POOL
        REFERERS = [
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://search.yahoo.com/",
            "https://duckduckgo.com/",
            "https://www.facebook.com/",
            "https://twitter.com/",
            "https://www.linkedin.com/",
            self.base_url
        ]

        # 2. REALISTIC REFERER/ORIGIN
        if not headers: headers = {}
        if "Referer" not in headers:
            headers["Referer"] = random.choice(REFERERS)
        if "Origin" not in headers and method.upper() in ["POST", "PUT", "PATCH"]:
            headers["Origin"] = self.base_url
        
        # Aggressive Retry Limit for Unstable Public Proxies
        # We NEVER give up on the pool. Even if they are shaky.
        max_retries = 200 
        backoff = 0.5 

        for attempt in range(max_retries + 1):
            
            # ROTATION LOGIC: Generate NEW Identity per attempt
            # 1. IP Spoofing
            spoof_headers = self._ip_spoof()
            
            # 2. Proxy Selection
            request_proxies = None
            if self.proxies:
                try:
                    proxy_url = random.choice(self.proxies)
                    request_proxies = {"http": proxy_url, "https": proxy_url}
                except IndexError:
                    pass
            
            # 3. Headers Merging
            request_headers = spoof_headers.copy()
            if self.global_headers:
                 request_headers.update(self.global_headers)
            if headers:
                request_headers.update(headers)
            
            request_headers["Connection"] = "close"

            # VERBOSE LOG (Only show on first attempt or if verbose enough to avoid spam)
            if self.verbose and attempt == 0:
                payload_preview = ""
                if json_body: payload_preview = f"| JSON: {str(json_body)[:50]}..."
                if form_body: payload_preview = f"| DATA: {str(form_body)[:50]}..."
                if params: payload_preview = f"| QUERY: {str(params)}"
                
                spoofed_ip = request_headers.get("X-Forwarded-For", "Unknown")
                proxy_log = f" [VIA PROXY: {request_proxies['http']}]" if request_proxies else " [DIRECT]"
                print(f"{Fore.GREEN}[TRAFFIC] {method} {url} [IP: {spoofed_ip}]{proxy_log} {payload_preview}{Style.RESET_ALL}")

            start_time = time.time()
            try:
                # Optimized Timeout for Proxies
                req_timeout = timeout or self.timeout
                if isinstance(req_timeout, (int, float)):
                    # (Connect Timeout, Read Timeout)
                    # Connect fast (3s) to discard dead proxies quickly.
                    # Read slow (20s) to allow WAF/Server to respond.
                    req_timeout = (3.0, 20.0)

                resp = self.session.request(
                    method=method.upper(),
                    url=url,
                    headers=request_headers,
                    params=params,
                    json=json_body,
                    data=form_body,
                    proxies=request_proxies,
                    timeout=req_timeout,
                    verify=False
                )
                elapsed = (time.time() - start_time) * 1000.0
                
                # RETRY LOGIC FOR 429 (Rate Limit) vs 403 (Forbidden)
                if resp.status_code == 429 and attempt < max_retries:
                    if self.verbose: 
                        print(f"{Fore.YELLOW}[!] 429 Rate Limit. Rotating Identity & Retrying...{Style.RESET_ALL}")
                    time.sleep(backoff)
                    backoff = min(backoff * 1.5, 2.0) 
                    continue 

                # For 403 (Forbidden): 
                if resp.status_code == 403:
                     # Only keep rotating if we haven't tried too many times (e.g. 50)
                     if attempt < 50:
                         if self.verbose:
                             print(f"{Fore.YELLOW}[!] 403 Forbidden (Proxy/IP Blocked). Rotating...{Style.RESET_ALL}")
                         time.sleep(0.2)
                         continue # FORCE ROTATION
                     else:
                         pass 

                # Best-effort JSON parsing
                json_data = None
                try:
                    json_data = resp.json()
                except ValueError:
                    pass

                if self.verbose:
                    status_color = Fore.GREEN if resp.status_code < 400 else Fore.YELLOW if resp.status_code < 500 else Fore.RED
                    if resp.status_code != 429: 
                        display_url = url.split('?')[0] # Shorten URL
                        print(f"{status_color}[<] {resp.status_code} {resp.reason} ({elapsed:.0f}ms) | {display_url}{Style.RESET_ALL}")

                return ResponseWrapper(
                    status_code=resp.status_code, 
                    headers=dict(resp.headers),
                    text=resp.text,
                    elapsed_ms=elapsed,
                    url=str(resp.url),
                    json_data=json_data
                )

            except requests.RequestException as e:
                # MARK PROXY AS DEAD (SILENTLY) - BUT DO NOT REMOVE FROM POOL
                # Removing them depletes the pool and causes fallback to local IP.
                # Just ignore and retry another random one.
                # if request_proxies:
                #    bad_proxy = request_proxies.get("http")
                #    with self.proxy_lock:
                #        if bad_proxy in self.proxies:
                #            self.proxies.remove(bad_proxy)
                
                # If we have retries left, continue
                if attempt < max_retries:
                    # Very fast retry
                    continue
                
                # STOP. NO DIRECT FALLBACK.
                # If we exhausted 200 retries and couldn't connect, we FAIL.
                # We do NOT compromise the user's IP address.
                raise ConnectionError(f"Max retries exited. All proxies failed.")

            except Exception as e:
                # Catch-all for other errors to prevent crashes
                if attempt < max_retries:
                    continue
                raise ConnectionError(f"Max retries exited. Error: {e}")
