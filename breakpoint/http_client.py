import time
import requests
import random
import threading
import os
import urllib.parse
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
    text: str
    elapsed_ms: float
    url: str
    json_data: Optional[Any] = None
    request_dump: str = ""
    response_dump: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    
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
    _dead_proxies = set()
    _proxy_lock = threading.Lock()
    _print_lock = threading.Lock()
    _proxies_loaded = False
    _init_notified = False
    _localhost_notified = False
    _last_recycle_log = 0.0

    @staticmethod
    def _is_internet_available() -> bool:
        """Fast check for local internet connectivity."""
        try:
            import socket
            # Try a reliable public DNS IP on port 53 or 80 (TCP)
            # Cloudflare (1.1.1.1) or Google (8.8.8.8)
            with socket.create_connection(("1.1.1.1", 53), timeout=1.5):
                return True
        except:
            try:
                import socket
                with socket.create_connection(("8.8.8.8", 53), timeout=1.5):
                    return True
            except:
                return False

    def __init__(self, base_url: str, timeout: float = 30.0, verbose: bool = False, headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url.rstrip("/")
        # Validate threading availability
        try:
            import threading
            # print(f"DEBUG: Threading module: {threading}")
        except ImportError:
            print("CRITICAL: Threading module missing in send() scope!")
        self.timeout = timeout
        self.verbose = verbose
        self.silence_404s = False # Used by engine to suppress spam in aggressive modes
        self.global_headers = headers or {}
        self.verify = False # Default to False for security testing
        self.session = requests.Session()
        
        # High-Concurrency Adapter
        adapter = requests.adapters.HTTPAdapter(pool_connections=1000, pool_maxsize=1000)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Robust Localhost Detection
        self._is_localhost = any(x in self.base_url.lower() for x in ["localhost", "127.0.0.1", "0.0.0.0"])
        
        # Unique Canary for Log Verification
        self.canary_id = str(uuid.uuid4())[:8]
        
        # Load proxies once
        if not HttpClient._proxies_loaded:
            self._load_proxies()

        # Adaptive Throttling
        self._current_delay = 0.0
        self._throttle_lock = threading.Lock()
        
        # PERSISTENT SESSION for State Management
        # We already initialized self.session above, but let's ensure headers are applied
        self.session.headers.update(self.global_headers)
        if not self.verify:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        # 3. Scope Enforcement
        self.scope_domain = urllib.parse.urlparse(base_url).netloc
        self.whitelist = {self.scope_domain, "127.0.0.1", "localhost"}

    def _is_in_scope(self, url: str) -> bool:
        """Verifies if the target URL is within the authorized scan scope."""
        parsed = urllib.parse.urlparse(url)
        return not parsed.netloc or parsed.netloc in self.whitelist

    def login(self, login_url: str, credentials: Dict[str, str]) -> bool:
        """
        Performs a POST login to establish a session.
        Auto-extracts CSRF tokens if found in the login page first.
        """
        try:
            # 1. Fetch login page to get CSRF tokens (Baseline)
            get_resp = self.send("GET", login_url)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(get_resp.text, 'html.parser')
            csrf_token = None
            csrf_input = soup.find('input', attrs={'name': re.compile(r'csrf', re.I)})
            if csrf_input:
                csrf_token = csrf_input.get('value')
                credentials[csrf_input.get('name')] = csrf_token
            
            # 2. Perform POST login
            post_resp = self.send("POST", login_url, json_body=credentials if "json" in get_resp.headers.get("Content-Type", "").lower() else None, form_body=urllib.parse.urlencode(credentials) if "json" not in get_resp.headers.get("Content-Type", "").lower() else None)
            
            if post_resp.status_code in [200, 302]:
                print(f"{Fore.GREEN}[*] Login Successful! Session established.{Style.RESET_ALL}")
                return True
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Login Failed: {e}{Style.RESET_ALL}")
            return False
        
        if self.verbose:
            with HttpClient._proxy_lock:
                if not HttpClient._init_notified:
                    mode = "ELITE PROXY" if HttpClient._proxies else "DIRECT"
                    print(f"[*] HttpClient initialized ({mode} MODE). Traffic Tag ID Sync: {self.canary_id}")
                    HttpClient._init_notified = True

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
                "data/proxies.txt"
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

    _soft_404_signature: Optional[Dict[str, Any]] = None
    _soft_404_checked = False
    _soft_404_lock = threading.Lock()

    def detect_soft_404(self):
        """Discovers if the target uses 'Soft 404' (200 OK for non-existent pages)."""
        if HttpClient._soft_404_checked:
            return

        with HttpClient._soft_404_lock:
            if HttpClient._soft_404_checked:
                return

            random_path = f"/bp-canary-{uuid.uuid4().hex[:8]}"
            try:
                # We use send() with is_canary=True to avoid recursive call to is_soft_404
                resp = self.send("GET", random_path, is_canary=True)
                if resp.status_code == 200:
                    # Look for 'page not found' style keywords to confirm it's an error page
                    not_found_keywords = ["not found", "404", "error", "doesn't exist", "cannot find"]
                    text_lower = resp.text.lower()
                    has_kw = any(kw in text_lower for kw in not_found_keywords)
                    
                    HttpClient._soft_404_signature = {
                        "status_code": 200,
                        "length": len(resp.text),
                        "title": self._extract_title(resp.text),
                        "has_keywords": has_kw
                    }
                    if self.verbose:
                        with HttpClient._print_lock:
                            print(f"{Fore.MAGENTA}[*] Soft 404 Calibration Complete. Error Page: {len(resp.text)} bytes | Title: '{HttpClient._soft_404_signature['title']}'{Style.RESET_ALL}")
                else:
                    HttpClient._soft_404_signature = None
            except:
                HttpClient._soft_404_signature = None
            HttpClient._soft_404_checked = True

    def is_soft_404(self, resp: ResponseWrapper) -> bool:
        """Checks if a response matches the detected Soft 404 signature."""
        if not HttpClient._soft_404_checked:
            return False # Skip if not checked yet to avoid race/recursion
        
        if not HttpClient._soft_404_signature:
            return False
            
        if resp.status_code == HttpClient._soft_404_signature["status_code"]:
            len_diff = abs(len(resp.text) - HttpClient._soft_404_signature["length"])
            # Tight match for soft 404: 5% length variance OR same title
            if len_diff < (HttpClient._soft_404_signature["length"] * 0.05) or len_diff < 50:
                title = self._extract_title(resp.text)
                if title == HttpClient._soft_404_signature["title"]:
                    return True
        return False

    def _extract_title(self, html: str) -> str:
        import re
        try:
            match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
            return match.group(1).strip() if match else ""
        except:
            return ""


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
        }
        
        # Randomize which ones we send to avoid static fingerprint
        subset = dict(random.sample(list(spoof_headers.items()), k=random.randint(3, 7)))
        
        # Core Evasion - LOOK LIKE A REAL BROWSER
        subset.update({
            "User-Agent": random.choice(USER_AGENTS),
            "DNT": "1",
            "Sec-Ch-Ua-Mobile": "?0",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Accept-Encoding": "gzip, deflate, br", 
            "Cache-Control": "max-age=0",
            "Sec-Ch-Ua": '"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"',
            "Sec-Ch-Ua-Platform": '"Windows"',
        })
        
        return subset

    def send(self, method: str, path: str, params: Dict = None, json_body: Dict = None, form_body: Any = None, headers: Dict = None, timeout: int = None, is_canary: bool = False, allow_redirects: bool = True) -> ResponseWrapper:
        """Sends a request with retry logic, evasion headers, and scope enforcement."""
        url = urllib.parse.urljoin(self.base_url, path)
        
        # SCOPE GUARD
        if not self._is_in_scope(url):
             print(f"{Fore.RED}[!] SCOPE VIOLATION: Blocked request to {url}{Style.RESET_ALL}")
             return ResponseWrapper(0, {}, "SCOPE_VIOLATION", 0, url)

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

        # Retry Loop logic: Localhost should fail fast and not retry 200 times.
        if self._is_localhost:
            max_retries = 5 
        else:
            max_retries = 200 # MAX PERSISTENCE for remote targets
            
        errors = []
        
        for attempt in range(max_retries):
            # 0. Adaptive Throttling Sleep
            with self._throttle_lock:
                if self._current_delay > 0:
                    time.sleep(self._current_delay)

            # 1. Build Headers
            req_headers = base_headers.copy()
            req_headers.update(self._get_bypass_headers())
            
            if "Referer" not in (headers or {}):
                req_headers["Referer"] = random.choice(REFERERS)
            
            if self.global_headers: req_headers.update(self.global_headers)
            if headers: req_headers.update(headers)
            
            # 2. Smart Proxy Rotation
            proxy_url = None
            proxies = None
            
            if self._is_localhost:
                # Silenced redundant logging for localhost
                if self.verbose and not HttpClient._localhost_notified:
                    with HttpClient._proxy_lock:
                        if not HttpClient._localhost_notified:
                            print(f"{Fore.CYAN}[*] Localhost detected. Bypassing proxies for direct connection.{Style.RESET_ALL}")
                            HttpClient._localhost_notified = True
            elif HttpClient._proxies:
                with HttpClient._proxy_lock:
                    # Filter out known dead proxies
                    valid_proxies = [p for p in HttpClient._proxies if p not in HttpClient._dead_proxies]
                    
                    # If we exhausted valid proxies, reset the pool
                    if not valid_proxies:
                        now = time.time()
                        if self.verbose and (now - HttpClient._last_recycle_log > 10.0): 
                            if not HttpClient._is_internet_available():
                                print(f"{Fore.RED}[!] WARNING: CONNECTION LOST. Local network or ISP is failing. Proxies are unresponsive.{Style.RESET_ALL}")
                            else:
                                print(f"{Fore.MAGENTA}[*] Proxy pool exhausted/cleaned. Recycling all {len(HttpClient._proxies)} proxies.{Style.RESET_ALL}")
                            HttpClient._last_recycle_log = now
                        HttpClient._dead_proxies.clear()
                        valid_proxies = list(HttpClient._proxies)

                if valid_proxies:
                    proxy_url = random.choice(valid_proxies)
                    proxies = {"http": proxy_url, "https": proxy_url}

            # 3. Request
            try:
                # Dynamic Read Timeout
                if self._is_localhost:
                    # LOCALHOST: Ultra fast timeouts (1s connect, 15s read)
                    connect_timeout = 1.0
                    read_timeout = 15.0
                else:
                    # REMOTE: Robust but resilient (5s connect, 30s read)
                    connect_timeout = 5.0 if proxy_url else 3.0
                    read_timeout = 30.0

                req_timeout = timeout if timeout is not None else (connect_timeout, read_timeout)

                # Perform the actual request using the persistent session
                resp = self.session.request(
                    method.upper(),
                    url,
                    params=params,
                    data=form_body,
                    json=json_body,
                    headers=req_headers,
                    timeout=req_timeout, # Use req_timeout which incorporates dynamic logic
                    verify=self.verify,
                    proxies=proxies, # Ensure proxies are still used
                    allow_redirects=allow_redirects
                )

                # Check for rate limiting or WAF block
                if resp.status_code in [403, 429]:
                    if self.verbose:
                        reason = "WAF Block" if resp.status_code == 403 else "Rate Limit"
                        # Only print every 50 attempts to avoid log spam, and use \r to keep it clean
                        if (attempt + 1) % 50 == 0:
                            with HttpClient._print_lock:
                                print(f"{Fore.YELLOW}[!] Connection Resistance detected ({reason}). Retrying... (Attempt {attempt+1}/{max_retries}){Style.RESET_ALL}", end='\r')
                    
                    # Incremental Backoff with Jitter
                    backoff = min(1.0, 0.1 * (attempt // 10 + 1))
                    if not self._is_localhost:
                        time.sleep(backoff + random.uniform(0.1, 0.3))
                    else:
                        time.sleep(0.05)
                    continue

                # Parse Success
                json_data = None
                try: json_data = resp.json()
                except: pass

                if self.verbose and not is_canary:
                    sc = resp.status_code
                    
                    # LOG SUPPRESSION: Silence 404s/405s in traffic logs to avoid terminal spam
                    # These are standard in fuzzer-style scanning and just clutter the UI.
                    if sc in [404, 405]:
                        pass 
                    else:
                        is_s404 = self.is_soft_404(ResponseWrapper(
                            status_code=resp.status_code, 
                            text=resp.text,
                            elapsed_ms=resp.elapsed.total_seconds()*1000,
                            url=str(resp.url),
                            headers=dict(resp.headers)
                        ))
                        
                        color = Fore.GREEN if sc < 400 else Fore.YELLOW if sc < 500 else Fore.RED
                        display_sc = str(sc)
                        if is_s404:
                            color = Fore.YELLOW
                            display_sc = f"{sc} (SOFT-404)"

                        with HttpClient._print_lock:
                            print(f"{color}[TRAFFIC] [<] {display_sc} {resp.reason} ({resp.elapsed.total_seconds()*1000:.0f}ms) | {url.split('?')[0]}{Style.RESET_ALL}")

                # Adaptive Throttling Control
                if resp.status_code == 429:
                    with self._throttle_lock:
                        # Increase delay exponentially up to 2 seconds
                        self._current_delay = min(self._current_delay + 0.5, 2.0)
                        if self.verbose:
                             print(f"{Fore.YELLOW}[!] RATE LIMITED (429). Throttling: {self._current_delay}s delay.{Style.RESET_ALL}")
                    time.sleep(self._current_delay)
                    continue
                elif resp.status_code == 200 and self._current_delay > 0:
                    with self._throttle_lock:
                         # Slowly decrease delay on success
                         self._current_delay = max(0, self._current_delay - 0.1)

                # 5. Build Dumps for Evidence
                req_dump = f"{method.upper()} {url}\n" + "\n".join(f"{k}: {v}" for k, v in req_headers.items())
                if json_body: req_dump += f"\n\n{json.dumps(json_body, indent=2)}"
                elif form_body: req_dump += f"\n\n{form_body}"

                # Limit response body in dump to avoid excessively large logs
                res_dump = f"HTTP/1.1 {resp.status_code} {resp.reason}\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) + f"\n\n{resp.text[:500]}{'...' if len(resp.text) > 500 else ''}"

                return ResponseWrapper(
                    status_code=resp.status_code, 
                    text=resp.text,
                    elapsed_ms=resp.elapsed.total_seconds() * 1000.0,
                    url=str(resp.url),
                    json_data=json_data,
                    request_dump=req_dump,
                    response_dump=res_dump,
                    headers=dict(resp.headers)
                )

            except Exception as e:
                # Mark proxy as dead if it failed connection
                if proxy_url:
                    with HttpClient._proxy_lock:
                        HttpClient._dead_proxies.add(proxy_url)

                errors.append(str(e))
                if attempt < max_retries - 1:
                    continue # Try again immediately
        
        last_err = errors[-1] if errors else 'Unknown'
        
        # Localhost crashes are different from remote blocks
        if self._is_localhost:
            msg = f"LOCALHOST ERROR: Target at {self.base_url} is unresponsive or crashed. Max retries (5) reached. Error: {last_err}"
        else:
            msg = f"Network Blocked: Max retries (200) exited. Firewall or ISP blocking traffic. Last error: {last_err}"
            if not HttpClient._is_internet_available():
                msg = f"CONNECTION LOST: Internet appears to be down on this host. Entire scan is stalled. Last error: {last_err}"
             
        raise ConnectionError(msg)
