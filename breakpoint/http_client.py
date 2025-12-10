import time
import requests
import random
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass, field

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

from colorama import Fore, Style

class HttpClient:
    def __init__(self, base_url: str, timeout: float = 1.0, verbose: bool = False):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        
        # OPTIMIZATION: High-Concurrency Connection Pooling
        # Prevents "stalling" by ensuring enough connections are kept open for threads
        adapter = requests.adapters.HTTPAdapter(pool_connections=200, pool_maxsize=200)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # mimic a real browser
        # Unique Canary for Log Verification
        import uuid
        self.canary_id = str(uuid.uuid4())[:8]
        
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "X-Breakpoint-ID": self.canary_id
        })
        
        if self.verbose:
            print(f"[*] HttpClient initialized. Traffic Tag: X-Breakpoint-ID: {self.canary_id}")

    def _jitter(self):
        """Adds a tiny random delay to avoid machine-like timing fingerprints"""
        # Reduced for aggressive speed requirements
        time.sleep(random.uniform(0.01, 0.05))

    def send(self, method: str, target: str, *, 
             headers: Optional[Dict[str, str]] = None, 
             params: Optional[Dict[str, Any]] = None, 
             json_body: Optional[Any] = None, 
             form_body: Optional[Dict[str, Any]] = None,
             timeout: Optional[float] = None) -> ResponseWrapper:
        
        url = target if target.startswith("http") else f"{self.base_url}/{target.lstrip('/')}"
        
        # Apply jitter
        self._jitter()
        
        # VERBOSE TRAFFIC LOG
        if self.verbose:
            payload_preview = ""
            if json_body: payload_preview = f"| JSON: {str(json_body)[:50]}..."
            if form_body: payload_preview = f"| DATA: {str(form_body)[:50]}..."
            if params: payload_preview = f"| QUERY: {str(params)}"
            print(f"{Fore.CYAN}[TRAFFIC] {method} {url} {payload_preview}{Style.RESET_ALL}")

        start_time = time.time()
        try:
            # Rotate UA per request for maximum evasion? 
            # Or keep session consistent? Real users keep session. 
            # But aggressive scanners might want rotation.
            # Let's keep session consistent for now to maintain cookies.
            
            resp = self.session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                json=json_body,
                data=form_body,
                timeout=timeout or self.timeout,
                verify=False # Ignore SSL errors for aggressive scanning
            )
            elapsed = (time.time() - start_time) * 1000.0
            
            # Best-effort JSON parsing
            json_data = None
            try:
                json_data = resp.json()
            except ValueError:
                pass

            if self.verbose:
                status_color = Fore.GREEN if resp.status_code < 400 else Fore.YELLOW if resp.status_code < 500 else Fore.RED
                print(f"{status_color}[<] {resp.status_code} {resp.reason} ({elapsed:.0f}ms){Style.RESET_ALL}")

            return ResponseWrapper(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text,
                elapsed_ms=elapsed,
                url=str(resp.url),
                json_data=json_data
            )

        except requests.RequestException as e:
            # Create a synthetic response for network errors so the engine doesn't crash hard
            elapsed = (time.time() - start_time) * 1000.0
            return ResponseWrapper(
                status_code=0, 
                headers={},
                text=str(e),
                elapsed_ms=elapsed,
                url=url,
                json_data={"error": str(e)}
            )
