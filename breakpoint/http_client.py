import time
import requests
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass, field

@dataclass
class ResponseWrapper:
    status_code: int
    headers: Dict[str, str]
    text: str
    elapsed_ms: float
    json_data: Optional[Any] = None
    
    @property
    def is_error(self):
        return self.status_code >= 500

    @property
    def is_client_error(self):
        return 400 <= self.status_code < 500

class HttpClient:
    def __init__(self, base_url: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def send(self, method: str, target: str, *, 
             headers: Optional[Dict[str, str]] = None, 
             params: Optional[Dict[str, Any]] = None, 
             json_body: Optional[Any] = None, 
             form_body: Optional[Dict[str, Any]] = None) -> ResponseWrapper:
        
        url = target if target.startswith("http") else f"{self.base_url}/{target.lstrip('/')}"
        
        start_time = time.time()
        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                json=json_body,
                data=form_body,
                timeout=self.timeout
            )
            elapsed = (time.time() - start_time) * 1000.0
            
            # Best-effort JSON parsing
            json_data = None
            try:
                json_data = resp.json()
            except ValueError:
                pass

            return ResponseWrapper(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text,
                elapsed_ms=elapsed,
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
                json_data={"error": str(e)}
            )
