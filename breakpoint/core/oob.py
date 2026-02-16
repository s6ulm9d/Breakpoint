
import threading
import http.server
import socketserver
import time
import uuid
import logging
from typing import Dict, Optional, List
from concurrent.futures import ThreadPoolExecutor

# Configure OOB Logger
logger = logging.getLogger("break_point.oob")
logger.setLevel(logging.INFO)

class OOBServer:
    """
    Robust Out-of-Band (OOB) Interaction Server.
    
    Features:
    - Lightweight HTTP Server (running in a background thread).
    - Unique Token Generation & Verification.
    - Zero False Positive Guarantee (Token existence = Proof).
    - Thread-safe storage of verified interactions.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(OOBServer, cls).__new__(cls)
        return cls._instance

    def __init__(self, port: int = 4444, bind_address: str = "0.0.0.0"):
        if hasattr(self, "_initialized"):
            return
            
        self.port = port
        self.bind_address = bind_address
        self.server: Optional[socketserver.TCPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.running = False
        
        # Interaction Store: {token: {"timestamp": float, "remote_ip": str, "method": str, "path": str, "source": "http"}}
        self.interactions: Dict[str, Dict] = {}
        self.interaction_lock = threading.Lock()
        
        self._initialized = True

    def start(self):
        """Starts the OOB HTTP Server in a background thread."""
        if self.running:
            return

        handler = self._create_handler()
        try:
            socketserver.TCPServer.allow_reuse_address = True
            self.server = socketserver.TCPServer((self.bind_address, self.port), handler)
            self.server.timeout = 1
            self.running = True
            
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            logger.info(f"OOB Server started on {self.bind_address}:{self.port}")
            print(f"[*] OOB Server listening on port {self.port}...")
        except Exception as e:
            logger.error(f"Failed to start OOB Server: {e}")
            print(f"[!] OOB Server failed to start: {e}")

    def stop(self):
        """Stops the OOB Server."""
        if self.running and self.server:
            self.running = False
            self.server.shutdown()
            self.server.server_close()
            if self.server_thread:
                self.server_thread.join()
            logger.info("OOB Server stopped.")

    def generate_payload(self, context: str = "generic") -> Dict[str, str]:
        """
        Generates a unique OOB payload and token.
        
        Returns:
            Dict: {"token": str, "url": str, "domain": str}
        """
        token = f"brk_{uuid.uuid4().hex[:8]}"
        # In a real deployed scenario, 'domain' would be a configured public domain.
        # For local/lab testing, it points to the local listener.
        
        # Detect if we should use localhost or an external IP? 
        # For now, we return the listener address.
        host = "127.0.0.1" if self.bind_address == "0.0.0.0" else self.bind_address
        url = f"http://{host}:{self.port}/{token}/{context}"
        
        return {
            "token": token,
            "url": url,
            "dnstoken": f"{token}.oob.breakpoint.local" # Placeholder for DNS if we had a DNS server
        }

    def verify(self, token: str, timeout: int = 0) -> bool:
        """
        Checks if a specific token has been triggered.
        
        Args:
            token: The unique token to check.
            timeout: Optional wait time in seconds (polling).
            
        Returns:
            True if interaction received, False otherwise.
        """
        start = time.time()
        while True:
            with self.interaction_lock:
                if token in self.interactions:
                    return True
            
            if time.time() - start >= timeout:
                break
            time.sleep(0.5)
            
        return False

    def get_interaction(self, token: str) -> Optional[Dict]:
        with self.interaction_lock:
            return self.interactions.get(token)

    def _record_interaction(self, token: str, data: Dict):
        with self.interaction_lock:
            if token not in self.interactions:
                self.interactions[token] = data
                logger.info(f"OOB Interaction captured for token: {token}")

    def _create_handler(self):
        oob_instance = self
        
        class OOBRequestHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass # Silence default logging
                
            def do_GET(self):
                self._handle_request("GET")
                
            def do_POST(self):
                self._handle_request("POST")
                
            def do_PUT(self):
                self._handle_request("PUT")
            
            def _handle_request(self, method):
                # Format: /<token>/<optional_context>
                path_parts = self.path.strip("/").split("/")
                if len(path_parts) >= 1:
                    token = path_parts[0]
                    # Simple validation: tokens start with brk_
                    if token.startswith("brk_"):
                        oob_instance._record_interaction(token, {
                            "timestamp": time.time(),
                            "remote_ip": self.client_address[0],
                            "method": method,
                            "path": self.path,
                            "user_agent": self.headers.get("User-Agent", "Unknown"),
                            "source": "http"
                        })
                
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")
                
        return OOBRequestHandler

    def _run_server(self):
        """Internal loop for the server thread."""
        if not self.server: return
        try:
            self.server.serve_forever()
        except Exception:
            pass
