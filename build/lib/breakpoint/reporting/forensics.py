import json
import time
import os
import threading

class ForensicLogger:
    def __init__(self, filepath="forensics_log.jsonl", verbose=False):
        self.filepath = filepath
        self.verbose = verbose
        self.lock = threading.Lock()
        
        # Clear old log, but careful with concurrency if multiple engines start
        # Only clear if it's the first init? Hard to know.
        # We'll just append.
        pass
            
    def log_request(self, method, url, req_headers, req_body, resp):
        # resp can be requests.Response OR ResponseWrapper
        
        status_code = 0
        response_time = 0
        
        if hasattr(resp, 'status_code'):
            status_code = resp.status_code
        
        # Handle elapsed
        if hasattr(resp, 'elapsed_ms'): # ResponseWrapper
             response_time = resp.elapsed_ms
        elif hasattr(resp, 'elapsed'): # requests.Response
             response_time = resp.elapsed.total_seconds() * 1000.0
             
        entry = {
            "timestamp": time.time(),
            "method": method,
            "url": url,
            "request_headers": dict(req_headers) if req_headers else {},
            "request_body": str(req_body)[:500] if req_body else "",
            "status_code": status_code,
            "response_time_ms": response_time
        }
        
        # Real-time verbose output
        if self.verbose:
            with self.lock:
                try:
                    from colorama import Fore, Style, init
                    init(autoreset=True)
                    # We might duplicate output if HttpClient also prints?
                    # HttpClient prints [TRAFFIC]. This prints [TRAFFIC] too?
                    # Engine passes verbose=True to both.
                    # Let's reduce noise here if HttpClient is doing the heavy lifting.
                    # But legacy checks don't use HttpClient.
                    # So we keep it.
                    pass 
                except ImportError:
                    pass
        
        try:
            with self.lock:
                with open(self.filepath, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
        except Exception:
            pass # Never crash on logging
