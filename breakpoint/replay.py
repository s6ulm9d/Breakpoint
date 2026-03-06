import os
import json
import datetime
from typing import List, Dict, Any, Optional
from colorama import Fore, Style

class ReplayManager:
    """Handles recording and replaying of attack sessions."""
    
    def __init__(self, session_dir: str = ".scan_sessions"):
        self.session_dir = session_dir
        self.current_session: List[Dict[str, Any]] = []
        self.target_url: Optional[str] = None
        os.makedirs(self.session_dir, exist_ok=True)

    def set_target(self, url: str):
        self.target_url = url

    def record_attack(self, module: str, endpoint: str, method: str, params: Optional[Dict] = None, json_body: Optional[Dict] = None, form_body: Any = None, payload: Optional[str] = None):
        """Records a single attack step."""
        entry = {
            "module": module,
            "endpoint": endpoint,
            "method": method,
            "params": params,
            "json_body": json_body,
            "form_body": form_body,
            "payload": payload,
            "timestamp": datetime.datetime.now().isoformat()
        }
        self.current_session.append(entry)

    def save_session(self):
        """Saves the current session to a timestamped JSON file."""
        if not self.current_session:
            return None

        timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        filename = f"{timestamp}.json"
        filepath = os.path.join(self.session_dir, filename)
        
        data = {
            "target": self.target_url,
            "timestamp": datetime.datetime.now().isoformat(),
            "attacks": self.current_session
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Update 'last.json' symlink-style pointer
            last_path = os.path.join(self.session_dir, "last.json")
            with open(last_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            return filepath
        except Exception as e:
            print(f"{Fore.RED}[REPLAY ERROR] Failed to save session: {e}{Style.RESET_ALL}")
            return None

    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Loads a session file by ID (timestamp) or 'last'."""
        if session_id == "last":
            filepath = os.path.join(self.session_dir, "last.json")
        else:
            # Check if it's a full path or just a filename
            if not session_id.endswith(".json"):
                session_id += ".json"
            filepath = os.path.join(self.session_dir, session_id)
            
        if not os.path.exists(filepath):
            print(f"{Fore.RED}[REPLAY ERROR] Session file not found: {filepath}{Style.RESET_ALL}")
            return None
            
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"{Fore.RED}[REPLAY ERROR] Failed to load session: {e}{Style.RESET_ALL}")
            return None

    def run_replay(self, session_data: Dict[str, Any], verbose: bool = False):
        """Executes the replayed attacks."""
        target = session_data.get("target")
        attacks = session_data.get("attacks", [])
        
        print(f"{Fore.CYAN}[REPLAY MODE] Replaying previous attack session{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[REPLAY MODE] Target loaded from session: {target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[REPLAY MODE] Executing {len(attacks)} recorded attacks...{Style.RESET_ALL}")
        
        from .http_client import HttpClient
        client = HttpClient(target, verbose=verbose)
        
        for i, attack in enumerate(attacks):
            module = attack.get("module", "unknown")
            endpoint = attack.get("endpoint", "/")
            method = attack.get("method", "GET")
            params = attack.get("params")
            json_body = attack.get("json_body")
            form_body = attack.get("form_body")
            
            print(f"    {Fore.WHITE}[{i+1}/{len(attacks)}] Replaying {module} on {endpoint}...{Style.RESET_ALL}")
            
            try:
                # Direct call to HttpClient.send to bypass discovery/AI logic
                client.send(
                    method=method,
                    path=endpoint,
                    params=params,
                    json_body=json_body,
                    form_body=form_body
                )
            except Exception as e:
                print(f"    {Fore.RED}[!] Replay failed for attack {i+1}: {e}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] Replay session completed.{Style.RESET_ALL}")
