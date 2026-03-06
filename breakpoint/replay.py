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

    def record_attack(self, module: str, endpoint: str, method: str, attack_type: str = "unknown", params: Optional[Dict] = None, json_body: Optional[Dict] = None, form_body: Any = None, payload: Optional[str] = None):
        """Records a single attack step."""
        entry = {
            "module": module,
            "endpoint": endpoint,
            "method": method,
            "attack_type": attack_type,
            "params": params,
            "json_body": json_body,
            "form_body": form_body,
            "payload": payload,
            "timestamp": datetime.datetime.now().isoformat()
        }
        self.current_session.append(entry)

    def save_session(self, results: Optional[List[Any]] = None):
        """Saves the current session to a timestamped JSON file."""
        if not self.current_session:
            return None

        from dataclasses import asdict
        timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        filename = f"{timestamp}.json"
        filepath = os.path.join(self.session_dir, filename)
        
        data = {
            "target": self.target_url,
            "timestamp": datetime.datetime.now().isoformat(),
            "attacks": self.current_session,
            "results": [asdict(r) if hasattr(r, '__dataclass_fields__') else r for r in (results or [])]
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

        except Exception as e:
            print(f"{Fore.RED}[REPLAY ERROR] Failed to load session: {e}{Style.RESET_ALL}")
            return None
