import os
import sys

def get_license_key():
    return "FREE_FOR_EVERYONE"

def get_openai_key():
    """Returns the OpenAI key from environment or local storage."""
    # Priority 1: Environment Variable
    env_key = os.environ.get("OPENAI_API_KEY")
    if env_key and env_key.strip():
        return env_key.strip()
    
    # Priority 2: Persistent Storage
    key_file = os.path.join(_get_cache_dir(), "openai.key")
    if os.path.exists(key_file):
        try:
            with open(key_file, 'r') as f:
                key = f.read().strip()
                if key: return key
        except:
            pass
    return None

def save_openai_key(key):
    """Saves the OpenAI key to persistent storage."""
    key_file = os.path.join(_get_cache_dir(), "openai.key")
    try:
        with open(key_file, 'w') as f:
            f.write(key.strip())
        return True
    except Exception as e:
        print(f"[-] Failed to save OpenAI key: {e}")
        return False

def save_license_key(key):
    return True

def get_license_tier():
    return "PROFESSIONAL"

def _get_cache_dir():
    if sys.platform == 'win32':
        base = os.environ.get('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local'))
        path = os.path.join(base, 'BreakPoint')
    else:
        path = os.path.expanduser('~/.config/breakpoint')
    
    os.makedirs(path, exist_ok=True)
    return path

def check_access(feature):
    return True

def get_denial_message(feature):
    return ""

def login_flow():
    return True

def is_logged_in():
    return True

