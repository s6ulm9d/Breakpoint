import os
import sys
import requests
import json
import time
import webbrowser

# Enterprise Validation Engine (Synced with Breakpoint-Web)
VALIDATION_ENDPOINT = "https://breakpoint-web-one.vercel.app/v1/validate"

def get_license_key():
    """Returns the license key from environment or local storage."""
    # Priority 1: Environment Variable
    env_key = os.environ.get("BREAKPOINT_LICENSE_KEY")
    if env_key:
        return env_key
    
    # Priority 2: Persistent Storage
    key_file = os.path.join(_get_cache_dir(), "license.key")
    if os.path.exists(key_file):
        try:
            with open(key_file, 'r') as f:
                return f.read().strip()
        except:
            pass
    return None

def get_openai_key():
    """Returns the OpenAI key from environment or local storage."""
    # Priority 1: Environment Variable
    env_key = os.environ.get("OPENAI_API_KEY")
    if env_key:
        return env_key
    
    # Priority 2: Persistent Storage
    key_file = os.path.join(_get_cache_dir(), "openai.key")
    if os.path.exists(key_file):
        try:
            with open(key_file, 'r') as f:
                return f.read().strip()
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
    """Saves the license key to persistent storage."""
    key_file = os.path.join(_get_cache_dir(), "license.key")
    try:
        with open(key_file, 'w') as f:
            f.write(key.strip())
        return True
    except Exception as e:
        print(f"[-] Failed to save license key: {e}")
        return False

def get_license_tier():
    """
    Server-verified runtime check.
    Returns: 'FREE' or 'PREMIUM'
    """
    key = get_license_key()
    if not key:
        return "FREE"

    # Minimal cache logic (expires every 1 hour)
    cache_dir = _get_cache_dir()
    cache_file = os.path.join(cache_dir, "license_cache.json")
    
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached = json.load(f)
                if time.time() - cached.get("timestamp", 0) < 3600:
                    if cached.get("key") == key:
                        return cached.get("tier", "FREE")
        except:
            pass

    # Remote Validation
    try:
        resp = requests.get(
            VALIDATION_ENDPOINT,
            headers={"Authorization": f"Bearer {key}"},
            timeout=10
        )
        
        # Ensure we got a successful response
        if resp.status_code == 200:
            try:
                data = resp.json()
                tier = data.get("tier", "FREE")
                
                # Update Cache
                try:
                    with open(cache_file, 'w') as f:
                        json.dump({"key": key, "tier": tier, "timestamp": time.time()}, f)
                except:
                    pass
                    
                return tier
            except json.JSONDecodeError:
                # Server returned 200 but not JSON (likely a static page/rewrite issue)
                pass
    except Exception:
        # Fails safely to FREE if server is unreachable
        pass

    return "FREE"

def _get_cache_dir():
    if sys.platform == 'win32':
        base = os.environ.get('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local'))
        path = os.path.join(base, 'BreakPoint')
    else:
        path = os.path.expanduser('~/.config/breakpoint')
    
    os.makedirs(path, exist_ok=True)
    return path

def check_access(feature):
    """
    Hard-gate for premium features.
    Features requiring PREMIUM: 'aggressive', 'production'
    """
    tier = get_license_tier()
    if tier == "PREMIUM":
        return True
    
    # Denial logic
    if feature in ['aggressive', 'production']:
        return False
    
    return True

def get_denial_message(feature):
    msg = f"\n[!] ACCESS DENIED: '{feature}' is a premium feature."
    msg += "\n[!] Source is public, but execution requires a server-verified subscription."
    
    key = get_license_key()
    if key:
        msg += f"\n[!] A key was detected but it failed validation with '{VALIDATION_ENDPOINT}'."
    else:
        msg += "\n[!] To enable, run 'breakpoint --login' to connect your account."
        
    msg += "\n[!] Visit https://breakpoint-web-one.vercel.app to subscribe."
    return msg

def login_flow():
    """Interactive login flow for the CLI."""
    print("\n" + "="*50)
    print("      BREAKPOINT // ACCOUNT CONNECTION")
    print("="*50)
    print("\n[*] Opening registration website...")
    webbrowser.open("https://breakpoint-web-one.vercel.app/registration")
    
    print("\n[!] Please log in to the website and copy your License Key.")
    print("[!] Website: https://breakpoint-web-one.vercel.app")
    
    try:
        key = input("\n[?] Enter License Key: ").strip()
        if not key:
            print("[-] Error: Key cannot be empty.")
            return False
            
        print("[*] Validating with server...")
        # Force a fresh validation using direct API endpoint
        resp = requests.get(
            VALIDATION_ENDPOINT,
            headers={"Authorization": f"Bearer {key}"},
            timeout=10
        )
        
        if resp.status_code == 200:
            content_type = resp.headers.get("Content-Type", "")
            if "application/json" not in content_type:
                print(f"[-] Error: Server returned success but unexpected format ({content_type.split(';')[0]})")
                if "<!doctype html" in resp.text.lower():
                    print(f"[-] Detail: Target endpoint is returning an HTML page. This is usually due to a routing error on the server (SPA catch-all).")
                return False
                
            try:
                data = resp.json()
                tier = data.get("tier", "FREE")
                ltype = data.get("type", tier)
                print(f"[+] Success! Account connected. Tier: {ltype}")
                save_license_key(key)
                
                # Clear cache for fresh start
                cache_file = os.path.join(_get_cache_dir(), "license_cache.json")
                if os.path.exists(cache_file):
                    os.remove(cache_file)
                    
                return True
            except json.JSONDecodeError:
                print(f"[-] Error: Server returned success but truncated or invalid JSON.")
                return False
        else:
            print(f"[-] Validation failed: Status {resp.status_code}")
            try:
                 # Try to parse error message if JSON
                err_data = resp.json()
                print(f"[-] Server message: {err_data.get('error', 'Unknown error')}")
            except:
                pass
            return False
            
    except KeyboardInterrupt:
        print("\n[!] Login cancelled.")
        return False
    except Exception as e:
        print(f"[-] Login error: {e}")
        return False

def is_logged_in():
    """Simple check if a license key exists locally or in env."""
    return get_license_key() is not None
