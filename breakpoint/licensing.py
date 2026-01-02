import os
import sys
import requests
import json
import time

# Runtime Validation Engine
# No hardcoded keys. No embedded credentials.
VALIDATION_ENDPOINT = "https://breakpoint-web-one.vercel.app/v1/validate"

def get_license_tier():
    """
    Server-verified runtime check.
    Returns: 'FREE' or 'PREMIUM'
    """
    key = os.environ.get("BREAKPOINT_LICENSE_KEY")
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
        # Note: In a real environment, this would use a secure POST with machine fingerprint
        resp = requests.get(
            VALIDATION_ENDPOINT,
            headers={"Authorization": f"Bearer {key}"},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            tier = data.get("tier", "FREE")
            
            # Update Cache
            try:
                with open(cache_file, 'w') as f:
                    json.dump({"key": key, "tier": tier, "timestamp": time.time()}, f)
            except:
                pass
                
            return tier
    except:
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
    
    key = os.environ.get("BREAKPOINT_LICENSE_KEY")
    if key:
        msg += f"\n[!] A key was detected in BREAKPOINT_LICENSE_KEY but it failed validation with '{VALIDATION_ENDPOINT}'."
    else:
        msg += "\n[!] To enable, set the BREAKPOINT_LICENSE_KEY environment variable."
        
    msg += "\n[!] Visit https://breakpoint-web-one.vercel.app to subscribe."
    return msg
