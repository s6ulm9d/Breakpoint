import hashlib
import os
import json

import sys

def get_app_data_dir():
    if sys.platform == 'win32':
        base = os.environ.get('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local'))
        path = os.path.join(base, 'BreakPoint')
    else:
        path = os.path.expanduser('~/.config/breakpoint')
    
    if not os.path.exists(path):
        try: os.makedirs(path)
        except: pass
    return path

LICENSE_FILE = os.path.join(get_app_data_dir(), "license.json")

def validate_license_key(key):
    """
    Validates the license key format:
    Format: BRK-[TYPE]-[RANDOM]-[CHECKSUM]
    Example: BRK-ENT-X7A9-F3B2
    (This is a simple offline check for demonstration. Real enterprise apps use RSA signatures.)
    """
    try:
        parts = key.split('-')
        if len(parts) != 4:
            return False
        if parts[0] != "BRK":
            return False
        
        # Simple checksum logic: Last 2 chars of checksum must match hash of first 3 parts
        payload = f"{parts[0]}-{parts[1]}-{parts[2]}"
        calc_hash = hashlib.sha256(payload.encode()).hexdigest()[:4].upper()
        
        if parts[3] == calc_hash:
            return parts[1] # Return 'ENT' or 'STD'
        return False
    except:
        return False

def get_license_status():
    """
    Returns:
    - 'ENTERPRISE': Full unlocked features.
    - 'COMMUNITY': Restricted mode.
    """
    key = os.environ.get("BREAKPOINT_LICENSE_KEY")
    
    # Check local file if env var missing
    if not key and os.path.exists(LICENSE_FILE):
        try:
            with open(LICENSE_FILE, 'r') as f:
                data = json.load(f)
                key = data.get("key")
        except:
            pass

    if key:
        tier = validate_license_key(key)
        if tier == "ENT":
            return "ENTERPRISE"
        if tier == "PRO":
            return "PROFESSIONAL"
            
    return "COMMUNITY"

def save_license(key):
    if not validate_license_key(key):
        raise ValueError("Invalid License Key Format")
        
    with open(LICENSE_FILE, 'w') as f:
        json.dump({"key": key, "activated_at": "timestamp"}, f)
    return True
