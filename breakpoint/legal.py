import os
import sys
import hashlib
import platform
import json
import socket
import datetime
from pathlib import Path

EULA_TEXT = """
================================================================================
                        BREAKPOINT ENTERPRISE EULA
================================================================================

1. AUTHORIZED USE ONLY
   You explicitly agree that you will only use this software on systems for which
   you have written permission to test. Unauthorized use is illegal.

2. LIABILITY
   The authors and copyright holders are not liable for any damage, service
   outages, or data loss caused by this software. You assume full responsibility
   for all actions taken with this tool.

3. DESTRUCTIVE CAPABILITIES
   This software contains modules designed to stress, crash, or exploit
   vulnerabilities in target systems. Do not use in production environments
   without strict authorization and backup plans.

4. COMPLIANCE
   You agree to comply with all applicable local, state, and federal laws
   regarding cybersecurity testing and software usage.

5. CONSENT LOGGING
   Your acceptance of this EULA is logged locally with a machine fingerprint
   and timestamp to prove authorized intent.

6. ACCEPTABLE USE POLICY (AUP)
   - Do NOT use for illegal extortion or ransomware.
   - Do NOT use against critical infrastructure (Power, Water, Medical) 
     without government-level authorization.
   - Do NOT redistribute weaponized modules to unauthorized parties.

================================================================================
"""

def get_app_data_dir():
    """Returns platform-specific AppData path."""
    if sys.platform == 'win32':
        base = os.environ.get('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local'))
        path = os.path.join(base, 'BreakPoint')
    else:
        path = os.path.expanduser('~/.config/breakpoint')
    
    if not os.path.exists(path):
        try: os.makedirs(path)
        except: pass
    return path

def get_consent_file_path():
    return os.path.join(get_app_data_dir(), "eula_consent.json")

def get_fingerprint():
    """Generates a unique machine fingerprint."""
    try:
        data = [
            socket.gethostname(),
            platform.machine(),
            platform.processor(),
            platform.system(),
            os.environ.get('USERNAME', 'unknown')
        ]
        raw = "|".join(str(x) for x in data)
        return hashlib.sha256(raw.encode()).hexdigest()
    except:
        return "unknown_fingerprint"

def has_accepted_eula():
    """Checks if valid consent exists."""
    path = get_consent_file_path()
    if not os.path.exists(path):
        return False
    
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            return data.get("accepted", False) and data.get("version") == "1.0"
    except:
        return False

def accept_eula():
    """Records user consent."""
    path = get_consent_file_path()
    data = {
        "accepted": True,
        "version": "1.0",
        "timestamp": datetime.datetime.now().isoformat(),
        "fingerprint": get_fingerprint(),
        "user": os.environ.get('USERNAME', 'unknown'),
        "platform": platform.platform()
    }
    
    with open(path, 'w') as f:
        json.dump(data, f, indent=4)

def prompt_eula():
    """Interactive EULA prompt."""
    print(EULA_TEXT)
    print("To restrict unauthorized use, you must explicitly accept these terms.")
    print("Type 'AGREE' to accept and continue, or anything else to exit.")
    
    if hasattr(sys.stdin, 'isatty') and sys.stdin.isatty():
        choice = input("Response: ").strip()
    else:
        # If not comprehensive TTY, we can't accept valid consent.
        # But for automation/CI where maybe they can't type, we might need a flag.
        # For this requirement: "Explicit consent", we enforce TTY or explicit env var.
        if os.environ.get("BREAKPOINT_ACCEPT_EULA") == "AGREE":
            choice = "AGREE"
        else:
            choice = "NO"

    if choice == "AGREE":
        accept_eula()
        print("\n[+] EULA Accepted. Audit log updated.")
        return True
    else:
        print("\n[!] EULA Declined. Exiting.")
        return False
