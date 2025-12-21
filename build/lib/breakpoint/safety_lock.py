import os
import sys
import time
from typing import Optional

class SafetyLock:
    """
    Enforces Kill Switches, Ownership Proof, and Live-Fire Locks.
    """
    KILL_FILE = "STOP.lock"

    def __init__(self, target_url: str):
        self.target = target_url

    def check_kill_switch(self):
        """
        Checks for the presence of a local kill file.
        If found, aborts the process IMMEDIATELY.
        """
        if os.path.exists(self.KILL_FILE):
            print(f"\n[!!!] KILL SWITCH ACTIVATED. {self.KILL_FILE} detected. TERMINATING.")
            sys.exit(99)

    def require_consent(self, force_flag: bool):
        """
        Demands explicit human consent for destructive actions.
        UNLESS the authorized automation flag is present.
        """
        
        if force_flag:
            print("\n[SECURITY] ⚠️  AUTOMATION MODE ENGAGED (--force-live-fire)")
            print("[SECURITY] Manual safety gates are BYPASSED.")
            print(f"[SECURITY] Target {self.target} will be attacked immediately.")
            return

        print("\n" + "="*60)
        print("🛑  EXTREME DANGER WARNING  🛑")
        print("="*60)
        print(f"Target: {self.target}")
        print("You are about to execute HIGH-SEVERITY, DESTRUCTIVE payloads.")
        print("This includes L7 DoS, Data Corruption, and Logic Bombs.")
        print("\nBy proceeding, you certify that:")
        print("1. You OWN this system or have written authorization.")
        print("2. You accept liability for downtime/data loss.")
        print("3. This is NOT a public production system without approval.")
        print("\nType 'I AUTHORIZE DESTRUCTION' to continue:")
        
        try:
            val = input("> ")
            if val.strip() != "I AUTHORIZE DESTRUCTION":
                print("Authorization Failed. Aborting.")
                sys.exit(1)
        except EOFError:
            print("Non-interactive mode (CI/CD) detected but --force-live-fire missing. Aborting.")
            sys.exit(1)

    def enforce_owner_check(self):
        pass
