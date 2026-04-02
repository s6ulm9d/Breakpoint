import os
import sys
import time
import hashlib
import ipaddress
import urllib.parse
import socket
import requests
from colorama import Fore, Style

class SafetyLock:
    """
    Enforces Kill Switches, Ownership Proof, and Live-Fire Locks.
    """
    KILL_FILE = "STOP.lock"

    def __init__(self, target_url: str):
        self.target = target_url
        self.parsed_url = urllib.parse.urlparse(self.target)
        self.domain = self.parsed_url.hostname or self.target
        # Generate a unique stable token per target domain
        self.token = "breakpoint-verify-" + hashlib.sha256(self.domain.encode()).hexdigest()[:16]

    def check_kill_switch(self):
        """
        Checks for the presence of a local kill file.
        If found, aborts the process IMMEDIATELY.
        """
        if os.path.exists(self.KILL_FILE):
            print(f"\n[!!!] KILL SWITCH ACTIVATED. {self.KILL_FILE} detected. TERMINATING.")
            sys.exit(99)

    def _is_local_or_internal(self) -> bool:
        """Determines if the target is localhost or an internal IP."""
        try:
            ip = socket.gethostbyname(self.domain)
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except:
            return False


    def _verify_well_known_file(self) -> bool:
        """Checks for the token at /.well-known/breakpoint-verify.txt"""
        url = urllib.parse.urljoin(self.target, "/.well-known/breakpoint-verify.txt")
        try:
            resp = requests.get(url, timeout=5, verify=False)
            if resp.status_code == 200 and self.token in resp.text:
                return True
        except:
            pass
        return False

    def enforce_owner_check(self, force_flag: bool = False):
        """
        Demands explicit verification of target ownership.
        """
        self.check_kill_switch()
        
        # Bypass for internal/local testing with a warning
        if self._is_local_or_internal():
            print(f"\n{Fore.YELLOW}[*] WARNING: Internal or Localhost Network Target Detected ({self.domain}).{Style.RESET_ALL}")
            print(" Skipping strict DNS/File verification checks.")
            return

        if force_flag:
            print(f"\n{Fore.RED}[SECURITY] [!] AUTOMATION MODE ENGAGED (--force-live-fire){Style.RESET_ALL}")
            print(f"{Fore.RED}[SECURITY] Target {self.target} will be attacked bypassing strict verification.{Style.RESET_ALL}")
            return

        print("\n" + "="*60)
        print(" [!] TARGET OWNERSHIP VERIFICATION REQUIRED [!] ")
        print("="*60)
        print(f"Target: {self.target}")
        print("Breakpoint is configured to prevent unauthorized scanning of external targets.")
        print("\nTo prove you own this target, please complete the following verification:")
        print(f"\n{Fore.CYAN}VERIFICATION METHOD: Well-Known File{Style.RESET_ALL}")
        print(f" Host a text file at:   {urllib.parse.urljoin(self.target, '/.well-known/breakpoint-verify.txt')}")
        print(f" Containing the Value:  {self.token}")
        
        print("\nChecking for verification...")
        max_attempts = 10
        for attempt in range(max_attempts):
            if self._verify_well_known_file():
                print(f"{Fore.GREEN}[+] Ownership Verification Successful! You may proceed.{Style.RESET_ALL}")
                return
            
            # Interactive prompt if verification fails
            print(f"\n{Fore.YELLOW}[!] Verification not found.{Style.RESET_ALL}")
            if not sys.stdin.isatty():
                print("Non-interactive mode detected. Exiting because verification failed.")
                sys.exit(1)
            
            val = input("Have you set up the verification? Type 'Y' to re-check, or 'N' to abort: ")
            if val.strip().upper() != 'Y':
                print("Aborting scan.")
                sys.exit(1)

        print(f"{Fore.RED}[!] Max verification attempts reached. Aborting.{Style.RESET_ALL}")
        sys.exit(1)

