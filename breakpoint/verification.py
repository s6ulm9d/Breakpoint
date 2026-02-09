import requests
import uuid
from urllib.parse import urlparse

VERIFICATION_FILENAME = "breakpoint-verification.txt"
EXPECTED_CONTENT = "BREAKPOINT-AUTH"

class TargetVerifier:
    @staticmethod
    def verify(base_url: str) -> bool:
        """
        Verifies ownership of the target domain by checking for a specific file.
        Returns True if verified, False otherwise.
        """
        parsed = urlparse(base_url)
        # Always allow localhost without file check
        if parsed.hostname in ["127.0.0.1", "localhost"]:
            return True
            
        verify_url = f"{base_url.rstrip('/')}/{VERIFICATION_FILENAME}"
        print(f"[*] Verifying ownership of {parsed.hostname}...")
        print(f"    -> Checking for validation file: {verify_url}")
        
        try:
            resp = requests.get(verify_url, timeout=5)
            if resp.status_code == 200 and EXPECTED_CONTENT in resp.text:
                print(f"[+] VERIFIED: Ownership confirmed. Access authorized for {parsed.hostname}.")
                return True
            else:
                print(f"[!] FAILED: Could not find '{EXPECTED_CONTENT}' in {verify_url}")
                print(f"    -> Got Status: {resp.status_code}")
                # print(f"    -> Response Body Preview: {resp.text[:50]}")
                return False
        except Exception as e:
            print(f"[!] ERROR: Connection failed during verification: {e}")
            return False
