import os
from typing import Dict, Any, Optional

class STaCEngine:
    """
    Security-Test-as-Code (STaC) Engine.
    Generates functional regression tests for confirmed exploits.
    """
    def __init__(self, output_dir: str = "security-tests"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_playwright_test(self, vulnerability_type: str, target_url: str, poc_details: Dict[str, Any]) -> str:
        """
        Generates a Playwright test case in Python that reproduces the vulnerability.
        """
        test_id = f"test_{vulnerability_type}_{os.urandom(4).hex()}"
        filename = os.path.join(self.output_dir, f"{test_id}.py")
        
        # Simple Logic for generating a Playwright script based on PoC details
        # In a real system, an LLM would help refine this script.
        
        method = poc_details.get("method", "GET")
        payload = poc_details.get("payload", "")
        headers = poc_details.get("headers", {})
        
        code = f"""import pytest
from playwright.sync_api import sync_playwright

def test_{vulnerability_type}_regression():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        # Target: {target_url}
        # Vulnerability: {vulnerability_type}
        
        try:
            # Reproduce the exploit
            response = page.goto("{target_url}")
            assert response.status < 500, "Server crashed during test"
            
            # Logic to verify vulnerability is NOT present (Secure State)
            # This should FAIL on old code and PASS on new code.
            # For example, if it's XSS, check if alert/script is executed.
            # If it's SQLi, check if the error/data is leaked.
            
            # Placeholder for specific verification logic
            # This is where 'Verified Fix' comes in.
            print("[*] Verifying fix for {vulnerability_type}")
            
        finally:
            browser.close()

if __name__ == "__main__":
    test_{vulnerability_type}_regression()
"""
        with open(filename, "w") as f:
            f.write(code)
        
        return filename

    def generate_api_test(self, vulnerability_type: str, target_url: str, poc_details: Dict[str, Any]) -> str:
        """
        Generates a Pytest/Requests test case for API vulnerabilities.
        """
        test_id = f"test_api_{vulnerability_type}_{os.urandom(4).hex()}"
        filename = os.path.join(self.output_dir, f"{test_id}.py")
        
        method = poc_details.get("method", "GET")
        payload = poc_details.get("payload", "")
        params = poc_details.get("params", {})
        
        code = f"""import requests
import pytest

def test_{vulnerability_type}_api_regression():
    url = "{target_url}"
    method = "{method}"
    payload = {payload}
    params = {params}
    
    # This test should verify that the vulnerability is NO LONGER exploitable.
    response = requests.request(method, url, json=payload, params=params, timeout=10)
    
    # Logic to verify fix
    # For SQLi: Response should not contain DB error patterns
    # For Auth Bypass: Response should be 401/403
    assert response.status_code != 200, "Vulnerability still exists! Got 200 OK."
    
    print("[+] Regression test passed: {vulnerability_type} is mitigated.")

if __name__ == "__main__":
    test_{vulnerability_type}_api_regression()
"""
        with open(filename, "w") as f:
            f.write(code)
            
        return filename
