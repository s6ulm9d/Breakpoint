import os
import hashlib

class PytestGenerator:
    def __init__(self, output_dir="tests"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def generate_test(self, vuln_data):
        """
        Generates a regression test for a vulnerability.
        """
        target_hash = hashlib.md5(vuln_data['target'].encode()).hexdigest()[:8]
        test_content = f"""import pytest
from breakpoint.http_client import HttpClient
from breakpoint.scenarios import SimpleScenario

def test_{vuln_data['type']}_{target_hash}():
    client = HttpClient()
    
    # Reproduction context
    target = "{vuln_data['target']}"
    method = "{vuln_data['method']}"
    
    print(f"[*] Running regression test for {vuln_data['type']} on {{target}}")
    
    # We expect the vulnerability to be patched, so signature should NOT appear
    result = client.send(method, target)
    
    assert result.status_code != 500, "Server crashed during regression test"
    assert "{vuln_data['signature']}" not in result.text, "Vulnerability signature still present!"
"""
        file_path = os.path.join(self.output_dir, f"test_{vuln_data['scenario_id']}.py")
        with open(file_path, "w") as f:
            f.write(test_content)
        return file_path

class PlaywrightGenerator:
    def __init__(self, output_dir="tests/e2e"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def generate_test(self, vuln_data):
        target_hash = hashlib.md5(vuln_data['target'].encode()).hexdigest()[:8]
        test_content = f"""from playwright.sync_api import sync_playwright
import pytest

def test_{vuln_data['type']}_e2e_{target_hash}():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        
        print(f"[*] Navigating to {{'{vuln_data['target']}'}} for E2E validation...")
        page.goto("{vuln_data['target']}", wait_until="networkidle")
        
        # Check for signature in the rendered DOM
        content = page.content()
        assert "{vuln_data['signature']}" not in content, "Vulnerability detected in rendered page!"
        
        browser.close()
"""
        file_path = os.path.join(self.output_dir, f"test_{vuln_data['scenario_id']}_e2e.py")
        with open(file_path, "w") as f:
            f.write(test_content)
        return file_path
