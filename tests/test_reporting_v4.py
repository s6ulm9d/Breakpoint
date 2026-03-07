import unittest
import os
import sys
from unittest.mock import MagicMock

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from breakpoint.reporting.generator import StructuredReportGenerator
from breakpoint.models import CheckResult, VulnerabilityStatus, Severity

class TestStructuredReport(unittest.TestCase):
    def setUp(self):
        self.mock_engine = MagicMock()
        self.mock_engine.base_url = "http://target-v4.com"
        self.mock_engine.env = "staging"
        self.mock_engine.diff_mode = False
        self.mock_engine.scan_id = "TEST-SCAN-123"
        
        # Mock Throttler
        self.mock_engine.throttler = MagicMock()
        self.mock_engine.throttler.total_requests = 1337
        
        # Mock Context
        self.mock_engine.context = MagicMock()
        self.mock_engine.context.discovered_endpoints = ["/api/v1/users", "/login", "/admin/debug"]
        self.mock_engine.context.tech_stack = MagicMock()
        self.mock_engine.context.tech_stack.languages = ["Python", "JavaScript"]
        self.mock_engine.context.tech_stack.frameworks = ["Next.js", "Flask"]
        self.mock_engine.context.tech_stack.servers = ["Nginx"]
        self.mock_engine.context.tech_stack.databases = ["PostgreSQL"]
        
        # Mock Attack Graph
        self.mock_engine.attack_graph = MagicMock()
        mock_path = MagicMock()
        mock_path.nodes = ["debug_exposure", "secret_leak", "sql_injection"]
        mock_path.description = "Attacker finds debug info, extracts secrets, and performs SQLi."
        mock_path.severity_score = 27.5
        self.mock_engine.attack_graph.generate_exploit_paths.return_value = [mock_path]
        
        # Sample Results
        self.results = [
            CheckResult(
                id="sqli_1", type="sql_injection", status="CONFIRMED", 
                severity="CRITICAL", details="Error-based SQLi on /api/v1/users",
                remediation="Use parameterized queries.", confidence="HIGH",
                artifacts=[{"request": "GET /?id='", "response": "SQL Syntax Error", "payload": "'"}]
            ),
            CheckResult(
                id="xss_1", type="reflected_xss", status="VULNERABLE", 
                severity="HIGH", details="Reflected XSS on /login",
                remediation="Escape output.", confidence="MEDIUM"
            ),
            CheckResult(
                id="debug_1", type="debug_exposure", status="CONFIRMED", 
                severity="MEDIUM", details="Stack trace exposed",
                remediation="Disable debug mode.", confidence="HIGH"
            ),
            CheckResult(
                id="secure_1", type="header_security", status="SECURE", 
                severity="INFO", details="CSP header present",
                remediation="N/A"
            )
        ]

    def test_report_generation(self):
        generator = StructuredReportGenerator(self.mock_engine)
        output_file = "test_report_v4.html"
        
        try:
            generator.generate(self.results, output_file)
            self.assertTrue(os.path.exists(output_file))
            
            with open(output_file, 'r') as f:
                content = f.read()
                
            # Verify all 14 sections are present (using headers or markers)
            sections_to_check = [
                "OPERATION METADATA", "EXPOSURE OVERVIEW", "ATTACK SURFACE CARTOGRAPHY",
                "EXPLOIT CHAIN ANALYSIS", "CONFIRMED EXPLOITATION RECORDS",
                "INJECTION ATTACK INTELLIGENCE", "IDENTITY & ACCESS COMPROMISE",
                "CLIENT-SIDE EXPLOITATION", "INTERNAL NETWORK ABUSE",
                "DATA EXPOSURE FINDINGS", "EVIDENCE REPOSITORY",
                "SECURITY HARDENING GUIDANCE", "SCAN DIAGNOSTICS",
                "REPLAY AUDIT"
            ]
            
            for section in sections_to_check:
                self.assertIn(section, content, f"Section '{section}' missing from report")
            
            # Verify specific data points
            self.assertIn("target-v4.com", content)
            self.assertIn("TEST-SCAN-123", content)
            self.assertIn("1337", content) # Total requests
            self.assertIn("SQL INJECTION", content)
            self.assertIn("debug_exposure → secret_leak → sql_injection", content)
            self.assertIn("Use parameterized queries.", content)
            
            print("[+] Verification Success: Report generated with all 14 sections.")
            
        finally:
            if os.path.exists(output_file):
                # We can keep it for manual inspection if needed, or remove it
                # os.remove(output_file)
                pass

if __name__ == '__main__':
    unittest.main()
