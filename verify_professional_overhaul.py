import sys
import os
import unittest
from unittest.mock import MagicMock, patch
import re

# Mocking modules that might not be easily importable or have dependencies
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from breakpoint.core.fingerprinter import TechFingerprinter
from breakpoint.core.context import TargetContext, TechStack
from breakpoint.crawler import Crawler
from breakpoint.reporting.premium import PremiumReportGenerator
from breakpoint.models import CheckResult

class TestProfessionalOverhaul(unittest.TestCase):
    
    def test_fingerprinting_confidence_and_conflict(self):
        """Verify that TechFingerprinter handles confidence and conflicts."""
        mock_client = MagicMock()
        
        # Scenario: Response has Next.js headers but ALSO Rails headers (conflict)
        # We want to see if it picks the one with higher confidence/score
        mock_resp = MagicMock()
        mock_resp.headers = {
            "X-Powered-By": "Next.js", # High weight for Next.js (0.9)
            "Server": "Phusion Passenger" # This would imply Rails (0.8 in older logic, let's check current)
        }
        # Wait, I mapped rails to "phusion passenger" in HEADER_SIGNATURES for rails
        mock_resp.headers = {
            "X-Powered-By": "Next.js",
            "X-Rails-Version": "7.0.0" # Not in my map but let's use what's there
        }
        # Re-using the actual HEADER_SIGNATURES from the code:
        # "next.js": {"x-powered-by": (["next.js"], 0.9)}
        # "rails": {"x-powered-by": (["phusion passenger"], 0.8)}
        
        mock_resp.headers = {
            "X-Powered-By": "Next.js",
            "Server": "wsgiserver" # Implies Django (0.4)
        }
        mock_resp.text = "<html><body>Some content</body></html>"
        mock_client.send.return_value = mock_resp
        
        context = TargetContext(base_url="http://test.com")
        fingerprinter = TechFingerprinter(mock_client)
        
        # Mock active probe to fail for both
        with patch.object(TechFingerprinter, '_active_probe'):
            enriched_context = fingerprinter.fingerprint("http://test.com", context)
            
        # Next.js (0.9) should beat Django (0.4)
        self.assertIn("next.js", enriched_context.tech_stack.frameworks)
        self.assertNotIn("django", enriched_context.tech_stack.frameworks)
        self.assertAlmostEqual(enriched_context.tech_stack.confidence_scores["next.js"], 0.9)

    def test_crawler_depth_discovery(self):
        """Verify Crawler parses meta files and extract JS routes."""
        mock_client = MagicMock()
        
        # Mock robots.txt
        robots_resp = MagicMock()
        robots_resp.status_code = 200
        robots_resp.text = "User-agent: *\nDisallow: /admin-secret\nAllow: /public-api"
        
        # Mock sitemap.xml
        sitemap_resp = MagicMock()
        sitemap_resp.status_code = 200
        sitemap_resp.text = "<urlset><url><loc>http://test.com/sitemap-path</loc></url></urlset>"
        
        # Mock JS file
        js_resp = MagicMock()
        js_resp.status_code = 200
        js_resp.text = "const api = '/api/v1/users'; const other = { path: '/dynamic-route' };"
        
        # Mock index.html
        index_resp = MagicMock()
        index_resp.status_code = 200
        index_resp.text = '<html><script src="/app.js"></script><form action="/login" method="POST"></form></html>'
        
        def side_effect(method, url, **kwargs):
            if "robots.txt" in url: return robots_resp
            if "sitemap.xml" in url: return sitemap_resp
            if "app.js" in url: return js_resp
            if url == "http://test.com": return index_resp
            # For fuzzing paths
            m = MagicMock()
            m.status_code = 404
            return m
            
        mock_client.send.side_effect = side_effect
        
        crawler = Crawler("http://test.com", mock_client)
        crawler.crawl()
        
        targets = [t["url"] for t in crawler.get_scan_targets()]
        
        self.assertIn("http://test.com/admin-secret", targets)
        self.assertIn("http://test.com/public-api", targets)
        self.assertIn("http://test.com/sitemap-path", targets)
        self.assertIn("http://test.com/api/v1/users", targets)
        self.assertIn("http://test.com/dynamic-route", targets)
        self.assertIn("http://test.com/login", targets)

    def test_premium_report_reproducibility(self):
        """Verify premium report contains Payload and Verification Evidence."""
        mock_engine = MagicMock()
        res = CheckResult(
            id="test-1",
            type="sql_injection",
            status="CONFIRMED",
            severity="CRITICAL",
            details="Confirmed math evaluation", # Added missing details argument
            endpoint="/api/v1/test",
            method="GET",
            parameter="id",
            remediation="Fix it.",
            description="Exploit found.",
            artifacts=[{"payload": "' OR 1=1 --", "response": "admin:hash"}]
        )
        
        generator = PremiumReportGenerator(mock_engine)
        html = generator._render_exploitation_records([res], "Injection")
        
        self.assertIn("Reproduction Payload", html)
        self.assertIn("Verification Evidence", html)
        self.assertIn("' OR 1=1 --", html)
        self.assertIn("admin:hash", html)

if __name__ == "__main__":
    unittest.main()
