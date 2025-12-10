import unittest
from unittest.mock import MagicMock, patch, Mock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from breakpoint.checks import sqli, xss
from breakpoint.models import Scenario

class TestSecurityChecks(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        
    @patch('breakpoint.checks.sqli.requests.get')
    def test_sqli_vulnerable(self, mock_get):
        """Test SQL Injection detection logic."""
        scenario = Scenario(id="sqli-1", type="sql_injection", target="/api/users", method="GET", config={"param": "id"})
        
        # Mock a response that looks like a MySQL error
        mock_response = Mock()
        mock_response.text = "You have an error in your SQL syntax; check the manual..."
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        result = sqli.check("http://localhost", scenario, self.logger)
        
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.severity, "HIGH")
        self.assertIn("SQL Error discovered (MySQL)", result.details)

    @patch('breakpoint.checks.sqli.requests.get')
    def test_sqli_secure(self, mock_get):
        """Test SQL Injection secure response."""
        scenario = Scenario(id="sqli-1", type="sql_injection", target="/api/users", method="GET", config={"param": "id"})
        
        mock_response = Mock()
        mock_response.text = "User not found"
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        result = sqli.check("http://localhost", scenario, self.logger)
        
        self.assertEqual(result.status, "SECURE")

    @patch('breakpoint.checks.xss.requests.get')
    def test_xss_reflected(self, mock_get):
        """Test Reflected XSS detection."""
        scenario = Scenario(id="xss-1", type="xss", target="/search", method="GET", config={"param": "q"})
        
        # Payload that gets reflected
        payload = "<script>alert(1)</script>"
        mock_response = Mock()
        mock_response.text = f"Search results for: {payload}"
        mock_get.return_value = mock_response
        
        result = xss.check("http://localhost", scenario, self.logger)
        
        # Note: Threading in tests might be flaky if we don't mock the ThreadPoolExecutor or ensure 'requests.get' is called correctly.
        # But since we mock at the module level 'breakpoint.checks.xss.requests.get', it should capture calls even in threads.
        
        self.assertEqual(result.status, "VULNERABLE")
        self.assertEqual(result.severity, "MEDIUM")
        self.assertIn("Reflected XSS", result.details)

if __name__ == '__main__':
    unittest.main()
