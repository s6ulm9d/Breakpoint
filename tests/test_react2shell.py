import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Create tests directory if it doesn't exist
# Add project root to path so we can import breakpoint modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from breakpoint.checks import react2shell
from breakpoint.models import Scenario

class TestReact2Shell(unittest.TestCase):
    def setUp(self):
        self.logger = MagicMock()
        self.scenario = Scenario(
            id="test-rce",
            type="react2shell",
            target="/api/tracker",
            method="POST",
            config={}
        )

    @patch('breakpoint.checks.react2shell.requests.post')
    def test_rce_returns_secure_on_404(self, mock_post):
        """Verify that the check returns SECURE immediately on 404."""
        # Setup mock to return 404
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        mock_post.return_value = mock_response

        # Execute check
        result = react2shell.check("http://localhost:3000", self.scenario, self.logger)

        # Assertions
        print(f"\n[Test Output] Result Status: {result.status}")
        print(f"[Test Output] Result Details: {result.details}")
        
        self.assertEqual(result.status, "SECURE")
        self.assertIn("Endpoint not found (404)", result.details)
        
        # Verify only 1 request was made (probe) - fails fast
        self.assertEqual(mock_post.call_count, 1)

if __name__ == '__main__':
    unittest.main()
