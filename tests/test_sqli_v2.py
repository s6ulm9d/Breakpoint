import unittest
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unittest.mock import MagicMock
from breakpoint.core.context import TargetContext
from breakpoint.attacks.active.sql_injection import SQLInjectionAttack
from breakpoint.scenarios import SimpleScenario
from breakpoint.http_client import ResponseWrapper
from breakpoint.core.models import VulnerabilityStatus, Severity

class TestSQLInjectionAttack(unittest.TestCase):
    def setUp(self):
        self.mock_client = MagicMock()
        self.context = TargetContext("http://test.com")
        self.attack = SQLInjectionAttack(self.mock_client, self.context)
        self.scenario = SimpleScenario("test_scenario", "GET", "http://test.com", config={"params": {"id": "1"}})

    def test_fingerprint_skip_nosql(self):
        # Scenario: Target is purely NoSQL (MongoDB)
        self.context.update_tech_stack("database", "MongoDB")
        
        # Should return False (Skip)
        self.assertFalse(self.attack.fingerprint(self.scenario))

    def test_fingerprint_allow_sql(self):
        # Scenario: Target is SQL (Postgres)
        self.context.update_tech_stack("database", "Postgres")
        self.assertTrue(self.attack.fingerprint(self.scenario))

    def test_fingerprint_hybrid(self):
        # Scenario: Target is Hybrid (Mongo + MySQL)
        self.context.update_tech_stack("database", "MongoDB")
        self.context.update_tech_stack("database", "MySQL")
        self.assertTrue(self.attack.fingerprint(self.scenario))

    def test_execute_error_based(self):
        # 1. Baseline: 200 OK
        resp_baseline = ResponseWrapper(status_code=200, text="User: Alice", elapsed_ms=10, url="http://test.com")
        
        # 2. Injection: 500 Error with SQL syntax
        resp_error = ResponseWrapper(status_code=500, text="Warning: mysql_fetch_array() expects parameter 1", elapsed_ms=10, url="http://test.com")
        
        # Mock responses in order: Baseline -> Injection 1 -> ...
        # Attack calls: baseline -> inject("'") -> ...
        self.mock_client.send.side_effect = [resp_baseline, resp_error]

        result = self.attack.execute(self.scenario)

        self.assertEqual(result.status, VulnerabilityStatus.CONFIRMED)
        self.assertEqual(result.severity, Severity.CRITICAL)
        details_str = str(result.details)
        self.assertIn("Error-Based SQLi detected", details_str)
        self.assertIn("mysql_fetch", details_str)

    def test_execute_boolean_based(self):
        # 1. Baseline: 200 OK (Content Len: 500)
        resp_baseline = ResponseWrapper(status_code=200, text="A"*500, elapsed_ms=10, url="http://test.com")
        
        # 2. Error Injection: 200 OK (No error message)
        resp_error_probe = ResponseWrapper(status_code=200, text="A"*500, elapsed_ms=10, url="http://test.com")

        # 3. Boolean True (OR 1=1): 200 OK (Content Len: 500 - Similar to baseline)
        resp_true = ResponseWrapper(status_code=200, text="A"*500, elapsed_ms=10, url="http://test.com")
        
        # 4. Boolean False (OR 1=2): 200 OK (Content Len: 100 - Different!)
        resp_false = ResponseWrapper(status_code=200, text="A"*100, elapsed_ms=10, url="http://test.com")

        # Mock sequence
        self.mock_client.send.side_effect = [
            resp_baseline,      # Baseline
            resp_error_probe,   # Error probe (fails to trigger error)
            resp_true,          # Boolean True payload
            resp_false          # Boolean False payload
        ]

        result = self.attack.execute(self.scenario)

        self.assertEqual(result.status, VulnerabilityStatus.CONFIRMED)
        details_str = str(result.details)
        self.assertIn("Boolean-Based SQLi detected", details_str)

    def test_execute_secure(self):
        # All responses consistent
        resp_ok = ResponseWrapper(status_code=200, text="A"*500, elapsed_ms=10, url="http://test.com")
        self.mock_client.send.return_value = resp_ok

        result = self.attack.execute(self.scenario)
        self.assertEqual(result.status, VulnerabilityStatus.SECURE)

if __name__ == '__main__':
    unittest.main()
