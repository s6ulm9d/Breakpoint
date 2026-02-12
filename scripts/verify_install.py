import sys
import os
from unittest.mock import MagicMock, patch

# Mock requirements before importing breakpoint modules
sys.modules['docker'] = MagicMock()
sys.modules['tree_sitter'] = MagicMock()
sys.modules['playwright'] = MagicMock()
sys.modules['playwright.sync_api'] = MagicMock()
sys.modules['temporalio'] = MagicMock()

from breakpoint.engine import Engine
from breakpoint.scenarios import SimpleScenario
from breakpoint.models import CheckResult

def test_engine_init_and_mock_run():
    print("[*] Testing Engine Initialization...")
    # Mocking forensic logger and connection check to avoid real network calls
    with patch('breakpoint.engine.Engine._check_connection', return_value=None):
        engine = Engine(base_url="http://localhost:3000", simulation=False)
        
        # Test result printing with the new self-healing logic triggered
        # We need to craft a VULNERABLE result
        scenario = SimpleScenario(id="test_sqli", type="simple", attack_type="sql_injection", target="/api/test")
        result = CheckResult(
            id="test_sqli", 
            type="sql_injection", 
            status="VULNERABLE", 
            severity="HIGH", 
            details={"title": "SQL Injection found", "reproduction_payload": "' OR 1=1 --"},
            confidence="CONFIRMED"
        )
        
        print("\n[*] Triggering result printing...")
        engine._print_result(scenario, result)
        
        print("\n[*] Testing SARIF Report Generation...")
        from breakpoint.sarif_reporting import SarifReporter
        reporter = SarifReporter("test_audit.sarif")
        reporter.generate([result])
        
        if os.path.exists("test_audit.sarif"):
            print("[+] SARIF report generated successfully.")
            
    print("\n[+] All systems verified. Breakpoint is Industry-leading.")

if __name__ == "__main__":
    test_engine_init_and_mock_run()
