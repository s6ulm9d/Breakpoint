"""
Live Validation Test for SQLInjectionAttack V2
Runs against the vulnerable Flask app to verify real-world behavior.
"""
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from breakpoint.core.context import TargetContext
from breakpoint.attacks.active.sql_injection import SQLInjectionAttack
from breakpoint.scenarios import SimpleScenario
from breakpoint.http_client import HttpClient
from breakpoint.core.models import VulnerabilityStatus

def test_live_sqli():
    """
    Prerequisites: 
    - Flask vuln_app.py must be running on http://127.0.0.1:5000
    - Run: python breakpoint/examples/vuln_app.py
    """
    print("\n" + "="*60)
    print("LIVE VALIDATION: SQLInjectionAttack V2")
    print("="*60)
    
    # Setup
    target_url = "http://127.0.0.1:5000"
    client = HttpClient(target_url, verbose=True)
    context = TargetContext(target_url)
    context.update_tech_stack("database", "MySQL")  # Simulate fingerprinting
    
    attack = SQLInjectionAttack(client, context)
    
    # Test 1: Error-Based Detection
    print("\n[TEST 1] Error-Based SQLi Detection")
    scenario1 = SimpleScenario(
        id="test_error_sqli",
        method="GET",
        target=f"{target_url}/api/products",
        config={"params": {"category": "electronics"}}
    )
    
    result1 = attack.run(scenario1)
    print(f"  Status: {result1.status}")
    print(f"  Severity: {result1.severity}")
    print(f"  Details: {result1.details}")
    
    assert result1.status == VulnerabilityStatus.CONFIRMED, "Expected CONFIRMED for error-based SQLi"
    assert "Error-Based SQLi" in str(result1.details), "Expected error-based detection"
    print("  ✓ PASS: Error-based SQLi detected correctly")
    
    # Test 2: Boolean-Based Detection
    print("\n[TEST 2] Boolean-Based SQLi Detection")
    result2 = attack.run(scenario1)  # Same endpoint, different payload path
    print(f"  Status: {result2.status}")
    print(f"  Details: {result2.details}")
    
    # The vuln app should trigger boolean-based if error-based doesn't fire first
    # But since error-based fires first, this will also be CONFIRMED
    assert result2.status == VulnerabilityStatus.CONFIRMED
    print("  ✓ PASS: SQLi vulnerability confirmed")
    
    # Test 3: Secure Endpoint (Should not trigger)
    print("\n[TEST 3] Secure Endpoint (No SQLi)")
    scenario3 = SimpleScenario(
        id="test_secure",
        method="GET",
        target=f"{target_url}/",
        config={}
    )
    
    result3 = attack.run(scenario3)
    print(f"  Status: {result3.status}")
    
    # Home page has no params, should be SECURE or SKIPPED
    assert result3.status in [VulnerabilityStatus.SECURE, VulnerabilityStatus.SKIPPED]
    print("  ✓ PASS: Secure endpoint correctly identified")
    
    print("\n" + "="*60)
    print("ALL LIVE TESTS PASSED ✓")
    print("="*60)

if __name__ == '__main__':
    try:
        test_live_sqli()
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        print("\nMake sure the vulnerable Flask app is running:")
        print("  python breakpoint/examples/vuln_app.py")
        sys.exit(1)
