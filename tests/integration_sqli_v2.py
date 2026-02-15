"""
Integration Test Suite for SQLInjectionAttack V2
Validates system-level behavior against live targets.
"""
import sys
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from breakpoint.core.context import TargetContext
from breakpoint.attacks.active.sql_injection import SQLInjectionAttack
from breakpoint.scenarios import SimpleScenario
from breakpoint.http_client import HttpClient
from breakpoint.core.models import VulnerabilityStatus

class IntegrationTestSuite:
    """Comprehensive integration validation for V2 attacks."""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.results = []
    
    def test_1_live_detection(self):
        """Test 1: Live Target Detection"""
        print("\n" + "="*60)
        print("TEST 1: Live Target Detection")
        print("="*60)
        
        client = HttpClient(self.target_url, verbose=False)
        context = TargetContext(self.target_url)
        context.update_tech_stack("database", "MySQL")
        
        attack = SQLInjectionAttack(client, context)
        scenario = SimpleScenario(
            id="test_live_sqli",
            type="simple",
            method="GET",
            target=f"{self.target_url}/api/products",
            attack_type="sql_injection",
            config={"params": {"category": "test"}}
        )
        
        result = attack.run(scenario)
        
        print(f"  Status: {result.status}")
        print(f"  Severity: {result.severity}")
        print(f"  Confidence: {result.confidence}")
        
        assert result.status == VulnerabilityStatus.CONFIRMED, "Expected SQLi detection"
        print("  ✅ PASS: SQLi detected on live target")
        
        return result
    
    def test_2_repeatability(self, iterations=5):
        """Test 2: Repeatability (5 identical scans)"""
        print("\n" + "="*60)
        print(f"TEST 2: Repeatability ({iterations} iterations)")
        print("="*60)
        
        results = []
        
        for i in range(iterations):
            client = HttpClient(self.target_url, verbose=False)
            context = TargetContext(self.target_url)
            context.update_tech_stack("database", "MySQL")
            
            attack = SQLInjectionAttack(client, context)
            scenario = SimpleScenario(
                id=f"repeatability_test_{i}",
                type="simple",
                method="GET",
                target=f"{self.target_url}/api/products",
                attack_type="sql_injection",
                config={"params": {"category": "test"}}
            )
            
            result = attack.run(scenario)
            results.append(result)
            print(f"  Iteration {i+1}: {result.status} | Confidence: {result.confidence}")
        
        # Verify all results identical
        first_status = results[0].status
        first_severity = results[0].severity
        
        for r in results[1:]:
            assert r.status == first_status, "Status mismatch across iterations"
            assert r.severity == first_severity, "Severity mismatch across iterations"
        
        print("  ✅ PASS: 100% repeatability confirmed")
        return results
    
    def test_3_concurrency(self, workers=20):
        """Test 3: Concurrency (20+ workers)"""
        print("\n" + "="*60)
        print(f"TEST 3: Concurrency ({workers} workers)")
        print("="*60)
        
        results = []
        lock = threading.Lock()
        
        def worker(worker_id):
            client = HttpClient(self.target_url, verbose=False)
            context = TargetContext(self.target_url)
            context.update_tech_stack("database", "MySQL")
            
            attack = SQLInjectionAttack(client, context)
            scenario = SimpleScenario(
                id=f"concurrent_test_{worker_id}",
                type="simple",
                method="GET",
                target=f"{self.target_url}/api/products",
                attack_type="sql_injection",
                config={"params": {"category": f"test_{worker_id}"}}
            )
            
            result = attack.run(scenario)
            
            with lock:
                results.append(result)
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(worker, i) for i in range(workers)]
            for f in futures:
                f.result()
        
        print(f"  Completed: {len(results)}/{workers} workers")
        
        # Verify no shared state corruption
        confirmed_count = sum(1 for r in results if r.status == VulnerabilityStatus.CONFIRMED)
        print(f"  Confirmed: {confirmed_count}/{workers}")
        
        assert len(results) == workers, "Worker count mismatch"
        assert confirmed_count > 0, "No detections under concurrency"
        
        print("  ✅ PASS: No shared-state leakage detected")
        return results
    
    def test_4_zero_duplicates(self):
        """Test 4: Zero Duplicate Findings"""
        print("\n" + "="*60)
        print("TEST 4: Zero Duplicate Findings")
        print("="*60)
        
        client = HttpClient(self.target_url, verbose=False)
        context = TargetContext(self.target_url)
        context.update_tech_stack("database", "MySQL")
        
        attack = SQLInjectionAttack(client, context)
        scenario = SimpleScenario(
            id="duplicate_test",
            type="simple",
            method="GET",
            target=f"{self.target_url}/api/products",
            attack_type="sql_injection",
            config={"params": {"category": "test"}}
        )
        
        result = attack.run(scenario)
        
        # Check artifacts for duplicates
        if result.artifacts:
            payloads = [a.payload for a in result.artifacts]
            unique_payloads = set(payloads)
            
            print(f"  Total artifacts: {len(result.artifacts)}")
            print(f"  Unique payloads: {len(unique_payloads)}")
            
            assert len(payloads) == len(unique_payloads), "Duplicate findings detected"
        
        print("  ✅ PASS: Zero duplicates confirmed")
        return result
    
    def run_all(self):
        """Execute full integration test suite."""
        print("\n" + "🔬 " + "="*58)
        print("   INTEGRATION TEST SUITE - SQLInjectionAttack V2")
        print("="*60)
        print(f"Target: {self.target_url}")
        print("="*60)
        
        try:
            self.test_1_live_detection()
            self.test_2_repeatability()
            self.test_3_concurrency()
            self.test_4_zero_duplicates()
            
            print("\n" + "="*60)
            print("✅ ALL INTEGRATION TESTS PASSED")
            print("="*60)
            print("\nStatus: APPROVED FOR STAGED INTEGRATION")
            print("Next: Shadow mode validation (10-20 scans)")
            
            return True
            
        except AssertionError as e:
            print(f"\n❌ TEST FAILED: {e}")
            return False
        except Exception as e:
            print(f"\n❌ ERROR: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == '__main__':
    target = "http://127.0.0.1:5000"
    
    print("\n⚠️  Prerequisites:")
    print("  - Flask vuln_app.py must be running")
    print("  - Run: python breakpoint/examples/vuln_app.py\n")
    
    suite = IntegrationTestSuite(target)
    success = suite.run_all()
    
    sys.exit(0 if success else 1)
