
import os
import sys
import datetime
from unittest.mock import MagicMock

# Add current directory to path
sys.path.append(os.getcwd())

from breakpoint.reporting.premium import PremiumReportGenerator
from breakpoint.models import CheckResult

def test_professional_report():
    print("[*] Testing Refined Professional Report...")
    
    # Mock Engine
    mock_engine = MagicMock()
    mock_engine.base_url = "http://e-connecto.sandbox.local:3000"
    mock_engine.source_path = "/Users/dev/projects/e-connecto/"
    mock_engine.scan_id = "AUDIT-2026-004"
    
    generator = PremiumReportGenerator(engine_instance=mock_engine)
    
    # Mock Results - Testing Refinements
    results = [
        # 1. SSTI (Must be Critical per User Req)
        CheckResult(
            id="BRK-SSTI-001",
            type="ssti_template_injection", # Matches 'ssti' in mapping -> Injection
            status="CONFIRMED",
            severity="CRITICAL",
            description="Server-Side Template Injection allows executing arbitrary code on the server via template expression evaluation.",
            details="Confirmed RCE via {{7*7}} in greeting parameter.",
            method="GET",
            endpoint="/welcome",
            parameter="name",
            remediation="Never pass user input to render_template_string(); use static templates",
            artifacts=[{"payload": "{{7*7}}", "response": "Hello 49!"}]
        ),
        # 2. XSS (Must be High per User Req)
        CheckResult(
            id="BRK-XSS-001",
            type="xss_reflected", # Matches 'xss' in mapping -> XSS
            status="VULNERABLE",
            severity="HIGH",
            description="Reflected XSS allows script execution in the context of the user's session.",
            details="Input reflected in search results.",
            method="GET",
            endpoint="/search",
            parameter="q",
            remediation="Use context-aware output encoding for all reflected inputs.",
            artifacts=[{"payload": "<script>alert(1)</script>", "response": "Search results for: <script>alert(1)</script>"}]
        ),
        # 3. Debug Exposure (Must be High per User Req)
        CheckResult(
            id="BRK-DEBUG-001",
            type="debug_exposure", # Matches 'Miscellaneous' but user wants technical summary
            status="CONFIRMED",
            severity="HIGH",
            description="Admin, debug, actuator, .env, phpinfo, and config.json endpoints accessible without authentication",
            details="Found exposed .env file.",
            method="GET",
            endpoint="/.env",
            parameter="N/A",
            remediation="Remove from prod; IP-allowlist /admin; block /.env at web server.",
            artifacts=[{"payload": "N/A", "response": "DB_PASSWORD=secret\nSECRET_KEY=123"}]
        ),
        # 4. Skipped finding (Muted style test)
        CheckResult(
            id="BRK-SKIP-001",
            type="log4shell",
            status="SKIPPED",
            severity="MEDIUM",
            description="Potential Log4Shell vulnerability.",
            details="Request timed out.",
            method="POST",
            endpoint="/api/login",
            parameter="User-Agent",
            remediation="Patch Log4j to version 2.17.1+.",
            artifacts=[]
        ),
        # 5. Info finding
        CheckResult(
            id="BRK-INFO-001",
            type="security_headers",
            status="SUSPECT",
            severity="INFO",
            description="Security headers are present. High-grade configuration confirmed.",
            details="HSTS and CSP found.",
            method="GET",
            endpoint="/",
            parameter="N/A",
            remediation="Security headers are present.",
            artifacts=[]
        )
    ]
    
    output_path = "refined_audit_report.html"
    generator.generate(results, output_path)
    
    with open(output_path, "r") as f:
        html = f.read()
    
    # VERIFICATION CHECKS
    print("[*] Verifying Refined Report Contents...")
    
    # 7 & 8: Summary Counts and Breakdown
    assert "Total Findings" in html
    assert ">4</p>" in html # The count '4' should be inside a paragraph tag
    assert "CRITICAL" in html and "HIGH" in html and "INFO" in html
    
    # Check if breakdown populated correctly
    assert "findings including CRITICAL severity vulnerabilities" in html 
    assert "findings including HIGH severity vulnerabilities" in html 
    
    # 1, 2, 3: Endpoint, Parameter, Payload
    assert "Endpoint" in html 
    assert "/welcome" in html
    assert "/.env" in html
    assert "Parameter" in html
    assert "name" in html
    assert "{{7*7}}" in html
    
    # 4: Severity Correction
    assert "sev-critical" in html
    assert "sev-high" in html
    
    # 9: Skipped Distinction
    assert "opacity: 0.7" in html
    assert "[SKIPPED]" in html
    
    # 10: Impact Confirmation
    assert "Hello 49!" in html 
    assert "DB_PASSWORD=secret" in html 
    assert "Not captured — payload delivered, response not conclusive" in html 
    
    print(f"    [+] Refined report verified. Saved to {output_path}")

if __name__ == "__main__":
    try:
        test_professional_report()
        print("\n[SUCCESS] Breakpoint Security Report Refinements Verified!")
    except Exception as e:
        print(f"\n[FAILURE] Verification failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
