import sys
import os
from datetime import datetime

# Adjust path to import breakpoint
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from breakpoint.reporting.premium import PremiumReportGenerator
from breakpoint.models import CheckResult, Severity

# Mock Engine
class MockEngine:
    def __init__(self):
        self.base_url = "https://e-connecto.corp.internal"
        self.scan_id = "BRK-PROF-2026"
        self.source_path = "/src/e-connecto"

# Generate mock results
results = [
    CheckResult(
        id="BRK-SQL-001",
        type="sqli_blind_time",
        status="CONFIRMED",
        severity="CRITICAL",
        details="Time-based SQL injection confirmed on 'id' parameter.",
        endpoint="/api/v1/users",
        method="GET",
        parameter="id",
        cwe="CWE-89",
        owasp="A03:2021",
        remediation="Use parameterized queries or an ORM with built-in protection.",
        artifacts=[{"payload": "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", "response": "Response delayed by 5.2s"}]
    ),
    CheckResult(
        id="BRK-AUTH-002",
        type="jwt_none_alg",
        status="CONFIRMED",
        severity="HIGH",
        details="JWT 'none' algorithm accepted by authentication endpoint.",
        endpoint="/rest/user/login",
        method="POST",
        parameter="Authorization Header",
        cwe="CWE-347",
        owasp="A07:2021",
        remediation="Disable 'none' algorithm support in JWT library configuration.",
        artifacts=[{"payload": "eyJhbGciOiJub25lIn0.eyIpOnRydWV9.", "response": "HTTP 200 OK"}]
    ),
     CheckResult(
        id="BRK-XSS-003",
        type="reflected_xss",
        status="CONFIRMED",
        severity="MEDIUM",
        details="Reflected XSS on 'search' parameter.",
        endpoint="/search",
        method="GET",
        parameter="q",
        cwe="CWE-79",
        owasp="A03:2021",
        remediation="Implement context-aware output encoding.",
        artifacts=[{"payload": "alert(1)", "response": "<div>alert(1)</div>"}]
    )
]

output_path = "/Users/sharanya/Desktop/diff/breakpoint/latest_professional_report.html"
generator = PremiumReportGenerator(MockEngine())
generator.generate(results, output_path)

print(f"Report generated at: {output_path}")
