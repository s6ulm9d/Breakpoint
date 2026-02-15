from dataclasses import dataclass
from typing import Dict, Any, Optional, List

@dataclass
class Scenario:
    id: str
    type: str
    target: str
    method: str
    config: Dict[str, Any]

@dataclass
class CheckResult:
    id: str
    type: str # e.g., "sql_injection", "xss"
    status: str # "SECURE" | "VULNERABLE" | "INCONCLUSIVE" | "ERROR" | "BLOCKED" | "WAF_INTERCEPTED"
    severity: str # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    details: str
    confidence: str = "TENTATIVE" # "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW" | "TENTATIVE"
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    remediation: Optional[str] = None
    artifacts: Optional[List[Dict[str, str]]] = None # List of {"request": "...", "response": "..."}
