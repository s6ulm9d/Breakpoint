from dataclasses import dataclass
from typing import Dict, Any, Optional

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
    type: str
    status: str # "SECURE" | "VULNERABLE" | "INCONCLUSIVE" | "ERROR" | "BLOCKED" | "WAF_INTERCEPTED" | "PROXY_FAILURE"
    severity: Optional[str]
    details: str
    confidence: Optional[str] = "UNKNOWN" # CONFIRMED | HIGH | MEDIUM | LOW | TENTATIVE
