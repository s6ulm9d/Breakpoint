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
    status: str # "SECURE" | "VULNERABLE" | "INCONCLUSIVE" | "ERROR"
    severity: Optional[str]
    details: str
