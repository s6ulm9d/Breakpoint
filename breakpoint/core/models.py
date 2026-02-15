from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class VulnerabilityStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUSPECT = "SUSPECT"
    VULNERABLE = "VULNERABLE"
    SECURE = "SECURE"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"

@dataclass
class AttackArtifact:
    """Evidence of the attack execution."""
    request_dump: str
    response_dump: str
    payload: Optional[str] = None
    description: str = ""

@dataclass
class AttackResult:
    """Standardized output for an attack execution."""
    scenario_id: str
    attack_id: str
    status: VulnerabilityStatus
    severity: Severity
    details: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[AttackArtifact] = field(default_factory=list)
    risk_score: float = 0.0 # 0.0 to 10.0
    confidence: float = 0.0 # 0.0 to 100.0
    reproduction_steps: str = ""
