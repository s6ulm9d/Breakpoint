from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from ..http_client import HttpClient, ResponseWrapper
from ..scenarios import SimpleScenario
from ..models import AttackResult, Severity, VulnerabilityStatus, AttackArtifact
from .context import TargetContext

class Attack(ABC):
    """
    Validation Engine Root Class.
    All V2 attack modules must inherit from this and implement the `execute` method.
    """
    
    # --- Framework Metadata (OVERRIDE THESE) ---
    ID: str = "generic_attack"
    NAME: str = "Generic Attack"
    DESCRIPTION: str = "No description available."
    SEVERITY: Severity = Severity.INFO
    TAGS: List[str] = ["generic"]

    def __init__(self, client: HttpClient, context: TargetContext):
        self.client = client
        self.context = context

    def run(self, scenario: SimpleScenario) -> AttackResult:
        """
        Orchestrator pattern (Template Method).
        DO NOT OVERRIDE unless extending core functionality.
        """
        # 1. Fingerprint Check (Should we even run?)
        if not self.fingerprint(scenario):
            return self._result(scenario, VulnerabilityStatus.SKIPPED, details="Technology mismatch or irrelevant context.")

        try:
            # 2. Execute Attack Logic
            # Note: Throttling is handled by HttpClient internally.
            # Note: Baseline variance data should be fetched from Context or Engine cache if needed.
            # But for simplicity, most attacks handle their own baseline logic or rely on HttpClient helpers.
            result = self.execute(scenario)
            
            # 3. Validation Logic (Optional)
            if result.status == VulnerabilityStatus.SUSPECT:
                result = self.validate(result)
            
            return result

        except Exception as e:
            # Global Exception Handler prevents engine crash
            return self._result(
                scenario, 
                VulnerabilityStatus.ERROR, 
                details=f"Attack execution failed: {str(e)}",
                severity=Severity.INFO
            )

    def fingerprint(self, scenario: SimpleScenario) -> bool:
        """
        Returns True if this attack applies to the current context.
        Override to implement tech-stack checks (e.g. only run SQLi if SQL DB detected).
        """
        return True

    @abstractmethod
    def execute(self, scenario: SimpleScenario) -> AttackResult:
        """
        Core attack logic. Must return AttackResult.
        """
        pass

    def validate(self, result: AttackResult) -> AttackResult:
        """
        Called automatically if status is SUSPECT.
        Implement OOB checks or secondary validation here.
        """
        return result

    def _result(self, scenario: SimpleScenario, status: VulnerabilityStatus, 
                details: Any = None, severity: Optional[Severity] = None, 
                artifacts: List[AttackArtifact] = None, confidence: float = 0.0) -> AttackResult:
        """Helper to construct standardized results."""
        return AttackResult(
            scenario_id=scenario.id,
            attack_id=self.ID,
            status=status,
            severity=severity or self.SEVERITY,
            details={"message": str(details)} if not isinstance(details, dict) else details,
            artifacts=artifacts or [],
            confidence=confidence
        )
