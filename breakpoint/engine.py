from typing import List, Dict, Any, Optional
import time
from .scenarios import ScenarioBase, SimpleScenario, FlowScenario
from .attacks import ATTACK_DISPATCHER
from .http_client import HttpClient
from .safety import check_target_safety
from .flows import FlowRunner
from .forensics import ForensicLogger
from .safety_lock import SafetyLock

class Engine:
    def __init__(self, base_url: str, forensic_log: Optional[ForensicLogger] = None):
        self.base_url = base_url.rstrip('/')
        
        # 1. Strict Safety First
        check_target_safety(self.base_url)
        
        self.client = HttpClient(self.base_url)
        self.forensics = forensic_log
        self.safety_lock = SafetyLock(self.base_url)

    def run_all(self, scenarios: List[ScenarioBase]) -> List[Dict[str, Any]]:
        results = []
        for s in scenarios:
            # 2. Kill Switch Loop Check
            self.safety_lock.check_kill_switch()
            
            if self.forensics:
                self.forensics.log_event("SCENARIO_START", {"id": s.id, "type": str(type(s))})
            
            if isinstance(s, SimpleScenario):
                res = self.run_simple(s)
            elif isinstance(s, FlowScenario):
                res = self.run_flow(s)
            else:
                res = {"id": s.id, "error": "Unknown scenario type", "passed": False}
                
            results.append(res)
            
            if self.forensics:
                self.forensics.log_event("SCENARIO_RESULT", {"id": s.id, "passed": res.get("passed", False)})
                
        return results

    def run_simple(self, scenario: SimpleScenario) -> Dict[str, Any]:
        handler = ATTACK_DISPATCHER.get(scenario.attack_type)
        if not handler:
            return {"scenario_id": scenario.id, "error": f"No handler for {scenario.attack_type}", "passed": False}
            
        try:
            return handler(self.client, scenario)
        except Exception as e:
            return {"scenario_id": scenario.id, "error": str(e), "passed": False}

    def run_flow(self, scenario: FlowScenario) -> Dict[str, Any]:
        runner = FlowRunner(self.client, scenario)
        return runner.run()
