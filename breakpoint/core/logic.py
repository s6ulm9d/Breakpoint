from typing import Dict, Any, List, Optional
import os
import json
import base64
import random
import string
import datetime
from ..models import CheckResult, Severity, VulnerabilityStatus

# ==========================================
# ELITE INTELLIGENCE & FORENSIC LOGIC
# ==========================================

class ConfidenceEngine:
    """Aggregates evidence from multiple detection layers."""
    @staticmethod
    def calculate(result: CheckResult, static_findings: List[Dict[str, Any]] = None, ai_confirmed: bool = False) -> str:
        score = 0
        if result.status == "VULNERABLE": score += 40
        elif result.status == "CONFIRMED": score += 70
        if static_findings:
            for find in static_findings:
                if find.get("sink", "").lower() in result.type.lower():
                    score += 30
                    break
        if ai_confirmed: score += 25
        if result.artifacts and len(result.artifacts) > 0: score += 5

        if score >= 90: return "CONFIRMED"
        if score >= 70: return "HIGH"
        if score >= 40: return "MEDIUM"
        if score >= 20: return "LOW"
        return "TENTATIVE"

class RiskScoringEngine:
    """Advanced Risk Scoring using environment context."""
    @staticmethod
    def evaluate(result: CheckResult, env: str = "prod") -> Dict[str, Any]:
        base_scores = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5, "INFO": 0.0}
        score = base_scores.get(result.severity, 5.0)
        env_multiplier = 1.2 if env == "prod" else 0.8 if env == "dev" else 1.0
        conf_multiplier = {"CONFIRMED": 1.1, "HIGH": 1.0, "MEDIUM": 0.8, "LOW": 0.6, "TENTATIVE": 0.4}.get(result.confidence, 0.5)
        final_score = min(10.0, score * env_multiplier * conf_multiplier)
        return {
            "score": round(final_score, 1),
            "level": "CRITICAL" if final_score >= 9.0 else "HIGH" if final_score >= 7.0 else "MEDIUM" if final_score >= 4.0 else "LOW",
            "impact": "High" if final_score > 7 else "Medium" if final_score > 4 else "Low",
            "likelihood": "Likely" if result.confidence in ["CONFIRMED", "HIGH"] else "Possible"
        }

class EvidenceCollector:
    """Stores raw requests/responses for audit trails."""
    def __init__(self, artifact_dir: str = "artifacts/evidence"):
        self.artifact_dir = artifact_dir
        os.makedirs(self.artifact_dir, exist_ok=True)

    def collect(self, check_type: str, request: Any, response: Any, artifacts: List[Dict[str, str]] = None):
        evidence_id = f"{check_type}_{datetime.datetime.now().strftime('%H%M%S_%f')}"
        entry = {
            "id": evidence_id, "timestamp": datetime.datetime.now().isoformat(), "type": check_type,
            "request": {"method": request.method, "url": request.url, "headers": dict(request.headers), "body": str(request.body)},
            "response": {"status": response.status_code, "headers": dict(response.headers), "body": response.text[:1000]},
            "artifacts": artifacts or []
        }
        with open(os.path.join(self.artifact_dir, f"{evidence_id}.json"), 'w') as f:
            json.dump(entry, f, indent=2)
        return entry

class FuzzingEngine:
    """Adaptive Fuzzing with mutation reinforcement."""
    def __init__(self):
        self.weights = {"sql": 1.0, "xss": 1.0, "rce": 1.0}

    def mutate(self, base: str, attack_type: str) -> str:
        mutant = base
        strategy = random.choice(["append", "char_swap", "encoding"])
        if strategy == "append": mutant += random.choice(["'", "\"", "--", ";"])
        elif strategy == "encoding": mutant = mutant.replace("<", "%3c").replace(">", "%3e")
        return mutant

    def record_feedback(self, attack_type: str, delta: float):
        if delta > 0.5: self.weights[attack_type] = min(5.0, self.weights.get(attack_type, 1.0) + 0.5)
        else: self.weights[attack_type] = max(0.5, self.weights.get(attack_type, 1.0) - 0.1)

class StateManager:
    """Stateful exploit modeling."""
    def __init__(self):
        self.csrf_tokens = {}
        self.auth_tokens = {}

    def update_state(self, target: str, response_text: str, headers: Dict[str, str]):
        if "csrf" in response_text.lower():
            import re
            match = re.search(r'name=["\']csrf-token["\']\s+content=["\'](.*?)["\']', response_text)
            if match: self.csrf_tokens[target] = match.group(1)
        auth = headers.get("Authorization")
        if auth and "Bearer" in auth: self.auth_tokens[target] = auth.split(" ")[1]
