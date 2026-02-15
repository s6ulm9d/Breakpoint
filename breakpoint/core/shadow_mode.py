"""
Shadow Mode Execution Engine
Runs V2 attacks in parallel with V1, logs comparison data without affecting reports.
"""
import json
import os
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path
from dataclasses import asdict

class ShadowModeLogger:
    """Captures V1 vs V2 comparison data for validation."""
    
    def __init__(self, output_dir: str = ".breakpoint/shadow_comparison"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.comparisons: List[Dict[str, Any]] = []
    
    def log_comparison(self, scenario_id: str, v1_result: Any, v2_result: Any):
        """Log a single V1 vs V2 comparison."""
        comparison = {
            "scenario_id": scenario_id,
            "timestamp": datetime.now().isoformat(),
            "v1": self._serialize_result(v1_result),
            "v2": self._serialize_result(v2_result),
            "metrics": self._compute_metrics(v1_result, v2_result)
        }
        self.comparisons.append(comparison)
    
    def _serialize_result(self, result) -> Dict[str, Any]:
        """Convert result to serializable format."""
        if hasattr(result, '__dict__'):
            # V2 AttackResult (dataclass)
            try:
                return asdict(result)
            except:
                pass
        
        # V1 CheckResult or dict
        if isinstance(result, dict):
            return result
        
        # Fallback: extract key attributes
        return {
            "status": getattr(result, 'status', 'UNKNOWN'),
            "severity": getattr(result, 'severity', 'UNKNOWN'),
            "details": str(getattr(result, 'details', '')),
        }
    
    def _compute_metrics(self, v1_result, v2_result) -> Dict[str, Any]:
        """Compute comparison metrics."""
        v1_status = getattr(v1_result, 'status', 'UNKNOWN')
        v2_status = getattr(v2_result, 'status', 'UNKNOWN')
        
        return {
            "status_match": v1_status == v2_status,
            "v1_detected": v1_status in ['CONFIRMED', 'VULNERABLE', 'SUSPECT'],
            "v2_detected": v2_status in ['CONFIRMED', 'VULNERABLE', 'SUSPECT'],
            "regression": v1_status in ['CONFIRMED', 'VULNERABLE'] and v2_status == 'SECURE',
            "improvement": v1_status == 'SECURE' and v2_status in ['CONFIRMED', 'VULNERABLE']
        }
    
    def save_session(self):
        """Save comparison data to disk."""
        output_file = self.output_dir / f"comparison_{self.session_id}.json"
        
        summary = self._generate_summary()
        
        data = {
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(),
            "total_comparisons": len(self.comparisons),
            "summary": summary,
            "comparisons": self.comparisons
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        return output_file, summary
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics."""
        if not self.comparisons:
            return {}
        
        total = len(self.comparisons)
        status_matches = sum(1 for c in self.comparisons if c['metrics']['status_match'])
        regressions = sum(1 for c in self.comparisons if c['metrics']['regression'])
        improvements = sum(1 for c in self.comparisons if c['metrics']['improvement'])
        
        v1_detections = sum(1 for c in self.comparisons if c['metrics']['v1_detected'])
        v2_detections = sum(1 for c in self.comparisons if c['metrics']['v2_detected'])
        
        return {
            "total_scenarios": total,
            "status_match_count": status_matches,
            "status_match_rate": status_matches / total if total > 0 else 0,
            "regressions": regressions,
            "improvements": improvements,
            "v1_detection_count": v1_detections,
            "v2_detection_count": v2_detections,
            "detection_parity": v2_detections / v1_detections if v1_detections > 0 else 0
        }
