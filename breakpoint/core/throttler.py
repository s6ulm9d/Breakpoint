"""
Adaptive Throttling Strategy
Prevents dev server crashes via payload intensity tiers and stability detection.
"""
import time
from typing import Dict, Optional
from dataclasses import dataclass
from enum import Enum

class PayloadIntensity(str, Enum):
    """Payload intensity tiers for adaptive throttling."""
    PASSIVE = "PASSIVE"       # Read-only, no mutations (e.g., header checks)
    LIGHT = "LIGHT"           # Single parameter injection
    MEDIUM = "MEDIUM"         # Multiple parameters, moderate payloads
    HEAVY = "HEAVY"           # Large payloads, batch requests
    EXTREME = "EXTREME"       # DoS-level stress testing

@dataclass
class StabilityMetrics:
    """Tracks target server stability."""
    total_requests: int = 0
    failed_requests: int = 0
    timeout_count: int = 0
    avg_response_time: float = 0.0
    last_failure_time: Optional[float] = None
    
    @property
    def failure_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.failed_requests / self.total_requests
    
    @property
    def is_unstable(self) -> bool:
        """Target is unstable if failure rate > 20% or recent failures."""
        if self.failure_rate > 0.2:
            return True
        
        # Recent failure (within last 5 seconds)
        if self.last_failure_time and (time.time() - self.last_failure_time) < 5:
            return True
        
        return False

class AdaptiveThrottler:
    """
    Adaptive throttling engine that adjusts attack intensity based on target stability.
    
    Logic Flow:
    1. Track stability metrics (failures, timeouts, response times)
    2. Classify attacks by intensity tier
    3. Apply backoff strategies when instability detected
    4. Skip EXTREME attacks on dev environments
    """
    
    # Attack intensity classification
    INTENSITY_MAP = {
        # PASSIVE - Safe for all environments
        "header_security": PayloadIntensity.PASSIVE,
        "git_exposure": PayloadIntensity.PASSIVE,
        "debug_exposure": PayloadIntensity.PASSIVE,
        "swagger_exposure": PayloadIntensity.PASSIVE,
        
        # LIGHT - Single injection points
        "xss": PayloadIntensity.LIGHT,
        "sql_injection": PayloadIntensity.LIGHT,
        "lfi": PayloadIntensity.LIGHT,
        "open_redirect": PayloadIntensity.LIGHT,
        
        # MEDIUM - Multiple parameters
        "jwt_weakness": PayloadIntensity.MEDIUM,
        "idor": PayloadIntensity.MEDIUM,
        "ssrf": PayloadIntensity.MEDIUM,
        "nosql_injection": PayloadIntensity.MEDIUM,
        
        # HEAVY - Large payloads
        "xml_bomb": PayloadIntensity.HEAVY,
        "json_bomb": PayloadIntensity.HEAVY,
        "prototype_pollution": PayloadIntensity.HEAVY,
        "deserialization_rce": PayloadIntensity.HEAVY,
        
        # EXTREME - DoS-level
        "dos_extreme": PayloadIntensity.EXTREME,
        "dos_slowloris": PayloadIntensity.EXTREME,
        "graphql_batching": PayloadIntensity.EXTREME,
        "traffic_spike": PayloadIntensity.EXTREME,
    }
    
    # Backoff delays (seconds) per intensity tier
    BACKOFF_DELAYS = {
        PayloadIntensity.PASSIVE: 0.0,
        PayloadIntensity.LIGHT: 0.5,
        PayloadIntensity.MEDIUM: 1.0,
        PayloadIntensity.HEAVY: 2.0,
        PayloadIntensity.EXTREME: 5.0,
    }
    
    def __init__(self, is_dev_env: bool = False):
        self.is_dev_env = is_dev_env
        self.metrics = StabilityMetrics()
        self.backoff_multiplier = 1.0
    
    def should_skip_attack(self, attack_id: str) -> bool:
        """
        Determines if an attack should be skipped based on intensity and stability.
        
        Logic:
        1. EXTREME attacks → Skip on dev environments
        2. HEAVY attacks → Skip if target unstable
        3. MEDIUM attacks → Skip if target critically unstable (failure rate > 50%)
        4. LIGHT/PASSIVE → Always run
        """
        intensity = self.INTENSITY_MAP.get(attack_id, PayloadIntensity.MEDIUM)
        
        # Rule 1: Skip EXTREME on dev
        if intensity == PayloadIntensity.EXTREME and self.is_dev_env:
            return True
        
        # Rule 2: Skip HEAVY if unstable
        if intensity == PayloadIntensity.HEAVY and self.metrics.is_unstable:
            return True
        
        # Rule 3: Skip MEDIUM if critically unstable
        if intensity == PayloadIntensity.MEDIUM and self.metrics.failure_rate > 0.5:
            return True
        
        return False
    
    def get_delay_before_attack(self, attack_id: str) -> float:
        """
        Returns delay (seconds) to wait before executing attack.
        
        Logic:
        1. Base delay from BACKOFF_DELAYS
        2. Multiply by backoff_multiplier (increases with failures)
        3. Add jitter to prevent thundering herd
        """
        intensity = self.INTENSITY_MAP.get(attack_id, PayloadIntensity.MEDIUM)
        base_delay = self.BACKOFF_DELAYS[intensity]
        
        # Apply backoff multiplier
        delay = base_delay * self.backoff_multiplier
        
        # Add jitter (±20%)
        import random
        jitter = delay * random.uniform(-0.2, 0.2)
        
        return max(0, delay + jitter)
    
    def record_request(self, success: bool, response_time: float, is_timeout: bool = False):
        """
        Records request outcome and updates stability metrics.
        
        Logic:
        1. Increment total_requests
        2. If failure → increment failed_requests, update last_failure_time
        3. If timeout → increment timeout_count
        4. Update avg_response_time (rolling average)
        5. Adjust backoff_multiplier based on failure rate
        """
        self.metrics.total_requests += 1
        
        if not success:
            self.metrics.failed_requests += 1
            self.metrics.last_failure_time = time.time()
        
        if is_timeout:
            self.metrics.timeout_count += 1
        
        # Update rolling average response time
        alpha = 0.3  # Smoothing factor
        self.metrics.avg_response_time = (
            alpha * response_time + 
            (1 - alpha) * self.metrics.avg_response_time
        )
        
        # Adjust backoff multiplier
        self._adjust_backoff()
    
    def _adjust_backoff(self):
        """
        Adjusts backoff multiplier based on failure rate.
        
        Logic:
        - Failure rate < 10% → Reduce backoff (min 1.0)
        - Failure rate 10-30% → Maintain backoff
        - Failure rate > 30% → Increase backoff (max 10.0)
        """
        failure_rate = self.metrics.failure_rate
        
        if failure_rate < 0.1:
            # Stable, reduce backoff
            self.backoff_multiplier = max(1.0, self.backoff_multiplier * 0.9)
        elif failure_rate > 0.3:
            # Unstable, increase backoff
            self.backoff_multiplier = min(10.0, self.backoff_multiplier * 1.5)
        # else: maintain current backoff
    
    def get_stability_report(self) -> Dict:
        """Returns current stability metrics for logging."""
        return {
            "total_requests": self.metrics.total_requests,
            "failed_requests": self.metrics.failed_requests,
            "failure_rate": f"{self.metrics.failure_rate * 100:.1f}%",
            "avg_response_time": f"{self.metrics.avg_response_time:.2f}ms",
            "is_unstable": self.metrics.is_unstable,
            "backoff_multiplier": f"{self.backoff_multiplier:.2f}x",
        }
