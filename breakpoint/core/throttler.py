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
        """Target is unstable if failure rate > 30% or recent failures."""
        if self.failure_rate > 0.3: 
            return True
        
        # Recent failure (within last 2 seconds)
        if self.last_failure_time and (time.time() - self.last_failure_time) < 2:
            return True
        
        return False

class AdaptiveThrottler:
    """
    Adaptive throttling engine that adjusts attack intensity based on target stability.
    """
    
    # Attack intensity classification
    INTENSITY_MAP = {
        # PASSIVE - Safe for all environments
        "header_security": PayloadIntensity.PASSIVE,
        "security_headers": PayloadIntensity.PASSIVE,
        "git_exposure": PayloadIntensity.PASSIVE,
        "git_exposure_check": PayloadIntensity.PASSIVE,
        "debug_exposure": PayloadIntensity.PASSIVE,
        "swagger_exposure": PayloadIntensity.PASSIVE,
        "clickjacking": PayloadIntensity.PASSIVE,
        "clickjacking_check": PayloadIntensity.PASSIVE,
        "env_exposure": PayloadIntensity.PASSIVE,
        "env_exposure_check": PayloadIntensity.PASSIVE,
        
        # LIGHT - Single injection points
        "xss": PayloadIntensity.LIGHT,
        "sql_injection": PayloadIntensity.LIGHT,
        "lfi": PayloadIntensity.LIGHT,
        "open_redirect": PayloadIntensity.LIGHT,
        "brute_force": PayloadIntensity.LIGHT,
        
        # MEDIUM - Multiple parameters
        "jwt_weakness": PayloadIntensity.MEDIUM,
        "jwt_none_alg": PayloadIntensity.MEDIUM,
        "idor": PayloadIntensity.MEDIUM,
        "ssrf": PayloadIntensity.MEDIUM,
        "ssrf_scan": PayloadIntensity.MEDIUM,
        "nosql_injection": PayloadIntensity.MEDIUM,
        "nosql_injection_login": PayloadIntensity.MEDIUM,
        "email_injection": PayloadIntensity.MEDIUM,
        "otp_reuse": PayloadIntensity.MEDIUM,
        
        # HEAVY - Large payloads / RCE
        "xml_bomb": PayloadIntensity.HEAVY,
        "json_bomb": PayloadIntensity.HEAVY,
        "prototype_pollution": PayloadIntensity.HEAVY,
        "deserialization_rce": PayloadIntensity.HEAVY,
        "rce": PayloadIntensity.HEAVY,
        "rce_params_post": PayloadIntensity.HEAVY,
        "rce_shell_shock": PayloadIntensity.HEAVY,
        "rce_reverse_shell_attempt": PayloadIntensity.HEAVY,
        "ssrf_cloud_metadata": PayloadIntensity.HEAVY,
        "ssrf_intranet_port_scan": PayloadIntensity.HEAVY,
        "file_upload_shell": PayloadIntensity.HEAVY,
        "react_server_component_injection": PayloadIntensity.HEAVY,
        "trust_boundary_violation": PayloadIntensity.HEAVY,
        "redos_validation_attack": PayloadIntensity.HEAVY,
        
        # EXTREME - DoS-level
        "dos_extreme": PayloadIntensity.EXTREME,
        "dos_extreme_annihilation_post": PayloadIntensity.EXTREME,
        "dos_slowloris": PayloadIntensity.EXTREME,
        "slowloris_dos": PayloadIntensity.EXTREME,
        "graphql_batching": PayloadIntensity.EXTREME,
        "graphql_batching_dos": PayloadIntensity.EXTREME,
        "traffic_spike": PayloadIntensity.EXTREME,
        "traffic_spike_load_post": PayloadIntensity.EXTREME,
    }
    
    # Backoff delays (seconds) per intensity tier
    BACKOFF_DELAYS = {
        PayloadIntensity.PASSIVE: 0.05, # Added small delay
        PayloadIntensity.LIGHT: 0.5,
        PayloadIntensity.MEDIUM: 1.5, # Increased
        PayloadIntensity.HEAVY: 3.5,  # Increased
        PayloadIntensity.EXTREME: 10.0, # Increased
    }
    
    def __init__(self, is_dev_env: bool = False):
        self.is_dev_env = is_dev_env
        self.metrics = StabilityMetrics()
        self.backoff_multiplier = 1.0
    
    def should_skip_attack(self, attack_id: str) -> bool:
        """Determines if an attack should be skipped based on intensity and stability."""
        intensity = self.INTENSITY_MAP.get(attack_id, PayloadIntensity.MEDIUM)
        
        # Rule 1: NEVER skip if not in dev environment (localhost)
        # Security pros want thorough scans on remote targets.
        if not self.is_dev_env:
            # Only skip if the server is technically DEAD (100% failure rate over 10+ requests)
            if self.metrics.total_requests > 10 and self.metrics.failure_rate > 0.95:
                return True
            return False

        # RULE: Skip EXTREME on dev always to prevent local crashes
        if intensity == PayloadIntensity.EXTREME:
            return True
        
        # Rule 2: Skip HEAVY if unstable (Dev Only)
        if intensity == PayloadIntensity.HEAVY and self.metrics.is_unstable:
            return True
        
        # Rule 3: Skip MEDIUM if critically unstable (Dev Only)
        if intensity == PayloadIntensity.MEDIUM and self.metrics.failure_rate > 0.7:
            return True
        
        return False
    
    def get_delay_before_attack(self, attack_id: str) -> float:
        """Returns delay (seconds) to wait before executing attack."""
        intensity = self.INTENSITY_MAP.get(attack_id, PayloadIntensity.MEDIUM)
        base_delay = self.BACKOFF_DELAYS[intensity]
        
        # Localhost gets a multiplier boost to be extra safe
        multiplier = self.backoff_multiplier
        if self.is_dev_env:
            multiplier *= 2.0
            
        delay = base_delay * multiplier
        
        # Add jitter (±10%)
        import random
        jitter = delay * random.uniform(-0.1, 0.1)
        
        return max(0, delay + jitter)
    
    def record_request(self, success: bool, response_time: float, is_timeout: bool = False):
        """Records request outcome and updates stability metrics."""
        self.metrics.total_requests += 1
        
        if not success:
            self.metrics.failed_requests += 1
            self.metrics.last_failure_time = time.time()
            # Less aggressive backoff: 1.5x instead of 2.0x, cap at 10.0x
            self.backoff_multiplier = min(10.0, self.backoff_multiplier * 1.5)
        else:
            # Quickly recover
            self.backoff_multiplier = max(1.0, self.backoff_multiplier * 0.8)
        
        if is_timeout:
            self.metrics.timeout_count += 1
        
        # Update rolling average response time
        alpha = 0.3
        self.metrics.avg_response_time = (
            alpha * response_time + 
            (1 - alpha) * self.metrics.avg_response_time
        )
    
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
            "suggested_concurrency": self.get_suggested_concurrency(10)
        }

    def get_suggested_concurrency(self, max_concurrency: int) -> int:
        """
        Suggests a concurrency level based on stability.
        
        - Stable (<5% failure): max_concurrency
        - Unstable (10-30% failure): 50% of max
        - Critically Unstable (>30% failure): 1 (Sequential)
        """
        rate = self.metrics.failure_rate
        if rate < 0.05:
            return max_concurrency
        if rate < 0.3:
            return max(2, int(max_concurrency * 0.5))
        return 1 # Sequential execution if target is dying
