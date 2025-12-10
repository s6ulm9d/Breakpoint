from dataclasses import dataclass
from typing import Any, Dict, Optional, List
import re

@dataclass
class AssertionResult:
    name: str
    passed: bool
    message: str
    metadata: Dict[str, Any]

def assert_status_in(response, allowed_codes: List[int]) -> AssertionResult:
    passed = response.status_code in allowed_codes
    return AssertionResult(
        name="status_check",
        passed=passed,
        message=f"Status {response.status_code} in {allowed_codes}" if passed else f"Status {response.status_code} NOT in {allowed_codes}",
        metadata={"actual": response.status_code, "allowed": allowed_codes}
    )

def assert_body_contains(response, pattern: str) -> AssertionResult:
    found = pattern in response.text
    return AssertionResult(
        name="body_contains",
        passed=found,
        message=f"Found pattern '{pattern}'" if found else f"Pattern '{pattern}' not found",
        metadata={}
    )

def assert_time_under(response, max_ms: float) -> AssertionResult:
    passed = response.elapsed_ms < max_ms
    return AssertionResult(
        name="latency_check",
        passed=passed,
        message=f"Latency {response.elapsed_ms:.2f}ms < {max_ms}ms" if passed else f"Latency {response.elapsed_ms:.2f}ms EXCEEDED {max_ms}ms",
        metadata={"actual": response.elapsed_ms, "max": max_ms}
    )

def assert_json_path_equals(response, path: str, expected: Any) -> AssertionResult:
    # Very simple json path support: "$.key.subkey"
    if not response.json_data:
        return AssertionResult("json_path", False, "No JSON in response", {})
    
    parts = path.replace("$.", "").split(".")
    current = response.json_data
    try:
        for p in parts:
            if isinstance(current, dict):
                current = current.get(p)
            elif isinstance(current, list) and p.isdigit():
                current = current[int(p)]
            else:
                return AssertionResult("json_path", False, f"Path {path} not found", {})
        
        passed = (current == expected)
        return AssertionResult(
            name="json_path_equals",
            passed=passed,
            message=f"Path {path} == {expected}" if passed else f"Path {path} value {current} != {expected}",
            metadata={"actual": current, "expected": expected}
        )
    except Exception as e:
        return AssertionResult("json_path", False, f"Error traversing path: {e}", {})

# Registry
ASSERTIONS = {
    "status_in": assert_status_in,
    "body_contains": assert_body_contains,
    "time_under": assert_time_under,
    "json_path_equals": assert_json_path_equals
}
