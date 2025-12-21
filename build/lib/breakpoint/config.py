from typing import Any, Dict
# [SECURITY] Redacted internal testing target
# Do not commit real targets to GitHub
DEFAULT_TARGET = "http://localhost:3000"

def get_config():
    return {
        "timeout": 10,
        "max_threads": 50,
        "user_agent": "BREAKPOINT_AUDIT_ENGINE/2.0"
    }
