# Central Intelligence Registry
# Defines Severity, Confidence, Descriptions, and Risk Scoring
from typing import Dict, Any, List
from dataclasses import dataclass, field

class RiskTier:
    LOW = "LOW"         # Informational, negligible impact
    MEDIUM = "MEDIUM"   # Limited exposure or misuse
    HIGH = "HIGH"       # Serious compromise potential
    CRITICAL = "CRITICAL" # Outage, takeover, legal risk

@dataclass
class AttackMetadata:
    name: str
    description: str
    risk_tier: str = RiskTier.LOW
    destructive: bool = False  # False = safe by design; True = can cause outage
    impact_simulation: str = "No impact analysis provided." # "If exploited, X would happen"
    impact_execution: str = "Standard probe execution."     # "We will flood X with Y packets"
    tags: List[str] = field(default_factory=list)
    payload_count: int = 0
    confidence: str = "LOW"
    severity: str = "LOW" # Legacy, mapping to risk_tier recommended
    
    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "risk_tier": self.risk_tier,
            "destructive": self.destructive,
            "impact_simulation": self.impact_simulation,
            "impact_execution": self.impact_execution,
            "tags": self.tags,
            "payload_count": self.payload_count,
            "confidence": self.confidence,
            "severity": self.severity
        }

# --- LEGACY DICT SUPPORT (MIGRATING TO CLASSES) ---
# We keep this for now to ensure we don't break existing lookups
ATTACK_KNOWLEDGE_BASE = {
    # --- INJECTION ---
    "sql_injection": {
        "name": "SQL Injection",
        "severity": "CRITICAL",
        "risk_tier": RiskTier.CRITICAL,
        "destructive": True,
        "impact_simulation": "Would allow unauthorized data access and potential deletion.",
        "impact_execution": "Injects payloads that may alter database state or dump tables.",
        "confidence": "HIGH",
        "description": "Attempts to subvert database queries using Union-based, Error-based, and Blind techniques.",
    },
    "nosql_injection": {
        "name": "NoSQL Injection",
        "severity": "HIGH",
        "risk_tier": RiskTier.HIGH,
        "destructive": False,
        "impact_simulation": "Could allow authentication bypass.",
        "impact_execution": "Injects NoSQL logic operators.",
        "confidence": "MEDIUM",
        "description": "Injects Mongo/NoSQL operator payloads to bypass authentication or leak data.",
    },
    "rce": {
        "name": "Remote Code Execution",
        "severity": "CRITICAL",
        "risk_tier": RiskTier.CRITICAL,
        "destructive": True,
        "impact_simulation": "Would grant full system control to attacker.",
        "impact_execution": "Executes shell commands on the server.",
        "confidence": "HIGH",
        "description": "Executes system commands via shell metacharacters in input fields.",
    },
    
    # --- DOS ---
    "slowloris": {
        "name": "Slowloris Denial of Service",
        "severity": "HIGH",
        "risk_tier": RiskTier.CRITICAL,
        "destructive": True,
        "impact_simulation": "Server connection pool exhaustion leading to unresponsiveness.",
        "impact_execution": "Opens thousands of connections and keeps them alive, blocking legitimate users.",
        "confidence": "HIGH",
        "description": "Exhausts connection pool by holding open partial HTTP requests.",
    },
    "dos_extreme": {
        "name": "High-Concurrency Stress Mode",
        "severity": "CRITICAL",
        "risk_tier": RiskTier.CRITICAL,
        "destructive": True,
        "impact_simulation": "Complete service outage due to resource exhaustion.",
        "impact_execution": "Floods the target with high-concurrency requests.",
        "confidence": "HIGH",
        "description": "Aggressive stress testing to induce failure.",
    },
    "advanced_dos": {
        "name": "Advanced HTTP Flood",
        "severity": "HIGH",
        "risk_tier": RiskTier.HIGH,
        "destructive": True,
        "impact_simulation": "Service degradation or temporary outage.",
        "impact_execution": "Sends high-volume complex HTTP requests.",
        "confidence": "MEDIUM",
        "description": "Layer 7 DoS using mixed HTTP methods and headers.",
    },
    "xml_bomb": {
        "name": "XML Bomb (Billion Laughs)",
        "severity": "HIGH",
        "risk_tier": RiskTier.HIGH,
        "destructive": True,
        "impact_simulation": "Memory exhaustion requiring service restart.",
        "impact_execution": "Sends nested XML entities to consume server RAM.",
        "confidence": "HIGH",
        "description": "Exponential XML entity expansion.",
    },
    
    # --- WEB EXPLOITS ---
    "xss": {
        "name": "Cross-Site Scripting (Reflected)",
        "severity": "MEDIUM",
        "risk_tier": RiskTier.MEDIUM,
        "destructive": False,
        "impact_simulation": "Execution of malicious scripts in victim browsers.",
        "impact_execution": "Injects script tags into parameters.",
        "confidence": "HIGH",
        "description": "Reflects user input without sanitization.",
    },
    "idor": {
        "name": "Insecure Direct Object Reference",
        "severity": "HIGH",
        "risk_tier": RiskTier.HIGH,
        "destructive": False,
        "impact_simulation": "Unauthorized access to other users' data.",
        "impact_execution": "Iterates through object IDs.",
        "confidence": "MEDIUM",
        "description": "Accesses restricted resources by manipulating IDs.",
    },
    "lfi": {
        "name": "Local File Inclusion",
        "severity": "CRITICAL",
        "risk_tier": RiskTier.CRITICAL,
        "destructive": False,
        "impact_simulation": "Exposure of sensitive system files (/etc/passwd).",
        "impact_execution": "Traverses directory paths.",
        "confidence": "HIGH",
        "description": "Reads local files via path traversal.",
    },
    "ssrf": {
        "name": "Server-Side Request Forgery",
        "severity": "CRITICAL",
        "risk_tier": RiskTier.CRITICAL,
        "destructive": False,
        "impact_simulation": "Access to internal network services or cloud metadata.",
        "impact_execution": "Forces server to connect to arbitrary URLs.",
        "confidence": "MEDIUM",
        "description": "Induces server to make outbound requests.",
    },
    "jwt_weakness": {
        "name": "JWT Weakness",
        "severity": "CRITICAL",
        "risk_tier": RiskTier.CRITICAL,
        "destructive": False,
        "impact_simulation": "Authentication bypass and account takeover.",
        "impact_execution": "Modifies JWT signatures and claims.",
        "confidence": "HIGH",
        "description": "Exploits weak or missing JWT signatures.",
    },
    
    # --- CONFIG ---
    "secret_leak": {
        "name": "Secret Leakage",
        "severity": "CRITICAL",
        "risk_tier": RiskTier.CRITICAL,
        "destructive": False,
        "impact_simulation": "Compromise of API keys and infrastructure credentials.",
        "impact_execution": "Scans responses for known secret patterns.",
        "confidence": "HIGH",
        "description": "Detects exposed secrets in HTTP responses.",
    },
    "debug_exposure": {
         "name": "Debug Mode Exposure",
         "severity": "MEDIUM",
         "risk_tier": RiskTier.MEDIUM,
         "destructive": False,
         "impact_simulation": "Information disclosure aiding further attacks.",
         "impact_execution": "Checks for debug pages and stack traces.",
         "confidence": "HIGH",
         "description": "Identifies enabled debug modes.",
    },

    # --- CVE ---
    "log4shell": {
        "name": "Log4Shell (CVE-2021-44228)",
        "severity": "CRITICAL",
        "risk_tier": RiskTier.CRITICAL,
        "destructive": True,
        "impact_simulation": "Remote Code Execution via logging.",
        "impact_execution": "Injects JNDI payloads.",
        "confidence": "MEDIUM",
        "description": "Exploits Log4j vulnerability.",
    },
    
    # --- DEFAULT ---
    "default": {
        "name": "Unknown Attack",
        "severity": "MEDIUM",
        "risk_tier": RiskTier.MEDIUM,
        "destructive": False,
        "impact_simulation": "Unknown impact.",
        "impact_execution": "Standard probe.",
        "confidence": "LOW",
        "description": "Standard security probe.",
    }
}

SEVERITY_SCORES = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 0.0
}

def get_metadata(attack_type: str) -> Dict[str, Any]:
    meta = ATTACK_KNOWLEDGE_BASE.get(attack_type, ATTACK_KNOWLEDGE_BASE["default"])
    if "risk_tier" not in meta:
        meta["risk_tier"] = RiskTier.MEDIUM
    if "destructive" not in meta:
        meta["destructive"] = False
    return meta
