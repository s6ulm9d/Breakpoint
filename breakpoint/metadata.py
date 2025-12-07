# Central Intelligence Registry
# Defines Severity, Confidence, Descriptions, and Risk Scoring
from typing import Dict, Any


ATTACK_KNOWLEDGE_BASE = {
    # --- INJECTION ---
    "sql_injection": {
        "name": "SQL Injection",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "description": "Attempts to subvert database queries using Union-based, Error-based, and Blind techniques.",
        "risk_factors": ["Data Exfiltration", "Auth Bypass"],
        "cwe": "CWE-89"
    },
    "nosql_injection": {
        "name": "NoSQL Injection",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "description": "Injects Mongo/NoSQL operator payloads to bypass authentication or leak data.",
        "risk_factors": ["Auth Bypass", "Data Leak"],
        "cwe": "CWE-943"
    },
    "rce": {
        "name": "Remote Code Execution",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "description": "Executes system commands via shell metacharacters in input fields.",
        "risk_factors": ["Full Server Compromise"],
        "cwe": "CWE-78"
    },
    "ssti": {
        "name": "Server-Side Template Injection",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "description": "Injects template engine syntax (Jinja2, Spring) to execute arbitrary code.",
        "risk_factors": ["RCE", "Information Disclosure"],
        "cwe": "CWE-1336"
    },
    
    # --- AUTH ---
    "jwt_weakness": {
        "name": "JWT Strong Attack",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "description": "Forges JWTs using 'None' algorithm or stripped signatures to escalate privileges.",
        "risk_factors": ["Identity Spoofing", "Privilege Escalation"],
        "cwe": "CWE-345"
    },
    "idor": {
        "name": "Insecure Direct Object Reference",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "description": "Accesses resources belonging to other users by manipulating IDs.",
        "risk_factors": ["Data Leak", "Unauthorized Access"],
        "cwe": "CWE-639"
    },
    "brute_force": {
        "name": "Brute Force / Rate Limit",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Tests if the application blocks automated credential stuffing attacks.",
        "risk_factors": ["Account Takeover"],
        "cwe": "CWE-307"
    },

    # --- CVE CLASSICS ---
    "log4shell": {
        "name": "Log4Shell (CVE-2021-44228)",
        "severity": "CRITICAL",
        "confidence": "MEDIUM", # Hard to verify without OOB
        "description": "Injects JNDI lookups into headers to trigger remote class loading.",
        "risk_factors": ["RCE"],
        "cwe": "CWE-502"
    },
    
    # --- DOS ---
    "slowloris": {
        "name": "Slowloris Denial of Service",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Exhausts connection pool by holding open partial HTTP requests.",
        "risk_factors": ["Service Unavailability"],
        "cwe": "CWE-400"
    },
    "xml_bomb": {
        "name": "XML Bomb (Billion Laughs)",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "Exponential XML entity expansion to consume memory.",
        "risk_factors": ["Service Crash"],
        "cwe": "CWE-776"
    },
    
    # --- CONFIG ---
    "secret_leak": {
        "name": "Secret Leakage",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "description": "Scans responses for API keys, private keys, and cloud credentials.",
        "risk_factors": ["Infrastructure Compromise"],
        "cwe": "CWE-200"
    },
}

SEVERITY_SCORES = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 0.0
}

def get_metadata(attack_type: str) -> Dict[str, Any]:
    meta = ATTACK_KNOWLEDGE_BASE.get(attack_type, {})
    if not meta:
        # Default fallback
        return {
            "name": attack_type.replace("_", " ").title(),
            "severity": "MEDIUM",
            "confidence": "LOW",
            "description": "Custom or unknown attack type.",
            "risk_factors": ["Unknown"],
            "cwe": "Unknown"
        }
    return meta
