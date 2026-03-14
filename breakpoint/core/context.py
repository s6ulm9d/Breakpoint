from dataclasses import dataclass, field
from typing import Set, Dict, Optional, Any

@dataclass
class TechStack:
    languages: Set[str] = field(default_factory=set)
    frameworks: Set[str] = field(default_factory=set) # e.g., 'React', 'Flask', 'Next.js'
    servers: Set[str] = field(default_factory=set) # e.g., 'nginx', 'apache'
    databases: Set[str] = field(default_factory=set)
    confidence_scores: Dict[str, float] = field(default_factory=dict) # tech -> score (0.0 to 1.0)

@dataclass
class AuthDetails:
    type: str = "none" # 'jwt', 'session', 'basic', 'none'
    token_name: Optional[str] = None # e.g., 'Authorization', 'X-Auth-Token'
    token_value: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    login_url: Optional[str] = None
    is_authenticated: bool = False

@dataclass
class TargetContext:
    """
    Core object holding the application model.
    Passed to all specialized attacks for intelligent decision making.
    """
    base_url: str
    tech_stack: TechStack = field(default_factory=TechStack)
    auth: AuthDetails = field(default_factory=AuthDetails)
    
    # Discovery Data
    endpoints: Set[str] = field(default_factory=set)
    discovered_endpoints: list = field(default_factory=list)  # Ordered list from crawler
    parameters: Set[str] = field(default_factory=set)
    
    # Security Controls
    waf_detected: bool = False
    rate_limit_threshold: int = 100
    
    # Global Config
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    # OOB Infrastructure (injected at runtime)
    oob_provider: Any = None 

    def update_tech_stack(self, key: str, value: str, confidence: float = 1.0):
        # Update existing score or set new one (additive logic could be used here)
        existing = self.tech_stack.confidence_scores.get(value, 0.0)
        self.tech_stack.confidence_scores[value] = max(existing, confidence)
        
        # Only add to active sets if confidence is high enough (0.8 threshold)
        if self.tech_stack.confidence_scores[value] >= 0.8:
            if key == "language": self.tech_stack.languages.add(value)
            elif key == "framework": self.tech_stack.frameworks.add(value)
            elif key == "server": self.tech_stack.servers.add(value)
            elif key == "database": self.tech_stack.databases.add(value)

    def is_stack_present(self, tech: str) -> bool:
        tech = tech.lower()
        all_tech = (self.tech_stack.languages | self.tech_stack.frameworks | 
                   self.tech_stack.servers | self.tech_stack.databases)
        return any(tech in t.lower() for t in all_tech)
