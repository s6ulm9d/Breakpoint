"""
Attack Graph Orchestration Engine
Chains attacks based on findings to simulate real-world exploitation paths.
"""
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from .models import AttackResult, VulnerabilityStatus

class ExploitPhase(str, Enum):
    """Attack chain phases."""
    RECONNAISSANCE = "RECONNAISSANCE"  # Info gathering
    INITIAL_ACCESS = "INITIAL_ACCESS"  # First foothold
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"  # Elevate permissions
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"  # Spread access
    EXFILTRATION = "EXFILTRATION"  # Data theft

@dataclass
class AttackNode:
    """Represents a single attack in the graph."""
    attack_id: str
    phase: ExploitPhase
    prerequisites: Set[str] = field(default_factory=set)  # Required findings
    enables: Set[str] = field(default_factory=set)  # Unlocks these attacks
    priority: int = 5  # 1-10, higher = more critical

@dataclass
class ExploitPath:
    """Represents a complete exploitation chain."""
    path_id: str
    nodes: List[str]  # Ordered attack IDs
    severity_score: float  # Cumulative risk
    description: str

class AttackGraph:
    """
    Attack orchestration engine that chains findings into exploitation paths.
    
    Core Concepts:
    1. **Nodes**: Individual attacks (e.g., jwt_weakness, idor)
    2. **Edges**: Dependencies (jwt_weakness → privilege_escalation)
    3. **Paths**: Complete exploitation chains (recon → access → escalation → exfil)
    
    Logic Flow:
    1. Build graph from attack definitions
    2. As findings occur, unlock dependent attacks
    3. Prioritize next attacks based on unlocked paths
    4. Generate exploitation narratives for reports
    """
    
    def __init__(self):
        self.nodes: Dict[str, AttackNode] = {}
        self.findings: Dict[str, AttackResult] = {}  # attack_id → result
        self.unlocked_attacks: Set[str] = set()
        self.completed_attacks: Set[str] = set()
        
        self._build_graph()
    
    def _build_graph(self):
        """
        Constructs the attack dependency graph.
        
        Chain Examples:
        1. JWT Weakness → Privilege Escalation
           - jwt_weakness (INITIAL_ACCESS) → idor (PRIVILEGE_ESCALATION)
        
        2. Debug Exposure → Credential Harvesting
           - debug_exposure (RECONNAISSANCE) → secret_leak (INITIAL_ACCESS)
        
        3. Open Redirect → Phishing → Session Hijacking
           - open_redirect (RECONNAISSANCE) → xss (INITIAL_ACCESS) → jwt_brute (PRIVILEGE_ESCALATION)
        
        4. Git Exposure → Secret Extraction → Database Access
           - git_exposure (RECONNAISSANCE) → secret_leak (INITIAL_ACCESS) → sql_injection (LATERAL_MOVEMENT)
        """
        
        # ===== RECONNAISSANCE PHASE =====
        self.add_node(AttackNode(
            attack_id="debug_exposure",
            phase=ExploitPhase.RECONNAISSANCE,
            enables={"secret_leak", "env_exposure"},
            priority=8
        ))
        
        self.add_node(AttackNode(
            attack_id="git_exposure",
            phase=ExploitPhase.RECONNAISSANCE,
            enables={"secret_leak", "env_exposure"},
            priority=9
        ))
        
        self.add_node(AttackNode(
            attack_id="swagger_exposure",
            phase=ExploitPhase.RECONNAISSANCE,
            enables={"idor", "api_abuse"},
            priority=7
        ))
        
        self.add_node(AttackNode(
            attack_id="graphql_introspection",
            phase=ExploitPhase.RECONNAISSANCE,
            enables={"graphql_batching", "idor"},
            priority=7
        ))
        
        # ===== INITIAL ACCESS PHASE =====
        self.add_node(AttackNode(
            attack_id="secret_leak",
            phase=ExploitPhase.INITIAL_ACCESS,
            prerequisites={"debug_exposure", "git_exposure"},  # OR condition
            enables={"sql_injection", "ssrf", "rce"},
            priority=9
        ))
        
        self.add_node(AttackNode(
            attack_id="xss",
            phase=ExploitPhase.INITIAL_ACCESS,
            enables={"jwt_brute", "session_hijacking"},
            priority=7
        ))
        
        self.add_node(AttackNode(
            attack_id="open_redirect",
            phase=ExploitPhase.INITIAL_ACCESS,
            enables={"xss", "phishing"},
            priority=6
        ))
        
        self.add_node(AttackNode(
            attack_id="jwt_weakness",
            phase=ExploitPhase.INITIAL_ACCESS,
            enables={"idor", "privilege_escalation"},
            priority=8
        ))
        
        # ===== PRIVILEGE ESCALATION PHASE =====
        self.add_node(AttackNode(
            attack_id="idor",
            phase=ExploitPhase.PRIVILEGE_ESCALATION,
            prerequisites={"jwt_weakness", "swagger_exposure"},
            enables={"data_exfiltration"},
            priority=9
        ))
        
        self.add_node(AttackNode(
            attack_id="sql_injection",
            phase=ExploitPhase.PRIVILEGE_ESCALATION,
            prerequisites={"secret_leak"},
            enables={"data_exfiltration", "rce"},
            priority=10
        ))
        
        self.add_node(AttackNode(
            attack_id="nosql_injection",
            phase=ExploitPhase.PRIVILEGE_ESCALATION,
            enables={"data_exfiltration"},
            priority=9
        ))
        
        # ===== LATERAL MOVEMENT PHASE =====
        self.add_node(AttackNode(
            attack_id="ssrf",
            phase=ExploitPhase.LATERAL_MOVEMENT,
            prerequisites={"secret_leak"},
            enables={"internal_scan", "cloud_metadata_theft"},
            priority=8
        ))
        
        self.add_node(AttackNode(
            attack_id="rce",
            phase=ExploitPhase.LATERAL_MOVEMENT,
            prerequisites={"sql_injection", "secret_leak"},
            enables={"full_compromise"},
            priority=10
        ))
        
        # ===== EXFILTRATION PHASE =====
        self.add_node(AttackNode(
            attack_id="data_exfiltration",
            phase=ExploitPhase.EXFILTRATION,
            prerequisites={"idor", "sql_injection"},
            priority=10
        ))
    
    def add_node(self, node: AttackNode):
        """Adds an attack node to the graph."""
        self.nodes[node.attack_id] = node
    
    def record_finding(self, attack_id: str, result: AttackResult):
        """
        Records an attack result and unlocks dependent attacks.
        
        Logic:
        1. Store result in findings
        2. Mark attack as completed
        3. If CONFIRMED/VULNERABLE → unlock dependent attacks
        4. Update unlocked_attacks set
        """
        self.findings[attack_id] = result
        self.completed_attacks.add(attack_id)
        
        # Only unlock if vulnerability confirmed
        if result.status in [VulnerabilityStatus.CONFIRMED, VulnerabilityStatus.VULNERABLE]:
            node = self.nodes.get(attack_id)
            if node:
                # Unlock all dependent attacks
                for dependent_id in node.enables:
                    if dependent_id not in self.completed_attacks:
                        self.unlocked_attacks.add(dependent_id)
    
    def get_next_attacks(self, max_count: int = 5) -> List[str]:
        """
        Returns prioritized list of next attacks to run.
        
        Logic:
        1. Filter unlocked attacks whose prerequisites are met
        2. Sort by priority (descending)
        3. Return top N
        """
        ready_attacks = []
        
        for attack_id in self.unlocked_attacks:
            node = self.nodes.get(attack_id)
            if not node:
                continue
            
            # Check if prerequisites met
            if self._prerequisites_met(node):
                ready_attacks.append((attack_id, node.priority))
        
        # Sort by priority (descending)
        ready_attacks.sort(key=lambda x: x[1], reverse=True)
        
        return [attack_id for attack_id, _ in ready_attacks[:max_count]]
    
    def _prerequisites_met(self, node: AttackNode) -> bool:
        """
        Checks if attack prerequisites are satisfied.
        
        Logic:
        - If no prerequisites → always ready
        - If prerequisites → at least ONE must be confirmed (OR logic)
        """
        if not node.prerequisites:
            return True
        
        # OR logic: Any prerequisite satisfied?
        for prereq_id in node.prerequisites:
            result = self.findings.get(prereq_id)
            if result and result.status in [VulnerabilityStatus.CONFIRMED, VulnerabilityStatus.VULNERABLE]:
                return True
        
        return False
    
    def generate_exploit_paths(self) -> List[ExploitPath]:
        """
        Generates complete exploitation paths from confirmed findings.
        
        Logic:
        1. Start from RECONNAISSANCE findings
        2. Follow edges to INITIAL_ACCESS
        3. Continue through PRIVILEGE_ESCALATION → LATERAL_MOVEMENT → EXFILTRATION
        4. Calculate cumulative severity score
        5. Generate human-readable narrative
        """
        paths = []
        
        # Find all confirmed reconnaissance findings
        recon_findings = [
            attack_id for attack_id, result in self.findings.items()
            if result.status in [VulnerabilityStatus.CONFIRMED, VulnerabilityStatus.VULNERABLE]
            and self.nodes.get(attack_id)
            and self.nodes[attack_id].phase == ExploitPhase.RECONNAISSANCE
        ]
        
        # Build paths from each recon finding
        for recon_id in recon_findings:
            path = self._build_path_from(recon_id)
            if len(path.nodes) > 1:  # Only include multi-step paths
                paths.append(path)
        
        return paths
    
    def _build_path_from(self, start_id: str) -> ExploitPath:
        """
        Builds exploitation path starting from a given attack.
        
        Logic:
        1. Start with initial attack
        2. Follow 'enables' edges to confirmed findings
        3. Continue until no more confirmed dependencies
        4. Calculate severity score (sum of individual severities)
        """
        path_nodes = [start_id]
        current_id = start_id
        visited = {start_id}
        
        while True:
            node = self.nodes.get(current_id)
            if not node:
                break
            
            # Find next confirmed attack in chain
            next_id = None
            for enabled_id in node.enables:
                if enabled_id in visited:
                    continue
                
                result = self.findings.get(enabled_id)
                if result and result.status in [VulnerabilityStatus.CONFIRMED, VulnerabilityStatus.VULNERABLE]:
                    next_id = enabled_id
                    break
            
            if not next_id:
                break
            
            path_nodes.append(next_id)
            visited.add(next_id)
            current_id = next_id
        
        # Calculate severity score
        severity_map = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}
        severity_score = sum(
            severity_map.get(self.findings[nid].severity.value, 0)
            for nid in path_nodes
            if nid in self.findings
        )
        
        # Generate description
        description = self._generate_path_description(path_nodes)
        
        return ExploitPath(
            path_id=f"path_{start_id}",
            nodes=path_nodes,
            severity_score=severity_score,
            description=description
        )
    
    def _generate_path_description(self, nodes: List[str]) -> str:
        """
        Generates human-readable exploitation narrative.
        
        Example:
        "Attacker discovers exposed .git directory (git_exposure), extracts secrets 
        (secret_leak), uses credentials to perform SQL injection (sql_injection), 
        and exfiltrates sensitive data (data_exfiltration)."
        """
        if not nodes:
            return "No exploitation path"
        
        phase_descriptions = {
            ExploitPhase.RECONNAISSANCE: "discovers",
            ExploitPhase.INITIAL_ACCESS: "gains access via",
            ExploitPhase.PRIVILEGE_ESCALATION: "escalates privileges using",
            ExploitPhase.LATERAL_MOVEMENT: "moves laterally with",
            ExploitPhase.EXFILTRATION: "exfiltrates data through",
        }
        
        narrative_parts = []
        for node_id in nodes:
            node = self.nodes.get(node_id)
            if node:
                verb = phase_descriptions.get(node.phase, "exploits")
                narrative_parts.append(f"{verb} {node_id.replace('_', ' ')}")
        
        return "Attacker " + ", then ".join(narrative_parts) + "."
