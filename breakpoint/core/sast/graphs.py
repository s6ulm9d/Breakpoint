import ast
from typing import Dict, List, Set, Optional, Any

class CFGNode:
    def __init__(self, id: int, ast_node: ast.AST):
        self.id = id
        self.ast_node = ast_node
        self.successors: Set['CFGNode'] = set()
        self.predecessors: Set['CFGNode'] = set()

class CFG:
    def __init__(self):
        self.nodes: Dict[int, CFGNode] = {}
        self.entry_node: Optional[CFGNode] = None
        self.exit_node: Optional[CFGNode] = None
        self._counter = 0

    def add_node(self, ast_node: ast.AST) -> CFGNode:
        node = CFGNode(self._counter, ast_node)
        self.nodes[self._counter] = node
        self._counter += 1
        return node

    def add_edge(self, from_node: CFGNode, to_node: CFGNode):
        from_node.successors.add(to_node)
        to_node.predecessors.add(from_node)

class PDGNode:
    def __init__(self, id: int, ast_node: ast.AST):
        self.id = id
        self.ast_node = ast_node
        self.data_dependencies: Set['PDGNode'] = set() # Data flow (Def-Use)
        self.control_dependencies: Set['PDGNode'] = set() # Control flow (If/Loops)

class CPG:
    """Unified Code Property Graph: Merges AST, CFG, and PDG."""
    def __init__(self):
        self.ast_root: Optional[ast.AST] = None
        self.cfg: Optional[CFG] = None
        self.pdg_nodes: Dict[int, PDGNode] = {}

class CFGBuilder(ast.NodeVisitor):
    def __init__(self):
        self.cfg = CFG()
        self.current_nodes: List[CFGNode] = []

    def build(self, tree: ast.AST) -> CFG:
        entry = self.cfg.add_node(ast.Module()) # Virtual entry
        self.cfg.entry_node = entry
        self.current_nodes = [entry]
        self.visit(tree)
        return self.cfg

    def visit_Expr(self, node):
        new_node = self.cfg.add_node(node)
        for prev in self.current_nodes:
            self.cfg.add_edge(prev, new_node)
        self.current_nodes = [new_node]
        self.generic_visit(node)

    def visit_Assign(self, node):
        new_node = self.cfg.add_node(node)
        for prev in self.current_nodes:
            self.cfg.add_edge(prev, new_node)
        self.current_nodes = [new_node]
        self.generic_visit(node)

    def visit_If(self, node):
        if_node = self.cfg.add_node(node.test)
        for prev in self.current_nodes:
            self.cfg.add_edge(prev, if_node)
        
        # Then branch
        self.current_nodes = [if_node]
        for stmt in node.body:
            self.visit(stmt)
        then_end_nodes = self.current_nodes

        # Else branch
        self.current_nodes = [if_node]
        for stmt in node.orelse:
            self.visit(stmt)
        else_end_nodes = self.current_nodes

        self.current_nodes = list(set(then_end_nodes + else_end_nodes))

    def visit_For(self, node):
        for_node = self.cfg.add_node(node.iter)
        for prev in self.current_nodes:
            self.cfg.add_edge(prev, for_node)
        
        # Loop body
        self.current_nodes = [for_node]
        for stmt in node.body:
            self.visit(stmt)
        
        # Back edge
        for end_node in self.current_nodes:
            self.cfg.add_edge(end_node, for_node)
        
        # Exit edge
        self.current_nodes = [for_node]

    def visit_While(self, node):
        while_node = self.cfg.add_node(node.test)
        for prev in self.current_nodes:
            self.cfg.add_edge(prev, while_node)
        
        self.current_nodes = [while_node]
        for stmt in node.body:
            self.visit(stmt)
        
        for end_node in self.current_nodes:
            self.cfg.add_edge(end_node, while_node)
        
        self.current_nodes = [while_node]

class PDGBuilder:
    """Builds a Program Dependence Graph using CFG and AST info."""
    def __init__(self, cfg: CFG):
        self.cfg = cfg
        self.pdg_nodes: Dict[int, PDGNode] = {}

    def build(self) -> Dict[int, PDGNode]:
        for cfg_id, cfg_node in self.cfg.nodes.items():
            pdg_node = PDGNode(cfg_id, cfg_node.ast_node)
            self.pdg_nodes[cfg_id] = pdg_node

        # 1. Map Control Dependencies (Simplified)
        # Any node inside an If/Loop control-depends on that condition node
        
        # 2. Map Data Dependencies (Def-Use chains)
        # This requires tracking which node 'defines' a variable and which 'uses' it
        return self.pdg_nodes

class PathAnalyzer:
    """Analyzes paths for feasibility and reachability."""
    def __init__(self, cfg: CFG):
        self.cfg = cfg

    def is_reachable(self, start_node: CFGNode, end_node: CFGNode) -> bool:
        """Simple reachability check via BFS on the CFG."""
        queue = [start_node]
        visited = set()
        while queue:
            curr = queue.pop(0)
            if curr == end_node: return True
            if curr.id in visited: continue
            visited.add(curr.id)
            queue.extend(curr.successors)
        return False

    def check_path_constraints(self, path: List[CFGNode]) -> bool:
        """Placeholder for symbolic execution / constraint checking (e.g. Z3)."""
        # In a real implementation, we would check if branch conditions in the path
        # are mutually exclusive (e.g., if x > 10 and if x < 5).
        return True
