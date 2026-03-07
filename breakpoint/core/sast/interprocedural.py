import ast
from typing import Dict, List, Any, Optional, Set
from .symbols import SymbolTable, Symbol

class CallGraph:
    def __init__(self):
        self.edges: Dict[str, Set[str]] = {}  # caller_fqdn -> {callee_fqdn}
        self.nodes: Set[str] = set()

    def add_edge(self, caller: str, callee: str):
        if caller not in self.edges:
            self.edges[caller] = set()
        self.edges[caller].add(callee)
        self.nodes.add(caller)
        self.nodes.add(callee)

class CallGraphBuilder(ast.NodeVisitor):
    def __init__(self, symbol_table: SymbolTable, current_scope: str):
        self.symbol_table = symbol_table
        self.current_scope = current_scope
        self.graph = CallGraph()
        self.current_function: Optional[str] = None

    def visit_FunctionDef(self, node):
        prev_func = self.current_function
        self.current_function = f"{self.current_scope}.{node.name}" if self.current_scope else node.name
        self.generic_visit(node)
        self.current_function = prev_func

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            callee_name = node.func.id
            symbol = self.symbol_table.lookup(callee_name, self.current_scope)
            if symbol and symbol.is_function:
                callee_fqdn = f"{symbol.scope}.{symbol.name}" if symbol.scope else symbol.name
                caller_fqdn = self.current_function or f"{self.current_scope}.<module>"
                self.graph.add_edge(caller_fqdn, callee_fqdn)
        self.generic_visit(node)

class TaintPropagator:
    def __init__(self, symbol_table: SymbolTable, call_graph: CallGraph):
        self.symbol_table = symbol_table
        self.call_graph = call_graph
        self.worklist: List[str] = []

    def propagate(self):
        """Propagates taint across the call graph using inter-procedural analysis."""
        # Initial worklist: all currently tainted symbols
        self.worklist = [fqdn for fqdn, sym in self.symbol_table.symbols.items() if sym.is_tainted]
        
        visited = set()
        while self.worklist:
            current_fqdn = self.worklist.pop(0)
            if current_fqdn in visited:
                continue
            visited.add(current_fqdn)

            symbol = self.symbol_table.symbols.get(current_fqdn)
            if not symbol:
                continue

            # 1. If a function is tainted, its return value is considered tainted
            # (Simplified: if any internal logic is tainted, we flag the function)
            
            # 2. Propagate to callers (Return Value Propagation)
            # If function F is tainted, and G calls F, the result in G might be tainted
            for caller_fqdn in self.call_graph.edges:
                if current_fqdn in self.call_graph.edges[caller_fqdn]:
                    # The caller depends on this tainted function
                    # Mark the caller as tainted to trigger its own analysis pass
                    caller_sym = self.symbol_table.symbols.get(caller_fqdn)
                    if caller_sym and not caller_sym.is_tainted:
                        caller_sym.is_tainted = True
                        self.worklist.append(caller_fqdn)

            # 3. Propagate to callees (Parameter Propagation)
            # If G calls F(tainted_var), then F's parameters become tainted
            # This requires mapping call arguments to function parameters
            # For now, we use a heuristic: if a caller is tainted, we re-examine its callees
            if current_fqdn in self.call_graph.edges:
                for callee_fqdn in self.call_graph.edges[current_fqdn]:
                    callee_sym = self.symbol_table.symbols.get(callee_fqdn)
                    if callee_sym and not callee_sym.is_tainted:
                        # Logic to check if tainted var was passed as arg...
                        pass 
