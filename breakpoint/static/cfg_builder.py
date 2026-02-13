import networkx as nx
import ast
from typing import Dict, List, Any

class CFGBuilder:
    def __init__(self):
        pass

    def build_cfg(self, ast_node) -> nx.DiGraph:
        """
        Builds a Control Flow Graph from an AST.
        """
        cfg = nx.DiGraph()
        
        # Simplified CFG construction for AST nodes (Python)
        if hasattr(ast_node, 'body'):
            prev = None
            for idx, stmt in enumerate(ast_node.body):
                node_id = f"stmt_{idx}"
                cfg.add_node(node_id, stmt=stmt)
                if prev:
                    cfg.add_edge(prev, node_id)
                prev = node_id
        
        return cfg

class PDGBuilder:
    def __init__(self):
        pass

    def build_pdg(self, cfg: nx.DiGraph) -> nx.DiGraph:
        """
        Builds a Program Dependence Graph from CFG (Data + Control dependencies).
        """
        pdg = cfg.copy()
        # Add data dependencies (naive implementation for structure)
        # In full implementation, we'd resolve variable def-use chains
        return pdg
