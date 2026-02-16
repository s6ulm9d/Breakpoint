import os
import ast
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod

# ==========================================
# ELITE STATIC ANALYSIS: ADAPTER ARCHITECTURE
# ==========================================

class BaseAdapter(ABC):
    """Abstract base for language-specific static analysis."""
    @abstractmethod
    def parse_source(self, code: str) -> Any: pass
    
    @abstractmethod
    def find_taint_paths(self, tree: Any, sources: List[str], sinks: List[str], sanitizers: List[str]) -> List[Dict[str, Any]]: pass

class PythonAdapter(BaseAdapter):
    """Deep Python Analysis using SSA-style Taint Tracking."""
    def parse_source(self, code: str) -> Optional[ast.AST]:
        try: return ast.parse(code)
        except: return None

    def find_taint_paths(self, tree: ast.AST, sources, sinks, sanitizers) -> List[Dict[str, Any]]:
        paths = []
        tainted_vars = set()

        class TaintVisitor(ast.NodeVisitor):
            def visit_Assign(self, node):
                # SSA-style tracking: If RHS is a source or contains a tainted var, LHS becomes tainted
                rhs_calls = [n.func.id for n in ast.walk(node.value) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
                rhs_names = [n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)]
                
                is_sourced = any(s in rhs_calls for s in sources)
                is_tainted = any(t in rhs_names for t in tainted_vars)
                
                if (is_sourced or is_tainted) and not any(san in rhs_calls for san in sanitizers):
                    for target in node.targets:
                        if isinstance(target, ast.Name): tainted_vars.add(target.id)
                self.generic_visit(node)

            def visit_Call(self, node):
                if isinstance(node.func, ast.Name) and node.func.id in sinks:
                    # Check if any argument is tainted
                    args = [n.id for arg in node.args for n in ast.walk(arg) if isinstance(n, ast.Name)]
                    if any(t in args for t in tainted_vars):
                        paths.append({
                            "sink": node.func.id,
                            "line": node.lineno,
                            "confidence": "HIGH",
                            "evidence": f"Tainted variable flows into {node.func.id}"
                        })
                self.generic_visit(node)

        TaintVisitor().visit(tree)
        return paths

class StaticAnalyzer:
    """Orchestrates multi-language static analysis with consolidated adapters."""
    def __init__(self, code_path: str):
        self.code_path = code_path
        self.adapters = {"python": PythonAdapter()}
        self.registry = {
            "sources": ["request", "input", "sys.argv", "os.environ", "get_param"],
            "sinks": ["eval", "exec", "os.system", "subprocess.run", "render_template_string"],
            "sanitizers": ["escape", "sanitize", "int", "bool"]
        }

    def analyze(self) -> List[Dict[str, Any]]:
        findings = []
        if not self.code_path or not os.path.exists(self.code_path): return findings
        
        if os.path.isdir(self.code_path):
            for root, _, files in os.walk(self.code_path):
                for file in files:
                    lang = self._detect_language(file)
                    if lang in self.adapters: findings.extend(self._analyze_file(os.path.join(root, file), lang))
        else:
            lang = self._detect_language(self.code_path)
            if lang in self.adapters: findings.extend(self._analyze_file(self.code_path, lang))
        return findings

    def _detect_language(self, filename: str) -> str:
        return "python" if filename.endswith(".py") else "unknown"

    def _analyze_file(self, file_path: str, lang: str) -> List[Dict[str, Any]]:
        findings = []
        adapter = self.adapters.get(lang)
        try:
            with open(file_path, "r", errors="ignore") as f: code = f.read()
            tree = adapter.parse_source(code)
            if tree:
                paths = adapter.find_taint_paths(tree, self.registry["sources"], self.registry["sinks"], self.registry["sanitizers"])
                for p in paths:
                    p.update({"file": file_path, "language": lang})
                    findings.append(p)
        except: pass
        return findings
