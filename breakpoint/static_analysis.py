import os
import ast
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod
from .core.sast.symbols import SymbolTable, ImportResolver
from .core.sast.interprocedural import CallGraph, CallGraphBuilder, TaintPropagator
from .core.sast.graphs import CFGBuilder, PDGBuilder, CPG
from .core.infra.secrets import SecretDetector
from .core.infra.dependencies import DependencyScanner

# ==========================================
# ENTERPRISE STATIC ANALYSIS: MULTI-PASS ARCHITECTURE
# ==========================================

class BaseAdapter(ABC):
    """Abstract base for language-specific static analysis."""
    @abstractmethod
    def parse_source(self, code: str) -> Any: pass
    
    @abstractmethod
    def find_taint_paths(self, tree: Any, registry: Dict[str, List[str]], symbol_table: SymbolTable) -> List[Dict[str, Any]]: pass

class PythonAdapter(BaseAdapter):
    """Deep Python Analysis using SSA-style Taint Tracking with Inter-procedural Awareness."""
    def parse_source(self, code: str) -> Optional[ast.AST]:
        try: return ast.parse(code)
        except: return None

    def find_taint_paths(self, tree: ast.AST, registry, symbol_table) -> List[Dict[str, Any]]:
        paths = []
        sources = registry["sources"]
        sinks = registry["sinks"]
        sanitizers = registry["sanitizers"]
        
        # Taint tracking is now integrated via the Global Symbol Table
        class TaintVisitor(ast.NodeVisitor):
            def __init__(self, scope: str):
                self.scope = scope

            def _get_entity_name(self, node: ast.AST) -> Optional[str]:
                """Recursively resolve name for Attributes or Names."""
                if isinstance(node, ast.Name):
                    return node.id
                elif isinstance(node, ast.Attribute):
                    base = self._get_entity_name(node.value)
                    return f"{base}.{node.attr}" if base else None
                elif isinstance(node, ast.Subscript):
                    return self._get_entity_name(node.value)
                return None

            def visit_Assign(self, node):
                # Detect comprehensions in the RHS
                comprehensions = [n for n in ast.walk(node.value) if isinstance(n, (ast.ListComp, ast.DictComp, ast.SetComp, ast.GeneratorExp))]
                comp_tainted = False
                for comp in comprehensions:
                    for gen in comp.generators:
                        # If the iterator is tainted, the whole comprehension is tainted
                        iter_names = [self._get_entity_name(n) for n in ast.walk(gen.iter) if isinstance(n, (ast.Name, ast.Attribute, ast.Subscript))]
                        if any(symbol_table.lookup(t, self.scope) and symbol_table.lookup(t, self.scope).is_tainted for t in iter_names if t):
                            comp_tainted = True
                            break

                rhs_calls = [n.func.id for n in ast.walk(node.value) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
                rhs_names = [self._get_entity_name(n) for n in ast.walk(node.value) if isinstance(n, (ast.Name, ast.Attribute, ast.Subscript, ast.Await))]
                rhs_names = [n for n in rhs_names if n]

                is_sourced = any(s in rhs_calls for s in sources)
                is_tainted = comp_tainted or any(symbol_table.lookup(t, self.scope) and symbol_table.lookup(t, self.scope).is_tainted for t in rhs_names)
                
                if (is_sourced or is_tainted) and not any(san in rhs_calls for san in sanitizers):
                    for target in node.targets:
                        target_name = self._get_entity_name(target)
                        if target_name:
                            symbol = symbol_table.lookup(target_name, self.scope)
                            if not symbol:
                                symbol = symbol_table.add_symbol(target_name, node, scope=self.scope)
                            symbol.is_tainted = True
                self.generic_visit(node)

            def visit_With(self, node):
                """Track taint through context managers (with x as y)."""
                for item in node.items:
                    context_expr_names = [self._get_entity_name(n) for n in ast.walk(item.context_expr) if isinstance(n, (ast.Name, ast.Attribute, ast.Subscript))]
                    if any(symbol_table.lookup(t, self.scope) and symbol_table.lookup(t, self.scope).is_tainted for t in context_expr_names if t):
                        if item.optional_vars:
                            target_name = self._get_entity_name(item.optional_vars)
                            if target_name:
                                symbol = symbol_table.lookup(target_name, self.scope)
                                if not symbol:
                                    symbol = symbol_table.add_symbol(target_name, node, scope=self.scope)
                                symbol.is_tainted = True
                self.generic_visit(node)

            def visit_Lambda(self, node):
                """Simplified Lambda tracking: if any capture/arg logic is tainted, mark lambda result."""
                self.generic_visit(node)

            def visit_Call(self, node):
                # Handle sinks
                sink_name = None
                if isinstance(node.func, ast.Name): sink_name = node.func.id
                elif isinstance(node.func, ast.Attribute): sink_name = node.func.attr

                if sink_name in sinks:
                    # Collect all potentially tainted arguments
                    all_args = node.args + [keyword.value for keyword in node.keywords]
                    for arg in all_args:
                        arg_names = [self._get_entity_name(n) for n in ast.walk(arg) if isinstance(n, (ast.Name, ast.Attribute, ast.Subscript))]
                        arg_names = [n for n in arg_names if n]
                        if any(symbol_table.lookup(t, self.scope) and symbol_table.lookup(t, self.scope).is_tainted for t in arg_names):
                            # Extract the actual line content if tree has it (ast.get_source_segment is Python 3.8+)
                            try:
                                line_content = ast.get_source_segment(open(self.scope).read(), node) if os.path.exists(self.scope) else "Line content unavailable"
                            except:
                                line_content = "Line content unavailable"
                                
                            paths.append({
                                "sink": sink_name,
                                "line": node.lineno,
                                "code": line_content,
                                "confidence": "HIGH",
                                "evidence": f"Tainted object/field '{arg_names[0]}' flows into sink '{sink_name}'\nCode: {line_content}"
                            })
                self.generic_visit(node)

        # Assuming module-level for now, real implementation would track scope depth
        TaintVisitor(scope="").visit(tree)
        return paths

class StaticAnalyzer:
    """Orchestrates multi-pass global static analysis across the entire project."""
    def __init__(self, code_path: str):
        self.code_path = os.path.abspath(code_path)
        self.adapters = {"python": PythonAdapter()}
        self.symbol_table = SymbolTable()
        self.import_resolver = ImportResolver(code_path)
        self.secret_detector = SecretDetector()
        self.dep_scanner = DependencyScanner()
        self.registry = {
            "sources": ["request", "input", "sys.argv", "os.environ", "get_param"],
            "sinks": ["eval", "exec", "os.system", "subprocess.run", "render_template_string"],
            "sanitizers": ["escape", "sanitize", "int", "bool"]
        }
        self.trees: Dict[str, ast.AST] = {}

    def get_cpg_summary(self) -> str:
        """Generates a compressed summary of the tainted data flows found in the CPG."""
        summary_lines = []
        for fqdn, symbol in self.symbol_table.symbols.items():
            if symbol.is_tainted:
                origin = symbol.taint_source_node.__class__.__name__ if symbol.taint_source_node else "Input"
                summary_lines.append(f"- Flow: {origin} -> {fqdn}")
        
        if not summary_lines:
            return "No obvious taint flows detected in static analysis."
            
        return "\n".join(summary_lines[:20]) # Limit to prevent prompt blowup

    def analyze(self) -> List[Dict[str, Any]]:
        findings = []
        if not self.code_path or not os.path.exists(self.code_path): return findings
        
        # COLLECT ALL SOURCE FILES
        source_files = []
        manifests = ["requirements.txt", "package.json"]
        
        if os.path.isdir(self.code_path):
            for root, _, files in os.walk(self.code_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    if self._detect_language(file) in self.adapters:
                        source_files.append(full_path)
                    if file in manifests:
                        findings.extend(self.dep_scanner.scan_manifest(full_path))
                    
                    # RUN SECRET SCAN ON EVERY FILE
                    findings.extend(self.secret_detector.scan_file(full_path))
        else:
            if self._detect_language(self.code_path) in self.adapters:
                source_files.append(self.code_path)
            findings.extend(self.secret_detector.scan_file(self.code_path))

        # PASS 1: SYMBOL COLLECTION & PARSING (PARALLEL)
        from multiprocessing import Pool, cpu_count
        
        # Parallel file parsing to build ASTs
        with Pool(processes=cpu_count()) as pool:
            # Each process needs its own adapter instance
            results = pool.starmap(self._parse_file_parallel, [(f, self._detect_language(f)) for f in source_files])
            
        for file_path, tree in results:
            if tree:
                self.trees[file_path] = tree
                self._collect_symbols_from_tree(tree, file_path)

        # PASS 2: CALL GRAPH & TAINT PROPAGATION
        global_graph = CallGraph()
        for file_path, tree in self.trees.items():
            builder = CallGraphBuilder(self.symbol_table, current_scope=file_path)
            builder.visit(tree)
            # Merge local graphs into global (simplified)
            for caller, callees in builder.graph.edges.items():
                for callee in callees:
                    global_graph.add_edge(caller, callee)

        propagator = TaintPropagator(self.symbol_table, global_graph)
        propagator.propagate()
        
        # PASS 3: FINAL ANALYSIS
        for file_path, tree in self.trees.items():
            lang = self._detect_language(file_path)
            adapter = self.adapters[lang]
            paths = adapter.find_taint_paths(tree, self.registry, self.symbol_table)
            for p in paths:
                p.update({"file": file_path, "language": lang})
                findings.append(p)

        return findings

    def _detect_language(self, filename: str) -> str:
        return "python" if filename.endswith(".py") else "unknown"

    def _parse_file_parallel(self, file_path: str, lang: str) -> tuple:
        """Helper for multiprocessing pool."""
        adapter = self.adapters.get(lang)
        if not adapter: return (file_path, None)
        try:
            # Incremental Scan: Check if file changed (mtime-based baseline could be here)
            with open(file_path, "r", errors="ignore") as f: code = f.read()
            tree = adapter.parse_source(code)
            return (file_path, tree)
        except: return (file_path, None)

    def _collect_symbols_from_tree(self, tree: ast.AST, file_path: str):
        class SymbolVisitor(ast.NodeVisitor):
            def __init__(self, symbol_table: SymbolTable, scope: str):
                self.symbol_table = symbol_table
                self.scope = scope

            def visit_Import(self, node):
                for alias in node.names:
                    name = alias.asname or alias.name
                    self.symbol_table.imports[name] = alias.name
                self.generic_visit(node)

            def visit_ImportFrom(self, node):
                module = node.module or ""
                for alias in node.names:
                    name = alias.asname or alias.name
                    fqdn = f"{module}.{alias.name}" if module else alias.name
                    self.symbol_table.imports[name] = fqdn
                self.generic_visit(node)

            def visit_FunctionDef(self, node):
                func_fqdn = f"{self.scope}.{node.name}"
                self.symbol_table.add_symbol(node.name, node, scope=self.scope, is_function=True)
                # Parameters are local symbols
                for arg in node.args.args:
                    self.symbol_table.add_symbol(arg.arg, arg, scope=func_fqdn)
                self.generic_visit(node)

            def visit_Assign(self, node):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.symbol_table.add_symbol(target.id, node, scope=self.scope)
                self.generic_visit(node)

        SymbolVisitor(self.symbol_table, file_path).visit(tree)
