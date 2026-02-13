from .cfg_builder import CFGBuilder
import ast

class TaintTracker:
    def __init__(self, sources=None, sinks=None):
        self.sources = sources or ["request", "input", "sys.argv", "os.environ"]
        self.sinks = sinks or ["eval", "exec", "os.system", "subprocess.call", "sqlite3.execute"]

    def find_paths(self, cfg):
        """
        Finds paths from sources to sinks in the CFG.
        """
        paths = []
        # Naive implementation: Check if sink is reachable from any function call
        # that looks like a source.
        # In a real static analyzer, we'd use data flow analysis (reaching definitions)
        # For Breakpoint, we return potential issues if we see source usage near sink calls
        
        # Simplified: Check for Sink usage
        for node, data in cfg.nodes(data=True):
            stmt = data.get('stmt')
            if isinstance(stmt, ast.Expr):
                if isinstance(stmt.value, ast.Call):
                    func_name = ""
                    if hasattr(stmt.value.func, "id"):
                        func_name = stmt.value.func.id
                    elif hasattr(stmt.value.func, "attr"):
                        func_name = stmt.value.func.attr
                    
                    if func_name in self.sinks:
                        paths.append({"type": "taint_sink_found", "sink": func_name})
                        
        return paths

class SymbolResolver:
    def resolve(self, symbol, scope):
        """
        Resolves symbols to definitions.
        """
        return scope.get(symbol)
