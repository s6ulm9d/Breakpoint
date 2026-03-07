import os
import ast
from typing import Dict, Any, List, Optional, Set

class Symbol:
    def __init__(self, name: str, node: ast.AST, scope: str, is_function: bool = False, is_class: bool = False):
        self.name = name
        self.node = node
        self.scope = scope
        self.is_function = is_function
        self.is_class = is_class
        self.is_tainted = False
        self.taint_source_node: Optional[ast.AST] = None
        self.type_hint: Optional[str] = None

class SymbolTable:
    def __init__(self):
        self.symbols: Dict[str, Symbol] = {}  # FQDN -> Symbol
        self.imports: Dict[str, str] = {}    # Alias -> FQDN

    def add_symbol(self, name: str, node: ast.AST, scope: str, **kwargs):
        fqdn = f"{scope}.{name}" if scope else name
        symbol = Symbol(name, node, scope, **kwargs)
        self.symbols[fqdn] = symbol
        return symbol

    def lookup(self, name: str, scope: str) -> Optional[Symbol]:
        # Try local scope first, then bubble up
        parts = scope.split('.') if scope else []
        while True:
            current_scope = '.'.join(parts)
            fqdn = f"{current_scope}.{name}" if current_scope else name
            if fqdn in self.symbols:
                return self.symbols[fqdn]
            if not parts:
                break
            parts.pop()
        
        # Check imports
        if name in self.imports:
            imported_fqdn = self.imports[name]
            return self.symbols.get(imported_fqdn)
            
        return None

class ImportResolver:
    def __init__(self, root_path: str):
        self.root_path = os.path.abspath(root_path)

    def resolve(self, module_name: str, current_file: str) -> Optional[str]:
        """Resolves a module name to a file path within the project root."""
        # Handle relative imports
        if module_name.startswith('.'):
            # Complex logic for relative imports
            return None 

        parts = module_name.split('.')
        # Try as a directory (__init__.py)
        dir_path = os.path.join(self.root_path, *parts)
        init_file = os.path.join(dir_path, "__init__.py")
        if os.path.exists(init_file):
            return init_file

        # Try as a file (.py)
        file_path = os.path.join(self.root_path, *parts[:-1], f"{parts[-1]}.py")
        if os.path.exists(file_path):
            return file_path

        return None
