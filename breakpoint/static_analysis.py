from .static.ast_parser import ASTParser
from .static.cfg_builder import CFGBuilder, PDGBuilder
from .static.taint_tracker import TaintTracker
import os

class StaticAnalyzer:
    def __init__(self, code_path):
        self.code_path = code_path
        self.parser = ASTParser()
        self.cfg_builder = CFGBuilder()
        self.pdg_builder = PDGBuilder()
        self.taint_tracker = TaintTracker()

    def analyze(self):
        """
        Runs full static analysis on the codebase.
        Returns a dict of findings:
        - Source-to-sink paths
        - Data flow vulnerabilities
        """
        findings = []
        try:
            # Analyze target file or directory
            if os.path.isdir(self.code_path):
                for root, _, files in os.walk(self.code_path):
                    for file in files:
                        if file.endswith(".py"):
                            findings.extend(self._analyze_file(os.path.join(root, file)))
            else:
                findings.extend(self._analyze_file(self.code_path))
        except Exception as e:
            # In production, we log this and proceed with runtime checks
            pass
        return findings

    def _analyze_file(self, file_path):
        findings = []
        # 1. Parse AST
        ast_tree = self.parser.parse_file(file_path)
        if not ast_tree:
            return findings

        # 2. Build CFG
        cfg = self.cfg_builder.build_cfg(ast_tree)
        
        # 3. Build PDG
        pdg = self.pdg_builder.build_pdg(cfg)
        
        # 4. Taint Analysis
        taint_paths = self.taint_tracker.find_paths(pdg)
        for path in taint_paths:
            path["file"] = file_path
            findings.append(path)

        return findings
