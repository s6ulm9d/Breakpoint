import os
import json
from typing import List, Dict, Any

class DependencyScanner:
    """Analyzes package manifests for outdated or vulnerable dependencies."""
    def __init__(self):
        # In a real tool, this would query an up-to-date database like OSV or NVD
        self.known_vulnerable = {
            "requests": {"version": "<2.31.0", "vulnerability": "SSRF in file uploads"},
            "flask": {"version": "<2.2.5", "vulnerability": "Potential DoS in session handling"},
            "django": {"version": "<4.2.1", "vulnerability": "Multiple CVEs"},
            "aiohttp": {"version": "<3.9.0", "vulnerability": "HTTP Request Smuggling"}
        }

    def scan_manifest(self, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        filename = os.path.basename(file_path)
        
        try:
            with open(file_path, "r") as f:
                if filename == "requirements.txt":
                    findings.extend(self._scan_requirements_txt(f.read(), file_path))
                elif filename == "package.json":
                    findings.extend(self._scan_package_json(f.read(), file_path))
        except: pass
        return findings

    def _scan_requirements_txt(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            
            parts = line.split("==")
            package = parts[0].strip().lower()
            version = parts[1].strip() if len(parts) > 1 else None
            
            if package in self.known_vulnerable:
                vuln_info = self.known_vulnerable[package]
                findings.append({
                    "type": "SCA",
                    "severity": "MEDIUM",
                    "package": package,
                    "version": version,
                    "vulnerability": vuln_info["vulnerability"],
                    "file": file_path,
                    "evidence": line
                })
        return findings

    def _scan_package_json(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        # Simplified scanning logic for JS dependencies
        return []
