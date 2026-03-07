import json
from typing import List, Dict, Any

class ReportGenerator:
    """Generates security reports in various formats (SARIF, JSON, HTML)."""
    
    CWE_MAPPING = {
        "SQL_INJECTION": "CWE-89",
        "COMMAND_INJECTION": "CWE-78",
        "SECRET": "CWE-798",
        "SCA": "CWE-1104",
        "SSTI": "CWE-1336",
        "XSS": "CWE-79"
    }

    def __init__(self, findings: List[Dict[str, Any]]):
        self.findings = findings

    def to_json(self) -> str:
        # Add CWE/OWASP info to findings
        for f in self.findings:
            f_type = f.get("type", "UNKNOWN").upper()
            f["cwe"] = self.CWE_MAPPING.get(f_type, "CWE-000")
        return json.dumps(self.findings, indent=2)

    def to_sarif(self) -> str:
        """Generates a SARIF v2.1.0 compatible report."""
        sarif = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Breakpoint SAST",
                            "version": "2.0.0",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        
        for f in self.findings:
            result = {
                "ruleId": self.CWE_MAPPING.get(f.get("type", "UNKNOWN").upper(), "CWE-000"),
                "message": {"text": f.get("evidence", "No evidence provided")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.get("file", "unknown")},
                            "region": {"startLine": f.get("line", 1)}
                        }
                    }
                ]
            }
            sarif["runs"][0]["results"].append(result)
            
        return json.dumps(sarif, indent=2)
