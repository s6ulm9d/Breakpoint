import json
from .metadata import get_metadata, SEVERITY_SCORES

class SarifReporter:
    def __init__(self, filename="report.sarif"):
        self.filename = filename

    def generate(self, results):
        rules = []
        rule_indices = {}
        
        sarif_results = []
        
        for res in results:
            if res.get("passed", True):
                continue
                
            atype = res.get("attack_type", "generic")
            meta = get_metadata(atype)
            
            # 1. Register Rule if not present
            if atype not in rule_indices:
                rule = {
                    "id": atype,
                    "name": meta["name"],
                    "shortDescription": {"text": meta["name"]},
                    "fullDescription": {"text": meta["description"]},
                    "properties": {
                        "security-severity": str(SEVERITY_SCORES.get(meta["severity"], 5.0)),
                        "tags": list(meta.get("risk_factors", [])) + ["security", meta.get("cwe", "Unknown")]
                    }
                }
                rules.append(rule)
                rule_indices[atype] = len(rules) - 1
            
            # 2. Add Result
            # Finding locations is hard without line numbers, so we point to the artifact (web target)
            details = res.get("details", {})
            msg = f"Attack {atype} failed. {str(details)[:200]}..."
            
            sarif_results.append({
                "ruleId": atype,
                "ruleIndex": rule_indices[atype],
                "level": "error" if meta["severity"] in ["CRITICAL", "HIGH"] else "warning",
                "message": {"text": msg},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "target_application"},
                        "region": {"startLine": 1}
                    }
                }]
            })

        output = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "BREAKPOINT",
                        "version": "2.0.0-ELITE",
                        "rules": rules
                    }
                },
                "results": sarif_results
            }]
        }
        
        with open(self.filename, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        print(f"SARIF Report generated: {self.filename}")
