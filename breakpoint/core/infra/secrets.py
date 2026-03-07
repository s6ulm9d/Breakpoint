import re
import math
from typing import List, Dict, Any

class SecretDetector:
    """Detects secrets using entropy-based and regex-based approaches."""
    def __init__(self):
        self.patterns = {
            "AWS Key": r"(?i)aws_access_key_id\s*[:=]\s*['\"]?(A3T[A-Z0-9]{16})['\"]?",
            "AWS Secret": r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?",
            "Generic Secret": r"(?i)(secret|password|passwd|api_key|token|auth)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{16,})['\"]?",
            "Private Key": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"
        }

    def calculate_entropy(self, text: str) -> float:
        """Calculates the Shannon entropy of a string."""
        if not text: return 0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(file_path, "r", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()

            # Regex-based detection
            for name, pattern in self.patterns.items():
                for i, line in enumerate(lines):
                    if re.search(pattern, line):
                        findings.append({
                            "type": "SECRET",
                            "severity": "CRITICAL",
                            "label": name,
                            "file": file_path,
                            "line": i + 1,
                            "evidence": line.strip()[:100]
                        })

            # Entropy-based detection for long strings
            strings = re.findall(r"['\"]([a-zA-Z0-9\-_+/=]{20,})['\"]", content)
            for s in strings:
                entropy = self.calculate_entropy(s)
                if entropy > 4.5: # Threshold for high-entropy strings
                    # Find line number (inefficient but works for now)
                    for i, line in enumerate(lines):
                        if s in line:
                            findings.append({
                                "type": "SECRET",
                                "severity": "HIGH",
                                "label": "High Entropy String (Potential credential)",
                                "file": file_path,
                                "line": i + 1,
                                "evidence": f"Entropy: {entropy:.2f} | String: {s[:10]}..."
                            })
                            break
        except: pass
        return findings
