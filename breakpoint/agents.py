import os
import json
import requests
from typing import List, Dict, Any, Optional
from .licensing import get_openai_key

class BaseAgent:
    def __init__(self, name: str, system_prompt: str, api_key: str = None):
        self.name = name
        self.system_prompt = system_prompt
        self.api_key = api_key or get_openai_key()
        self.api_url = "https://api.openai.com/v1/chat/completions"

    def chat(self, user_input: str) -> str:
        if not self.api_key:
            return f"[MOCK {self.name}] (Key missing): Response to {user_input[:20]}..."
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": user_input}
            ],
            "temperature": 0.2
        }

        try:
            resp = requests.post(self.api_url, headers=headers, json=data, timeout=45)
            if resp.status_code == 200:
                return resp.json()['choices'][0]['message']['content'].strip()
            else:
                return f"[ERROR {self.name}] API Status {resp.status_code}: {resp.text[:100]}"
        except Exception as e:
            return f"[ERROR {self.name}] Exception: {str(e)}"

class BreakerAgent(BaseAgent):
    def __init__(self):
        prompt = "Expert pentester. Generate Python PoC for the reported vulnerability. Code ONLY."
        super().__init__("Breaker", prompt)

class ValidatorAgent(BaseAgent):
    def __init__(self):
        prompt = "Verify vulnerability from PoC output. Reply ONLY 'CONFIRMED' or 'FAILED'."
        super().__init__("Validator", prompt)

class AdversarialLoop:
    def __init__(self, sandbox=None, max_iterations: int = 2):
        self.breaker = BreakerAgent()
        self.validator = ValidatorAgent()
        self.sandbox = sandbox
        self.max_iterations = max_iterations

    def run(self, vulnerability_report: str, source_code: str, target_url: str = "http://localhost:3000") -> dict:
        """Executes the Breaker -> Validator loop with aggressive token saving."""
        # Truncate inputs to save tokens
        vulnerability_report = vulnerability_report[:500]
        source_code = source_code[:1000]

        print(f"\n[*] AI Validation Loop (Max Iter: {self.max_iterations})...")
        
        context = f"Vulnerability: {vulnerability_report}\nCode: {source_code}\nTarget: {target_url}\nRequirement: Print '[!] ATTEMPT SUCCESSFUL' on success."
        poc = self.breaker.chat(context)
        
        if not poc or "import " not in poc:
            return {"status": "HEURISTIC", "confidence": "LOW", "poc": None, "details": "Breaker failed PoC generation."}
            
        if "```python" in poc:
            poc = poc.split("```python")[1].split("```")[0].strip()
        elif "```" in poc:
            poc = poc.split("```")[1].split("```")[0].strip()

        if not self.sandbox or not self.sandbox.is_healthy():
            return {"status": "UNVERIFIED", "confidence": "LOW", "poc": poc, "details": "Sandbox unavailable."}

        print(f"    [>] Executing PoC...")
        success, output = self.sandbox.execute_poc(poc)
        
        val_prompt = f"Report: {vulnerability_report}\nOutput:\n{output[:1000]}\nConfirm if successful."
        validation_decision = self.validator.chat(val_prompt).strip().upper()

        if "CONFIRMED" in validation_decision:
            return {"status": "CONFIRMED", "confidence": "HIGH", "poc": poc, "details": "AI Validator confirmed reproduction."}
        elif "[!] ATTEMPT SUCCESSFUL" in output:
             return {"status": "CONFIRMED", "confidence": "MEDIUM", "poc": poc, "details": "PoC triggered success indicator."}
        
        return {"status": "FAILED", "confidence": "LOW", "poc": poc, "details": f"Validator decision: {validation_decision}. Logs: {output[:100]}..."}
