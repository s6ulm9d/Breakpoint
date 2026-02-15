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
        prompt = (
            "You are an expert pentester. Generate a Python PoC script to reproduce the reported vulnerability. "
            "Output ONLY the code block."
        )
        super().__init__("Breaker", prompt)

class ValidatorAgent(BaseAgent):
    def __init__(self):
        prompt = (
            "Verify the vulnerability based on the PoC output. Reply ONLY 'CONFIRMED' or 'FAILED'."
        )
        super().__init__("Validator", prompt)

class AdversarialLoop:
    def __init__(self, sandbox=None, max_iterations: int = 3):
        self.breaker = BreakerAgent()
        self.validator = ValidatorAgent()
        self.sandbox = sandbox
        self.max_iterations = max_iterations

    def run(self, vulnerability_report: str, source_code: str, target_url: str = "http://localhost:3000") -> dict:
        """
        Executes the Breaker -> Validator loop.
        """
        print(f"\n[*] Starting Adversarial Validation Loop (Max Iterations: {self.max_iterations})...")
        print(f"    [Target: {target_url}]")
        
        # 1. Breaker generates PoC
        context = f"Vulnerability: {vulnerability_report}\nCode Snippet: {source_code}\nTarget URL: {target_url}\nRequirement: Print '[!] ATTEMPT SUCCESSFUL' if the vulnerability is reproduced."
        poc = self.breaker.chat(context)

        if not poc or "import " not in poc:
            return {"status": "HEURISTIC", "confidence": "LOW", "poc": None, "details": "Breaker could not generate valid PoC code."}
            
        if "```python" in poc:
            poc = poc.split("```python")[1].split("```")[0].strip()
        elif "```" in poc:
            poc = poc.split("```")[1].split("```")[0].strip()

        # 2. Execution Phase
        if not self.sandbox or not self.sandbox.is_healthy():
            return {"status": "UNVERIFIED", "confidence": "LOW", "poc": poc, "details": "Sandbox unavailable."}

        print(f"    [>] Executing PoC in Sandbox...")
        success, output = self.sandbox.execute_poc(poc)
        
        # 3. Validator analyzes the REAL output
        val_prompt = (
            f"Vulnerability Report: {vulnerability_report}\n"
            f"Expected Target: {target_url}\n"
            f"PoC Output:\n{output}\n\n"
            f"Does the PoC output prove the vulnerability exists on {target_url}?\n"
            f"Reply ONLY 'CONFIRMED' or 'FAILED'."
        )
        validation_decision = self.validator.chat(val_prompt).strip().upper()

        if "CONFIRMED" in validation_decision:
            return {"status": "CONFIRMED", "confidence": "HIGH", "poc": poc, "details": "AI Validator confirmed reproduction."}
        elif "[!] ATTEMPT SUCCESSFUL" in output:
             return {"status": "CONFIRMED", "confidence": "MEDIUM", "poc": poc, "details": "PoC triggered success indicator."}
        
        return {"status": "FAILED", "confidence": "LOW", "poc": poc, "details": f"Validator decision: {validation_decision}. Logs: {output[:100]}..."}
