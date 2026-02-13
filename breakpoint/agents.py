import os
import json
from typing import List, Dict, Any, Optional

class BaseAgent:
    def __init__(self, name: str, system_prompt: str):
        self.name = name
        self.system_prompt = system_prompt

    def chat(self, user_input: str) -> str:
        # Placeholder for LLM interaction
        # In a real deployment, this connects to OpenAI/Anthropic/Local LLM
        return f"[MOCK {self.name}] Response to: {user_input[:20]}..."

class BreakerAgent(BaseAgent):
    def __init__(self):
        prompt = (
            "You are the Breaker. Your objective is to find an exploit for the provided vulnerability report or code snippet. "
            "You must generate a working Proof-of-Concept (PoC) script (preferable Python or Playwright). "
            "Output only the PoC and a brief explanation."
        )
        super().__init__("Breaker", prompt)

class ValidatorAgent(BaseAgent):
    def __init__(self):
        prompt = (
            "You are the Validator. Given a potential vulnerability and a Breaker's PoC, "
            "your objective is to verify if it works against the target. "
            "You assume the role of an attacker validating their exploit. "
            "Reply with 'CONFIRMED' if it works, or 'FAILED' if it does not."
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
        Returns a dict with 'status', 'confidence', 'poc', 'details'.
        """
        print(f"\n[*] Starting Adversarial Validation Loop (Max Iterations: {self.max_iterations})...")
        print(f"    [Target: {target_url}]")
        
        # 1. Breaker generates PoC
        try:
            # Provide target URL to the breaker for context
            context = f"Report: {vulnerability_report}\nCode:\n{source_code}\nTarget URL: {target_url}"
            poc = self.breaker.chat(context)
        except Exception as e:
            return {"status": "ERROR", "confidence": "LOW", "poc": None, "details": f"Breaker failed: {str(e)}"}

        if not poc or "import " not in poc:
            return {"status": "HEURISTIC", "confidence": "LOW", "poc": None, "details": "Breaker could not generate valid PoC code."}
            
        # Extract code block if LLM wrapped it in markdown
        if "```python" in poc:
            poc = poc.split("```python")[1].split("```")[0].strip()
        elif "```" in poc:
            poc = poc.split("```")[1].split("```")[0].strip()

        # 2. Validator tries to confirm (Reproduction Attempt)
        success_count = 0
        total_attempts = 2 # Reduced for real execution speed
        execution_logs = []
        
        if self.sandbox and self.sandbox.is_healthy():
            print(f"    [>] Executing PoC in Sandbox ({total_attempts} runs)...")
            for i in range(total_attempts):
                success, output = self.sandbox.execute_poc(poc)
                execution_logs.append(output)
                
                # Check output for confirmation keywords or signs of success
                if success and ("[!] Vulnerability Confirmed" in output or "[+]" in output):
                    success_count += 1
                elif success and "Status Code: 200" not in output and "Status Code:" in output:
                    # Heuristic: non-200 might mean crash or something interesting
                    success_count += 0.5 
        else:
            print("    [!] Sandbox unavailable. Falling back to Heuristic/LLM Simulation.")
            for i in range(total_attempts):
                validation_response = self.validator.chat(f"PoC: {poc}")
                if "CONFIRMED" in validation_response:
                    success_count += 1
                
        # 3. Decision Logic
        confidence_ratio = success_count / total_attempts
        
        status = "SUSPECT"
        confidence = "LOW"
        
        if confidence_ratio >= 0.8:
            status = "CONFIRMED"
            confidence = "HIGH"
        elif confidence_ratio >= 0.4:
            status = "SUSPECT"
            confidence = "MEDIUM"
        else:
            status = "SECURE"
            confidence = "HIGH"

        return {
            "status": status,
            "confidence": confidence,
            "poc": poc if status in ["CONFIRMED", "SUSPECT"] else None,
            "details": f"Validation success rate: {success_count}/{total_attempts}. Logs: {str(execution_logs)[:200]}..."
        }
