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

    def run(self, vulnerability_report: str, source_code: str, target_url: str = "http://localhost:3000", cpg_context: str = None) -> dict:
        """Executes the Breaker -> Validator loop with iterative refinement and CPG augmentation."""
        # Truncate inputs to save tokens
        vulnerability_report = vulnerability_report[:500]
        source_code = source_code[:1000]

        print(f"\n[*] AI Validation Loop (Max Iter: {self.max_iterations})...")
        
        last_error = ""
        current_poc = None
        
        for i in range(self.max_iterations):
            iteration_msg = f" (Attempt {i+1}/{self.max_iterations})" if i > 0 else ""
            print(f"    [>] Generating PoC{iteration_msg}...")
            
            context = f"Vulnerability: {vulnerability_report}\nCode: {source_code}\nTarget: {target_url}\nRequirement: Print '[!] ATTEMPT SUCCESSFUL' on success."
            
            if cpg_context:
                context += f"\n\nSTRUCTURAL CONTEXT (CPG Flow): {cpg_context}"
                
            if last_error:
                context += f"\n\nCRITICAL: Your previous attempt FAILED with this output:\n---\n{last_error}\n---\nAnalyze the error and refine the payload/logic to bypass or fix the issue."

            current_poc = self.breaker.chat(context)
            
            if not current_poc or "import " not in current_poc:
                # If it's a second attempt and still failing, just stop or keep trying?
                # We'll continue the loop if iterations remain.
                last_error = "Breaker failed to generate a valid Python script containing 'import'."
                continue
                
            if "```python" in current_poc:
                current_poc = current_poc.split("```python")[1].split("```")[0].strip()
            elif "```" in current_poc:
                current_poc = current_poc.split("```")[1].split("```")[0].strip()

            if not self.sandbox or not self.sandbox.is_healthy():
                return {"status": "UNVERIFIED", "confidence": "LOW", "poc": current_poc, "details": "Sandbox unavailable."}

            print(f"    [>] Executing PoC...")
            success, output = self.sandbox.execute_poc(current_poc)
            
            # 1. Immediate Success Indicator
            if "[!] ATTEMPT SUCCESSFUL" in output:
                print(f"    {Fore.GREEN}[+] Success detected in logs!{Style.RESET_ALL}")
                return {"status": "CONFIRMED", "confidence": "HIGH", "poc": current_poc, "details": "PoC triggered success indicator."}
            
            # 2. AI Validation Decision
            val_prompt = f"Report: {vulnerability_report}\nOutput:\n{output[:1000]}\nConfirm if successful."
            validation_decision = self.validator.chat(val_prompt).strip().upper()

            if "CONFIRMED" in validation_decision:
                return {"status": "CONFIRMED", "confidence": "HIGH", "poc": current_poc, "details": "AI Validator confirmed reproduction."}
            
            # 3. Handle Failure and Loop
            print(f"    {Fore.YELLOW}[-] Attempt {i+1} failed. Refining...{Style.RESET_ALL}")
            last_error = output[:1500] # Provide enough context for the breaker

        return {"status": "FAILED", "confidence": "LOW", "poc": current_poc, "details": f"Failed after {self.max_iterations} attempts. Last logs: {last_error[:100]}..."}
