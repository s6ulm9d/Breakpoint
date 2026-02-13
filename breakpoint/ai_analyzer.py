import os
import json
import requests
from typing import List, Dict, Any
from .licensing import get_openai_key

class AIAnalyzer:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or get_openai_key()
        self.api_url = "https://api.openai.com/v1/chat/completions"

    def analyze_source_code(self, source_path: str, available_modules: List[str]) -> List[str]:
        """
        Analyzes source code files to suggest applicable attack modules.
        """
        if not self.api_key:
            print("[!] AI Analysis skipped: No OpenAI API key configured.")
            return available_modules

        print(f"[*] AI Phase: Analyzing source code at {source_path}...")
        
        # Collect a summary of the codebase (file structure, key imports, etc.)
        summary_data = self._summarize_directory(source_path)
        code_summary = summary_data["summary"]
        file_count = summary_data["count"]
        
        print(f"    -> Summarized {file_count} relevant source files.")
        
        prompt = (
            f"You are a senior security researcher. Given the following summary of a project's source code, "
            f"determine which of these security attack modules are most applicable to test this project: {available_modules}.\n\n"
            f"Project Summary:\n{code_summary}\n\n"
            f"Respond with ONLY a JSON list of module IDs that should be enabled. "
            f"Explain nothing else."
        )

        if os.environ.get("BREAKPOINT_VERBOSE") == "1":
            print(f"\n[DEBUG] AI Prompt:\n{prompt}\n")

        recommended = self._call_ai(prompt)
        if recommended:
            print(f"    -> AI recommended {len(recommended)} relevant modules.")
            return recommended
        return available_modules

    def analyze_target_url(self, url: str, available_modules: List[str]) -> List[str]:
        """
        Analyzes a hosted URL (headers, response snippet) to suggest attack modules.
        """
        if not self.api_key:
            return available_modules

        print(f"[*] AI Phase: Analyzing hosted target {url}...")
        
        try:
            resp = requests.get(url, timeout=10, verify=False)
            context = {
                "url": url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:1000] # First 1KB
            }
        except Exception as e:
            print(f"    [-] AI analysis failed to reach target: {e}")
            return available_modules

        prompt = (
            f"You are a white-hat hacker. Analyze this target URL info and suggest which of these "
            f"security attack modules are relevant: {available_modules}.\n\n"
            f"Context:\n{json.dumps(context, indent=2)}\n\n"
            f"Respond with ONLY a JSON list of module IDs. Explain nothing else."
        )

        recommended = self._call_ai(prompt)
        if recommended:
            print(f"    -> AI filtered down to {len(recommended)} modules based on target stack.")
            return recommended
        return available_modules

    def _call_ai(self, prompt: str) -> List[str]:
        if not self.api_key: return None
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": "gpt-4o-mini", # Efficient for analysis
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0
        }
        
        try:
            resp = requests.post(self.api_url, headers=headers, json=data, timeout=30)
            if resp.status_code == 200:
                result = resp.json()['choices'][0]['message']['content'].strip()
                # Clean markdown if JSON is wrapped
                if "```json" in result:
                    result = result.split("```json")[1].split("```")[0].strip()
                elif "```" in result:
                    result = result.split("```")[1].split("```")[0].strip()
                
                return json.loads(result)
            else:
                print(f"    [!] AI API Error (Status {resp.status_code}): {resp.text}")
        except Exception as e:
            print(f"    [!] AI API Exception: {e}")
        return None

    def _summarize_directory(self, path: str) -> Dict[str, Any]:
        summary = []
        file_count = 0
        exclude_dirs = {'.venv', 'venv', 'node_modules', '.git', '__pycache__', 'dist', 'build'}
        
        for root, dirs, files in os.walk(path):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            if file_count > 50: break # Safety cap
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.go', '.java', '.php', '.yaml', '.yml', '.env')):
                    # Prioritize "interesting" security files
                    priority = 0
                    lower_file = file.lower()
                    if any(x in lower_file for x in ['auth', 'route', 'api', 'ctrl', 'controller', 'config', 'middleware']):
                        priority = 1
                    
                    file_count += 1
                    rel_path = os.path.relpath(os.path.join(root, file), path)
                    try:
                        with open(os.path.join(root, file), 'r', errors='ignore') as f:
                            content = f.read(1024) # Increased to 1KB for better context
                        summary.append((priority, f"File: {rel_path}\nSnippet: {content}..."))
                    except:
                        continue
        
        # Sort by priority so AI sees important files first
        summary.sort(key=lambda x: x[0], reverse=True)
        final_summary = [s[1] for s in summary]

        return {
            "summary": "\n\n".join(final_summary),
            "count": file_count
        }
