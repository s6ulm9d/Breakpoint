import os
import json
import requests
from typing import List, Dict, Any
from .licensing import get_openai_key
from colorama import Fore, Style

class AIAnalyzer:
    def __init__(self, api_key: str = None, forensic_log=None):
        self.api_key = api_key or get_openai_key()
        self.api_url = "https://api.openai.com/v1/chat/completions"
        self.logger = forensic_log

    def analyze_source_code(self, source_path: str, available_modules: List[str]) -> List[str]:
        """
        Analyzes source code files to suggest applicable attack modules.
        """
        if not self.api_key:
            print("[!] AI Analysis skipped: No OpenAI API key configured.")
            return available_modules

        print(f"[*] AI Phase: Analyzing source code at {source_path}...")
        
        summary_data = self._summarize_directory(source_path)
        code_summary = summary_data["summary"]
        file_count = summary_data["count"]
        
        print(f"    -> Summarized {file_count} relevant source files.")
        
        prompt = (
            f"You are a critical security researcher. Given the following summary of a project's source code, "
            f"determine which of these security attack modules are strictly relevant to test this specific project: {available_modules}.\n"
            f"Do not recommend modules if the technology they target is not present in the code.\n\n"
            f"Project Summary:\n{code_summary}\n\n"
            f"Respond with ONLY a JSON list of module IDs. Be conservative. Explain nothing else."
        )

        if os.environ.get("BREAKPOINT_VERBOSE") == "1":
            print(f"\n[DEBUG] AI Prompt:\n{prompt}\n")

        recommended = self._call_ai(prompt)
        if isinstance(recommended, list):
            print(f"    -> AI filtered down to {len(recommended)} relevant modules.")
            if self.logger:
                self.logger.log_event("AI_SOURCE_ANALYSIS", {"source": source_path, "recommended": recommended})
            return recommended
        return available_modules

    def analyze_target_url(self, url: str, available_modules: List[str]) -> List[str]:
        """
        Analyzes a hosted URL to suggest attack modules.
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
                "body_snippet": resp.text[:1000]
            }
        except Exception as e:
            print(f"    [-] AI analysis failed to reach target: {e}")
            return available_modules

        prompt = (
            f"You are a professional auditor. Analyze this target URL info and suggest which of these "
            f"attack modules are relevant: {available_modules}.\n\n"
            f"Context:\n{json.dumps(context, indent=2)}\n\n"
            f"Respond with ONLY a JSON list of module IDs. Explain nothing else."
        )

        recommended = self._call_ai(prompt)
        if isinstance(recommended, list):
            print(f"    -> AI filtered down to {len(recommended)} modules based on target stack.")
            if self.logger:
                self.logger.log_event("AI_TARGET_ANALYSIS", {"url": url, "recommended": recommended})
            return recommended
        return available_modules

    def verify_source_match(self, source_path: str, url: str) -> bool:
        """
        Verifies if the source code provided matches the tech stack of the target URL.
        Prevents faking results with mismatched source.
        """
        if not self.api_key: return True

        print(f"[*] AI Phase: Cross-verifying source code with target {url}...")
        
        # 1. Target Info (Headers/Body)
        try:
            resp = requests.get(url, timeout=10, verify=False)
            target_info = {
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:1000]
            }
        except:
            target_info = {"error": "Target unreachable"}

        # 2. Source Info
        summary_data = self._summarize_directory(source_path)
        source_summary = summary_data["summary"]

        prompt = (
            f"You are a rigorous security auditor. Compare the target URL info with the project source code.\n\n"
            f"Target URL Info:\n{json.dumps(target_info, indent=2)}\n\n"
            f"Source Code Summary:\n{source_summary}\n\n"
            f"QUESTION: Does this source code actually belong to the software running at the target URL?\n"
            f"Identify if there is a technology mismatch (e.g. source is Node.js but target headers show PHP).\n\n"
            f"Respond with ONLY a JSON object: {{\"match\": true/false, \"reason\": \"string explanation\"}}."
        )

        try:
            res_dict = self._call_ai(prompt)
            if isinstance(res_dict, dict):
                if not res_dict.get("match", True):
                    reason = res_dict.get("reason", "Unknown mismatch")
                    print(f"    {Fore.RED}[!] WARNING: Project mismatch detected!{Style.RESET_ALL}")
                    print(f"    [!] AI Reason: {reason}")
                    if self.logger:
                        self.logger.log_event("PROJECT_MISMATCH", {"url": url, "source": source_path, "reason": reason})
                    return False
                print(f"    [+] Source/Target verification passed.")
                return True
        except:
            pass
        return True

    def _call_ai(self, prompt: str) -> Any:
        if not self.api_key: return None
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0
        }
        
        try:
            resp = requests.post(self.api_url, headers=headers, json=data, timeout=30)
            if resp.status_code == 200:
                result = resp.json()['choices'][0]['message']['content'].strip()
                if "```json" in result:
                    result = result.split("```json")[1].split("```")[0].strip()
                elif "```" in result:
                    result = result.split("```")[1].split("```")[0].strip()
                
                try:
                    return json.loads(result)
                except:
                    return result
            else:
                if os.environ.get("BREAKPOINT_VERBOSE") == "1":
                    print(f"    [!] AI API Error (Status {resp.status_code})")
        except Exception:
            pass
        return None

    def _summarize_directory(self, path: str) -> Dict[str, Any]:
        summary = []
        file_count = 0
        exclude_dirs = {'.venv', 'venv', 'node_modules', '.git', '__pycache__', 'dist', 'build'}
        
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            if file_count > 50: break
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.go', '.java', '.php', '.yaml', '.yml', '.env', '.html', '.css', '.json')):
                    priority = 1 if any(x in file.lower() for x in ['auth', 'route', 'api', 'ctrl', 'config', 'middleware', 'package', 'requirements']) else 0
                    file_count += 1
                    rel_path = os.path.relpath(os.path.join(root, file), path)
                    try:
                        with open(os.path.join(root, file), 'r', errors='ignore') as f:
                            content = f.read(1500)
                        summary.append((priority, f"File: {rel_path}\nSnippet: {content}..."))
                    except:
                        continue
        
        summary.sort(key=lambda x: x[0], reverse=True)
        return {
            "summary": "\n\n".join([s[1] for s in summary]),
            "count": file_count
        }
