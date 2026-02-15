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
        Provides module descriptions to the AI for better decision making.
        """
        if not self.api_key:
            print("[!] AI Analysis skipped: No OpenAI API key configured.")
            return available_modules

        from .metadata import ATTACK_KNOWLEDGE_BASE
        module_context = []
        for m in available_modules:
            desc = ATTACK_KNOWLEDGE_BASE.get(m, {}).get("description", "No description available.")
            module_context.append(f"- {m}: {desc}")
        
        module_desc_str = "\n".join(module_context)

        print(f"[*] AI Phase: Deep-analyzing source code at {source_path}...")
        
        summary_data = self._summarize_directory(source_path)
        code_summary = summary_data["summary"]
        file_tree = summary_data["tree"]
        file_count = summary_data["count"]
        
        print(f"    -> Parsed {file_count} files and generated structural context.")
        
        prompt = (
            f"You are an elite cyber-security auditor and penetration tester.\n"
            f"Your task is to map a project's source code to relevant security testing modules.\n\n"
            f"STRATEGY:\n"
            f"1. Analyze the project structure and technology stack (languages, frameworks, databases).\n"
            f"2. Identify potential attack surfaces based on the code snippets (APIs, auth flows, file handling).\n"
            f"3. Select modules that target the detected technologies. Do NOT select modules for technologies not present (e.g., don't pick NoSQL injection if only SQL is used).\n\n"
            f"AVAILABLE MODULES:\n{module_desc_str}\n\n"
            f"PROJECT ARCHITECTURE:\n{file_tree}\n\n"
            f"CODE CONTEXT:\n{code_summary}\n\n"
            f"RESPONSE FORMAT:\n"
            f"Respond with a JSON object containing:\n"
            f"- 'reasoning': A brief explanation of your discovery.\n"
            f"- 'selected_modules': A list of module IDs (strings) from the available list.\n\n"
            f"Be precise and conservative. Focus on high-impact relevance."
        )

        if os.environ.get("BREAKPOINT_VERBOSE") == "1":
            print(f"\n[DEBUG] AI Prompt:\n{prompt}\n")

        res = self._call_ai(prompt)
        if isinstance(res, dict) and "selected_modules" in res:
            recommended = res["selected_modules"]
            reasoning = res.get("reasoning", "No reasoning provided.")
            print(f"    [+] AI Reasoning: {reasoning}")
            print(f"    [+] AI filtered down to {len(recommended)} relevant modules.")
            
            if self.logger:
                self.logger.log_event("AI_SOURCE_ANALYSIS", {
                    "source": source_path, 
                    "recommended": recommended,
                    "reasoning": reasoning
                })
            return recommended
        
        return available_modules

    def analyze_target_url(self, url: str, available_modules: List[str]) -> List[str]:
        """
        Analyzes a hosted URL to suggest attack modules based on fingerprinting.
        """
        if not self.api_key:
            return available_modules

        print(f"[*] AI Phase: Fingerprinting hosted target {url}...")
        
        try:
            resp = requests.get(url, timeout=10, verify=False)
            context = {
                "url": url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:2000]
            }
        except Exception as e:
            print(f"    [-] AI analysis failed to reach target: {e}")
            return available_modules

        from .metadata import ATTACK_KNOWLEDGE_BASE
        module_context = []
        for m in available_modules:
            desc = ATTACK_KNOWLEDGE_BASE.get(m, {}).get("description", "No description available.")
            module_context.append(f"- {m}: {desc}")
        
        module_desc_str = "\n".join(module_context)

        prompt = (
            f"You are a professional security auditor. Fingerprint the following target based on its HTTP response and select the relevant attack modules.\n\n"
            f"TARGET CONTEXT:\n{json.dumps(context, indent=2)}\n\n"
            f"AVAILABLE MODULES:\n{module_desc_str}\n\n"
            f"RESPONSE FORMAT:\n"
            f"Respond with a JSON object containing:\n"
            f"- 'fingerprint': A summary of the detected stack (e.g. 'Express.js on Node with Nginx').\n"
            f"- 'selected_modules': A list of relevant module IDs from the provided list.\n\n"
            f"Be accurate. If the stack is unknown, be broad but logical."
        )

        res = self._call_ai(prompt)
        if isinstance(res, dict) and "selected_modules" in res:
            recommended = res["selected_modules"]
            fingerprint = res.get("fingerprint", "Unknown")
            print(f"    [+] AI Fingerprint: {fingerprint}")
            print(f"    [+] AI selected {len(recommended)} modules for this stack.")
            if self.logger:
                self.logger.log_event("AI_TARGET_ANALYSIS", {
                    "url": url, 
                    "recommended": recommended,
                    "fingerprint": fingerprint
                })
            return recommended
        return available_modules

    def verify_source_match(self, source_path: str, url: str) -> bool:
        """
        Verifies if the source code provided matches the tech stack of the target URL.
        Prevents faking results with mismatched source.
        """
        if not self.api_key: return True

        print(f"[*] AI Phase: Strict Cross-Verification (Source vs Target {url})...")
        
        # 1. Target Info (Headers/Body)
        try:
            resp = requests.get(url, timeout=10, verify=False)
            target_info = {
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:4000], # Significant increase to find unique strings
                "status_code": resp.status_code
            }
        except:
            target_info = {"error": "Target unreachable (Server Down?)"}

        # 2. Source Info
        summary_data = self._summarize_directory(source_path)
        source_summary = summary_data["summary"]
        file_tree = summary_data["tree"]

        prompt = (
            f"You are a paranoid and cynical security auditor. A user has provided a local source code directory "
            f"and a target URL to scan. Your job is to determine if they are LYING about the source code.\n\n"
            f"TARGET URL LIVE DATA:\n{json.dumps(target_info, indent=2)}\n\n"
            f"PROVIDED SOURCE CODE STRUCTURE:\n{file_tree}\n\n"
            f"PROVIDED SOURCE CODE SNIPPETS:\n{source_summary}\n\n"
            f"RULES FOR DETERMINATION:\n"
            f"1. LOOK FOR POSITIVE PROOF: Do you see unique product names, specific framework versions, "
            f"or custom API route patterns in BOTH the source and the target HTML/Headers?\n"
            f"2. TECHNOLOGY MATCH IS NOT ENOUGH: Just because both use 'Node.js' or 'React' is NOT proof. "
            f"There must be a specific correlation (e.g., a custom class name in source exists in the target body).\n"
            f"3. CHECK FOR IMPOSSIBILITIES: If the target headers say 'Server: Apache/2.4.41 (Ubuntu)' but the source "
            f"is a Go-based Gin server, this is a 100% mismatch.\n"
            f"4. SKEPTICISM BY DEFAULT: If the target body is minimal (e.g. a simple login page) and you cannot find "
            f"a single unique string or logic pattern connecting it to the 100+ files in the source, you MUST assume a mismatch.\n\n"
            f"Respond with ONLY a JSON object: {{\"match\": true/false, \"reason\": \"string explanation\", \"confidence\": 0-100}}."
        )

        try:
            res_dict = self._call_ai(prompt)
            if isinstance(res_dict, dict):
                match_found = res_dict.get("match", True)
                reason = res_dict.get("reason", "No reason provided.")
                confidence = res_dict.get("confidence", 0)
                
                # We are more aggressive now: even a slight doubt (low confidence match) triggers a warning or abort
                if not match_found:
                    print(f"    {Fore.RED}[!] VERIFICATION FAILED: Project mismatch detected!{Style.RESET_ALL}")
                    print(f"    [!] AI Reason: {reason}")
                    print(f"    [!] AI Confidence: {confidence}%")
                    if self.logger:
                        self.logger.log_event("PROJECT_MISMATCH", {"url": url, "source": source_path, "reason": reason})
                    return False
                
                # If it's a match but with suspicious confidence
                if match_found and confidence < 40:
                     print(f"    {Fore.YELLOW}[!] WARNING: AI is unsure if this source matches (Confidence {confidence}%).{Style.RESET_ALL}")
                     print(f"    [!] Defaulting to ABORT for security integrity.")
                     return False

                print(f"    [+] Source/Target verification passed (AI Confidence: {confidence}%).")
                return True
        except Exception as e:
            if os.environ.get("BREAKPOINT_VERBOSE") == "1":
                print(f"[DEBUG] AI Verification Error: {e}")
        return True # Default to True only on API failure

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
                if resp.status_code == 429:
                    print(f"\n{Fore.RED}[!] AI QUOTA EXHAUSTED: Your OpenAI API tokens have finished or you are being rate-limited.{Style.RESET_ALL}")
                    print(f"{Fore.RED}[!] Upgrade your OpenAI plan or change your API key: 'breakpoint --openai-key <NEW_KEY>'{Style.RESET_ALL}")
                elif os.environ.get("BREAKPOINT_VERBOSE") == "1":
                    print(f"    [!] AI API Error (Status {resp.status_code})")
        except Exception:
            pass
        return None

    def _summarize_directory(self, path: str) -> Dict[str, Any]:
        """
        Generates a structural and content-based summary of the project.
        Extracts key security indicators from source files.
        """
        summary = []
        file_tree = []
        file_count = 0
        exclude_dirs = {'.venv', 'venv', 'node_modules', '.git', '__pycache__', 'dist', 'build', 'venv', 'artifacts', 'tests'}
        
        # High-priority files that usually define the tech stack and entry points
        priority_files = {
            'package.json', 'requirements.txt', 'go.mod', 'pom.xml', 'docker-compose.yml',
            'Dockerfile', 'main.py', 'app.py', 'index.js', 'server.js', 'routes.php',
            'config.php', 'settings.py', '.env.example', '.env'
        }

        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            rel_root = os.path.relpath(root, path)
            indent = "  " * (0 if rel_root == "." else rel_root.count(os.sep) + 1)
            
            if rel_root != ".":
                file_tree.append(f"{indent}{os.path.basename(root)}/")

            for file in files:
                rel_path = os.path.relpath(os.path.join(root, file), path)
                file_tree.append(f"{indent}  {file}")
                
                if file_count > 100: continue # Limit to prevent pathologically large summaries
                
                if file.endswith(('.py', '.js', '.ts', '.go', '.java', '.php', '.yaml', '.yml', '.env', '.html', '.css', '.json')):
                    is_priority = file in priority_files or any(x in file.lower() for x in ['auth', 'route', 'api', 'ctrl', 'config', 'middleware', 'database', 'db'])
                    
                    if not is_priority and file_count > 50:
                        continue # If not priority, skip after 50 files to keep summary focused
                    
                    file_count += 1
                    try:
                        with open(os.path.join(root, file), 'r', errors='ignore') as f:
                            # Read more of priority files
                            read_size = 3000 if is_priority else 1000
                            content = f.read(read_size)
                            
                            # Clean up content: minor minification to save tokens
                            lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith(('#', '//', '/*'))]
                            processed_content = "\n".join(lines[:60]) # First 60 non-empty non-comment lines
                            
                            prio_score = 10 if is_priority else 1
                            summary.append((prio_score, f"File: {rel_path}\nSnippet:\n{processed_content}\n---"))
                    except:
                        continue
        
        summary.sort(key=lambda x: x[0], reverse=True)
        return {
            "summary": "\n\n".join([s[1] for s in summary[:40]]), # Top 40 interesting files
            "tree": "\n".join(file_tree[:100]), # Top 100 entries of file tree
            "count": file_count
        }
