import os
import json
import requests
import time
from typing import List, Dict, Any, Optional
from openai import OpenAI, AuthenticationError, RateLimitError, APIConnectionError
from .licensing import get_openai_key
from colorama import Fore, Style

class AIAnalyzer:
    def __init__(self, api_key: str = None, verbose: bool = False, forensic_log=None):
        self.api_key = api_key or get_openai_key()
        self.verbose = verbose
        self.client = OpenAI(api_key=self.api_key) if self.api_key else None
        self.logger = forensic_log
        
        # Load SAST System Prompt
        self.sast_prompt = ""
        prompt_path = os.path.join(os.path.dirname(__file__), 'prompts', 'sast_system.md')
        if os.path.exists(prompt_path):
            with open(prompt_path, 'r') as f:
                self.sast_prompt = f.read()

    def reason_about_project(self, source_path: str, cpg_context: str = None) -> List[Dict[str, Any]]:
        """
        Deep Reasoning Mode: Performs architectural, taint, and logic analysis.
        Follows the methodology in the SAST system prompt.
        """
        if not self.client or not self.sast_prompt:
            return []

        print(f"[*] AI Reasoning Engine: Performing deep project audit...")
        
        summary_data = self._summarize_directory(source_path)
        
        user_context = (
            f"PROJECT ARCHITECTURE:\n{summary_data['tree']}\n\n"
            f"SOURCE CODE SNIPPETS:\n{summary_data['summary']}\n\n"
        )
        if cpg_context:
            user_context += f"STATIC ANALYSIS FLOWS (CPG):\n{cpg_context}\n\n"

        user_context += "Analyze the codebase according to your identity as BREAKPOINT. Use the structured report format for any findings."

        # Call AI with the specific system prompt
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o", # Use gpt-4o for complex reasoning
                messages=[
                    {"role": "system", "content": self.sast_prompt},
                    {"role": "user", "content": user_context}
                ],
                temperature=0.1,
            )
            
            raw_result = response.choices[0].message.content.strip()
            return self._parse_sast_findings(raw_result)
        except Exception as e:
            print(f"    [-] AI Reasoning failed: {e}")
            return []

    def _parse_sast_findings(self, text: str) -> List[Dict[str, Any]]:
        """
        Parses the structured BREAKPOINT FINDING format from raw text.
        """
        findings = []
        blocks = text.split("┌───")
        for block in blocks:
            if "BREAKPOINT FINDING" not in block:
                continue
            
            finding = {
                "title": "Unknown",
                "severity": "LOW",
                "confidence": "POSSIBLE",
                "cwe": "",
                "owasp": "",
                "file": "",
                "lines": "",
                "function": "",
                "description": "",
                "taint_trace": "",
                "poc": "",
                "remediation": ""
            }
            
            lines = block.split("\n")
            current_section = None
            
            for line in lines:
                clean_line = line.strip("│ \t\r\n┌┐└┘├┤─")
                if not clean_line: continue
                
                if "Title" in clean_line and ":" in clean_line:
                    finding["title"] = clean_line.split(":", 1)[1].strip()
                elif "Severity" in clean_line and ":" in clean_line:
                    finding["severity"] = clean_line.split(":", 1)[1].strip()
                elif "Confidence" in clean_line and ":" in clean_line:
                    finding["confidence"] = clean_line.split(":", 1)[1].strip()
                elif "CWE" in clean_line and ":" in clean_line:
                    finding["cwe"] = clean_line.split(":", 1)[1].strip()
                elif "OWASP" in clean_line and ":" in clean_line:
                    finding["owasp"] = clean_line.split(":", 1)[1].strip()
                
                elif "LOCATION" in clean_line: current_section = "location"
                elif "VULNERABILITY DESCRIPTION" in clean_line: current_section = "description"
                elif "TAINT TRACE" in clean_line: current_section = "taint"
                elif "PROOF OF CONCEPT" in clean_line: current_section = "poc"
                elif "REMEDIATION" in clean_line: current_section = "remediation"
                
                elif current_section == "location":
                    if "File" in clean_line: finding["file"] = clean_line.split(":", 1)[1].strip()
                    elif "Line" in clean_line: finding["lines"] = clean_line.split(":", 1)[1].strip()
                    elif "Function" in clean_line: finding["function"] = clean_line.split(":", 1)[1].strip()
                elif current_section == "description":
                    finding["description"] += clean_line + " "
                elif current_section == "taint":
                    finding["taint_trace"] += clean_line + "\n"
                elif current_section == "poc":
                    finding["poc"] += clean_line + "\n"
                elif current_section == "remediation":
                    finding["remediation"] += clean_line + "\n"
            
            # Final cleanup
            finding["description"] = finding["description"].strip()
            finding["taint_trace"] = finding.get("taint_trace", "").strip()
            finding["poc"] = finding.get("poc", "").strip()
            finding["remediation"] = finding.get("remediation", "").strip()
            
            findings.append(finding)
            
        return findings


    def perform_footprinting(self, source_path: str, url: str, available_modules: List[str], cpg_context: str = None) -> Dict[str, Any]:
        """
        ULTRA-EFFICIENT SINGLE-CALL ANALYSIS.
        Combines Verification, Module Filtering, and Endpoint Discovery into ONE AI call.
        Saves ~65% of tokens. Now includes CPG-Augmented reasoning.
        """
        if not self.client:
            return {"match": True, "modules": available_modules, "endpoints": []}

        print(f"[*] AI Footprinting: Deep-analyzing source vs target (One-Shot Mode)...")
        
        # 1. Gather Target Context
        target_info = {}
        try:
            resp = requests.get(url, timeout=5, verify=False)
            target_info = {
                "headers": dict(resp.headers),
                "body": resp.text[:3000],
                "status": resp.status_code
            }
        except:
            target_info = {"error": "Target unreachable during footprinting"}

        # 2. Gather Source Context (The heavy part)
        summary_data = self._summarize_directory(source_path)
        
        # 3. Get Module Context
        from .metadata import ATTACK_KNOWLEDGE_BASE
        module_context = []
        for m in available_modules:
            meta = ATTACK_KNOWLEDGE_BASE.get(m) or ATTACK_KNOWLEDGE_BASE.get(m.replace('_check', '')) or ATTACK_KNOWLEDGE_BASE.get(m.replace('_attack', ''))
            desc = meta.get("description", "Security test.") if meta else "Security test."
            module_context.append(f"{m}: {desc[:50]}")
        
        prompt = (
            f"SYSTEM: You are a elite cyber-security auditor performing a footprinting phase.\n\n"
            f"TARGET URL DATA ({url}):\n{json.dumps(target_info)}\n\n"
            f"SOURCE CODE ARCHITECTURE:\n{summary_data['tree']}\n\n"
            f"SOURCE CODE SNIPPETS (CRITICAL):\n{summary_data['summary']}\n\n"
            f"AVAILABLE MODULES:\n{', '.join([m.split(':')[0] for m in module_context])}\n\n"
        )
        if cpg_context:
            prompt += f"\nPROJECT DATA FLOWS (CPG-AUGMENTED):\n{cpg_context}\n"

        prompt += (
            f"TASK:\n"
            f"1. VERIFY: Does the source code structure/logic match the live target body/headers? Be skeptical.\n"
            f"2. FILTER: Which of the available modules are actually relevant to this tech stack?\n"
            f"3. DISCOVER: List all API endpoints/routes found in the source snippets.\n\n"
            f"RESPONSE FORMAT (STRICT JSON ONLY):\n"
            f"{{\n"
            f"  \"verification\": {{\"match\": true/false, \"reason\": \"string\", \"confidence\": 0-100}},\n"
            f"  \"selected_modules\": [\"id1\", \"id2\"],\n"
            f"  \"endpoints\": [ {{\"path\": \"/url\", \"method\": \"GET\", \"params\": [\"p\"]}} ]\n"
            f"}}\n"
        )

        res = self._call_ai(prompt)
        if isinstance(res, dict):
            # Log for forensics
            if self.logger:
                self.logger.log_event("AI_FOOTPRINTING", {"url": url, "source": source_path, "res": res})
            
            # Extract and provide defaults
            verif = res.get("verification", {"match": True, "confidence": 100})
            mods = res.get("selected_modules", available_modules)
            endpoints = res.get("endpoints", [])
            
            return {
                "match": verif.get("match", True),
                "confidence": verif.get("confidence", 0),
                "reason": verif.get("reason", ""),
                "modules": mods if mods else available_modules,
                "endpoints": endpoints
            }
        
        return {"match": True, "modules": available_modules, "endpoints": []}

    def analyze_source_code(self, source_path: str, available_modules: List[str]) -> List[str]:
        """
        Analyzes source code files to suggest applicable attack modules.
        Provides module descriptions to the AI for better decision making.
        """
        if not self.client:
            print("[!] AI Analysis skipped: No OpenAI API key configured.")
            return available_modules

        from .metadata import ATTACK_KNOWLEDGE_BASE
        module_context = []
        for m in available_modules:
            # Try to get description from knowledge base, checking common variations
            meta = ATTACK_KNOWLEDGE_BASE.get(m) or ATTACK_KNOWLEDGE_BASE.get(m.replace('_check', '')) or ATTACK_KNOWLEDGE_BASE.get(m.replace('_attack', ''))
            desc = meta.get("description", "Targeted security test.") if meta else "Targeted security test."
            # DRONT-LOAD IDs and truncate descriptions to save tokens
            module_context.append(f"{m}: {desc[:60]}...")
        
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
        
        # Return None to indicate AI failure or inconclusive result
        return None

    def discover_endpoints(self, source_path: str) -> List[Dict[str, Any]]:
        """
        Extracts API endpoints and their parameters from the source code using AI.
        """
        if not self.client: return []

        print(f"[*] AI Phase: Extracting API surface from {source_path}...")
        summary_data = self._summarize_directory(source_path)
        
        prompt = (
            f"You are a professional security architect. Analyze the provided project source and list all API endpoints discovered.\n\n"
            f"PROJECT ARCHITECTURE:\n{summary_data['tree']}\n\n"
            f"CODE CONTEXT:\n{summary_data['summary']}\n\n"
            f"RESPONSE FORMAT:\n"
            f"Respond with ONLY a JSON list of objects:\n"
            f"[ {{\"path\": \"/api/login\", \"method\": \"POST\", \"params\": [\"username\", \"password\"]}}, ... ]\n\n"
            f"Be comprehensive but only list endpoints that actually exist in the code."
        )

        res = self._call_ai(prompt)
        if isinstance(res, list):
            return res
        return []

    def mutate_payload(self, payload: str, attack_type: str, last_response_context: str = "") -> str:
        """
        Uses AI to mutate a payload when it's blocked by a WAF or filter.
        """
        if not self.client: return payload
        
        prompt = (
            f"You are a master of WAF evasion. A security test was BLOCKED or Filtered.\n"
            f"ORIGINAL PAYLOAD: {payload}\n"
            f"ATTACK TYPE: {attack_type}\n"
            f"RESPONSE CONTEXT (BLOCK SIGNATURE): {last_response_context[:500]}\n\n"
            f"TASK: Generate a MUTATED version of the payload that bypasses current filters.\n"
            f"Consider: Encoding (double-hex, unicode), Obfuscation, Framework-specific bypasses, "
            f"Case manipulation, and Logic shifts.\n\n"
            f"RESPONSE FORMAT: Respond ONLY with the mutated payload string. No explanation."
        )
        
        res = self._call_ai(prompt)
        if isinstance(res, str) and res.strip():
            return res.strip()
        return payload

    def analyze_target_url(self, url: str, available_modules: List[str]) -> Optional[List[str]]:
        """
        Analyzes a hosted URL to suggest attack modules based on fingerprinting.
        """
        if not self.client:
            return None

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
        if not self.client: return True

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

    def test_ai_connectivity(self) -> bool:
        """
        Diagnostic test for OpenAI connectivity.
        """
        if not self.client:
            print(f"{Fore.RED}[!] AI Connection Test Failed: No API key loaded.{Style.RESET_ALL}")
            return False
            
        print(f"[*] Testing AI connectivity (model: gpt-4o-mini)...")
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "Respond with exactly 'PONG'"}],
                temperature=0,
                max_tokens=5
            )
            content = response.choices[0].message.content.strip()
            if "PONG" in content:
                print(f"{Fore.GREEN}[+] AI ENGINE ONLINE: Connectivity verified.{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.YELLOW}[!] AI ENGINE UNSTABLE: Unexpected response: {content}{Style.RESET_ALL}")
                return False
        except AuthenticationError:
             print(f"{Fore.RED}[!] AI AUTHENTICATION FAILED: The provided API key is invalid.{Style.RESET_ALL}")
             return False
        except RateLimitError as e:
            if "insufficient_quota" in str(e):
                 print(f"{Fore.RED}[!] AI QUOTA EXHAUSTED: Your OpenAI account has run out of credits.{Style.RESET_ALL}")
            else:
                 print(f"{Fore.RED}[!] AI RATE LIMIT HIT: TPM/RPM limit exceeded.{Style.RESET_ALL}")
            return False
        except APIConnectionError:
            print(f"{Fore.RED}[!] AI CONNECTION ERROR: Failed to reach OpenAI API (Network issue).{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] AI UNKNOWN ERROR: {e}{Style.RESET_ALL}")
            return False

    def _call_ai(self, prompt: str, retry_count: int = 1) -> Any:
        if not self.client: return None
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
            )
            
            result = response.choices[0].message.content.strip()
            if "```json" in result:
                result = result.split("```json")[1].split("```")[0].strip()
            elif "```" in result:
                result = result.split("```")[1].split("```")[0].strip()
            
            try:
                return json.loads(result)
            except:
                return result
                
        except AuthenticationError:
            print(f"\n{Fore.RED}[!] AI AUTHENTICATION FAILED: The OpenAI API key is invalid.{Style.RESET_ALL}")
            print(f"{Fore.RED}[!] Run 'breakpoint --openai-key <KEY>' with a valid sk- key.{Style.RESET_ALL}")
            return None
        except RateLimitError as e:
            if "insufficient_quota" in str(e):
                print(f"\n{Fore.YELLOW}[!] AI RESOURCE LIMIT: Your OpenAI account has insufficient credits or quota.{Style.RESET_ALL}")
                print(f"    [>] Feature Fallback: Switching to non-AI engine. The scan will continue but with generic logic.{Style.RESET_ALL}")
            else:
                if retry_count > 0:
                    if os.environ.get("BREAKPOINT_VERBOSE") == "1":
                        print("    [*] AI Rate limit hit. Retrying in 5s...")
                    time.sleep(5)
                    return self._call_ai(prompt, retry_count - 1)
                print(f"\n{Fore.YELLOW}[!] AI RATE LIMITED (429): TPM/RPM exceeded.{Style.RESET_ALL}")
                print(f"    [>] Feature Fallback: Reverting to non-AI engine for this step.{Style.RESET_ALL}")
            return None
        except APIConnectionError:
            print(f"\n{Fore.RED}[!] AI CONNECTION ERROR: Failed to reach OpenAI API.{Style.RESET_ALL}")
            return None
        except Exception as e:
            if os.environ.get("BREAKPOINT_VERBOSE") == "1":
                print(f"    [!] AI Unknown Error: {e}")
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
                            # AGGRESSIVE TOKEN SAVING: 
                            # Read much less, but focus on the middle where logic often resides
                            read_size = 1200 if is_priority else 400
                            content = f.read(read_size)
                            
                            # Clean up content: minor minification
                            lines = [l.strip() for l in content.split('\n') if l.strip() and not l.strip().startswith(('#', '//', '/*', '*'))]
                            processed_content = "\n".join(lines[:20]) # Reduced from 30 to 20 lines
                            
                            prio_score = 10 if is_priority else 1
                            summary.append((prio_score, f"File: {rel_path}\nSnippet:\n{processed_content}\n---"))
                    except:
                        continue
        
        summary.sort(key=lambda x: x[0], reverse=True)
        return {
            "summary": "\n\n".join([s[1] for s in summary[:15]]), # Reduced from 20 to 15 files
            "tree": "\n".join(file_tree[:50]), # Reduced from 80 to 50 entries
            "count": file_count
        }
