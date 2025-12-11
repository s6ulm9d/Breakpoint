import yaml
import requests
from typing import List, Dict, Any, Optional
from .reporting.forensics import ForensicLogger
from .checks import headers, bruteforce, reflection, performance, react2shell, sqli, xss, ssrf
from .attacks import dos_extreme
from .models import Scenario, CheckResult

def load_scenarios(path: str) -> List[Scenario]:
    with open(path, 'r') as f:
        data = yaml.safe_load(f)
    return [Scenario(
        id=item['id'],
        type=item['type'],
        target=item['target'],
        method=item.get('method', 'GET'),
        config=item.get('config', {})
    ) for item in data]

class Engine:
    def __init__(self, base_url: str, forensic_log: Optional[ForensicLogger] = None, verbose: bool = False):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        # Use provided logger or create a new one
        self.logger = forensic_log if forensic_log else ForensicLogger(verbose=verbose)
        self._check_connection()

    def _check_connection(self):
        """Fail fast if target is down."""
        try:
            print(f"[*] Probing target accessibility: {self.base_url}...")
            # Suppress SSL warnings for localhost
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            
            requests.get(self.base_url, timeout=5, verify=False)
            print("    -> Target UP (Connection Successful).")
        except requests.exceptions.ConnectionError:
            print(f"\n❌ ERROR: Could not connect to {self.base_url}")
            print(f"   Reason: Connection Refused or Host Unreachable.")
            if "localhost" in self.base_url or "127.0.0.1" in self.base_url:
                print("   💡 Tip: Are you sure the server is running on this port?")
                print("   💡 Tip: Check if you need 'http://' instead of 'https://'.")
            import sys; sys.exit(1)
        except Exception as e:
            print(f"⚠️ Warning: Connectivity probe failed ({e}), but proceeding...")

    def run_all(self, scenarios: List[Scenario], concurrency: int = 5) -> List[CheckResult]:
        import concurrent.futures
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from colorama import Fore, Style, init
        init(autoreset=True)
        
        # Concurrency level: Use global default if provided, otherwise default to high parallelism
        # NOTE: self.concurrency controls are handled in CLI now
        results = []

        # Split scenarios: DoS MUST run last to avoid killing the server while checking XSS/SQLi
        dos_scenarios = [s for s in scenarios if s.type == "dos_slowloris"]
        std_scenarios = [s for s in scenarios if s.type != "dos_slowloris"]
        
        # 1. Run Standard Vulnerability Checks (Fast, Parallel)
        if std_scenarios:
            print(f"[*] Phase 1: Running {len(std_scenarios)} vulnerability checks (High Speed)...")
            try:
                with ThreadPoolExecutor(max_workers=concurrency) as executor:
                    future_to_scenario = {executor.submit(self._execute_scenario, s): s for s in std_scenarios}
                    
                    try:
                        for future in as_completed(future_to_scenario):
                            scenario = future_to_scenario[future]
                            try:
                                # 🚨 GLOBAL TIMEOUT: Kill any scenario taking > 60 seconds
                                result = future.result(timeout=60)
                                results.append(result)
                                color = Fore.GREEN if result.status in ["PASSED", "SECURE"] else Fore.RED
                                print(f"    -> {color}[{result.status}] {result.details[:50]}...{Style.RESET_ALL}")
                                
                            except concurrent.futures.TimeoutError:
                                print(f"{Fore.RED}    -> [TIMEOUT] Scenario {scenario.id} exceeded 60s limit. KILLED.{Style.RESET_ALL}")
                                results.append(CheckResult(scenario.id, scenario.type, "ERROR", None, "Execution timed out (60s limit)."))
                                
                            except Exception as exc:
                                print(f"{Fore.RED}    -> [ERROR] Scenario {scenario.id} generated an exception: {exc}{Style.RESET_ALL}")
                    except KeyboardInterrupt:
                        print(f"\n{Fore.RED}[!] User interrupted scan (Ctrl+C). Exiting immediately...{Style.RESET_ALL}")
                        import os; os._exit(1)
            except KeyboardInterrupt:
                 import os; os._exit(1)

        # 2. Run Destructive DoS (Last)
        if dos_scenarios:
            print(f"\n[*] Phase 2: Execution Destructive DoS Attacks ({len(dos_scenarios)})...")
            for s in dos_scenarios:
                 # DoS is blocking usually, but we run it directly here
                 res = self._execute_scenario(s)
                 results.append(res)
                 color = Fore.GREEN if res.status in ["PASSED", "SECURE"] else Fore.RED
                 print(f"    -> {color}[{res.status}] {res.details[:50]}...{Style.RESET_ALL}")
                    
        return results

    def _execute_scenario(self, s: Scenario) -> CheckResult:
        """Executes a single scenario and returns its CheckResult."""
        try:
            # Resolve actual check type (Handle SimpleScenario wrapper)
            check_type = s.attack_type if getattr(s, 'type', '') == 'simple' and hasattr(s, 'attack_type') else s.type
            
            # === LEGACY CHECKS (Direct Request) ===
            if check_type == "header_security":
                return headers.check(self.base_url, s, self.logger)
            # brute_force moved to new attacks
            elif check_type == "reflection":
                return reflection.check(self.base_url, s, self.logger)
            elif check_type == "performance":
                return performance.check(self.base_url, s, self.logger)
            elif check_type == "react2shell":
                return react2shell.check(self.base_url, s, self.logger)
            elif check_type == "ssrf":
                return ssrf.check(self.base_url, s, self.logger)
            
            # === NEW ATTACKS (HttpClient Based) ===
            # Lazy import to avoid circular dep issues during init
            from .http_client import HttpClient
            from .attacks import crlf, xxe, rce, web_exploits, dos_extreme, cve_classics, brute
            from .attacks import config_exposure, ssti, logic, jwt_weakness, deserialization, idor, lfi
            from .attacks import sqli as attack_sqli
            
            # Adapter: Create a fresh client for this thread
            client = HttpClient(self.base_url, verbose=self.verbose)
            
            res_dict = {}
            # === DISPATCHER ===
            if check_type == "crlf_injection":
                res_dict = crlf.run_crlf_injection(client, s)
            elif check_type == "xxe_exfil":
                res_dict = xxe.run_xxe_exfil(client, s)
            elif check_type == "prototype_pollution":
                res_dict = web_exploits.run_prototype_pollution(client, s)
            elif check_type == "rce":
                res_dict = rce.run_rce_attack(client, s)
            elif check_type == "sql_injection":
                res_dict = attack_sqli.run_sqli_attack(client, s)
            elif check_type == "xss":
                res_dict = web_exploits.run_xss_scan(client, s)
            elif check_type == "open_redirect":
                res_dict = web_exploits.run_open_redirect(client, s)
            elif check_type == "brute_force":
                res_dict = brute.run_brute_force(client, s)
            elif check_type == "advanced_dos":
                res_dict = web_exploits.run_advanced_dos(client, s)
            
            # Exposure & Secrets
            elif check_type == "debug_exposure":
                res_dict = config_exposure.run_debug_exposure(client, s)
            elif check_type == "secret_leak":
                res_dict = config_exposure.run_secret_leak(client, s)
            
            # Injection
            elif check_type == "ssti":
                res_dict = ssti.run_ssti_attack(client, s)
            elif check_type == "insecure_deserialization":
                res_dict = deserialization.run_deserialization_check(client, s)
            
            # Auth & IDOR
            elif check_type == "jwt_weakness":
                res_dict = jwt_weakness.run_jwt_attack(client, s)
            elif check_type == "idor":
                res_dict = idor.run_idor_check(client, s)
            elif check_type == "lfi":
                res_dict = lfi.run_lfi_attack(client, s)

            # CVEs (Map strictly to yaml types)
            elif check_type in ["log4shell", "cve_log4shell"]:
                res_dict = cve_classics.run_log4j_attack(client, s)
            elif check_type in ["spring4shell", "cve_spring4shell"]:
                res_dict = cve_classics.run_spring4shell(client, s)
            elif check_type in ["struts2_rce", "cve_struts2"]:
                res_dict = cve_classics.run_struts2_rce(client, s)
            
            # Logic
            elif check_type == "race_condition":
                res_dict = logic.run_race_condition(client, s)
            elif check_type == "otp_reuse":
                res_dict = logic.run_otp_reuse(client, s)
            
            elif check_type == "slowloris" or check_type == "dos_slowloris": # Handle alias
                # DoS usually uses its own logic, assuming it returns CheckResult or compatible
                return dos_extreme.check(self.base_url, s, self.logger)
            else:
                return CheckResult(s.id, check_type, "ERROR", "LOW", f"Unknown check type: {check_type}")

            # Convert Dict to CheckResult
            status = "PASSED" if res_dict.get("passed") else "VULNERABLE"
            # If skipped
            if res_dict.get("skipped"):
                status = "SECURE"
                
            details = res_dict.get("details", "")
            if isinstance(details, dict):
                # Flatten for simple display if needed, or keep as dict
                # CheckResult expects 'str' for details in some versions, but we updated it to be flexible?
                # Let's stringify for safety if it's complex
                import json
                # details_str = json.dumps(details) 
                # Actually, our reporters now handle dict details cleanly!
                pass

            return CheckResult(
                id=s.id,
                type=s.type,
                status=status,
                severity="HIGH", # Default for these attacks
                details=details
            )

        except Exception as e:
            # Internal errors should be marked as ERROR/LOW, not VULNERABLE/HIGH
            return CheckResult(s.id, s.type, "ERROR", "LOW", f"Internal Error: {str(e)}")
