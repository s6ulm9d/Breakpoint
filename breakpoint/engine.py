
import requests
from typing import List, Dict, Any, Optional
from .forensics import ForensicLogger
from .attacks import omni
from .models import Scenario, CheckResult
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import os
import threading
import hashlib

# NEW MODULES
from .static_analysis import StaticAnalyzer
from .agents import AdversarialLoop
from .artifacts.poc_generator import PoCGenerator, ArtifactManager
from .stac.generators import PytestGenerator, PlaywrightGenerator
from .sandbox import Sandbox

# IMPACT MAPPING: Translate technical findings to Business Impact (What broke?)
ATTACK_IMPACTS = {
    "sql_injection": "Database Compromise. Attackers can dump data, bypass auth, or destroy the DB.",
    "nosql_injection": "Database Compromise. Attackers can bypass auth or dump NoSQL data.",
    "rce": "Full System Compromise. Attackers have complete control over the server.",
    "cve_classics": "Remote Code Execution. Critical system compromise.",
    "lfi": "Sensitive Data Exposure. Attackers can read system files and secrets.",
    "xxe_exfil": "File Theft & SSRF. Attackers can read internal files or scan networks.",
    "ssrf": "Internal Network Breach. Attackers can access cloud metadata or internal services.",
    "xss": "Client-Side Compromise. Attackers can steal user sessions (Cookies) or deface the site.",
    "idor": "Authorization Bypass. Attackers can access private data of other users.",
    "jwt_weakness": "Authentication Bypass. Attackers can forge identities and take over accounts.",
    "brute_force": "Account Takeover. Weak credentials allow unauthorized access.",
    "dos_slowloris": "Service Outage. The application becomes unresponsive (Availability Loss).",
    "advanced_dos": "Service Degradation. Resource exhaustion causes extreme latency or crashes.",
    "crlf_injection": "Integrity Loss. Attackers can poison headers, fixate sessions, or deface content.",
    "prototype_pollution": "Application Instability. Logic corruption or Denial of Service.",
    "open_redirect": "Phishing Risk. Users can be redirected to malicious sites trusting your domain.",
}

class Engine:
    SHUTDOWN_SIGNAL = False

    def __init__(self, base_url: str, forensic_log: Optional[ForensicLogger] = None, verbose: bool = False, headers: Dict[str, str] = None, simulation: bool = False, source_path: str = None, diff_mode: bool = False, git_range: str = None):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        self.simulation = simulation
        self.headers = headers or {}
        
        # Extended Intelligence
        self.source_path = source_path
        self.diff_mode = diff_mode
        self.git_range = git_range
        self.static_analyzer = StaticAnalyzer(source_path) if source_path else None
        self.poc_gen = PoCGenerator()
        self.artifact_mgr = ArtifactManager()
        self.stac_gen = PytestGenerator()
        self.e2e_gen = PlaywrightGenerator()
        self.sandbox = Sandbox()
        self.adv_loop = AdversarialLoop(sandbox=self.sandbox)
        
        # Use provided logger or create a new one
        self.logger = forensic_log if forensic_log else ForensicLogger(verbose=verbose)
        
        # Robust Localhost Detection for Engine
        self._is_localhost = any(x in self.base_url.lower() for x in ["localhost", "127.0.0.1", "0.0.0.0"])
        
        # Shared cache to prevent redundant 404 probes in parallel execution
        self._dead_paths = set()
        self._cache_lock = threading.Lock()
        
        self.findings_hashes = set()

        self._check_connection()

    def _check_connection(self):
        """Fail fast if target is down."""
        try:
            print(f"[*] Probing target accessibility: {self.base_url}...")
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            
            resp = requests.get(self.base_url, timeout=10, verify=False, headers=self.headers)
            print(f"    -> Target UP (Status: {resp.status_code}).")
        except Exception as e:
            from .http_client import HttpClient
            print(f"\n[!] FATAL ERROR: Could not connect to {self.base_url}")
            if not HttpClient._is_internet_available():
                print("   [!] YOUR INTERNET CONNECTION IS DOWN.")
            else:
                print(f"   Reason: {e}")
            import sys; sys.exit(1)

    def run_all(self, scenarios: List[Scenario], concurrency: int = 5) -> List[CheckResult]:
        init(autoreset=True)
        if not concurrency: concurrency = 500
        if self._is_localhost:
            limit = 25 if any(s.config.get("aggressive") for s in scenarios if hasattr(s, 'config')) else 5
            if concurrency > limit: concurrency = limit
             
        results = []
        rate_limit_hits = 0

        # PHASE 0: STATIC INTELLIGENCE & DIFF
        static_findings = []
        if self.static_analyzer and self.source_path:
            print(f"\n[*] PHASE 0: Static Intelligence & Code Analysis...")
            if self.diff_mode:
                print(f"    (Differential Scan: Analyzing changes in {self.git_range or 'HEAD'})")
            
            static_findings = self.static_analyzer.analyze()
            print(f"    -> Static Findings: {len(static_findings)} potential sink paths identified.")
            
            # Filter scenarios based on static findings (Strict Mode)
            if static_findings:
                pass 

        # Split scenarios
        dos_types = [
            "dos_slowloris", "slowloris", "dos_extreme", 
            "advanced_dos", "redos", "xml_bomb", "json_bomb", 
            "crash", "traffic_spike"
        ]
        dos_scenarios = [s for s in scenarios if s.type in dos_types]
        std_scenarios = [s for s in scenarios if s.type not in dos_types]
        
        print(f"[*] STARTING ENGINE: {len(std_scenarios) + len(dos_scenarios)} scenarios (Concurrency: {concurrency})...")

        shutdown_event = threading.Event()
        def monitor_shutdown():
            while not Engine.SHUTDOWN_SIGNAL and not shutdown_event.is_set():
                import time; time.sleep(0.1)
            shutdown_event.set()
        threading.Thread(target=monitor_shutdown, daemon=True).start()

        executor = ThreadPoolExecutor(max_workers=concurrency)
        try:
            # PHASE 1: Runtime Validation (Standard)
            if std_scenarios:
                future_to_std = {executor.submit(self._execute_scenario, s): s for s in std_scenarios}
                
                for future in as_completed(future_to_std):
                    if Engine.SHUTDOWN_SIGNAL or shutdown_event.is_set(): 
                        executor.shutdown(wait=False, cancel_futures=True); break
                    scenario = future_to_std[future]
                    try:
                        result = future.result() 
                        
                        # DEDUPLICATION CHECK
                        if result.status == "VULNERABLE":
                            if self._is_duplicate(result):
                                continue

                        # PHASE 2: ADVERSARIAL VALIDATION (The "Breaker" Loop)
                        if result.status == "VULNERABLE":
                            print(f"    [!] Vulnerability Detected ({result.type}). Initiating Adversarial Validation...")
                            # log attempt
                            self.logger.log_event("VULNERABILITY_CANDIDATE", {"id": scenario.id, "type": result.type})
                            
                            # Attempt to 'break' (validate) it fully
                            snippet = "Source unavailable"
                            
                            # New Agent Logic returns dict
                            validation_result = self.adv_loop.run(
                                vulnerability_report=str(result.details), 
                                source_code=snippet,
                                target_url=self.base_url + scenario.target
                            )
                            
                            # Decision Logic
                            if validation_result["status"] == "CONFIRMED":
                                result.confidence = "CONFIRMED"
                                result.status = "CONFIRMED"
                                print(f"    [+] VALIDATOR CONFIRMED: Checks passed. Generating Artifacts.")
                                
                                # PHASE 3: ARTIFACT GENERATION
                                # Generate PoC
                                poc_path = self.poc_gen.generate_poc(
                                    result.type, self.base_url + scenario.target, 
                                    result.details.get('reproduction_payload') if isinstance(result.details, dict) else "N/A", result.details if isinstance(result.details, dict) else {}
                                )
                                self.logger.log_event("ARTIFACT_GENERATED", {"type": "PoC", "path": poc_path})
                                
                                # Save Verified PoC if available
                                if validation_result.get("poc"):
                                    verified_poc_path = self.poc_gen.save_llm_poc(result.type, validation_result["poc"])
                                    self.logger.log_event("ARTIFACT_GENERATED", {"type": "VerifiedPoC", "path": verified_poc_path})
                                
                                # Generate Regression
                                test_path = self.stac_gen.generate_test({
                                    "type": result.type, "target": self.base_url + scenario.target,
                                    "scenario_id": scenario.id, "method": scenario.method,
                                    "signature": "VULNERABLE"
                                })
                                self.logger.log_event("ARTIFACT_GENERATED", {"type": "RegressionTest", "path": test_path})
                                
                                # Generate E2E Regression
                                e2e_path = self.e2e_gen.generate_test({
                                    "type": result.type, "target": self.base_url + scenario.target,
                                    "scenario_id": scenario.id, "method": scenario.method,
                                    "signature": "VULNERABLE"
                                })
                                self.logger.log_event("ARTIFACT_GENERATED", {"type": "E2ETest", "path": e2e_path})
                            
                            elif validation_result["status"] == "SUSPECT":
                                result.confidence = validation_result["confidence"]
                                result.status = "SUSPECT"
                                print(f"    [?] VALIDATOR SUSPECT: Partial reproduction. ({validation_result['details']})")
                            
                            else:
                                result.confidence = "LOW"
                                result.status = "SECURE" # Should NOT report if not reproducible
                                result.details = f"Validation Failed: {validation_result['details']}"
                                print(f"    [-] VALIDATOR FAILED: Mark as SECURE.")

                        if result.status != "SECURE":
                            results.append(result)
                            self._print_result(scenario, result)
                        
                        if result.status == "BLOCKED": rate_limit_hits += 1
                        
                    except Exception as exc:
                        if not Engine.SHUTDOWN_SIGNAL:
                            results.append(CheckResult(scenario.id, scenario.type or "unknown", "ERROR", None, f"Exception: {str(exc)}"))

            # PHASE 4: Destructive / DoS Scenarios
            if dos_scenarios and not shutdown_event.is_set():
                print(f"\n[*] PHASE 4: Executing {len(dos_scenarios)} resource-intensive/destructive attacks...")
                for s in dos_scenarios:
                    if shutdown_event.is_set(): break
                    try:
                        result = self._execute_scenario(s) # Sequential for safety
                        results.append(result)
                        self._print_result(s, result)
                    except Exception: pass

        except (KeyboardInterrupt, SystemExit):
            Engine.SHUTDOWN_SIGNAL = True
            print(f"\n{Fore.RED}[!] TERMINATING: Instant Shutdown Triggered.{Style.RESET_ALL}")
            shutdown_event.set()
            executor.shutdown(wait=False, cancel_futures=True)
            os._exit(0)
        finally:
            executor.shutdown(wait=True)
            # Final Signature
            self.logger.sign_run()

        return results

    def _is_duplicate(self, result: CheckResult) -> bool:
        """Calculate unique hash for finding deduplication."""
        try:
            # Hash based on type, details (simplified), and id
            details_str = str(result.details)[:200]
            unique_str = f"{result.type}:{result.id}:{details_str}"
            h = hashlib.sha256(unique_str.encode()).hexdigest()
            if h in self.findings_hashes:
                return True
            self.findings_hashes.add(h)
            return False
        except:
            return False

    def _execute_scenario(self, s: Scenario) -> CheckResult:
        try:
            check_type = s.attack_type if getattr(s, 'type', '') == 'simple' and hasattr(s, 'attack_type') else s.type
            
            # SIMULATION CHECK
            from breakpoint.metadata import get_metadata
            meta = get_metadata(check_type)
            if self.simulation and meta.get("destructive", False):
                return CheckResult(s.id, check_type, "SIMULATED", meta.get("risk_tier", "MEDIUM"), f"[SIMULATION MODE] Impact Assessment: {meta.get('impact_simulation')}", "SIMULATED")

            from .http_client import HttpClient
            from .attacks import omni
            
            client = HttpClient(self.base_url, verbose=self.verbose, headers=self.headers)
            
            with self._cache_lock:
                if s.target in self._dead_paths:
                    return CheckResult(s.id, check_type, "SKIPPED", "INFO", f"Endpoint {s.target} confirmed unreachable.")

            # DISPATCHER (OMNI CONSOLIDATED)
            res_dict = {}
            if check_type == "header_security": res_dict = omni.run_header_security_check(client, s)
            elif check_type == "ssrf": res_dict = omni.run_ssrf_attack(client, s)
            elif check_type in ["rce", "react2shell"]: res_dict = omni.run_rce_attack(client, s)
            elif check_type == "xss": res_dict = omni.run_xss_scan(client, s)
            elif check_type == "crlf_injection": res_dict = omni.run_crlf_injection(client, s)
            elif check_type == "prototype_pollution": res_dict = omni.run_prototype_pollution(client, s)
            elif check_type == "sql_injection": res_dict = omni.run_sqli_attack(client, s)
            elif check_type == "open_redirect": res_dict = omni.run_open_redirect(client, s)
            elif check_type == "brute_force": res_dict = omni.run_brute_force(client, s)
            elif check_type == "advanced_dos": res_dict = omni.run_advanced_dos(client, s)
            elif check_type == "debug_exposure": res_dict = omni.run_debug_exposure(client, s)
            elif check_type == "secret_leak": res_dict = omni.run_secret_leak(client, s)
            elif check_type == "swagger_exposure": res_dict = omni.run_swagger_check(client, s)
            elif check_type == "git_exposure": res_dict = omni.run_git_exposure(client, s)
            elif check_type == "env_exposure": res_dict = omni.run_env_exposure(client, s)
            elif check_type == "phpinfo": res_dict = omni.run_phpinfo(client, s)
            elif check_type == "ds_store_exposure": res_dict = omni.run_ds_store(client, s)
            elif check_type == "ssti": res_dict = omni.run_ssti_attack(client, s)
            elif check_type == "insecure_deserialization": res_dict = omni.run_insecure_deserialization(client, s)
            elif check_type == "jwt_weakness": res_dict = omni.run_jwt_attack(client, s)
            elif check_type == "idor": res_dict = omni.run_idor_check(client, s)
            elif check_type == "lfi": res_dict = omni.run_lfi_attack(client, s)
            elif check_type == "clickjacking": res_dict = omni.run_clickjacking(client, s)
            elif check_type == "cors_origin": res_dict = omni.run_cors_misconfig(client, s)
            elif check_type == "host_header": res_dict = omni.run_host_header_injection(client, s)
            elif check_type == "email_injection": res_dict = omni.run_email_injection(client, s)
            elif check_type == "nosql_injection": res_dict = omni.run_nosql_injection(client, s)
            elif check_type == "ldap_injection": res_dict = omni.run_ldap_injection(client, s)
            elif check_type == "xpath_injection": res_dict = omni.run_xpath_injection(client, s)
            elif check_type == "ssi_injection": res_dict = omni.run_ssi_injection(client, s)
            elif check_type == "request_smuggling": res_dict = omni.run_request_smuggling(client, s)
            elif check_type == "graphql_introspection": res_dict = omni.run_graphql_introspection(client, s)
            elif check_type == "graphql_batching": res_dict = omni.run_graphql_batching(client, s)
            elif check_type in ["log4shell", "cve_log4shell"]: res_dict = omni.run_cve_log4shell(client, s)
            elif check_type == "cache_deception": res_dict = omni.run_cache_deception(client, s)
            elif check_type == "race_condition": res_dict = omni.run_race_condition(client, s)
            elif check_type == "otp_reuse": res_dict = omni.run_otp_reuse(client, s)
            elif check_type == "rsc_server_action_forge": res_dict = omni.run_rsc_server_action_forge(client, s)
            elif check_type == "rsc_ssr_ssrf": res_dict = omni.run_ssr_ssrf(client, s)
            elif check_type == "rsc_hydration_collapse": res_dict = omni.run_hydration_collapse(client, s)
            elif check_type in ["rsc_flight_trust_boundary_violation", "rsc_flight_deserialization_abuse"]:
                res_dict = omni.run_flight_trust_boundary_violation(client, s)
            elif check_type == "json_bomb": res_dict = omni.run_json_bomb(client, s)
            elif check_type == "http_desync": res_dict = omni.run_http_desync(client, s)
            elif check_type == "poodle": res_dict = omni.run_poodle_check(client, s)
            elif check_type == "file_upload_abuse": res_dict = omni.run_file_upload_abuse(client, s)
            elif check_type == "zip_slip": res_dict = omni.run_zip_slip(client, s)
            elif check_type == "rsc_cache_poisoning": res_dict = omni.run_rsc_cache_poisoning(client, s)
            elif check_type in ["dos_extreme", "slowloris", "dos_slowloris"]:
                res_dict = omni.run_dos_extreme(client, s)
            else:
                return CheckResult(s.id, check_type, "SKIPPED", "INFO", f"Check not implemented: {check_type}")

            # Convert Dict to CheckResult
            status = "SECURE"
            if res_dict.get("status"):
                status = res_dict.get("status")
            elif res_dict.get("rate_limited"): status = "BLOCKED" 
            elif res_dict.get("skipped"): status = "INCONCLUSIVE"
            elif not res_dict.get("passed", True): status = "VULNERABLE"
            
            return CheckResult(
                id=s.id,
                type=check_type,
                status=status,
                severity="HIGH",
                details=res_dict.get("details", ""),
                confidence=res_dict.get("confidence", "HIGH") if status == "VULNERABLE" else "P.O.C"
            )

        except Exception as e:
            # Mask internal errors as skipped if benign
            return CheckResult(s.id, s.type, "SKIPPED", "LOW", f"Internal Exception: {str(e)}")

    def _print_result(self, scenario: Scenario, result: CheckResult):
        color = Fore.GREEN
        if result.status == "CONFIRMED":
            color = Fore.RED + Style.BRIGHT
        elif result.status == "SUSPECT":
            color = Fore.CYAN
        elif result.status == "VULNERABLE":
            color = Fore.RED # Should be rare if loop is working
        elif result.status in ["ERROR", "PROXY_FAILURE"]:
            color = Fore.MAGENTA
        elif result.status in ["BLOCKED", "WAF_INTERCEPTED"]:
            color = Fore.YELLOW
        elif result.status == "INCONCLUSIVE":
            color = Fore.BLUE
        elif result.status == "SECURE":
            color = Fore.GREEN
        elif result.status == "SKIPPED":
            color = Fore.WHITE

        print(f"    -> {color}[{result.status}] {scenario.id}: {str(result.details)[:80]}...{Style.RESET_ALL}")
        
        if result.status == "CONFIRMED":
            print(f"\n{Fore.RED}" + "="*60)
            print(f" CONFIRMED VULNERABILITY: {result.type.upper()}")
            print(f"="*60 + f"{Style.RESET_ALL}")
            
            # Confidence
            conf = result.confidence or "HIGH"
            print(f" {Fore.RED}{'Confidence:':<20}{Style.RESET_ALL} {conf}")
            
            # Impact
            impact = ATTACK_IMPACTS.get(result.type, "Security Compromise")
            print(f" {Fore.RED}{'Business Impact:':<20}{Style.RESET_ALL} {impact}")
            
            # Evidence
            print(f" {Fore.RED}{'Evidence:':<20}{Style.RESET_ALL} See artifacts/poc_*.py")
            
            print(f"{Fore.RED}" + "="*60 + f"{Style.RESET_ALL}\n")
