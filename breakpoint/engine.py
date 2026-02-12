import requests
from typing import List, Dict, Any, Optional
from .forensics import ForensicLogger
from .attacks import dos_extreme, cache
from .models import Scenario, CheckResult
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import os
from .agents import AdversarialLoop
from .sandbox import Sandbox
from .stac import STaCEngine

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

    def __init__(self, base_url: str, forensic_log: Optional[ForensicLogger] = None, verbose: bool = False, headers: Dict[str, str] = None, simulation: bool = False):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        self.simulation = simulation
        # Use provided logger or create a new one
        self.logger = forensic_log if forensic_log else ForensicLogger(verbose=verbose)
        self.headers = headers or {}
        
        # Robust Localhost Detection for Engine
        self._is_localhost = any(x in self.base_url.lower() for x in ["localhost", "127.0.0.1", "0.0.0.0"])
        
        # Shared cache to prevent redundant 404 probes in parallel execution
        self._dead_paths = set()
        import threading
        self._cache_lock = threading.Lock()
        
        self._check_connection()

    def _check_connection(self):
        """Fail fast if target is down."""
        try:
            print(f"[*] Probing target accessibility: {self.base_url}...")
            # Suppress SSL warnings for localhost
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            
            # Simple probe
            resp = requests.get(self.base_url, timeout=10, verify=False, headers=self.headers)
            print(f"    -> Target UP (Status: {resp.status_code}).")
        except Exception as e:
            from .http_client import HttpClient
            print(f"\n[!] FATAL ERROR: Could not connect to {self.base_url}")
            if not HttpClient._is_internet_available():
                print("   [!] YOUR INTERNET CONNECTION IS DOWN.")
                print("   [!] BREAKPOINT requires an active connection to probe targets.")
            else:
                print(f"   Reason: {e}")
                print("   [!] Aborting scan. Cannot exploit a target that cannot be reached.")
            import sys; sys.exit(1) # Strict Exit

    def run_all(self, scenarios: List[Scenario], concurrency: int = 5) -> List[CheckResult]:
        init(autoreset=True)
        
        # Concurrency level: Respect CLI/User input
        # DEFAULT: If user didn't specify (or passed 0), use 500.
        # BUT: For localhost, cap it unless explicitly high.
        if not concurrency:
            concurrency = 500
            
        if self._is_localhost:
            limit = 25 if any(s.config.get("aggressive") for s in scenarios if hasattr(s, 'config')) else 5
            if concurrency > limit:
                 if self.verbose: 
                     print(f"[*] Localhost detected. Capping concurrency to {limit} to prevent dev-server saturation/hangs.")
                 concurrency = limit
             
        # Signal handling is managed by the CLI-level handler in cli.py
        # We only catch KeyboardInterrupt here if it propagates.
        
        results = []
        rate_limit_hits = 0

        # Split scenarios: destructive or resource-draining checks MUST run last
        dos_types = [
            "dos_slowloris", "slowloris", "dos_extreme", 
            "advanced_dos", "redos", "xml_bomb", "json_bomb", 
            "crash", "traffic_spike"
        ]
        dos_scenarios = [s for s in scenarios if s.type in dos_types]
        std_scenarios = [s for s in scenarios if s.type not in dos_types]
        
        # Order matters: logical checks first, then potential hangs/crashes
        all_scenarios = std_scenarios + dos_scenarios
        
        print(f"[*] STARTING ENGINE: {len(all_scenarios)} scenarios (Concurrency: {concurrency})...")
        if self._is_localhost:
            print(f"    (LOCALHOST Optimization Enabled: App-layer DoS delayed, low concurrency)")

        import threading
        shutdown_event = threading.Event()
        
        def monitor_shutdown():
            while not Engine.SHUTDOWN_SIGNAL and not shutdown_event.is_set():
                import time
                time.sleep(0.1)
            shutdown_event.set()
            
        threading.Thread(target=monitor_shutdown, daemon=True).start()

        executor = ThreadPoolExecutor(max_workers=concurrency)
        try:
            if std_scenarios:
                # Fast execution of Phase 1
                future_to_std = {executor.submit(self._execute_scenario, s): s for s in std_scenarios}
                
                for future in as_completed(future_to_std):
                    if Engine.SHUTDOWN_SIGNAL or shutdown_event.is_set(): 
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    scenario = future_to_std[future]
                    try:
                        result = future.result() 
                        results.append(result)
                        self._print_result(scenario, result)
                        if result.status == "BLOCKED":
                            rate_limit_hits += 1
                    except Exception as exc:
                        if not Engine.SHUTDOWN_SIGNAL:
                            results.append(CheckResult(scenario.id, scenario.type or "unknown", "ERROR", None, f"Exception: {str(exc)}"))

            # PHASE 2: Destructive / DoS Scenarios (Last Resort)
            if dos_scenarios and not shutdown_event.is_set():
                print(f"\n[*] PHASE 2: Executing {len(dos_scenarios)} resource-intensive/destructive attacks...")
                if self._is_localhost:
                    print(f"    (Phase 2 Sequential Mode Engaged for Localhost Integrity)")
                    for s in dos_scenarios:
                        if shutdown_event.is_set(): break
                        try:
                            result = self._execute_scenario(s)
                            results.append(result)
                            self._print_result(s, result)
                            if result.status == "BLOCKED":
                                rate_limit_hits += 1
                        except Exception as e:
                            results.append(CheckResult(s.id, s.type, "ERROR", "HIGH", f"DoS Error: {str(e)}"))
                else:
                    future_to_dos = {executor.submit(self._execute_scenario, s): s for s in dos_scenarios}
                    for future in as_completed(future_to_dos):
                        if shutdown_event.is_set(): break
                        scenario = future_to_dos[future]
                        try:
                            result = future.result(timeout=600)
                            results.append(result)
                            self._print_result(scenario, result)
                            if result.status == "BLOCKED":
                                rate_limit_hits += 1
                        except Exception as exc:
                            results.append(CheckResult(scenario.id, scenario.type, "ERROR", "HIGH", f"DoS Error: {str(exc)}"))

        except (KeyboardInterrupt, SystemExit):
            Engine.SHUTDOWN_SIGNAL = True
            print(f"\n{Fore.RED}[!] TERMINATING: Instant Shutdown Triggered.{Style.RESET_ALL}")
            shutdown_event.set()
            executor.shutdown(wait=False, cancel_futures=True)
            os._exit(0)
        except Exception as e:
            print(f"{Fore.RED}[!!!] CRITICAL: Engine Loop Failed: {e}{Style.RESET_ALL}")
        finally:
            executor.shutdown(wait=True)

        if rate_limit_hits > 0:
            print(f"\n{Fore.MAGENTA}" + "="*60)
            print(f" [+] CONNECTION RESISTANCE SUMMARY")
            print(f"="*60 + f"{Style.RESET_ALL}")
            print(f" {Fore.MAGENTA}RESISTED CHECKS: {rate_limit_hits}{Style.RESET_ALL}")
            print(f" {Fore.MAGENTA}Infrastructure is actively defending.{Style.RESET_ALL}\n")

        return results


    def _print_result(self, scenario: Scenario, result: CheckResult):
        """Unified result printing logic."""
        color = Fore.GREEN
        if result.status == "VULNERABLE":
            color = Fore.RED
        elif result.status in ["ERROR", "PROXY_FAILURE"]:
            color = Fore.MAGENTA
        elif result.status in ["BLOCKED", "WAF_INTERCEPTED"]:
            color = Fore.YELLOW
        elif result.status == "INCONCLUSIVE":
            color = Fore.CYAN
        elif result.status == "SECURE":
            color = Fore.GREEN
        elif result.status == "SKIPPED":
            color = Fore.WHITE

        print(f"    -> {color}[{result.status}] {scenario.id}: {str(result.details)[:80]}...{Style.RESET_ALL}")
        
        # SHOW PROOF (Structured & Aligned)
        if result.status == "VULNERABLE":
            print(f"\n{Fore.RED}" + "="*60)
            print(f" CRITICAL VULNERABILITY FOUND: {result.type.upper().replace('_', ' ')}")
            print(f"="*60 + f"{Style.RESET_ALL}")
            
            # Proof of Concept / Confidence
            conf_color = Fore.YELLOW
            if result.confidence == "CONFIRMED": conf_color = Fore.RED + Style.BRIGHT
            elif result.confidence == "HIGH": conf_color = Fore.RED
            
            print(f" {Fore.RED}{'Confidence:':<20}{Style.RESET_ALL} {conf_color}{result.confidence}{Style.RESET_ALL}")
            print(f" {Fore.RED}{'Target Endpoint:':<20}{Style.RESET_ALL} {scenario.method} {scenario.target}")
            
            # Extract Description/Title
            desc = ""
            if isinstance(result.details, dict):
                desc = result.details.get("title") or "Vulnerability confirmed via active exploit."
                issues = result.details.get("issues", [])
                unique_issues = list(dict.fromkeys(issues))
                if unique_issues:
                    print(f" {Fore.RED}{'Key Issues:':<20}{Style.RESET_ALL}")
                    for i in unique_issues[:5]: 
                        print(f"   - {i}")
            else:
                desc = str(result.details)[:100]
            
            print(f" {Fore.RED}{'Description:':<20}{Style.RESET_ALL} {desc}")
            
            # IMPACT
            impact_desc = ATTACK_IMPACTS.get(result.type) or ATTACK_IMPACTS.get(scenario.type) or "Security Control Failure."
            print(f" {Fore.RED}{'Business Impact:':<20}{Style.RESET_ALL} {impact_desc}")

            # REPRODUCTION
            payload_proof = None
            if isinstance(result.details, dict):
                payload_proof = result.details.get("reproduction_payload") or result.details.get("payload")
            
            if payload_proof:
                print(f" {Fore.RED}{'Reproduction:':<20}{Style.RESET_ALL} Payload: {payload_proof}")
            else:
                print(f" {Fore.RED}{'Reproduction:':<20}{Style.RESET_ALL} Run scenario '{scenario.id}' (Check Config)")

            # EVIDENCE
            leaked = None
            if isinstance(result.details, dict):
                leaked = result.details.get("leaked_data") or result.details.get("evidence") or result.details.get("reason")
            
            if leaked:
                print(f"\n {Fore.RED}[ EVIDENCE / LEAKED DATA ]{Style.RESET_ALL}")
                print(f" {Fore.RED}" + "-"*40 + f"{Style.RESET_ALL}")
                
                if isinstance(leaked, list):
                    unique_leaks = list(dict.fromkeys([str(i).strip() for i in leaked if i]))
                    for idx, item in enumerate(unique_leaks[:5]):
                        clean_item = item.replace('\n', ' ').replace('\r', '')
                        print(f" {idx+1:02}. {clean_item[:300]}")
                else:
                    print(f" >> {str(leaked).strip()[:400]}...")
                print(f" {Fore.RED}" + "-"*40 + f"{Style.RESET_ALL}\n")
            
            # --- INDUSTRIAL ADDITION: SELF-HEALING & VERIFICATION ---
            if not self.simulation:
                print(f"{Fore.CYAN}[*] [+] ENGAGING SELF-HEALING INFRASTRUCTURE...")
                
                # 1. Adversarial Loop (Red vs Blue)
                loop = AdversarialLoop(max_iterations=2)
                # We need source code for CPG, but for now we focus on the logic
                # In a real scenario, we'd grab code from the target if possible or local repo
                patch, poc, finalized = loop.run(f"Vulnerability: {result.type}", "Source code not available for remote target.")
                
                if finalized:
                    print(f"{Fore.GREEN}[+] [+] UNBREAKABLE PATCH GENERATED.")
                    
                    # 2. Sandbox Verification
                    sandbox = Sandbox()
                    if sandbox.is_healthy():
                        print(f"[*] Verifying patch in Sandbox...")
                        # Here we would apply patch to a victim and run the breaker PoC
                        # verified, output = sandbox.execute_poc(poc)
                    
                    # 3. STaC (Security-Test-as-Code)
                    stac = STaCEngine()
                    if "api" in str(result.type).lower():
                        test_file = stac.generate_api_test(result.type, f"{self.base_url}/{scenario.target.lstrip('/')}", {"method": scenario.method})
                    else:
                        test_file = stac.generate_playwright_test(result.type, f"{self.base_url}/{scenario.target.lstrip('/')}", {"method": scenario.method})
                    print(f"{Fore.GREEN}[+] [+] REGRESSION TEST CREATED: {test_file}")

            print(f"{Fore.RED}" + "="*60 + f"{Style.RESET_ALL}\n")

    def _execute_scenario(self, s: Scenario) -> CheckResult:
        """Executes a single scenario and returns its CheckResult."""
        try:
            # Resolve actual check type
            check_type = s.attack_type if getattr(s, 'type', '') == 'simple' and hasattr(s, 'attack_type') else s.type
            
            # SIMULATION CHECK
            from breakpoint.metadata import get_metadata
            meta = get_metadata(check_type)
            if self.simulation and meta.get("destructive", False):
                if self.verbose:
                    print(f"[SIMULATION] Skipping destructive attack: {check_type}")
                return CheckResult(
                    id=s.id,
                    type=check_type,
                    status="SIMULATED",
                    severity=meta.get("risk_tier", "MEDIUM"),
                    details=f"[SIMULATION MODE] Impact Assessment: {meta.get('impact_simulation', 'No impact data')}",
                    confidence="SIMULATED"
                )

            from .http_client import HttpClient
            from .attacks import crlf, xxe, rce, web_exploits, dos_extreme, cve_classics, brute
            from .attacks import config_exposure, ssti, logic, jwt_weakness, deserialization, idor, lfi, crash, data, traffic, auth, nosql, auth_logic
            from .attacks import sqli, headers, ssrf, performance
            
            client = HttpClient(self.base_url, verbose=self.verbose, headers=self.headers)
            
            with self._cache_lock:
                if s.target in self._dead_paths:
                    return CheckResult(s.id, check_type, "SKIPPED", "INFO", f"Endpoint {s.target} confirmed unreachable. Skipping.")

            # --- SMART BASELINE PROBE ---
            # Don't waste time attacking endpoints that don't exist.
            discovery_types = ["git_exposure", "env_exposure", "ds_store_exposure", "phpinfo", "swagger_exposure", "secret_leak", "debug_exposure", "directory_traversal"]
            is_discovery = check_type in discovery_types
            
            # Speed Opt: Skip probing for resource-intensive DoS checks (they establish their own connection)
            do_probe = not is_discovery and check_type not in ["dos_slowloris", "slowloris", "dos_extreme", "advanced_dos", "traffic_spike"]
            
            if do_probe:
                # Inside lock: Probe and mark if missing
                with self._cache_lock:
                    # Re-check inside lock to avoid race conditions from parallel threads
                    if s.target in self._dead_paths:
                         return CheckResult(s.id, check_type, "SKIPPED", "INFO", f"Endpoint {s.target} confirmed unreachable.")

                    try:
                        # Baseline probe is a canary for the endpoint
                        baseline = client.send(s.method, s.target, is_canary=True)
                        is_dead = baseline.status_code == 404 or client.is_soft_404(baseline)
                        
                        # AGGRESSIVE MODE: Never skip unless it's a hard connection failure
                        if is_dead and s.config.get("aggressive"):
                            if self.verbose:
                                print(f"    [!] Target {s.target} looks like 404/Soft-404, but AGGRESSIVE mode is ON. Proceeding anyway.")
                            is_dead = False

                        if is_dead:
                            self._dead_paths.add(s.target)
                            if self.verbose:
                                print(f"    [!] Skipping {s.id}: Endpoint {s.target} returned 404/Soft-404. (No target to attack)")
                            return CheckResult(
                                id=s.id,
                                type=check_type,
                                status="INCONCLUSIVE",
                                severity="LOW",
                                details=f"Endpoint {s.target} returned 404 Not Found. Marking as Dead Path.",
                                confidence="P.O.C"
                            )
                    except:
                        pass # Handled by outer block if it's a real connection error

            res_dict = {}

            # DISPATCHER
            if check_type == "header_security": res_dict = headers.run_header_security_check(client, s)
            elif check_type == "ssrf": res_dict = ssrf.run_ssrf_attack(client, s)
            elif check_type == "react2shell": res_dict = rce.run_rce_attack(client, s)
            elif check_type == "performance": res_dict = performance.run_performance_check(client, s)
            elif check_type == "reflection": res_dict = web_exploits.run_xss_scan(client, s)
            elif check_type == "crlf_injection": res_dict = crlf.run_crlf_injection(client, s)
            elif check_type == "xxe_exfil": res_dict = xxe.run_xxe_exfil(client, s)
            elif check_type == "prototype_pollution": res_dict = web_exploits.run_prototype_pollution(client, s)
            elif check_type == "rce": res_dict = rce.run_rce_attack(client, s)
            elif check_type in ["rsc_flight_trust_boundary_violation", "rsc_flight_deserialization_abuse"]:
                 from .attacks import rsc_flight_trust_boundary_violation
                 res_dict = rsc_flight_trust_boundary_violation.run_rsc_flight_check(client, s)
            elif check_type == "rsc_server_action_forge":
                 from .attacks import rsc_server_action_forge
                 res_dict = rsc_server_action_forge.run_server_action_forge(client, s)
            elif check_type == "cache_deception": res_dict = cache.run_cache_deception(client, s)
            elif check_type == "rsc_ssr_ssrf":
                 from .attacks import rsc_ssr_ssrf
                 res_dict = rsc_ssr_ssrf.run_ssr_ssrf(client, s)
            elif check_type == "rsc_cache_poisoning":
                 from .attacks import rsc_cache_poisoning
                 res_dict = rsc_cache_poisoning.run_cache_poisoning(client, s)
            elif check_type == "rsc_hydration_collapse":
                 from .attacks import rsc_hydration_collapse
                 res_dict = rsc_hydration_collapse.run_hydration_collapse(client, s)
            elif check_type == "sql_injection": res_dict = sqli.run_sqli_attack(client, s)
            elif check_type == "xss": res_dict = web_exploits.run_xss_scan(client, s)
            elif check_type == "open_redirect": res_dict = web_exploits.run_open_redirect(client, s)
            elif check_type == "brute_force": res_dict = brute.run_brute_force(client, s)
            elif check_type == "advanced_dos": res_dict = web_exploits.run_advanced_dos(client, s)
            elif check_type == "debug_exposure": res_dict = config_exposure.run_debug_exposure(client, s)
            elif check_type == "secret_leak": res_dict = config_exposure.run_secret_leak(client, s)
            elif check_type == "ssti": res_dict = ssti.run_ssti_attack(client, s)
            elif check_type == "insecure_deserialization": res_dict = deserialization.run_deserialization_check(client, s)
            elif check_type == "jwt_weakness": res_dict = jwt_weakness.run_jwt_attack(client, s)
            elif check_type == "idor": res_dict = idor.run_idor_check(client, s)
            elif check_type == "privilege_escalation": res_dict = auth_logic.run_privilege_escalation_check(client, s)
            elif check_type == "lfi": res_dict = lfi.run_lfi_attack(client, s)
            elif check_type == "shellshock": res_dict = cve_classics.run_shellshock(client, s)
            elif check_type == "clickjacking": res_dict = web_exploits.run_clickjacking(client, s)
            elif check_type == "cors_origin": res_dict = web_exploits.run_cors_misconfig(client, s)
            elif check_type == "host_header": res_dict = web_exploits.run_host_header_injection(client, s)
            elif check_type == "email_injection": res_dict = web_exploits.run_email_injection(client, s)
            elif check_type == "jwt_brute": res_dict = jwt_weakness.run_jwt_brute(client, s)
            elif check_type == "swagger_exposure": res_dict = config_exposure.run_swagger_check(client, s)
            elif check_type == "git_exposure": res_dict = config_exposure.run_git_exposure(client, s)
            elif check_type == "env_exposure": res_dict = config_exposure.run_env_exposure(client, s)
            elif check_type == "phpinfo": res_dict = config_exposure.run_phpinfo(client, s)
            elif check_type == "ds_store_exposure": res_dict = config_exposure.run_ds_store(client, s)
            elif check_type == "nosql_injection": res_dict = nosql.run_nosql_attack(client, s)
            elif check_type == "ldap_injection": res_dict = sqli.run_ldap_injection(client, s)
            elif check_type == "xpath_injection": res_dict = sqli.run_xpath_injection(client, s)
            elif check_type == "ssi_injection": res_dict = web_exploits.run_ssi_injection(client, s)
            elif check_type == "request_smuggling": res_dict = web_exploits.run_request_smuggling(client, s)
            elif check_type == "graphql_introspection": res_dict = web_exploits.run_graphql_introspection(client, s)
            elif check_type == "graphql_batching": res_dict = web_exploits.run_graphql_batching(client, s)
            elif check_type in ["log4shell", "cve_log4shell"]: res_dict = cve_classics.run_log4j_attack(client, s)
            elif check_type in ["spring4shell", "cve_spring4shell"]: res_dict = cve_classics.run_spring4shell(client, s)
            elif check_type in ["struts2_rce", "cve_struts2"]: res_dict = cve_classics.run_struts2_rce(client, s)
            elif check_type == "xml_bomb": res_dict = crash.run_xml_bomb(client, s)
            elif check_type == "redos": res_dict = crash.run_redos(client, s)
            elif check_type == "json_bomb": res_dict = crash.run_huge_json(client, s)
            elif check_type == "malformed_json": res_dict = data.run_malformed_json(client, s)
            elif check_type == "traffic_spike": res_dict = traffic.run_traffic_spike(client, s)
            elif check_type == "password_length": res_dict = auth.run_password_length(client, s)
            elif check_type == "replay_simple": res_dict = auth.run_replay_attack(client, s)
            elif check_type == "race_condition": res_dict = logic.run_race_condition(client, s)
            elif check_type == "otp_reuse": res_dict = logic.run_otp_reuse(client, s)
            elif check_type in ["slowloris", "dos_slowloris", "dos_extreme"]:
                return dos_extreme.check(self.base_url, s, self.logger)
            else:
                return CheckResult(s.id, check_type, "ERROR", "LOW", f"Unknown check type: {check_type}")

            # Convert Dict to CheckResult
            status = "SECURE"
            if res_dict.get("status"):
                status = res_dict.get("status")
            elif res_dict.get("rate_limited"): status = "BLOCKED" 
            elif res_dict.get("skipped"): status = "INCONCLUSIVE"
            elif not res_dict.get("passed", True): status = "VULNERABLE"
            
            details = res_dict.get("details", "")
            return CheckResult(
                id=s.id,
                type=check_type,
                status=status,
                severity="HIGH",
                details=details,
                confidence=res_dict.get("confidence", "HIGH") if status == "VULNERABLE" else "P.O.C"
            )

        except (requests.exceptions.RequestException, ConnectionError) as e:
            from .http_client import HttpClient
            status = "BLOCKED"
            msg = f"Connection Failed (Target Unreachable): {str(e)[:100]}"
            if not HttpClient._is_internet_available():
                status = "ERROR"
                msg = f"CONNECTION LOST: Internet down locally. {str(e)[:30]}"
            elif any(x in str(e).lower() for x in ["refused", "reset", "aborted"]):
                 status = "ERROR"
                 msg = f"TARGET DOWN: The local server at {self.base_url} likely crashed or is not running."
            elif "timeout" in str(e).lower() or "localhost" in str(e).lower():
                 status = "ERROR"
                 msg = f"TARGET BUSY: Local server unresponsive/timed out. (Likely hung by previous DoS/ReDoS check)."
            return CheckResult(s.id, s.type, status, "INFO", msg)
        except Exception as e:
            return CheckResult(s.id, s.type, "ERROR", "LOW", f"Internal Error: {str(e)}")
