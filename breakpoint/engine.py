
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

# IMPACT MAPPING: Translate technical findings to enterprise-grade metadata
ATTACK_METADATA = {
    "sql_injection": {"severity": "CRITICAL", "cwe": "CWE-89", "owasp": "A03:2021", "remediation": "Use parameterized queries or ORMs. Sanitize all user inputs."},
    "nosql_injection": {"severity": "CRITICAL", "cwe": "CWE-943", "owasp": "A03:2021", "remediation": "Use safe API methods for NoSQL databases and avoid string concatenation in queries."},
    "rce": {"severity": "CRITICAL", "cwe": "CWE-94", "owasp": "A03:2021", "remediation": "Avoid sensitive functions like eval(). Use strict allow-lists for OS command arguments."},
    "lfi": {"severity": "HIGH", "cwe": "CWE-22", "owasp": "A01:2021", "remediation": "Use absolute paths or map IDs to files. Validate path traversals like '../'."},
    "ssrf": {"severity": "HIGH", "cwe": "CWE-918", "owasp": "A10:2021", "remediation": "Use allow-lists for internal requests. Disable unused protocols (file://, dict://)."},
    "xss": {"severity": "MEDIUM", "cwe": "CWE-79", "owasp": "A03:2021", "remediation": "Use Context-Aware output encoding. Implement a strong Content Security Policy (CSP)."},
    "idor": {"severity": "HIGH", "cwe": "CWE-639", "owasp": "A01:2021", "remediation": "Implement object-level access control. Use non-predictable identifiers (UUIDs)."},
    "jwt_weakness": {"severity": "HIGH", "cwe": "CWE-345", "owasp": "A07:2021", "remediation": "Use strong signing algorithms (RS256). Verify all claims and signature integrity."},
    "brute_force": {"severity": "MEDIUM", "cwe": "CWE-307", "owasp": "A07:2021", "remediation": "Implement account lockouts and rate limiting. Enforce multi-factor authentication (MFA)."},
    "cve_log4shell": {"severity": "CRITICAL", "cwe": "CWE-502", "owasp": "A06:2021", "remediation": "Patch Log4j to version 2.17.1+. Disable remote JNDI lookups."},
    "cve_spring4shell": {"severity": "CRITICAL", "cwe": "CWE-94", "owasp": "A03:2021", "remediation": "Patch Spring Framework and move to modern Tomcat versions (>9.0.62)."},
    "open_redirect": {"severity": "LOW", "cwe": "CWE-601", "owasp": "A01:2021", "remediation": "Use allow-lists for redirection targets. Prefer relative URLs."},
}

import threading as _threading

class Engine:
    SHUTDOWN_SIGNAL = False
    PRINT_LOCK = _threading.Lock()

    def __init__(self, base_url: str, forensic_log: Optional[ForensicLogger] = None, verbose: bool = False, headers: Dict[str, str] = None, simulation: bool = False, source_path: str = None, diff_mode: bool = False, git_range: str = None, thorough: bool = False, enable_oob: bool = True):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        self.simulation = simulation
        self.headers = headers or {}
        self.thorough = thorough
        
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
        
        # ===== ADVANCED FEATURES INTEGRATION =====
        # 1. OOB Service (Enabled by default)
        self.oob_enabled = enable_oob
        if self.oob_enabled:
            from .oob import OOBCorrelator
            self.oob_correlator = OOBCorrelator()
            if self.verbose:
                print("[*] OOB Service: ENABLED (Blind vulnerability detection active)")
        else:
            self.oob_correlator = None
            if self.verbose:
                print("[*] OOB Service: DISABLED")
        
        # 2. Adaptive Throttler (Prevents dev server crashes)
        from .core.throttler import AdaptiveThrottler
        self.throttler = AdaptiveThrottler(is_dev_env=self._is_localhost)
        if self.verbose and self._is_localhost:
            print("[*] Adaptive Throttling: ENABLED (Dev environment detected)")
        
        # 3. Attack Graph (Enables attack chaining)
        from .core.attack_graph import AttackGraph
        self.attack_graph = AttackGraph()
        if self.verbose:
            print("[*] Attack Graph: ENABLED (Exploitation path tracking active)")
        
        # 4. Target Context (Will be populated by fingerprinter)
        from .core.context import TargetContext
        self.context = TargetContext(base_url=self.base_url)
        self.context.oob_provider = self.oob_correlator  # Inject OOB into context

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

    def run_all(self, scenarios: List[Scenario], concurrency: int = 10) -> List[CheckResult]:
        """Main execution loop for all selected checks."""
        # TARGET HEARTBEAT CHECK
        print(f"[*] Verifying target connectivity: {self.base_url}...")
        from .http_client import HttpClient
        client = HttpClient(self.base_url, verbose=self.verbose, headers=self.headers)
        try:
            hb_resp = client.send("GET", "/", timeout=5)
            if hb_resp.status_code == 0:
                print(f"{Fore.RED}[!] ABORT: Target {self.base_url} is unreachable or connection refused.{Style.RESET_ALL}")
                return []
        except Exception as e:
            print(f"{Fore.RED}[!] ABORT: Connection to target failed: {str(e)}{Style.RESET_ALL}")
            return []

        init(autoreset=True)
        if not concurrency: concurrency = 500
        if self._is_localhost:
            limit = 25 if any(s.config.get("aggressive") for s in scenarios if hasattr(s, 'config')) else 5
            if concurrency > limit: concurrency = limit
             
        results = []
        rate_limit_hits = 0

        # PHASE 1: TARGET DISCOVERY & FINGERPRINTING
        print(f"\n[*] PHASE 1: Discovery & Tech Fingerprinting...")
        from .core.fingerprinter import TechFingerprinter
        from .crawler import Crawler
        
        # Use new TechFingerprinter to populate context
        fingerprinter = TechFingerprinter(client)
        self.context = fingerprinter.fingerprint(self.base_url, self.context)
        
        # Display detected tech stack
        tech_summary = []
        if self.context.tech_stack.languages:
            tech_summary.append(f"Languages: {', '.join(self.context.tech_stack.languages)}")
        if self.context.tech_stack.frameworks:
            tech_summary.append(f"Frameworks: {', '.join(self.context.tech_stack.frameworks)}")
        if self.context.tech_stack.servers:
            tech_summary.append(f"Servers: {', '.join(self.context.tech_stack.servers)}")
        if self.context.tech_stack.databases:
            tech_summary.append(f"Databases: {', '.join(self.context.tech_stack.databases)}")
        
        if tech_summary:
            print(f"    -> Tech Stack Identified:")
            for item in tech_summary:
                print(f"       • {item}")
        else:
            print(f"    -> Tech Stack: Unable to fingerprint (generic target)")
        
        crawler = Crawler(self.base_url, client)
        print(f"    -> Starting recursive discovery (Max Depth: 3)...")
        crawler.crawl()
        new_targets = crawler.get_scan_targets()
        print(f"    -> Discovery Complete: Found {len(new_targets)} unique endpoints/forms.")
        
        # Store discovered endpoints in context
        for target in new_targets:
            self.context.discovered_endpoints.append(target.get("url", ""))
            if target.get("method") == "POST":
                # Create a dynamic scenario if not already covered
                pass

        # Separate scenarios into standard and DoS
        std_scenarios = [s for s in scenarios if not s.config.get("destructive", False)]
        dos_scenarios = [s for s in scenarios if s.config.get("destructive", False)]

        print(f"[*] STARTING ENGINE: {len(std_scenarios) + len(dos_scenarios)} active scenarios...")

        import threading as _threading
        shutdown_event = _threading.Event()
        def monitor_shutdown():
            while not Engine.SHUTDOWN_SIGNAL and not shutdown_event.is_set():
                import time; time.sleep(0.1)
            shutdown_event.set()
        _threading.Thread(target=monitor_shutdown, daemon=True).start()

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

                        skip_ai_types = ["header_security", "clickjacking", "git_exposure", "env_exposure", "phpinfo", "ds_store_exposure", "swagger_exposure", "debug_exposure", "cache_deception"]
                        
                        if result.status == "VULNERABLE" and result.type not in skip_ai_types:
                            print(f"    [!] Vulnerability Detected ({result.type}). Initiating Adversarial Validation...")
                            # log attempt
                            self.logger.log_event("VULNERABILITY_CANDIDATE", {"id": scenario.id, "type": result.type})
                            
                            # Attempt to 'break' (validate) it fully
                            snippet = "Source unavailable"
                            
                            # New Agent Logic returns dict
                            validation_result = self.adv_loop.run(
                                vulnerability_report=str(result.details), 
                                source_code=snippet,
                                target_url=self.base_url + (scenario.target if scenario.target.startswith('/') else '/' + scenario.target)
                            )
                            
                            # Log validation attempt summary
                            self.logger.log_event("VALIDATION_RESULT", {"type": result.type, "status": validation_result["status"]})

                            # Decision Logic
                            if validation_result["status"] == "CONFIRMED":
                                result.confidence = "CONFIRMED"
                                result.status = "CONFIRMED"
                                print(f"    {Fore.GREEN}[+] VALIDATOR CONFIRMED: Checks passed.{Style.RESET_ALL}")
                                
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
                            
                            elif validation_result["status"] == "SUSPECT":
                                result.confidence = validation_result["confidence"]
                                result.status = "SUSPECT"
                                print(f"    [?] VALIDATOR SUSPECT: Partial reproduction. ({validation_result['details']})")
                            elif validation_result["status"] == "UNVERIFIED":
                                result.confidence = "LOW"
                                result.status = "VULNERABLE" 
                                result.details = f"Validation Skipped: {validation_result['details']}"
                            
                            else:
                                if result.type in ["sql_injection", "rce", "ssrf", "lfi", "nosql_injection"]:
                                     result.confidence = "LOW"
                                     result.status = "SUSPECT"
                                     result.details = f"Validation Failed: {validation_result['details']}"
                                     print(f"    {Fore.YELLOW}[-] VALIDATION INCONCLUSIVE: Mark as SUSPECT.{Style.RESET_ALL}")
                                else:
                                     result.status = "VULNERABLE"
                        
                        elif result.status == "VULNERABLE" and result.type in skip_ai_types:
                             # Auto-confirm simple exposure findings
                             result.status = "CONFIRMED"
                             result.confidence = "CONFIRMED"
                             print(f"    {Fore.GREEN}[+] AUTO-CONFIRMED: {result.type} verified.{Style.RESET_ALL}")

                        if result.status != "SECURE":
                            results.append(result)
                            self._print_result(scenario, result)
                        
                        if result.status == "BLOCKED" and not self.thorough: 
                            rate_limit_hits += 1
                            # Relaxed check for localhost to avoid annoyance
                            limit = 50 if self._is_localhost else 3
                            if rate_limit_hits > limit:
                                print(f"\n{Fore.YELLOW}[!] CRITICAL: Target is aggressively rate-limiting (429/403). Aborting to avoid total lockout.{Style.RESET_ALL}")
                                shutdown_event.set()
                                break
                        elif result.status == "BLOCKED" and self.thorough:
                             if self.verbose: print(f"{Fore.YELLOW}    [!] BLOCKED but THOROUGH mode is active. Continuing scan.{Style.RESET_ALL}")
                        
                        if result.status == "ERROR" and "Target Unresponsive" in result.details:
                            print(f"\n{Fore.RED}[!] FATAL: Target at {self.base_url} is unresponsive or crashed. Aborting scan.{Style.RESET_ALL}")
                            shutdown_event.set()
                            break
                        
                    except Exception as exc:
                        if not Engine.SHUTDOWN_SIGNAL:
                            # Use the new CheckResult constructor for errors too
                            meta = ATTACK_METADATA.get(scenario.type, {"severity": "INFO", "cwe": "N/A", "owasp": "N/A", "remediation": "N/A"})
                            results.append(CheckResult(
                                id=scenario.id,
                                type=scenario.type or "unknown",
                                status="ERROR",
                                severity=meta["severity"],
                                details=f"Exception: {str(exc)}",
                                confidence="LOW",
                                cwe=meta["cwe"],
                                owasp=meta["owasp"],
                                remediation=meta["remediation"],
                                artifacts=None
                            ))

            # PHASE 4: Destructive / DoS Scenarios
            if dos_scenarios and not shutdown_event.is_set():
                print(f"\n[*] PHASE 4: Executing {len(dos_scenarios)} resource-intensive/destructive attacks...")
                future_to_dos = {executor.submit(self._execute_scenario, s): s for s in dos_scenarios}
                for future in as_completed(future_to_dos):
                    if Engine.SHUTDOWN_SIGNAL or shutdown_event.is_set():
                        executor.shutdown(wait=False, cancel_futures=True); break
                    scenario = future_to_dos[future]
                    try:
                        result = future.result()
                        results.append(result)
                        self._print_result(scenario, result)
                    except Exception as exc:
                        if not Engine.SHUTDOWN_SIGNAL:
                            meta = ATTACK_METADATA.get(scenario.type, {"severity": "INFO", "cwe": "N/A", "owasp": "N/A", "remediation": "N/A"})
                            results.append(CheckResult(
                                id=scenario.id,
                                type=scenario.type or "unknown",
                                status="ERROR",
                                severity=meta["severity"],
                                details=f"Exception: {str(exc)}",
                                confidence="LOW",
                                cwe=meta["cwe"],
                                owasp=meta["owasp"],
                                remediation=meta["remediation"],
                                artifacts=None
                            ))

        except (KeyboardInterrupt, SystemExit):
            Engine.SHUTDOWN_SIGNAL = True
            print(f"\n{Fore.RED}[!] TERMINATING: Instant Shutdown Triggered.{Style.RESET_ALL}")
            shutdown_event.set()
            executor.shutdown(wait=False, cancel_futures=True)
            os._exit(0)
        finally:
            executor.shutdown(wait=True)
            
            # ===== EXPLOITATION PATH GENERATION =====
            if self.verbose:
                print(f"\n[*] Generating Exploitation Paths...")
            
            paths = self.attack_graph.generate_exploit_paths()
            if paths:
                print(f"\n{'='*60}")
                print(f"EXPLOITATION PATHS DISCOVERED ({len(paths)})")
                print(f"{'='*60}")
                for idx, path in enumerate(paths, 1):
                    print(f"\nPath {idx} (Severity Score: {path.severity_score:.1f}/40):")
                    print(f"  Chain: {' → '.join(path.nodes)}")
                    print(f"  {path.description}")
                print(f"{'='*60}\n")
            
            # ===== THROTTLING REPORT =====
            if self.verbose and self._is_localhost:
                stability_report = self.throttler.get_stability_report()
                print(f"\n[*] Target Stability Report:")
                print(f"    Total Requests: {stability_report['total_requests']}")
                print(f"    Failed Requests: {stability_report['failed_requests']}")
                print(f"    Failure Rate: {stability_report['failure_rate']}")
                print(f"    Avg Response Time: {stability_report['avg_response_time']}")
                print(f"    Target Status: {'UNSTABLE' if stability_report['is_unstable'] else 'STABLE'}")
                print(f"    Backoff Multiplier: {stability_report['backoff_multiplier']}")
            
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
            
            # ===== ADAPTIVE THROTTLING =====
            # Check if this attack should be skipped based on intensity and stability
            if self.throttler.should_skip_attack(check_type):
                attack_meta = ATTACK_METADATA.get(check_type, {"severity": "INFO", "cwe": "N/A", "owasp": "N/A", "remediation": "N/A"})
                if self.verbose:
                    print(f"    -> [THROTTLED] Skipping {check_type} (target unstable or dev environment)")
                return CheckResult(
                    id=s.id,
                    type=check_type,
                    status="SKIPPED",
                    severity=attack_meta["severity"],
                    details=f"Skipped due to adaptive throttling (intensity tier protection)",
                    confidence="N/A",
                    cwe=attack_meta["cwe"],
                    owasp=attack_meta["owasp"],
                    remediation=attack_meta["remediation"]
                )
            
            # Apply delay before attack
            import time
            delay = self.throttler.get_delay_before_attack(check_type)
            if delay > 0:
                time.sleep(delay)
            
            # SIMULATION CHECK
            from breakpoint.metadata import get_metadata
            meta = get_metadata(check_type)
            if self.simulation and meta.get("destructive", False):
                # Use ATTACK_METADATA for severity, cwe, owasp, remediation
                attack_meta = ATTACK_METADATA.get(check_type, {"severity": "INFO", "cwe": "N/A", "owasp": "N/A", "remediation": "N/A"})
                return CheckResult(
                    id=s.id,
                    type=check_type,
                    status="SIMULATED",
                    severity=attack_meta["severity"],
                    details=f"[SIMULATION MODE] Impact Assessment: {meta.get('impact_simulation')}",
                    confidence="SIMULATED",
                    cwe=attack_meta["cwe"],
                    owasp=attack_meta["owasp"],
                    remediation=attack_meta["remediation"]
                )

            from .http_client import HttpClient
            from .attacks import omni
            
            client = HttpClient(self.base_url, verbose=self.verbose, headers=self.headers)
            
            with self._cache_lock:
                if s.target in self._dead_paths and not self.thorough:
                    # Use ATTACK_METADATA for severity, cwe, owasp, remediation
                    attack_meta = ATTACK_METADATA.get(check_type, {"severity": "INFO", "cwe": "N/A", "owasp": "N/A", "remediation": "N/A"})
                    return CheckResult(
                        id=s.id,
                        type=check_type,
                        status="SKIPPED",
                        severity=attack_meta["severity"],
                        details=f"Endpoint {s.target} unreachable (cached).",
                        confidence="LOW",
                        cwe=attack_meta["cwe"],
                        owasp=attack_meta["owasp"],
                        remediation=attack_meta["remediation"]
                    )

            from .utils import ResponseStabilizer, StructuralComparator
            
            # PHASE 2: BASELINE STABILIZATION
            # Compute variance to ignore dynamic tokens (timestamps, IDs)
            variance_mask = ResponseStabilizer.get_variance_mask(client, s.method, s.target, params=s.config.get("params"), body=s.config.get("json_body"))
            print(f"    -> Baseline Stabilized (Mask: {len(variance_mask)} volatile points).") if self.verbose else None

            # DISPATCHER (OMNI CONSOLIDATED)
            res_dict = {}
            if check_type in ["header_security", "security_headers"]: res_dict = omni.run_header_security_check(client, s)
            elif check_type in ["ssrf", "ssrf_scan"]: res_dict = omni.run_ssrf_attack(client, s)
            elif check_type in ["rce", "react2shell", "rce_params_post"]: res_dict = omni.run_rce_attack(client, s)
            elif check_type in ["xss", "xss_reflected"]: res_dict = omni.run_xss_scan(client, s)
            elif check_type == "crlf_injection": res_dict = omni.run_crlf_injection(client, s)
            elif check_type == "prototype_pollution": res_dict = omni.run_prototype_pollution(client, s)
            elif check_type in ["sql_injection", "sqli_blind_time", "blind_sqli_destructive"]: res_dict = omni.run_sqli_attack(client, s)
            elif check_type == "open_redirect": res_dict = omni.run_open_redirect(client, s)
            elif check_type in ["brute_force", "brute_force_basic"]: res_dict = omni.run_brute_force(client, s)
            elif check_type in ["advanced_dos", "advanced_dos_checks"]: res_dict = omni.run_advanced_dos(client, s)
            elif check_type == "debug_exposure": res_dict = omni.run_debug_exposure(client, s)
            elif check_type in ["secret_leak", "secret_leak_check"]: res_dict = omni.run_secret_leak(client, s)
            elif check_type in ["swagger_exposure", "swagger_ui_exposure"]: res_dict = omni.run_swagger_check(client, s)
            elif check_type in ["git_exposure", "git_exposure_check"]: res_dict = omni.run_git_exposure(client, s)
            elif check_type in ["env_exposure", "env_exposure_check"]: res_dict = omni.run_env_exposure(client, s)
            elif check_type in ["phpinfo", "phpinfo_exposure"]: res_dict = omni.run_phpinfo(client, s)
            elif check_type in ["ds_store_exposure", "ds_store"]: res_dict = omni.run_ds_store(client, s)
            elif check_type in ["ssti", "ssti_template_injection"]: res_dict = omni.run_ssti_attack(client, s)
            elif check_type in ["insecure_deserialization", "deserialization_rce"]: res_dict = omni.run_insecure_deserialization(client, s)
            elif check_type in ["jwt_weakness", "jwt_none_alg"]: res_dict = omni.run_jwt_attack(client, s)
            elif check_type in ["jwt_brute", "jwt_weak_key_brute"]: res_dict = omni.run_jwt_brute(client, s)
            elif check_type in ["idor", "idor_numeric"]: res_dict = omni.run_idor_check(client, s)
            elif check_type in ["lfi", "lfi_path_traversal"]: res_dict = omni.run_lfi_attack(client, s)
            elif check_type in ["clickjacking", "clickjacking_check"]: res_dict = omni.run_clickjacking(client, s)
            elif check_type == "cors_origin": res_dict = omni.run_cors_misconfig(client, s)
            elif check_type == "host_header": res_dict = omni.run_host_header_injection(client, s)
            elif check_type in ["email_injection", "email_header_injection"]: res_dict = omni.run_email_injection(client, s)
            elif check_type in ["nosql_injection", "nosql_injection_login"]: res_dict = omni.run_nosql_injection(client, s)
            elif check_type in ["ldap_injection", "ldap_injection_search"]: res_dict = omni.run_ldap_injection(client, s)
            elif check_type in ["xpath_injection", "xpath_injection_xml"]: res_dict = omni.run_xpath_injection(client, s)
            elif check_type == "ssi_injection": res_dict = omni.run_ssi_injection(client, s)
            elif check_type in ["request_smuggling", "http_request_smuggling"]: res_dict = omni.run_request_smuggling(client, s)
            elif check_type == "graphql_introspection": res_dict = omni.run_graphql_introspection(client, s)
            elif check_type == "graphql_batching": res_dict = omni.run_graphql_batching(client, s)
            elif check_type in ["log4shell", "cve_log4shell", "log4shell_recursive_delete"]: res_dict = omni.run_cve_log4shell(client, s)
            elif check_type in ["cache_deception", "cache_poison_check"]: res_dict = omni.run_cache_deception(client, s)
            elif check_type == "race_condition": res_dict = omni.run_race_condition(client, s)
            elif check_type == "otp_reuse": res_dict = omni.run_otp_reuse(client, s)
            elif check_type in ["rsc_server_action_forge", "server_side_action_forge"]: res_dict = omni.run_rsc_server_action_forge(client, s)
            elif check_type in ["rsc_ssr_ssrf", "rsc_framework_ssrf"]: res_dict = omni.run_ssr_ssrf(client, s)
            elif check_type in ["rsc_hydration_collapse", "hydration_collapse"]: res_dict = omni.run_hydration_collapse(client, s)
            elif check_type in ["rsc_flight_trust_boundary_violation", "rsc_flight_deserialization_abuse", "trust_boundary_violation", "react_server_component_injection"]:
                res_dict = omni.run_flight_trust_boundary_violation(client, s)
            elif check_type in ["json_bomb", "json_bomb_attack"]: res_dict = omni.run_json_bomb(client, s)
            elif check_type == "http_desync": res_dict = omni.run_http_desync(client, s)
            elif check_type == "poodle": res_dict = omni.run_poodle_check(client, s)
            elif check_type in ["dos_extreme", "slowloris", "dos_slowloris", "traffic_spike", "password_length", "replay_simple", "dos_extreme_high_concurrency_stress_mode"]:
                res_dict = omni.run_dos_extreme(client, s) 
            elif check_type in ["redos", "redos_validation_attack"]: res_dict = omni.run_redos(client, s)
            elif check_type == "xml_bomb": res_dict = omni.run_xml_bomb(client, s)
            elif check_type == "advanced_dos": res_dict = omni.run_advanced_dos(client, s)
            elif check_type in ["xxe_exfil", "xxe_external_entity"]: res_dict = omni.run_xxe_exfil(client, s)
            elif check_type in ["malformed_json_check", "malformed_json"]: res_dict = omni.run_malformed_json(client, s)
            elif check_type == "file_upload_abuse": res_dict = omni.run_file_upload_abuse(client, s)
            elif check_type == "zip_slip": res_dict = omni.run_zip_slip(client, s)
            elif check_type == "rsc_cache_poisoning": res_dict = omni.run_rsc_cache_poisoning(client, s)
            elif check_type == "cve_spring4shell": res_dict = omni.run_cve_spring4shell(client, s)
            elif check_type in ["cve_struts2", "struts2_rce"]: res_dict = omni.run_cve_struts2(client, s)
            elif check_type == "shellshock": res_dict = omni.run_shellshock(client, s)
            else:
                # Use ATTACK_METADATA for severity, cwe, owasp, remediation
                attack_meta = ATTACK_METADATA.get(check_type, {"severity": "INFO", "cwe": "N/A", "owasp": "N/A", "remediation": "N/A"})
                return CheckResult(
                    id=s.id,
                    type=check_type,
                    status="SKIPPED",
                    severity=attack_meta["severity"],
                    details=f"Check Implementation Missing: {check_type}",
                    confidence="LOW",
                    cwe=attack_meta["cwe"],
                    owasp=attack_meta["owasp"],
                    remediation=attack_meta["remediation"]
                )

            # Convert Dict to CheckResult
            status = "SECURE"
            if res_dict.get("status"):
                status = res_dict.get("status")
            elif res_dict.get("rate_limited"): status = "BLOCKED" 
            elif res_dict.get("skipped"): status = "INCONCLUSIVE"
            elif not res_dict.get("passed", True): status = "VULNERABLE"
            
            # Fetch Enterprise Metadata
            meta = ATTACK_METADATA.get(check_type, {"severity": "INFO", "cwe": "N/A", "owasp": "N/A", "remediation": "N/A"})
            
            # Create Production-Grade Result
            return CheckResult(
                id=s.id,
                type=check_type,
                status=status,
                severity=meta["severity"] if status in ["VULNERABLE", "CONFIRMED", "SUSPECT"] else "INFO",
                details=str(res_dict.get("details", "")),
                confidence=res_dict.get("confidence", "TENTATIVE") if status == "VULNERABLE" else "P.O.C",
                cwe=meta["cwe"],
                owasp=meta["owasp"],
                remediation=meta["remediation"],
                artifacts=res_dict.get("artifacts")
            )
            
            # ===== POST-EXECUTION TRACKING =====
            # 1. Record in attack graph for chaining
            # Convert CheckResult to AttackResult format for graph
            from .core.models import AttackResult, VulnerabilityStatus, Severity
            
            # Map status to VulnerabilityStatus
            status_map = {
                "CONFIRMED": VulnerabilityStatus.CONFIRMED,
                "VULNERABLE": VulnerabilityStatus.VULNERABLE,
                "SUSPECT": VulnerabilityStatus.SUSPECT,
                "SECURE": VulnerabilityStatus.SECURE,
                "SKIPPED": VulnerabilityStatus.SKIPPED,
                "BLOCKED": VulnerabilityStatus.BLOCKED,
                "ERROR": VulnerabilityStatus.ERROR
            }
            
            # Map severity to Severity enum
            severity_map_enum = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
                "INFO": Severity.INFO
            }
            
            graph_result = AttackResult(
                scenario_id=s.id,
                attack_id=check_type,
                status=status_map.get(status, VulnerabilityStatus.SECURE),
                severity=severity_map_enum.get(meta["severity"], Severity.INFO),
                details=str(res_dict.get("details", "")),
                artifacts=[]
            )
            
            self.attack_graph.record_finding(check_type, graph_result)
            
            # 2. Record throttling metrics
            success = status not in ["ERROR", "BLOCKED"]
            is_timeout = "timeout" in str(res_dict.get("details", "")).lower()
            response_time = res_dict.get("response_time", 100)  # Default 100ms if not tracked
            self.throttler.record_request(success, response_time, is_timeout)
            
            return CheckResult(
                id=s.id,
                type=check_type,
                status=status,
                severity=meta["severity"] if status in ["VULNERABLE", "CONFIRMED", "SUSPECT"] else "INFO",
                details=str(res_dict.get("details", "")),
                confidence=res_dict.get("confidence", "TENTATIVE") if status == "VULNERABLE" else "P.O.C",
                cwe=meta["cwe"],
                owasp=meta["owasp"],
                remediation=meta["remediation"],
                artifacts=res_dict.get("artifacts")
            )

        except Exception as e:
            err_str = str(e)
            # Use ATTACK_METADATA for severity, cwe, owasp, remediation
            attack_meta = ATTACK_METADATA.get(check_type, {"severity": "INFO", "cwe": "N/A", "owasp": "N/A", "remediation": "N/A"})

            # Special Handling for Localhost Crashes/Timeouts (Windows/Linux/Mac)
            if "localhost error" in err_str.lower() or "refused" in err_str.lower() or "unreachable" in err_str.lower() or "timeout" in err_str.lower() or "10061" in err_str:
                target_msg = "Target Unresponsive"
                if "127.0.0.1" in self.base_url or "localhost" in self.base_url:
                    target_msg = "LOCALHOST ERROR: Dev Server Crashed or Overwhelmed"
                return CheckResult(s.id, check_type, "ERROR", "HIGH", f"{target_msg}: {err_str}")

            if "Max retries" in err_str or "429" in err_str or "403" in err_str:
                return CheckResult(
                    id=s.id,
                    type=check_type,
                    status="BLOCKED",
                    severity=attack_meta["severity"],
                    details=f"Rate Limited: {err_str}",
                    confidence="LOW",
                    cwe=attack_meta["cwe"],
                    owasp=attack_meta["owasp"],
                    remediation=attack_meta["remediation"]
                )
            
            return CheckResult(s.id, check_type, "ERROR", "LOW", f"Engine Failure: {err_str}")

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

        with Engine.PRINT_LOCK:
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
