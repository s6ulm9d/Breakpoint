
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
from .core.logic import ConfidenceEngine, RiskScoringEngine, EvidenceCollector

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
    "union_sqli": {"severity": "CRITICAL", "cwe": "CWE-89", "owasp": "A03:2021", "remediation": "Use parameterized queries. Avoid reflecting data in UNION SELECT."},
    "second_order_sqli": {"severity": "CRITICAL", "cwe": "CWE-89", "owasp": "A03:2021", "remediation": "Validate data at both input and point of use in queries."},
    "graphql_depth": {"severity": "HIGH", "cwe": "CWE-770", "owasp": "A04:2021", "remediation": "Implement query depth and complexity limits in GraphQL."},
    "elasticsearch_injection": {"severity": "HIGH", "cwe": "CWE-943", "owasp": "A03:2021", "remediation": "Sanitize ES query strings. Use parameterized ES templates."},
    "dom_xss": {"severity": "MEDIUM", "cwe": "CWE-79", "owasp": "A03:2021", "remediation": "Use safe DOM sinks (textContent) instead of innerHTML/eval."},
    "mutation_xss": {"severity": "MEDIUM", "cwe": "CWE-79", "owasp": "A03:2021", "remediation": "Use modern sanitizers that handle browser parsing quirks."},
    "csrf": {"severity": "MEDIUM", "cwe": "CWE-352", "owasp": "A01:2021", "remediation": "Implement anti-CSRF tokens or use SameSite=Strict cookies."},
    "csti": {"severity": "MEDIUM", "cwe": "CWE-94", "owasp": "A03:2021", "remediation": "Avoid reflecting user input inside template delimiters."},
    "mass_assignment": {"severity": "HIGH", "cwe": "CWE-915", "owasp": "A01:2021", "remediation": "Use DTOs or explicit allow-lists for model updates."},
    "tenant_isolation": {"severity": "CRITICAL", "cwe": "CWE-639", "owasp": "A01:2021", "remediation": "Enforce strict tenant boundary checks at the data layer."},
    "oauth_redirect": {"severity": "HIGH", "cwe": "CWE-601", "owasp": "A01:2021", "remediation": "Validate OAuth redirect URIs against a strict allow-list."},
    "unicode_bypass": {"severity": "MEDIUM", "cwe": "CWE-176", "owasp": "A03:2021", "remediation": "Normalize Unicode strings before validation."},
    "verb_tampering": {"severity": "MEDIUM", "cwe": "CWE-285", "owasp": "A01:2021", "remediation": "Restrict allowed HTTP methods in server configuration."},
    "null_byte": {"severity": "HIGH", "cwe": "CWE-158", "owasp": "A03:2021", "remediation": "Strip null bytes and use safe file handling APIs."},
    "archive_bomb": {"severity": "HIGH", "cwe": "CWE-409", "owasp": "A04:2021", "remediation": "Limit zip extraction size and depth. Use safe decompression libraries."},
    "cswsh": {"severity": "HIGH", "cwe": "CWE-1385", "owasp": "A01:2021", "remediation": "Validate the Origin header during WebSocket handshakes."},
    "request_smuggling": {"severity": "CRITICAL", "cwe": "CWE-444", "owasp": "A06:2021", "remediation": "Use HTTP/2 entirely or ensure frontend/backend agree on TE/CL parsing."},
    "http_desync": {"severity": "HIGH", "cwe": "CWE-444", "owasp": "A06:2021", "remediation": "Disable connection reuse for ambiguous requests."},
    "jndi_injection": {"severity": "CRITICAL", "cwe": "CWE-917", "owasp": "A03:2021", "remediation": "Disable JNDI lookups or remove the JNDI lookup class from the classpath."},
    "race_condition": {"severity": "HIGH", "cwe": "CWE-362", "owasp": "A01:2021", "remediation": "Use database transactions with proper isolation levels (Serializable) or distributed locks."},
    "graphql_batching": {"severity": "MEDIUM", "cwe": "CWE-770", "owasp": "A04:2021", "remediation": "Disable batching or limit query complexity/depth."},
    "xpath_injection": {"severity": "HIGH", "cwe": "CWE-91", "owasp": "A03:2021", "remediation": "Use parameterized XPath queries or pre-compiled path expressions."},
    "ldap_injection": {"severity": "HIGH", "cwe": "CWE-90", "owasp": "A03:2021", "remediation": "Escape LDAP filter characters or use framework-provided safe search methods."},
    "zip_slip": {"severity": "HIGH", "cwe": "CWE-22", "owasp": "A01:2021", "remediation": "Validate filenames in archives against path traversal before extraction."},
}

ATTACK_IMPACTS = {
    "sql_injection": "Unauthorized database access, data theft, and potential administrative takeover.",
    "nosql_injection": "Authentication bypass and unauthorized document access.",
    "rce": "Full system compromise. Attacker can execute arbitrary commands as the application user.",
    "lfi": "Exposure of sensitive system files (/etc/passwd, configuration files) and potential RCE via log poisoning.",
    "ssrf": "Internal network scanning and access to sensitive cloud metadata services.",
    "xss": "Session hijacking, credential theft, and defacement of the application for users.",
    "idor": "Unauthorized access to private user data, orders, or restricted administrative records.",
    "jwt_weakness": "Authentication bypass, allowing attackers to forge identities.",
    "mass_assignment": "Elevation of privilege by updating protected database fields.",
    "tenant_isolation": "Cross-tenant data leakage in a multi-tenant environment.",
    "header_security": "Increased susceptibility to Clickjacking and MIME-type sniffing attacks.",
    "clickjacking": "Users can be tricked into performing unintended actions on the site.",
    "open_redirect": "Phishing attacks by redirecting users to malicious domains.",
    "prototype_pollution": "Potential RCE or logic bypass in JavaScript environments.",
}

import threading as _threading

class Engine:
    SHUTDOWN_SIGNAL = False
    PRINT_LOCK = _threading.Lock()

    def __init__(self, base_url: str, forensic_log: Optional[ForensicLogger] = None, verbose: bool = False, headers: Dict[str, str] = None, simulation: bool = False, source_path: str = None, diff_mode: bool = False, git_range: str = None, thorough: bool = False, enable_oob: bool = True, force_aggressive: bool = False):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        self.simulation = simulation
        self.headers = headers or {}
        self.thorough = thorough
        self.force_aggressive = force_aggressive
        
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
        self.evidence_collector = EvidenceCollector()
        self.static_findings = []
        
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
            from .core.oob import OOBServer
            # Start the OOB server if not already running
            self.oob_server = OOBServer()
            try:
                self.oob_server.start()
                if self.verbose:
                    print(f"[*] OOB Server: LISTENING (Port {self.oob_server.port})")
            except Exception as e:
                print(f"[!] OOB Server startup failed: {e}")
                self.oob_server = None
        else:
            self.oob_server = None
            if self.verbose:
                print("[*] OOB Service: DISABLED")
        
        # 2. Adaptive Throttler (Prevents dev server crashes)
        from .core.throttler import AdaptiveThrottler
        self.throttler = AdaptiveThrottler(is_dev_env=self._is_localhost)
        if self.verbose and self._is_localhost:
            print("[*] Adaptive Throttling: ENABLED (Dev environment detected)")
        
        if self.force_aggressive:
            print(f"{Fore.YELLOW}[!] FORCE MODE: Skipping stability protections (Intensity tier protection disabled).{Style.RESET_ALL}")
        
        # 3. Attack Graph (Enables attack chaining)
        from .core.attack_graph import AttackGraph
        self.attack_graph = AttackGraph()
        if self.verbose:
            print("[*] Attack Graph: ENABLED (Exploitation path tracking active)")
        
        # 4. Target Context (Will be populated by fingerprinter)
        from .core.context import TargetContext
        self.context = TargetContext(base_url=self.base_url)
        self.context.oob_provider = self.oob_server  # Inject OOB into context

        # 5. Elite Reporting (Consolidated)
        from .reporting import EliteHTMLReporter
        self.reporter = EliteHTMLReporter(target_url=self.base_url)

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
        
        # Inject OOB Server into client
        if hasattr(self, 'oob_enabled') and self.oob_enabled and self.oob_server:
            client.oob_server = self.oob_server
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
        
        # RUN ELITE STATIC ANALYSIS FIRST
        if self.static_analyzer:
            print(f"[*] Starting Elite Static Analysis (SSA-based Taint Tracking)...")
            self.static_findings = self.static_analyzer.analyze()
            print(f"    -> Static Analysis Complete: {len(self.static_findings)} flow patterns identified.")
        
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
                future_to_std = {}
                results_processed = 0
                total_to_process = len(std_scenarios)
                
                # Submit tasks task-by-task to respect dynamic concurrency
                scenario_iterator = iter(std_scenarios)
                
                while results_processed < total_to_process:
                    if Engine.SHUTDOWN_SIGNAL or shutdown_event.is_set():
                        break
                    
                    # 1. Fill the executor up to the SUGGESTED concurrency limit
                    suggested_limit = self.throttler.get_suggested_concurrency(concurrency)
                    active_futures = [f for f in future_to_std if not f.done()]
                    
                    while len(active_futures) < suggested_limit:
                        try:
                            s = next(scenario_iterator)
                            future = executor.submit(self._execute_scenario, s)
                            future_to_std[future] = s
                            active_futures.append(future)
                        except StopIteration:
                            break # No more scenarios
                    
                    # 2. Process any completed futures
                    done_futures = [f for f in future_to_std if f.done() and f not in [None]]
                    if not done_futures and active_futures:
                        # Wait for at least one to finish
                        done_futures, _ = concurrent.futures.wait(active_futures, return_when=concurrent.futures.FIRST_COMPLETED, timeout=0.1)
                    
                    for future in done_futures:
                        if future in future_to_std:
                            scenario = future_to_std.pop(future)
                            results_processed += 1
                            try:
                                result = future.result()
                                
                                # RECORD IN GRAPH & UNLOCK DEPENDENCIES
                                self.attack_graph.record_finding(result.type, result)
                                
                                # CHECK FOR UNLOCKED ATTACKS
                                next_ids = self.attack_graph.get_next_attacks(max_count=3)
                                if next_ids:
                                    for nid in next_ids:
                                        # Find scenario in global pool if not already run
                                        matched = [s for s in std_scenarios if s.id == nid and s.id not in self.attack_graph.completed_attacks]
                                        if matched:
                                            # Prioritize this scenario by injecting it into the iterator or next batch
                                            # For simplicity, we just submit it now
                                            new_future = executor.submit(self._execute_scenario, matched[0])
                                            future_to_std[new_future] = matched[0]
                                            total_to_process += 1
                                
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
                                    snippet = result.vulnerable_code if hasattr(result, 'vulnerable_code') and result.vulnerable_code else "Source unavailable"
                                    
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
                                        print(f"    {Fore.GREEN}[+] ADVERSARIAL VALIDATION SUCCESS: Exploitation route verified and confirmed.{Style.RESET_ALL}")
                                        
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
                                        print(f"    {Fore.YELLOW}[?] ADVERSARIAL VALIDATION PARTIAL: Indicator of vulnerability detected but full exploit unconfirmed. ({validation_result['details']}){Style.RESET_ALL}")
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

                                results.append(result)
                                self._print_result(scenario, result)
                                
                                if result.status == "BLOCKED" and not self.thorough: 
                                    rate_limit_hits += 1
                                    # Relaxed check for localhost to avoid annoyance
                                    limit = 50 if self._is_localhost else 3
                                    if rate_limit_hits > limit:
                                        print(f"\n{Fore.YELLOW}[!] CRITICAL: Target is aggressively rate-limiting (429/403). Aborting to avoid total lockout.{Style.RESET_ALL}")
                                        shutdown_event.set()
                                        Engine.SHUTDOWN_SIGNAL = True
                                        break
                                elif result.status == "BLOCKED" and self.thorough:
                                     if self.verbose: print(f"{Fore.YELLOW}    [!] BLOCKED but THOROUGH mode is active. Continuing scan.{Style.RESET_ALL}")
                                
                                if result.status == "ERROR" and "Target Unresponsive" in result.details:
                                    print(f"\n{Fore.RED}[!] FATAL: Target at {self.base_url} is unresponsive or crashed. Aborting scan.{Style.RESET_ALL}")
                                    shutdown_event.set()
                                    Engine.SHUTDOWN_SIGNAL = True
                                    break
                                
                            except Exception as exc:
                                    # Use the new CheckResult constructor for errors too
                                    meta = ATTACK_METADATA.get(s.type if hasattr(s, 'type') else "unknown", {"severity": "INFO", "cwe": "N/A", "owasp": "N/A", "remediation": "N/A"})
                                    results.append(CheckResult(
                                        id=scenario.id,
                                        type=check_type,
                                        status="ERROR",
                                        severity=meta["severity"],
                                        details=f"Exception: {str(exc)}",
                                        confidence="LOW",
                                        cwe=meta["cwe"],
                                        owasp=meta["owasp"],
                                        remediation=meta["remediation"],
                                        artifacts=None
                                    ))

                # FILL REMAINING IF ABORTED (Ensure 100% reporting coverage)
                if shutdown_event.is_set() or Engine.SHUTDOWN_SIGNAL:
                    # Cleanly consume the iterator to find what was left behind
                    while True:
                        try:
                            s = next(scenario_iterator)
                            meta = ATTACK_METADATA.get(s.type if hasattr(s, 'type') else "unknown", {"severity": "INFO", "cwe": "N/A", "owasp": "N/A", "remediation": "N/A"})
                            results.append(CheckResult(
                                id=s.id, type=getattr(s, 'type', 'unknown'), status="SKIPPED", severity="INFO",
                                details="Scan Aborted: Target became unstable or blocked.", confidence="LOW",
                                cwe=meta["cwe"], owasp=meta["owasp"], remediation=meta["remediation"]
                            ))
                        except StopIteration: break
                    
                    # Also collect any in-flight futures that we cancelled
                    for future, s in future_to_std.items():
                        if s.id not in [r.id for r in results]:
                            meta = ATTACK_METADATA.get(s.type if hasattr(s, 'type') else "unknown", {"severity": "INFO", "cwe": "N/A", "owasp": "N/A", "remediation": "N/A"})
                            results.append(CheckResult(
                                id=s.id, type=getattr(s, 'type', 'unknown'), status="SKIPPED", severity="INFO",
                                details="Scan Aborted: Task cancelled during execution.", confidence="LOW",
                                cwe=meta["cwe"], owasp=meta["owasp"], remediation=meta["remediation"]
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
        import uuid
        attack_id = f"BRK-{uuid.uuid4().hex[:8].upper()}"
        try:
            check_type = s.attack_type if getattr(s, 'type', '') == 'simple' and hasattr(s, 'attack_type') else s.type
            
            # ===== ADAPTIVE THROTTLING =====
            # Check if this attack should be skipped based on intensity and stability
            # SKIP if (Throttler says so AND NOT in Force Mode)
            if self.throttler.should_skip_attack(check_type) and not self.force_aggressive:
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
            

            from .http_client import HttpClient
            from .attacks import omni
            
            client = HttpClient(self.base_url, verbose=self.verbose, headers=self.headers)
            if hasattr(self, 'oob_enabled') and self.oob_enabled and self.oob_server:
                client.oob_server = self.oob_server
            
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
            if self.verbose and len(variance_mask) > 100:
                print(f"    -> Baseline Stabilized (Mask: {len(variance_mask)} volatile points).")

            # DISPATCHER (OMNI CONSOLIDATED)
            res_dict = {}
            if check_type in ["header_security", "security_headers", "security_header_misconfiguration"]: 
                res_dict = omni.run_header_security_check(client, s)
            elif check_type in ["ssrf", "ssrf_scan", "blind_ssrf", "ssrf_cloud_metadata", "rsc_ssr_ssrf", "rsc_framework_ssrf"]: 
                res_dict = omni.run_ssrf_attack(client, s)
            elif check_type in ["rce", "react2shell", "rce_params_post", "os_command_injection", "code_injection", "cve_2024_nodejs_rce", "ghostscript_rce", "imagick_rce", "ruby_on_rails_rce_cve", "spring_cloud_function_rce", "confluence_rce_cve", "f5_big_ip_rce", "citric_adc_rce", "vmware_vcenter_rce", "outlook_cve_rce", "electron_rce_ipc", "tauri_rce_bypass", "rce_reverse_shell_attempt", "shellshock", "rce_shell_shock"]: 
                res_dict = omni.run_rce_attack(client, s)
            elif check_type in ["xss", "xss_reflected", "stored_xss", "reflected_xss"]: 
                res_dict = omni.run_xss_scan(client, s)
            elif check_type in ["crlf_injection", "http_response_splitting"]: 
                res_dict = omni.run_crlf_injection(client, s)
            elif check_type == "prototype_pollution": 
                res_dict = omni.run_prototype_pollution(client, s)
            elif check_type in ["sql_injection", "sqli_blind_time", "blind_sqli_destructive", "blind_sqli", "union_sqli", "time_sqli", "error_sqli", "second_order_sqli"]: 
                res_dict = omni.run_sqli_attack(client, s)
            elif check_type in ["open_redirect", "malicious_redirect"]: 
                res_dict = omni.run_open_redirect(client, s)
            elif check_type in ["brute_force", "brute_force_basic", "broken_authentication", "authentication_bypass", "credential_stuffing", "authorization_bypass", "api_auth_bypass", "api_authorization_bypass"]: 
                res_dict = omni.run_brute_force(client, s)
            elif check_type in ["advanced_dos", "advanced_dos_checks", "slow_post", "slow_post_attack", "application_layer_dos"]: 
                res_dict = omni.run_advanced_dos(client, s)
            elif check_type in ["clickjacking", "clickjacking_check"]:
                s_copy = s
                s_copy.id = "clickjacking" # Narrow the scope for the omni check
                res_dict = omni.run_header_security_check(client, s_copy)
            elif check_type in ["password_length", "password_length_dos"]:
                res_dict = omni.run_password_length_dos(client, s)
            elif check_type in ["email_injection", "email_header_injection"]:
                res_dict = omni.run_email_injection(client, s)
            elif check_type in ["replay_simple", "auth_replay_check"]:
                res_dict = omni.run_replay_check(client, s)
            elif check_type in ["debug_exposure", "debug_mode_exposure", "stack_trace_disclosure", "source_code_disclosure", "directory_listing_exposure", "webpack_sourcemap_leak", "node_inspect_vulnerability", "flask_debug_leak", "react_native_debugger_exposure"]: 
                res_dict = omni.run_debug_exposure(client, s)
            elif check_type in ["secret_leak", "secret_leak_check", "secret_leak_scan", "firebase_db_exposure", "s3_bucket_enumeration", "ssh_key_leak", "npm_auth_token_leak", "django_secret_key_leak"]: 
                res_dict = omni.run_secret_leak(client, s)
            elif check_type in ["swagger_exposure", "swagger_ui_exposure"]: 
                res_dict = omni.run_swagger_check(client, s)
            elif check_type in ["git_exposure", "git_exposure_check"]: 
                res_dict = omni.run_git_exposure(client, s)
            elif check_type in ["env_exposure", "env_exposure_check"]: 
                res_dict = omni.run_env_exposure(client, s)
            elif check_type in ["phpinfo", "phpinfo_exposure"]: 
                res_dict = omni.run_phpinfo(client, s)
            elif check_type in ["ds_store_exposure", "ds_store"]: 
                res_dict = omni.run_ds_store(client, s)
            elif check_type in ["ssti", "ssti_template_injection", "exotic_injection_template"]: 
                res_dict = omni.run_ssti_attack(client, s)
            elif check_type in ["insecure_deserialization", "deserialization_rce", "object_injection", "phar_deserialization", "python_pickle_deserialization", "rsc_payload_deserialization", "java_rmi_deserialization", "asp_net_viewstate_mac"]: 
                res_dict = omni.run_insecure_deserialization(client, s)
            elif check_type in ["jwt_weakness", "jwt_none_alg", "jwt_signature_bypass", "jwt_key_confusion"]: 
                res_dict = omni.run_jwt_attack(client, s)
            elif check_type in ["jwt_brute", "jwt_weak_key_brute"]: 
                res_dict = omni.run_jwt_brute(client, s)
            elif check_type in ["idor", "idor_numeric", "mass_assignment", "mass_assignment_user", "hidden_form_field_manipulation", "access_control_bypass", "excessive_data_exposure"]: 
                res_dict = omni.run_idor_check(client, s)
            elif check_type in ["lfi", "lfi_path_traversal", "rfi", "path_traversal", "directory_traversal", "local_file_inclusion_etc_passwd", "file_inclusion_polyglot"]: 
                res_dict = omni.run_lfi_attack(client, s)
            elif check_type == "cors_origin": 
                res_dict = omni.run_cors_misconfig(client, s)
            elif check_type in ["host_header", "host_header_injection", "host_header_cache_poisoning"]: 
                res_dict = omni.run_host_header_injection(client, s)
            elif check_type in ["nosql_injection", "nosql_injection_login"]: 
                res_dict = omni.run_nosql_injection(client, s)
            elif check_type in ["ldap_injection", "ldap_injection_search"]: 
                res_dict = omni.run_ldap_injection(client, s)
            elif check_type in ["xpath_injection", "xpath_injection_xml"]: 
                res_dict = omni.run_xpath_injection(client, s)
            elif check_type == "ssi_injection": 
                res_dict = omni.run_ssi_injection(client, s)
            elif check_type in ["request_smuggling", "http_request_smuggling", "chunked_encoding_smuggling", "te_cl_desync", "cl_te_desync", "h2c_smuggling", "cl_cl_desync_probe", "te_te_desync_probe"]: 
                res_dict = omni.run_request_smuggling(client, s)
            elif check_type in ["http_desync", "http_desync_attack"]: 
                res_dict = omni.run_http_desync(client, s)
            elif check_type in ["graphql_introspection", "graphql_batching", "graphql_alias_overload", "graphql_circular_frag"]: 
                res_dict = omni.run_graphql_introspection(client, s)
            elif check_type in ["log4shell", "cve_log4shell", "log4shell_recursive_delete", "log4shell_obfuscated", "log4shell_jndi_ldap_bypass"]: 
                res_dict = omni.run_cve_log4shell(client, s)
            elif check_type in ["cache_deception", "cache_poison_check", "web_cache_poisoning", "web_cache_deception", "cdn_cache_key_confusion", "edge_cache_poisoning", "nextjs_cache_poison"]: 
                res_dict = omni.run_cache_deception(client, s)
            elif check_type in ["race_condition", "duplicate_transaction", "duplicate_payment", "coupon_reuse", "refund_logic"]: 
                res_dict = omni.run_race_condition(client, s)
            elif check_type == "otp_reuse": 
                res_dict = omni.run_otp_reuse(client, s)
            elif check_type in ["rsc_server_action_forge", "server_side_action_forge", "rsc_action_id_brute"]: 
                res_dict = omni.run_rsc_server_action_forge(client, s)
            elif check_type in ["rsc_hydration_collapse", "hydration_collapse", "rsc_suspense_leak"]: 
                res_dict = omni.run_hydration_collapse(client, s)
            elif check_type in ["rsc_flight_trust_boundary_violation", "rsc_flight_deserialization_abuse", "trust_boundary_violation", "react_server_component_injection"]:
                res_dict = omni.run_flight_trust_boundary_violation(client, s)
            elif check_type in ["json_bomb", "json_bomb_attack"]: res_dict = omni.run_json_bomb(client, s)
            elif check_type in ["redos", "redos_validation_attack"]: res_dict = omni.run_redos(client, s)
            elif check_type in ["xml_bomb", "fast-xml-parser-rce"]: res_dict = omni.run_xml_bomb(client, s)
            elif check_type in ["xxe_exfil", "xxe_external_entity"]: res_dict = omni.run_xxe_exfil(client, s)
            elif check_type in ["malformed_json_check", "malformed_json"]: res_dict = omni.run_malformed_json(client, s)
            elif check_type in ["file_upload_abuse", "unrestricted_file_upload", "malicious_file_upload", "file_type_validation_bypass", "polyglot_file_upload", "content_type_confusion", "file_overwrite_upload", "file_upload_shell"]: 
                res_dict = omni.run_file_upload_abuse(client, s)
            elif check_type in ["zip_slip", "zip_slip_path_traversal"]: res_dict = omni.run_zip_slip(client, s)
            elif check_type in ["cve_spring4shell", "spring4shell"]: res_dict = omni.run_cve_spring4shell(client, s)
            elif check_type in ["cve_struts2", "struts2_rce", "struts2_s2_061"]: res_dict = omni.run_cve_struts2(client, s)
            elif check_type in ["elasticsearch_injection", "es_injection"]: res_dict = omni.run_elasticsearch_injection(client, s)
            elif check_type in ["search_injection", "server_side_search"]: res_dict = omni.run_server_side_search_injection(client, s)
            elif check_type in ["parameter_pollution", "hpp", "wpp", "parameter_smuggling"]: res_dict = omni.run_parameter_pollution(client, s)
            elif check_type in ["csrf", "login_csrf", "samesite_cookie_bypass"]: res_dict = omni.run_csrf_check(client, s)
            elif check_type == "password_reset_poisoning": res_dict = omni.run_password_reset_poisoning(client, s)
            elif check_type in ["session_fixation", "session_hijacking", "token_replay_attack"]: res_dict = omni.run_session_fixation(client, s)
            elif check_type in ["tenant_isolation", "tenant_isolation_bypass", "cross_tenant_data_exposure"]: res_dict = omni.run_tenant_isolation_check(client, s)
            elif check_type in ["oauth_redirect", "oauth_redirect_uri_manipulation"]: res_dict = omni.run_oauth_redirect_manipulation(client, s)
            elif check_type in ["verb_tampering", "http_verb_tampering", "http_method_override"]: res_dict = omni.run_verb_tampering(client, s)
            elif check_type in ["archive_bomb", "zip_bomb"]: res_dict = omni.run_archive_bomb(client, s)
            elif check_type == "poodle": res_dict = omni.run_poodle_check(client, s)
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
            result = CheckResult(
                id=s.id,
                type=check_type,
                status=status,
                severity=meta["severity"] if status in ["VULNERABLE", "CONFIRMED", "SUSPECT"] else "INFO",
                details=str(res_dict.get("details", "")),
                confidence=res_dict.get("confidence", "TENTATIVE"), 
                cwe=meta["cwe"],
                owasp=meta["owasp"],
                remediation=meta["remediation"],
                artifacts=res_dict.get("artifacts", [])
            )
            
            # --- ELITE SCORING PASS ---
            if result.status in ["VULNERABLE", "CONFIRMED", "SUSPECT"]:
                # 1. Calc Confidence
                result.confidence = ConfidenceEngine.calculate(
                    result, 
                    static_findings=self.static_findings,
                    ai_confirmed=(result.status == "CONFIRMED")
                )
                
                # 2. Calc Risk
                risk = RiskScoringEngine.evaluate(result)
                result.description = f"{ATTACK_IMPACTS.get(check_type, 'Security Compromise')} | Risk Score: {risk['score']} ({risk['level']})"
                
                # 3. Store Evidence
                if result.artifacts:
                    for art in result.artifacts:
                         # Attempt to collect last interaction as evidence
                         pass # handled by caller/dispatcher usually
            
            # ===== POST-EXECUTION TRACKING =====
            # 1. Record in attack graph for chaining
            from .models import AttackResult, VulnerabilityStatus, Severity
            
            status_map = {
                "CONFIRMED": VulnerabilityStatus.CONFIRMED,
                "VULNERABLE": VulnerabilityStatus.VULNERABLE,
                "SUSPECT": VulnerabilityStatus.SUSPECT,
                "SECURE": VulnerabilityStatus.SECURE,
                "SKIPPED": VulnerabilityStatus.SKIPPED,
                "BLOCKED": VulnerabilityStatus.BLOCKED,
                "ERROR": VulnerabilityStatus.ERROR
            }
            
            severity_map_enum = {
                "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, 
                "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.INFO
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
            response_time = res_dict.get("response_time", 50)
            self.throttler.record_request(success, response_time, is_timeout)
            
            # ENRICH RESULT FROM METADATA
            attack_info = ATTACK_METADATA.get(check_type, {})
            result.severity = attack_info.get("severity", "LOW")
            result.remediation = attack_info.get("remediation", "N/A")
            result.description = ATTACK_IMPACTS.get(check_type, "Security Compromise")

            # ATTEMPT TO FIND VULNERABLE CODE IF CONFIRMED
            if result.status == "CONFIRMED" and self.source_path:
                result.vulnerable_code = self._find_vulnerable_code(result.type, s.target)

            result.attack_id = attack_id
            return result

        except Exception as e:
            err_str = str(e)
            attack_meta = ATTACK_METADATA.get(check_type, {"severity": "INFO", "cwe": "N/A", "owasp": "N/A", "remediation": "N/A"})

            # Record FAILURE in throttler even on exception
            self.throttler.record_request(success=False, response_time=500, is_timeout="timeout" in err_str.lower())

            # Special Handling for Localhost Crashes/Timeouts
            if "connection refused" in err_str.lower() or "target machine actively refused" in err_str.lower() or "10061" in err_str:
                target_msg = "LOCALHOST ERROR: Connection Refused (Server likely crashed or down)"
                return CheckResult(s.id, check_type, "ERROR", "HIGH", f"{target_msg}: {err_str}")
            
            if "timeout" in err_str.lower():
                 return CheckResult(s.id, check_type, "SKIPPED", "INFO", f"Request Timed Out (Target slow): {err_str}")

            if "localhost error" in err_str.lower() or "unreachable" in err_str.lower():
                target_msg = "Target Unresponsive"
                if "127.0.0.1" in self.base_url or "localhost" in self.base_url:
                    target_msg = "LOCALHOST ERROR: Target is struggling"
                return CheckResult(s.id, check_type, "ERROR", "HIGH", f"{target_msg}: {err_str}")

            if "Max retries" in err_str or "429" in err_str or "403" in err_str:
                return CheckResult(
                    id=s.id,
                    type=check_type,
                    status="BLOCKED",
                    severity=attack_meta["severity"],
                    details=f"Request blocked or rate-limited: {err_str}",
                    confidence="HIGH",
                    cwe=attack_meta["cwe"],
                    owasp=attack_meta["owasp"],
                    remediation=attack_meta["remediation"]
                )
            
            import traceback
            err_str = f"{str(e)}\n{traceback.format_exc() if self.verbose else ''}"
            # Ensure we return a valid CheckResult even on error
            attack_meta = ATTACK_METADATA.get(check_type, {"severity": "INFO", "cwe": "N/A", "owasp": "N/A", "remediation": "N/A"})
            return CheckResult(s.id, check_type, "ERROR", attack_meta["severity"], f"Engine Failure: {err_str[:200]}")

    def _find_vulnerable_code(self, attack_type: str, target_path: str) -> str:
        """Heuristically finds the source code responsible for a vulnerability."""
        if not self.source_path or not os.path.exists(self.source_path):
            return "Source path not found."
            
        # Strategy 1: Map URL to file
        # Simple mapping: /api/login -> login.js, login.ts, route.ts inside api/login
        potential_files = []
        clean_path = target_path.strip("/")
        
        # Look for the path in the directory structure
        for root, _, files in os.walk(self.source_path):
            if clean_path and clean_path in root.replace("\\", "/"):
                for f in files:
                    if f.endswith((".ts", ".js", ".py", ".go", ".php", ".tsx", ".jsx")):
                        potential_files.append(os.path.join(root, f))
        
        if not potential_files:
             # Strategy 2: Search for the endpoint string in all files
             import subprocess
             try:
                 # Use git grep if available, else standard grep
                 cmd = ["grep", "-r", "-l", target_path, self.source_path]
                 out = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
                 potential_files.extend(out.splitlines()[:5])
             except:
                 pass

        if potential_files:
            # Pick the best file and extract context
            target_file = potential_files[0]
            try:
                with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    # Find a line that looks suspicious based on attack_type
                    keywords = {
                        "sql_injection": ["SELECT", "FROM", "WHERE", "query(", "execute("],
                        "nosql_injection": ["find(", "findOne(", "$ne", "$gt"],
                        "rce": ["exec(", "spawn(", "system(", "eval("],
                        "ssti": ["render(", "template", "{{", "{%"],
                    }
                    search_keys = keywords.get(attack_type, [target_path])
                    
                    target_line = -1
                    for i, line in enumerate(lines):
                        if any(k in line for k in search_keys):
                            target_line = i
                            break
                    
                    if target_line != -1:
                        start = max(0, target_line - 3)
                        end = min(len(lines), target_line + 4)
                        snippet = "".join(lines[start:end])
                        return f"File: {os.path.relpath(target_file, self.source_path)}\n---\n{snippet}"
            except:
                pass
                
        return "Automatic code localization failed. Manual audit required."

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
            # Main result line with ID and Status
            print(f"    -> {color}[{result.status}]{Style.RESET_ALL} [{result.attack_id or 'N/A'}] {scenario.id}: {str(result.details)[:80]}...")
            
            if result.status == "CONFIRMED":
                print(f"\n{Fore.RED}" + "="*60)
                print(f" CONFIRMED VULNERABILITY: {result.type.upper()}")
                print(f"="*60 + f"{Style.RESET_ALL}")
                
                # Impact
                print(f" {Fore.RED}{'Business Impact:':<20}{Style.RESET_ALL} {result.description or 'Security Compromise'}")
                
                # Vulnerable Code
                if result.vulnerable_code:
                    print(f"\n {Fore.YELLOW}MODERN OFFENSIVE LOCALIZATION (Responsible Code):{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}{result.vulnerable_code}{Style.RESET_ALL}")
                
                # Evidence
                print(f"\n {Fore.RED}{'Evidence:':<20}{Style.RESET_ALL} See Consolidated Elite Audit Report for precise exploit payloads.")
                
                print(f"{Fore.RED}" + "="*60 + f"{Style.RESET_ALL}\n")
