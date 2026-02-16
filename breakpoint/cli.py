from .reporting import EliteHTMLReporter
from .sarif_reporting import SarifReporter
from .engine import Engine
from .scenarios import load_scenarios, SimpleScenario, FlowScenario
from .reporting import ConsoleReporter, generate_json_report
from .metadata import get_metadata
from .safety_lock import SafetyLock
from .forensics import ForensicLogger
from .ai_analyzer import AIAnalyzer
from .http_client import HttpClient
from .licensing import check_access, get_denial_message, get_license_tier, login_flow, get_license_key, get_openai_key, save_openai_key
import argparse
import sys
import os
import signal
import shutil
import datetime
import subprocess
import requests
import questionary
from colorama import Fore, Style, init
import threading

def signal_handler(sig, frame):
    from .engine import Engine
    Engine.SHUTDOWN_SIGNAL = True
    # Use os._exit(0) for an immediate, clean termination of all threads
    os._exit(0)

def get_app_data_dir():
    """Returns platform-specific AppData path, creating it if needed."""
    if sys.platform == 'win32':
        base = os.environ.get('LOCALAPPDATA', os.path.expanduser('~\\AppData\\Local'))
        path = os.path.join(base, 'BreakPoint')
    else:
        path = os.path.expanduser('~/.config/breakpoint')
    
    if not os.path.exists(path):
        try: os.makedirs(path)
        except: pass
    return path

def get_documents_dir():
    """Returns platform-specific Documents/Reports path."""
    if sys.platform == 'win32':
        base = os.path.join(os.environ.get('USERPROFILE', os.path.expanduser('~')), 'Documents')
        path = os.path.join(base, 'BreakPoint', 'Reports')
    else:
        path = os.path.expanduser('~/Documents/BreakPoint/Reports')
    
    if not os.path.exists(path):
        try: os.makedirs(path)
        except: pass
    return path

def get_default_scenarios_path():
    """Resolves path to embedded omni_attack_all.yaml"""
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
        return os.path.join(base_path, 'breakpoint', 'omni_attack_all.yaml')
    else:
        return os.path.join(os.path.dirname(__file__), 'omni_attack_all.yaml')

def handle_update():
    print("[*] Checking for updates...")
    repo = "soulmad/breakpoint"
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            latest = data.get("tag_name", "Unknown")
            current = "3.0.0-ELITE"
            print(f"[+] Latest Version: {latest}")
            print(f"[+] Current Version: {current}")
            if latest != current and latest != "Unknown":
                print(f"[!] Update Available: {data.get('html_url')}")
                if os.path.exists(".git"):
                    print("[*] Git detected. Running pull...")
                    subprocess.run(["git", "pull"])
            else:
                print("[+] You are up to date.")
    except Exception as e:
        print(f"[-] Update check failed: {e}")
    sys.exit(0)

def check_internet_connectivity():
    """Checks internet connectivity and latency."""
    print("[*] Checking Internet Connectivity...", end="\r")
    targets = ["https://1.1.1.1", "https://google.com"]
    latency = None
    
    for target in targets:
        try:
            start = datetime.datetime.now()
            requests.get(target, timeout=5)
            end = datetime.datetime.now()
            latency = (end - start).total_seconds() * 1000
            break
        except:
            continue
            
    if latency is None:
        print(f"[{Fore.RED}!{Style.RESET_ALL}] Internet: {Fore.RED}NO INTERNET{Style.RESET_ALL}        ")
    elif latency > 500:
        print(f"[{Fore.YELLOW}!{Style.RESET_ALL}] Internet: {Fore.YELLOW}SLOW ({int(latency)}ms){Style.RESET_ALL}    ")
    else:
        print(f"[{Fore.GREEN}+{Style.RESET_ALL}] Internet: {Fore.GREEN}GOOD ({int(latency)}ms){Style.RESET_ALL}    ")

def main():
    init(autoreset=True)
    signal.signal(signal.SIGINT, signal_handler)
    
    # 1. ROBUST SHORTHAND & COMMAND HANDLING
    if len(sys.argv) > 1:
        skip_transformation = ["update", "--update", "--login", "--license-key", "--openai-key", "--version", "-v"]
        if sys.argv[1] in skip_transformation:
            if sys.argv[1] == "update" or sys.argv[1] == "--update":
                handle_update()
        else:
            for i in range(1, len(sys.argv)):
                arg = sys.argv[i]
                if arg.startswith("-"):
                    continue
                if arg.startswith("http"):
                    if "--base-url" not in sys.argv:
                        sys.argv[i] = arg
                        sys.argv.insert(i, "--base-url")
                    break
                if arg == "scan" and i + 1 < len(sys.argv):
                    sys.argv[i] = "--base-url"
                    break

    parser = argparse.ArgumentParser(
        description="BREAKPOINT // SYSTEM BREAKER",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("-v", "--version", action="version", version="BREAKPOINT v3.0.0-ELITE")
    parser.add_argument("--update", action="store_true", help="Check for updates")
    parser.add_argument("--login", action="store_true", help="Connect your Breakpoint account")
    
    target_group = parser.add_argument_group("Targeting")
    target_group.add_argument("--base-url", help="Target URL")
    target_group.add_argument("--scenarios", help="Path to YAML scenarios file")
    target_group.add_argument("--force-live-fire", action="store_true", help="Bypass safety checks")
    target_group.add_argument("--source", help="Path to source code for static analysis and AI project review")
    target_group.add_argument("--diff", action="store_true", help="Enable differential scan mode")
    target_group.add_argument("--git-range", help="Git range for differential analysis (e.g. HEAD~1..HEAD)")
    target_group.add_argument("--attacks", help="Comma-separated list of attack modules to run (Manual override)")
    target_group.add_argument("--interactive", action="store_true", help="Select attack modules interactively via checkboxes")
    
    out_group = parser.add_argument_group("Reporting")
    out_group.add_argument("--json-report", help="Path to JSON output")
    out_group.add_argument("--html-report", help="Path to HTML Report") 
    out_group.add_argument("--sarif-report", help="Path to SARIF output")
    
    conf_group = parser.add_argument_group("Configuration")
    conf_group.add_argument("--env", choices=["dev", "staging", "production"], help="Operational Environment (Mandatory for scans)")
    conf_group.add_argument("--simulation", action="store_true", help="Run in Impact Simulation mode")
    conf_group.add_argument("--concurrency", type=int, default=None)
    conf_group.add_argument("--aggressive", action="store_true", help="Enable destructive attacks")
    conf_group.add_argument("--force", action="store_true", help="Force execution: Skip stability/intensity protections")
    conf_group.add_argument("--thorough", action="store_true", help="Thorough mode: Ignore rate limits and continue regardless of blocks")
    conf_group.add_argument("--verbose", action="store_true")
    conf_group.add_argument("--continuous", action="store_true")
    conf_group.add_argument("--interval", type=int, default=0)
    parser.add_argument("--license-key", help="Specify subscription key")
    parser.add_argument("--openai-key", help="Set or update OpenAI API key for AI-driven project analysis")
    parser.add_argument("--headers", action="append", help="Global headers (Key:Value)")
    
    args, unknown = parser.parse_known_args()
    
    if args.verbose:
        os.environ["BREAKPOINT_VERBOSE"] = "1"

    # Handle license key flag (Non-interactive activation)
    if args.license_key:
        os.environ["BREAKPOINT_LICENSE_KEY"] = args.license_key
        if not args.base_url and not args.login:
            from .licensing import VALIDATION_ENDPOINT, save_license_key, _get_cache_dir
            print(f"[*] Activating with License Key...")
            try:
                resp = requests.get(
                    VALIDATION_ENDPOINT,
                    headers={"Authorization": f"Bearer {args.license_key}"},
                    timeout=10
                )
                if resp.status_code == 200:
                    data = resp.json()
                    tier = data.get("type", data.get("tier", "FREE"))
                    print(f"[+] Success! {tier} license activated and saved.")
                    save_license_key(args.license_key)
                    cache_file = os.path.join(_get_cache_dir(), "license_cache.json")
                    if os.path.exists(cache_file): os.remove(cache_file)
                    sys.exit(0)
                else:
                    print(f"[-] Validation failed: Status {resp.status_code}")
                    sys.exit(1)
            except Exception as e:
                print(f"[-] Activation error: {e}")
                sys.exit(1)

    # Handle OpenAI key flag
    if args.openai_key:
        if save_openai_key(args.openai_key):
            print(f"[+] OpenAI API key saved successfully.")
            if not args.base_url: sys.exit(0)
        else:
            sys.exit(1)

    # 0. MANDATORY LOGIN CHECK
    if args.login:
        if login_flow():
            sys.exit(0)
        sys.exit(1)

    # Check if logged in
    from .licensing import is_logged_in
    if not is_logged_in():
        print(f"\n{Fore.YELLOW}[!] LOGIN REQUIRED: Breakpoint requires a connected account.{Style.RESET_ALL}")
        print("[!] Visit https://breakpoint-web-one.vercel.app to register.")
        print("[!] Run 'breakpoint --login' to connect your account.")
        if sys.stdin.isatty():
             choice = input("\n[?] Would you like to log in now? (y/n): ").lower()
             if choice == 'y':
                 if login_flow():
                     print("\n[+] Login successful. Please re-run your command.")
                     sys.exit(0)
        sys.exit(1)

    if unknown:
        print(f"[!] Error: Unknown arguments detected: {unknown}")
        sys.exit(1)

    if not args.base_url:
        parser.print_help()
        sys.exit(1)

    if not args.env:
        print(f"\n{Fore.RED}[!] Error: --env <dev|staging|production> is mandatory for scans.{Style.RESET_ALL}")
        sys.exit(1)

    # 2. RUNTIME LICENSE ENFORCEMENT
    if args.aggressive:
        if not check_access("aggressive"):
            print(get_denial_message("aggressive"))
            sys.exit(1)
    if args.env == "production":
        if not check_access("production"):
            print(get_denial_message("production"))
            sys.exit(1)

    # 3. EULA CHECK
    from .legal import has_accepted_eula, prompt_eula
    if not has_accepted_eula():
        if not prompt_eula():
            sys.exit(1)

    # Defaults
    if args.concurrency is None:
        if any(x in args.base_url.lower() for x in ["localhost", "127.0.0.1", "0.0.0.0", "::1"]):
            args.concurrency = 15 if args.aggressive else 8
            if args.verbose:
                print(f"[*] Dev/Localhost detected: Capping concurrency to {args.concurrency} to ensure stability.")
        else:
            args.concurrency = 100 if args.aggressive else 40
    global_headers = {}
    if args.headers:
        for h in args.headers:
            if ":" in h:
                k, v = h.split(":", 1)
                global_headers[k.strip()] = v.strip()

    BANNER = r"""
  ____  _____  ______          _   _ _____   ____ _____ _   _ _______ 
 |  _ \|  __ \|  ____|   /\   | |/ /|  __ \ / __ \|_   _| \ | |__   __|
 | |_) | |__) | |__     /  \  | ' / | |__) | |  | | | | |  \| |  | |   
 |  _ <|  _  /|  __|   / /\ \ |  <  |  ___/| |  | | | | | . ` |  | |   
 | |_) | | \ \| |____ / ____ \| . \ | |    | |__| |_| |_| |\  |  | |   
 |____/|_|  \_\______/_/    \_\_|\_\|_|     \____/|_____|_| \_|  |_|   
    """
    print(f"{Fore.RED}{BANNER}")
    print(f"{Fore.RED}    BREAKPOINT // WEAPONIZED RESILIENCE ENGINE")
    print(f"{Fore.RED}    \"Production is already broken.\"{Style.RESET_ALL}\n")

    check_internet_connectivity()
    tier = get_license_tier()
    print(f"[*] LICENSE: {tier} EDITION")
    
    # 0. Global API Key Requirement
    openai_key = get_openai_key()
    if not openai_key:
         print(f" {Fore.RED}[!] ABORTED: OpenAI API key is missing.{Style.RESET_ALL}")
         print(f" {Fore.RED}    Breakpoint requires an AI key for project footprinting and adversarial validation.{Style.RESET_ALL}")
         print(f" {Fore.YELLOW}    Provide one using: 'breakpoint --openai-key <KEY>'{Style.RESET_ALL}\n")
         sys.exit(1)
    else:
         print(f" {Fore.GREEN}[+] AI Engine: ONLINE{Style.RESET_ALL}")

    logger = ForensicLogger()
    print(f" {Fore.CYAN}[*] Forensic Audit initialized.{Style.RESET_ALL}")
    print("-" * 60)
    
    app_data = get_app_data_dir()
    config_path = os.path.join(app_data, "omni_attack_all.yaml")
    try:
        src = get_default_scenarios_path()
        if os.path.exists(src):
            shutil.copy(src, config_path)
    except Exception: pass

    scenarios_path = args.scenarios
    if not scenarios_path:
        app_cfg = os.path.join(get_app_data_dir(), "default_scenarios.yaml")
        scenarios_path = app_cfg if os.path.exists(app_cfg) else get_default_scenarios_path()

    try:
        scenarios = load_scenarios(scenarios_path)
        # Fix: Collect the actual attack modules (attack_type), not the scenario category (simple/flow)
        available_module_ids = sorted(list(set([getattr(s, 'attack_type', s.type) for s in scenarios])))
        selected_module_ids = available_module_ids

        # --- 1. MODULE SELECTION ---
        if args.interactive:
            import questionary
            print("\n[*] Initializing Interactive Attack Selector...")
            choices = [questionary.Choice(m, checked=True) for m in available_module_ids]
            selected_module_ids = questionary.checkbox(
                "Select attack modules to enable:",
                choices=choices,
                style=questionary.Style([
                    ('qmark', 'fg:#ff5f00 bold'),
                    ('question', 'bold'),
                    ('answer', 'fg:#00afff bold'),
                    ('pointer', 'fg:#00afff bold'),
                    ('selected', 'fg:#00afff'),
                    ('checkbox', 'fg:#00afff'),
                    ('separator', 'fg:#6c6c6c'),
                    ('instruction', 'fg:#6c6c6c italic'),
                ])
            ).ask()
            if not selected_module_ids:
                print(f"{Fore.YELLOW}[!] No modules selected. Aborting.{Style.RESET_ALL}")
                sys.exit(0)
        elif args.attacks:
            requested = [a.strip().lower() for a in args.attacks.split(',')]
            if "all" in requested:
                selected_module_ids = available_module_ids
                print(f"[*] Command line selection: Enabling ALL attack modules.")
            else:
                selected_module_ids = [m for m in available_module_ids if m in requested]
                print(f"[*] Command line selection: Running {len(selected_module_ids)} specific modules.")
        
        # Ensure we don't start the AI phase with 0 modules
        if not selected_module_ids and available_module_ids:
            selected_module_ids = available_module_ids
            print(f"{Fore.YELLOW}[!] Warning: No valid modules matched your selection. Defaulting to ALL.{Style.RESET_ALL}")

        # --- MANDATORY CONNECTIVITY CHECK ---
        print(f"[*] Verifying target connectivity: {args.base_url}...")
        client = HttpClient(args.base_url, headers=global_headers)
        try:
            hb = client.send("GET", "/", timeout=5)
            if hb.status_code == 0:
                print(f"{Fore.RED}[!] ABORT: Target {args.base_url} is unreachable.{Style.RESET_ALL}")
                sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] ABORT: Connection failed: {e}{Style.RESET_ALL}")
            sys.exit(1)

        # --- 2. AI SOURCE ANALYSIS (One-Shot Footprinting) ---
        if args.source:
            analyzer = AIAnalyzer(forensic_log=logger)
            footprint = analyzer.perform_footprinting(args.source, args.base_url, available_module_ids)
            
            # A. Verification
            if not footprint.get("match", True):
                print(f"\n{Fore.RED}[!] ABORTING: Source code does not match the target URL.{Style.RESET_ALL}")
                print(f"{Fore.RED}[!] AI Confidence: {footprint.get('confidence')}% | Reason: {footprint.get('reason')}{Style.RESET_ALL}")
                print(f"[!] To run a generic scan without source verification, omit the --source flag.")
                sys.exit(1)
            
            # B. Module Filtering (Only if manual override not set)
            if not args.attacks and not args.interactive:
                selected_module_ids = footprint.get("modules", available_module_ids)
                print(f"    [+] AI Phase: Smart filtering enabled ({len(selected_module_ids)} modules).")
            
            # C. Endpoint Discovery
            discovered_surface = footprint.get("endpoints", [])
            if discovered_surface:
                print(f"    [+] AI Phase: {len(discovered_surface)} dynamic endpoints discovered.")
                critical_modules = [
                    "sql_injection", "nosql_injection", "rce", "ssti", 
                    "lfi", "idor", "open_redirect", "xss", "prototype_pollution",
                    "jwt_weakness", "mass_assignment", "tenant_isolation"
                ]
                for entry in discovered_surface:
                    path, method, params = entry.get('path', '/'), entry.get('method', 'GET').upper(), entry.get('params', [])
                    for mod_id in selected_module_ids:
                        if mod_id in critical_modules:
                             scenarios.append(SimpleScenario(
                                 id=f"ai_{mod_id}_{path.replace('/', '_').strip('_')}",
                                 type="simple", attack_type=mod_id, target=path, method=method,
                                 config={"fields": params, "aggressive": args.aggressive}
                             ))
                print(f"    [+] Dynamic Surface: Added {len(scenarios) - len([s for s in scenarios if not s.id.startswith('ai_')])} targeted scenarios.")
        else:
             print(f"\n{Fore.CYAN}[*] URL-ONLY MODE: AI Analysis Disabled (No source path provided).{Style.RESET_ALL}")

        # FINAL SELECTION SUMMARY
        if args.source:
             if selected_module_ids == available_module_ids and len(available_module_ids) > 0:
                 print(f"\n {Fore.YELLOW}--- AI ANALYSIS SKIPPED/FAILED (FULL SCAN FALLBACK) ---{Style.RESET_ALL}")
                 print(f" {Fore.YELLOW}[!] Using all {len(selected_module_ids)} available modules as a safe baseline.{Style.RESET_ALL}")
             else:
                 print(f"\n {Fore.CYAN}--- AI ANALYSIS COMPLETE ---{Style.RESET_ALL}")
                 print(f" AI has selected {Fore.YELLOW}{len(selected_module_ids)}{Style.RESET_ALL} relevant modules for this target:")
        else:
             print(f"\n {Fore.CYAN}--- MODULE SELECTION ---{Style.RESET_ALL}")
             print(f" {Fore.YELLOW}{len(selected_module_ids)}{Style.RESET_ALL} modules configured for execution:")
        
        sorted_modules = sorted(selected_module_ids) if selected_module_ids else []
        for i in range(0, len(sorted_modules), 4):
            chunk = sorted_modules[i:i+4]
            print(f"    • {', '.join(chunk)}")
        print("-" * 60)

        # Fix: Filter based on the actual attack module ID
        scenarios = [s for s in scenarios if getattr(s, 'attack_type', s.type) in selected_module_ids]

        # --- DEDUPLICATION: Ensure "Elite" precision by removing identical probes ---
        unique_scenarios = []
        seen_fingerprints = set()
        import json

        # Module Synonyms: Normalize these to prevent redundant scans across overlapping modules
        SYNONYMS = {
            "clickjacking": "header_security",
            "clickjacking_check": "header_security",
            "cors_origin": "header_security",
            "security_headers": "header_security",
            "blind_sqli": "sql_injection",
            "union_sqli": "sql_injection",
            "time_sqli": "sql_injection",
            "error_sqli": "sql_injection",
            "reflected_xss": "xss",
            "stored_xss": "xss"
        }
        
        for s in scenarios:
            # Create a unique fingerprint for this scenario's logical execution
            config_json = json.dumps(getattr(s, 'config', {}), sort_keys=True)
            
            # Use synonym if available to normalize the module type
            m_type = getattr(s, 'attack_type', s.type)
            norm_type = SYNONYMS.get(m_type, m_type)

            fingerprint = (
                norm_type,
                s.target,
                s.method,
                config_json
            )
            
            if fingerprint not in seen_fingerprints:
                unique_scenarios.append(s)
                seen_fingerprints.add(fingerprint)
            elif args.verbose:
                print(f"    [-] Removing redundant scenario: {s.id} (Matches existing probe in {norm_type})")
        
        scenarios = unique_scenarios
        
        if not scenarios:
            print(f"\n{Fore.RED}[!] ERROR: No valid attack scenarios remain.{Style.RESET_ALL}")
            sys.exit(1)

    except Exception as e:
        print(f"\n[!!!] FATAL: Failed to load/filter scenarios: {e}")
        sys.exit(1)

    # SAFETY GATE
    if args.aggressive or args.force_live_fire:
        if args.env == "production":
             print(f"\n{Fore.RED}" + "#"*60)
             print(" CRITICAL: TARGETING PRODUCTION ENVIRONMENT")
             print(" DESTRUCTIVE MODES ENABLED\n" + "#"*60 + f"{Style.RESET_ALL}\n")
             if not args.force_live_fire:
                  if sys.stdin.isatty():
                      print(f"Type {Fore.RED}'I AUTHORIZE DESTRUCTION'{Style.RESET_ALL} to proceed:")
                      if input().strip() != "I AUTHORIZE DESTRUCTION": sys.exit(1)
                  else: sys.exit(1)
        elif sys.stdin.isatty() and not args.force_live_fire:
            print(f"\n{Fore.RED}" + "!"*60 + "\n WARNING: DESTRUCTIVE MODE ENABLED\n" + "!"*60 + f"{Style.RESET_ALL}")
            print(f"\nType {Fore.RED}'I AUTHORIZE DESTRUCTION'{Style.RESET_ALL} to proceed:")
            if input().strip() != "I AUTHORIZE DESTRUCTION": sys.exit(1)
        print(f"\n{Fore.GREEN}[+] DESTRUCTION AUTHORIZED. UNLEASHING CHAOS...{Style.RESET_ALL}\n")
        logger.log_override_event(mode="AGGRESSIVE", target=args.base_url, env=args.env)

    engine = Engine(
        base_url=args.base_url, forensic_log=logger, 
        verbose=args.verbose, headers=global_headers, 
        simulation=args.simulation, source_path=args.source,
        diff_mode=args.diff, git_range=args.git_range,
        thorough=args.thorough, force_aggressive=args.force
    )
    if args.aggressive:
         for s in scenarios:
            if hasattr(s, 'config'): s.config['aggressive'] = True

    iteration = 0
    while True:
        iteration += 1
        if args.continuous:
             print(f"\n{Fore.YELLOW}=== ITERATION #{iteration} ==={Style.RESET_ALL}")
        try:
            print(f" {Fore.CYAN}[*] TARGET:  {args.base_url}")
            print(f" [!] ENV:     {args.env.upper()}")
            print(f" [*] MODE:    {'SIMULATION' if args.simulation else 'EXECUTION'}")
            print(f" [+] ATTACKS: {len(scenarios)}\n")
            results = engine.run_all(scenarios, concurrency=args.concurrency)
        except Exception as e:
            print(f"\n[!!!] CRITICAL FAILURE: {e}")
            logger.log_event("CRASH", {"error": str(e)})
            sys.exit(1)
        integrity = logger.sign_run()
        reporter = ConsoleReporter()
        reporter.print_summary(results)
        forensic_meta = {"run_id": integrity["run_id"], "final_hash": integrity["final_hash"], "signature": integrity["signature"], "target": args.base_url, "iteration": iteration}
        if args.json_report: generate_json_report(results, args.json_report)
        if args.html_report:
            from .reporting import EliteHTMLReporter
            EliteHTMLReporter(args.base_url).generate_global_report(results, args.html_report)
        if args.sarif_report: SarifReporter(args.sarif_report).generate(results)
        if not args.continuous: break
        if args.interval > 0: import time; time.sleep(args.interval)
    sys.exit(0)

if __name__ == "__main__":
    main()
