from breakpoint.html_reporting import HtmlReporter
from breakpoint.sarif_reporting import SarifReporter
from breakpoint.engine import Engine
from breakpoint.scenarios import load_scenarios
from breakpoint.reporting import ConsoleReporter, generate_json_report
from breakpoint.metadata import get_metadata
from breakpoint.safety_lock import SafetyLock
from breakpoint.forensics import ForensicLogger
from breakpoint.economics import FailureEconomics
from breakpoint.licensing import check_access, get_denial_message, get_license_tier
import argparse
import sys
import os
import signal
import shutil
import datetime
import subprocess
import requests
from colorama import Fore, Style, init

def signal_handler(sig, frame):
    print("\n[!] Force Quitting (Ctrl+C detected)...")
    sys.stdout.flush()
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
    """Resolves path to embedded default_scenarios.yaml"""
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
        return os.path.join(base_path, 'breakpoint', 'default_scenarios.yaml')
    else:
        return os.path.join(os.path.dirname(__file__), 'default_scenarios.yaml')

def handle_update():
    print("[*] Checking for updates...")
    repo = "soulmad/breakpoint"
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            latest = data.get("tag_name", "Unknown")
            current = "2.6.3-ELITE"
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

def main():
    init(autoreset=True)
    
    # 1. ROBUST SHORTHAND & COMMAND HANDLING
    # This handles "update", "scan <url>", "<url>", and even common mistakes like "--http..."
    if len(sys.argv) > 1:
        # Handle update first to avoid required args
        if sys.argv[1] == "update" or "--update" in sys.argv:
            handle_update()

        # Iterate and fix shorthand/mistakes
        for i in range(1, len(sys.argv)):
            arg = sys.argv[i]
            # Handle shorthand URL (starts with http or --http)
            if arg.startswith("http") or arg.startswith("--http"):
                # Clean up if they used --http...
                clean_url = arg.lstrip('-')
                # Only insert if --base-url isn't already there
                if "--base-url" not in sys.argv:
                    sys.argv[i] = clean_url
                    sys.argv.insert(i, "--base-url")
                else:
                    sys.argv[i] = clean_url
                break
            
            # Handle "scan <url>"
            if arg == "scan" and i + 1 < len(sys.argv):
                sys.argv[i] = "--base-url"
                break

    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="BREAKPOINT // SYSTEM BREAKER",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("-v", "--version", action="version", version="BREAKPOINT v2.6.3-ELITE")
    parser.add_argument("--update", action="store_true", help="Check for updates")
    
    target_group = parser.add_argument_group("Targeting")
    target_group.add_argument("--base-url", help="Target URL")
    target_group.add_argument("--scenarios", help="Path to YAML scenarios file")
    target_group.add_argument("--force-live-fire", action="store_true", help="Bypass safety checks")
    
    out_group = parser.add_argument_group("Reporting")
    out_group.add_argument("--json-report", help="Path to JSON output")
    out_group.add_argument("--html-report", help="Path to HTML Report") 
    out_group.add_argument("--sarif-report", help="Path to SARIF output")
    
    conf_group = parser.add_argument_group("Configuration")
    conf_group.add_argument("--env", required=True, choices=["dev", "staging", "production"], help="Operational Environment (Mandatory)")
    conf_group.add_argument("--simulation", action="store_true", help="Run in Impact Simulation mode")
    conf_group.add_argument("--concurrency", type=int, default=None)
    conf_group.add_argument("--aggressive", action="store_true")
    conf_group.add_argument("--verbose", action="store_true")
    conf_group.add_argument("--continuous", action="store_true")
    conf_group.add_argument("--interval", type=int, default=0)
    parser.add_argument("--license-key", help="Specify subscription key (Alternative to BREAKPOINT_LICENSE_KEY env)")
    parser.add_argument("--headers", action="append", help="Global headers (Key:Value)")
    
    args, unknown = parser.parse_known_args()

    # Handle license key flag
    if args.license_key:
        os.environ["BREAKPOINT_LICENSE_KEY"] = args.license_key

    if unknown:
        print(f"[!] Error: Unknown arguments detected: {unknown}")
        if any("BRK-" in u for u in unknown):
             print("[!] Tip: It looks like you're trying to pass a license key directly. Use '--license-key <KEY>' instead.")
        sys.exit(1)

    if not args.base_url:
        parser.print_help()
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
    from breakpoint.legal import has_accepted_eula, prompt_eula
    if not has_accepted_eula():
        if not prompt_eula():
            sys.exit(1)

    # Defaults
    if args.concurrency is None:
        args.concurrency = 200 if args.aggressive else 50
        
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
    print(f"{Fore.RED}   BREAKPOINT — WEAPONIZED RESILIENCE ENGINE")
    print(f"{Fore.RED}       \"Production is already broken.\"{Style.RESET_ALL}\n")

    tier = get_license_tier()
    print(f"[*] LICENSE: {tier} EDITION")

    logger = ForensicLogger()
    print(f"[*] Forensic Audit Log Initialized: {logger.log_file}")
    
    # Scenarios Logic
    # 0. AUTO-INIT WORKSPACE (Silent)
    app_data = get_app_data_dir()
    config_path = os.path.join(app_data, "default_scenarios.yaml")
    
    try:
        src = get_default_scenarios_path()
        if os.path.exists(src):
            shutil.copy(src, config_path)
    except Exception:
        pass

    scenarios_path = args.scenarios
    if not scenarios_path:
        app_cfg = os.path.join(get_app_data_dir(), "default_scenarios.yaml")
        scenarios_path = app_cfg if os.path.exists(app_cfg) else get_default_scenarios_path()

    try:
        scenarios = load_scenarios(scenarios_path)
    except Exception as e:
        print(f"\n[!!!] FATAL: Failed to load scenarios: {e}")
        sys.exit(1)

    # SAFETY GATE
    if args.aggressive or args.force_live_fire:
        if args.env == "production":
             print(f"\n{Fore.RED}" + "#"*60)
             print(" CRITICAL: TARGETING PRODUCTION ENVIRONMENT")
             print(" DESTRUCTIVE MODES ENABLED")
             print(" ############################################################")
             print(" You are about to unleash aggressive attacks against a PRODUCTION system.")
             print(" #"*60 + f"{Style.RESET_ALL}\n")
             
             if not args.force_live_fire:
                  if sys.stdin.isatty():
                      print(f"Type {Fore.RED}'I AUTHORIZE DESTRUCTION'{Style.RESET_ALL} to proceed:")
                      if input().strip() != "I AUTHORIZE DESTRUCTION":
                         sys.exit(1)
                  else:
                      sys.exit(1)

        elif sys.stdin.isatty() and not args.force_live_fire:
            print(f"\n{Fore.RED}" + "!"*60)
            print(" WARNING: DESTRUCTIVE MODE ENABLED")
            print("!"*60 + f"{Style.RESET_ALL}")
            print(f"\nType {Fore.RED}'I AUTHORIZE DESTRUCTION'{Style.RESET_ALL} to proceed:")
            if input().strip() != "I AUTHORIZE DESTRUCTION":
                sys.exit(1)

        print(f"\n{Fore.GREEN}[+] DESTRUCTION AUTHORIZED. UNLEASHING CHAOS...{Style.RESET_ALL}\n")
        logger.log_override_event(mode="AGGRESSIVE", target=args.base_url, env=args.env)

    engine = Engine(base_url=args.base_url, forensic_log=logger, verbose=args.verbose, headers=global_headers, simulation=args.simulation)
    
    if args.aggressive:
         for s in scenarios:
            if hasattr(s, 'config'):
                s.config['aggressive'] = True

    iteration = 0
    while True:
        iteration += 1
        if args.continuous:
             print(f"\n{Fore.YELLOW}=== ITERATION #{iteration} ==={Style.RESET_ALL}")
             
        try:
            print(f"[*] TARGET: {args.base_url}")
            print(f"[*] ENV: {args.env.upper()}")
            print(f"[*] MODE: {'SIMULATION' if args.simulation else 'EXECUTION'}")
            print(f"[*] PAYLOADS: {len(scenarios)}")
            
            results = engine.run_all(scenarios, concurrency=args.concurrency)
            
        except Exception as e:
            print(f"\n[!!!] CRITICAL FAILURE: {e}")
            logger.log_event("CRASH", {"error": str(e)})
            sys.exit(1)

        econ = FailureEconomics()
        damage = econ.calculate_impact(results)
        integrity = logger.sign_run()
        
        reporter = ConsoleReporter()
        reporter.print_summary(results)
        
        forensic_meta = {"run_id": integrity["run_id"], "final_hash": integrity["final_hash"], "signature": integrity["signature"], "target": args.base_url, "iteration": iteration}

        if args.json_report: generate_json_report(results, args.json_report)
        if args.html_report: HtmlReporter(args.html_report).generate(results, damage, forensic_meta)
        if args.sarif_report: SarifReporter(args.sarif_report).generate(results)
        
        if not args.continuous: break
        
        import time
        if args.interval > 0: time.sleep(args.interval)

    sys.exit(0)

if __name__ == "__main__":
    main()
