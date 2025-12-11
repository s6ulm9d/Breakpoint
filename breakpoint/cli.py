from breakpoint.html_reporting import HtmlReporter
from breakpoint.sarif_reporting import SarifReporter
from breakpoint.engine import Engine
from breakpoint.scenarios import load_scenarios
from breakpoint.reporting import ConsoleReporter, generate_json_report
from breakpoint.metadata import get_metadata
from breakpoint.safety_lock import SafetyLock
from breakpoint.forensics import ForensicLogger
from breakpoint.economics import FailureEconomics
from breakpoint.licensing import get_license_status, save_license
import argparse
import sys
import os
import signal
import shutil
import datetime

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

def main():
    # 0. AUTO-INIT WORKSPACE (Silent)
    app_data = get_app_data_dir()
    config_path = os.path.join(app_data, "default_scenarios.yaml")
    
    if not os.path.exists(config_path):
        try:
            src = get_default_scenarios_path()
            if os.path.exists(src):
                shutil.copy(src, config_path)
        except:
            pass

    # 1. ARGUMENT MAGIC
    if len(sys.argv) > 1:
        # Handle "update" command or "--update" flag
        if sys.argv[1] == "update" or "--update" in sys.argv:
             print("[*] Checking for updates...")
             print("[*] Channel: https://github.com/soulmad/breakpoint/releases")
             
             # Attempt Git Pull first (In-Place Update)
             is_git = os.path.exists(os.path.join(os.getcwd(), ".git"))
             if is_git:
                 print("[*] Git repository detected. Attempting in-place update...")
                 try:
                     import subprocess
                     # Check connection first by fetching
                     subprocess.check_call(["git", "fetch"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                     # Pull logic
                     result = subprocess.run(["git", "pull"], capture_output=True, text=True)
                     if result.returncode == 0:
                         if "Already up to date" in result.stdout:
                             print(f"[+] You are already up to date (v2.5.1-ELITE).")
                         else:
                             print(f"[+] Successfully updated to latest version.")
                             print(f"    {result.stdout.strip()}")
                     else:
                         print(f"[-] Update failed: {result.stderr}")
                 except Exception as e:
                     print(f"[-] Auto-update failed: {e}")
                 sys.exit(0)

             # Fallback to API check for binary/non-git users
             try:
                 import requests
                 repo = "soulmad/breakpoint"
                 url = f"https://api.github.com/repos/{repo}/releases/latest"
                 resp = requests.get(url, timeout=5)
                 if resp.status_code == 200:
                    data = resp.json()
                    latest = data.get("tag_name", "Unknown")
                    print(f"[+] Latest Version: {latest}")
                    print(f"[+] Current Version: 2.5.1-ELITE")
                    if latest != "Unknown" and latest != "2.5.1-ELITE":
                         print(f"[!] Update Available! Download at: {data.get('html_url')}")
                    else:
                         print("[+] You are up to date.")
             except Exception as e:
                print(f"[!] Update Check Failed: {e}")
             sys.exit(0)
             
        # Handle "register"
        if sys.argv[1] == "register":
             if len(sys.argv) < 3:
                 print("Usage: breakpoint register <KEY>")
                 sys.exit(1)
             key = sys.argv[2]
             try:
                 save_license(key)
                 print(f"[+] License Activated: {key}")
             except Exception as e:
                 print(f"[-] Activation Failed: {e}")
             sys.exit(0)

        # Handle "scan URL" or "URL"
        if sys.argv[1].startswith("http"):
            sys.argv.insert(1, "--base-url")
        elif sys.argv[1] == "scan" and len(sys.argv) > 2:
            sys.argv[1] = "--base-url"
        elif sys.argv[1] == "scan":
             # Just "scan" without url?
             pass

    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="BREAKPOINT // SYSTEM BREAKER",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("-v", "--version", action="version", version="BREAKPOINT v2.5.1-ELITE")
    parser.add_argument("--update", action="store_true", help="Update the tool in-place")
    
    target_group = parser.add_argument_group("Targeting")
    target_group.add_argument("--base-url", help="Target URL (e.g., http://localhost:3000)")
    target_group.add_argument("--scenarios", help="Path to YAML scenarios file")
    target_group.add_argument("--force-live-fire", action="store_true", help="Bypass safety checks")
    
    out_group = parser.add_argument_group("Reporting")
    out_group.add_argument("--json-report", help="Path to JSON output")
    out_group.add_argument("--html-report", help="Path to HTML Report") 
    out_group.add_argument("--sarif-report", help="Path to SARIF output")
    
    conf_group = parser.add_argument_group("Configuration")
    conf_group.add_argument("--concurrency", type=int, default=None)
    conf_group.add_argument("--aggressive", action="store_true")
    conf_group.add_argument("--verbose", action="store_true")
    conf_group.add_argument("--continuous", action="store_true")
    conf_group.add_argument("--interval", type=int, default=0)
    
    # Catch known commands to prevent error
    args, unknown = parser.parse_known_args()

    if unknown:
        print(f"[!] Error: Unknown arguments detected: {unknown}")
        print("    Please check the command properly.")
        sys.exit(1)
    
    # If using "init" manually (depreciated but safe to ignore)
    if "init" in sys.argv:
        print("[*] Workspace is auto-managed. Initialization complete.")
        sys.exit(0)

    # Require URL manually if not passed
    if not args.base_url:
        parser.print_help()
        sys.exit(1)

    # Defaults
    if args.concurrency is None:
        args.concurrency = 20 if args.aggressive else 5

    # Report Path Default
    if not args.html_report and not args.json_report and not args.sarif_report:
        try:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            reports_dir = get_reports_dir()
            args.html_report = os.path.join(reports_dir, f"audit_{ts}.html")
            print(f"[*] Report will be saved to: {args.html_report}")
        except:
            pass

    from colorama import Fore, Style, init
    init(autoreset=True)
    
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

    license_type = get_license_status()
    print(f"[*] LICENSE: {license_type} EDITION")

    logger = ForensicLogger()
    print(f"[*] Forensic Audit Log Initialized: {logger.log_file}")
    
    # Scenarios Logic
    scenarios_path = args.scenarios
    if not scenarios_path:
        # Check AppData first
        app_cfg = os.path.join(get_app_data_dir(), "default_scenarios.yaml")
        if os.path.exists(app_cfg):
             scenarios_path = app_cfg
        else:
             scenarios_path = get_default_scenarios_path()

    try:
        scenarios = load_scenarios(scenarios_path)
    except Exception as e:
        print(f"\n[!!!] FATAL: Failed to load scenarios: {e}")
        sys.exit(1)

    engine = Engine(base_url=args.base_url, forensic_log=logger, verbose=args.verbose)
    
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
            print(f"[*] PAYLOADS: {len(scenarios)}")
            print("[*] EXECUTING...")
            
            results = engine.run_all(scenarios, concurrency=args.concurrency)
            
        except Exception as e:
            print(f"\n[!!!] CRITICAL FAILURE: {e}")
            logger.log_event("CRASH", {"error": str(e)})
            if not args.continuous: sys.exit(1)

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
