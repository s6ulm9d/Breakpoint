from .html_reporting import HtmlReporter
from .sarif_reporting import SarifReporter
from .engine import Engine
from .scenarios import load_scenarios
from .reporting import ConsoleReporter, generate_json_report
from .metadata import get_metadata
from .safety_lock import SafetyLock
from .forensics import ForensicLogger
from .economics import FailureEconomics
import argparse
import sys
import os
import signal

def signal_handler(sig, frame):
    print("\n[!] Force Quitting (Ctrl+C detected)...")
    sys.stdout.flush()
    os._exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    # 1. PREPARE CLI
    parser = argparse.ArgumentParser(
        description="BREAKPOINT // SYSTEM BREAKER",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n  python -m breakpoint --base-url http://target.com --scenarios list.yaml\n  python -m breakpoint --base-url http://target.com --scenarios list.yaml --aggressive --verbose"
    )
    
    parser.add_argument("-v", "--version", action="version", version="BREAKPOINT v2.0.0-ELITE")

    # Target Group
    target_group = parser.add_argument_group("Targeting")
    target_group.add_argument("--base-url", required=True, help="Target URL (e.g., http://localhost:3000)")
    target_group.add_argument("--scenarios", required=True, help="Path to YAML scenarios file")
    target_group.add_argument("--force-live-fire", action="store_true", help="Bypass safety checks for automation")
    
    # Output Group
    out_group = parser.add_argument_group("Reporting")
    out_group.add_argument("--json-report", help="Path to JSON output")
    out_group.add_argument("--html-report", help="Path to HTML Report") 
    out_group.add_argument("--sarif-report", help="Path to SARIF output")
    
    # Config Group
    conf_group = parser.add_argument_group("Configuration")
    conf_group.add_argument("--concurrency", type=int, default=None, help="Number of concurrent threads (Default: 5, or 20 in Aggressive)")
    conf_group.add_argument("--aggressive", action="store_true", help="Enable AGGRESSIVE mode (Higher rates, heavier payloads)")
    conf_group.add_argument("--verbose", action="store_true", help="Show raw network traffic")
    conf_group.add_argument("--continuous", action="store_true", help="Run in continuous loop mode (Infinite)")
    conf_group.add_argument("--interval", type=int, default=0, help="Seconds to wait between iterations in continuous mode")
    
    args = parser.parse_args()

    # Smart Defaults
    if args.concurrency is None:
        args.concurrency = 20 if args.aggressive else 5

    from colorama import Fore, Style, init
    init(autoreset=True)
    
    BANNER = r"""
  ____  _____  ______          _   _  __ _____   ____  _____ _   _ _______ 
 |  _ \|  __ \|  ____|   /\   | |/ /|  __ \ / __ \|_   _| \ | |__   __|
 | |_) | |__) | |__     /  \  | ' / | |__) | |  | | | | |  \| |  | |   
 |  _ <|  _  /|  __|   / /\ \ |  <  |  ___/| |  | | | | | . ` |  | |   
 | |_) | | \ \| |____ / ____ \| . \ | |    | |__| |_| |_| |\  |  | |   
 |____/|_|  \_\______/_/    \_\_|\_\|_|     \____/|_____|_| \_|  |_|   
    """
    print(f"{Fore.RED}{BANNER}")
    print(f"{Fore.RED}   BREAKPOINT — WEAPONIZED RESILIENCE ENGINE")
    print(f"{Fore.RED}       \"Production is already broken.\"{Style.RESET_ALL}\n")

    # 1. LOCK & CONSENT (DISABLED BY USER REQUEST)
    # lock = SafetyLock(args.base_url)
    # lock.check_kill_switch()
    # lock.require_consent(args.force_live_fire)
    
    # 2. INITIALIZE FORENSICS
    logger = ForensicLogger()
    print(f"[*] Forensic Audit Log Initialized: {logger.log_file}")
    
    try:
        scenarios = load_scenarios(args.scenarios)
    except Exception as e:
        print(f"\n[!!!] FATAL: Failed to load scenarios from '{args.scenarios}': {e}")
        sys.exit(1)

    engine = Engine(base_url=args.base_url, forensic_log=logger, verbose=args.verbose)
    
    if args.aggressive:
        print("[!!!] AGGRESSIVE MODE ENABLED. SCALING PAYLOADS.")
        for s in scenarios:
            if hasattr(s, 'config'):
                s.config['aggressive'] = True

    iteration = 0
    while True:
        iteration += 1
        if args.continuous:
             print(f"\n{Fore.YELLOW}==========================================")
             print(f"[*] CONTINUOUS MODE: STARTING ITERATION #{iteration}")
             print(f"=========================================={Style.RESET_ALL}")
             
        try:
            print(f"[*] TARGET ACQUIRED: {args.base_url}")
            print(f"[*] PAYLOADS LOADED: {len(scenarios)}")
            print(f"[*] MODE: {'AGGRESSIVE' if args.aggressive else 'STANDARD'} (Concurrency: {args.concurrency})")
            print("[*] EXECUTING...")
            
            results = engine.run_all(scenarios, concurrency=args.concurrency)
            
        except Exception as e:
            print(f"\n[!!!] CRITICAL ENGINE FAILURE: {e}")
            logger.log_event("ENGINE_CRASH", {"error": str(e)})
            if not args.continuous:
                sys.exit(1)

        # 4. DAMAGE ASSESSMENT
        econ = FailureEconomics()
        damage = econ.calculate_impact(results)
        
        # 5. SEAL THE LOGS (Incremental update in continuous mode)
        # We don't close the log file effectively, just sign current state
        integrity = logger.sign_run()
        
        # 6. REPORT
        reporter = ConsoleReporter()
        reporter.print_summary(results)
        
        forensic_meta = {
            "run_id": integrity["run_id"], 
            "final_hash": integrity["final_hash"], 
            "signature": integrity["signature"], 
            "target": args.base_url,
            "iteration": iteration
        }

        if args.json_report: 
            generate_json_report(results, args.json_report)
            
        if args.html_report:
            # One Single Comprehensive Report
            print(f"Generating Report: {args.html_report}")
            HtmlReporter(args.html_report).generate(results, damage, forensic_meta)

        if args.sarif_report: 
            SarifReporter(args.sarif_report).generate(results)
        
        if not args.continuous:
            break
            
        import time
        if args.interval > 0:
            print(f"[*] Sleeping for {args.interval}s...")
            time.sleep(args.interval)

    sys.exit(0)

if __name__ == "__main__":
    main()
