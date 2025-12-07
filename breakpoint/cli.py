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

def main():
    parser = argparse.ArgumentParser(description="BREAKPOINT // SYSTEM BREAKER")
    
    # Modes
    parser.add_argument("--base-url", help="Target URL")
    parser.add_argument("--scenarios", help="Path to YAML scenarios")
    parser.add_argument("--force-live-fire", action="store_true", help="Attempt automation (Disabled in code)")
    
    # Reports
    parser.add_argument("--json-report", help="Output JSON findings")
    parser.add_argument("--html-report", help="Output Comprehensive HTML Report") 
    parser.add_argument("--sarif-report", help="Output SARIF")
    
    args = parser.parse_args()
    
    if not args.base_url or not args.scenarios:
        print("ERROR: Missing target arguments.")
        sys.exit(1)

    # 1. LOCK & CONSENT
    lock = SafetyLock(args.base_url)
    lock.check_kill_switch()
    lock.require_consent(args.force_live_fire)
    
    # 2. INITIALIZE FORENSICS
    logger = ForensicLogger()
    print(f"[*] Forensic Audit Log Initialized: {logger.log_file}")
    
    # 3. EXECUTE
    try:
        scenarios = load_scenarios(args.scenarios)
        engine = Engine(base_url=args.base_url, forensic_log=logger)
        
        print(f"[*] TARGET ACQUIRED: {args.base_url}")
        print(f"[*] PAYLOADS LOADED: {len(scenarios)}")
        print("[*] EXECUTING...")
        
        results = engine.run_all(scenarios)
        
    except Exception as e:
        print(f"\n[!!!] CRITICAL ENGINE FAILURE: {e}")
        logger.log_event("ENGINE_CRASH", {"error": str(e)})
        sys.exit(1)

    # 4. DAMAGE ASSESSMENT
    econ = FailureEconomics()
    damage = econ.calculate_impact(results)
    
    # 5. SEAL THE LOGS
    integrity = logger.sign_run()
    
    # 6. REPORT
    reporter = ConsoleReporter()
    reporter.print_summary(results)
    
    forensic_meta = {
        "run_id": integrity["run_id"], 
        "final_hash": integrity["final_hash"], 
        "signature": integrity["signature"], 
        "target": args.base_url
    }

    if args.json_report: 
        generate_json_report(results, args.json_report)
        
    if args.html_report:
        # One Single Comprehensive Report
        print(f"Generating Report: {args.html_report}")
        HtmlReporter(args.html_report).generate(results, damage, forensic_meta)

    if args.sarif_report: 
        SarifReporter(args.sarif_report).generate(results)
    
    sys.exit(0)

if __name__ == "__main__":
    main()
