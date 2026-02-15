import json
import sys
from colorama import Fore, Style, init

init(autoreset=True)

class ConsoleReporter:
    def print_summary(self, results):
        print("\n" + "="*60)
        print("BREAKPOINT AUDIT SUMMARY")
        print("="*60)
        
        passed = [r for r in results if r.status in ["SECURE", "PASSED"]]
        vulnerable = [r for r in results if r.status in ["VULNERABLE", "CONFIRMED"]]
        suspect = [r for r in results if r.status == "SUSPECT"]
        skipped = [r for r in results if r.status in ["SKIPPED", "INCONCLUSIVE", "SIMULATED"]]
        blocked = [r for r in results if r.status in ["BLOCKED", "WAF_INTERCEPTED"]]
        errors = [r for r in results if r.status in ["ERROR", "PROXY_FAILURE"]]
        
        print(f"Total Checks: {len(results)}")
        print(f"PASSED:   {Fore.GREEN}{len(passed)}{Style.RESET_ALL}")
        print(f"SUSPECT:  {Fore.CYAN}{len(suspect)}{Style.RESET_ALL}")
        print(f"BLOCKED:  {Fore.YELLOW}{len(blocked)}{Style.RESET_ALL}")
        print(f"SKIPPED:  {Fore.WHITE}{len(skipped)}{Style.RESET_ALL}")
        print(f"ERRORS:   {Fore.MAGENTA}{len(errors)}{Style.RESET_ALL}")
        print(f"FAILED:   {Fore.RED}{len(vulnerable)}{Style.RESET_ALL} (Confirmed Vulnerabilities)")
        
        if vulnerable:
            print("\n[!] CRITICAL FINDINGS:")
            for f in vulnerable:
                 # Clean details
                 d = str(f.details)[:100].replace('\n', ' ')
                 print(f" - {Fore.RED}[{f.type}]{Style.RESET_ALL} {d}...")
        
        if blocked:
             print(f"\n{Fore.YELLOW}[!] NOTE: {len(blocked)} checks were BLOCKED by the target (429/403).{Style.RESET_ALL}")
        
        print("="*60 + "\n")

def generate_json_report(results, filename):
    data = [
        {
            "id": r.id,
            "type": r.type,
            "status": r.status,
            "severity": r.severity,
            "details": r.details
        }
        for r in results
    ]
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"JSON Report written to: {filename}")
