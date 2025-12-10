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
        failed = [r for r in results if r.status not in ["SECURE", "PASSED"]]
        
        print(f"Total Checks: {len(results)}")
        print(f"PASSED: {Fore.GREEN}{len(passed)}{Style.RESET_ALL}")
        print(f"FAILED: {Fore.RED}{len(failed)}{Style.RESET_ALL}")
        
        if failed:
            print("\n[!] CRITICAL FINDINGS:")
            for f in failed:
                print(f" - [{f.type}] {f.details}")
        
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
