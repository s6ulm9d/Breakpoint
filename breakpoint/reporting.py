import json
import sys
from typing import List, Dict, Any
from colorama import init, Fore, Style

init()

class ConsoleReporter:
    def print_summary(self, results: List[Dict[str, Any]]):
        print(f"\n{Style.BRIGHT}=== ATTACK SIMULATION REPORT ==={Style.RESET_ALL}\n")
        
        passed_count = 0
        total = len(results)
        
        for res in results:
            s_id = res.get("scenario_id", "unknown")
            passed = res.get("passed", False)
            p_str = f"{Fore.GREEN}PASS{Style.RESET_ALL}" if passed else f"{Fore.RED}FAIL{Style.RESET_ALL}"
            is_flow = res.get("flow", False)
            type_label = "FLOW" if is_flow else res.get("attack_type", "simple")
            
            print(f"[{p_str}] {s_id} ({type_label})")
            
            if not passed:
                details = res.get("details", {})
                if isinstance(details, dict):
                    # Simple attack details
                    issues = details.get("issues", [])
                    if issues:
                        for i in issues:
                            print(f"      {Fore.YELLOW}- {i}{Style.RESET_ALL}")
                    elif "error" in details:
                        print(f"      {Fore.RED}Error: {details['error']}{Style.RESET_ALL}")
                    # Traffic specific
                    if "success_rate_percent" in details:
                         print(f"      Stats: Success {details.get('success_rate_percent')}%")

                elif isinstance(details, str):
                    print(f"      {details}")
                    
                # Flow details
                assertions = res.get("assertions", [])
                for a in assertions:
                    if not a.get("passed"):
                        print(f"      {Fore.RED}Assertion Failed: {a.get('name')} - {a.get('msg')}{Style.RESET_ALL}")

            if passed:
                passed_count += 1

        score = (passed_count / total * 100) if total > 0 else 0.0
        print(f"\n{Style.BRIGHT}Overall Resilience Score: {score:.1f}%{Style.RESET_ALL}")
        print(f"Passed: {passed_count}/{total}")

def generate_json_report(results: List[Dict[str, Any]], output_path: str):
    passed = sum(1 for r in results if r.get("passed"))
    total = len(results)
    
    report = {
        "summary": {
            "total": total,
            "passed": passed,
            "score": (passed / total * 100) if total > 0 else 0.0
        },
        "results": results
    }
    
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\nJSON Report written to: {output_path}")
    except Exception as e:
        print(f"{Fore.RED}Failed to write JSON report: {e}{Style.RESET_ALL}")
