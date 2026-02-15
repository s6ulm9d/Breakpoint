"""
Comprehensive Breakpoint Testing Script
Tests both vulnerable apps with multiple scenarios
"""

import subprocess
import time
import os
import sys
from datetime import datetime

def print_header(text):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70 + "\n")

def run_command(cmd, description):
    print(f"[*] {description}")
    print(f"    Command: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result

def start_app(script, port, name):
    print(f"[*] Starting {name} on port {port}...")
    proc = subprocess.Popen([sys.executable, script], 
                           stdout=subprocess.PIPE, 
                           stderr=subprocess.PIPE)
    time.sleep(3)  # Wait for app to start
    return proc

def stop_app(proc, name):
    print(f"[*] Stopping {name}...")
    proc.terminate()
    proc.wait()

def main():
    print_header("BREAKPOINT COMPREHENSIVE TESTING")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Test scenarios
    scenarios = [
        {
            "name": "E-commerce API (Port 5001)",
            "script": "test_targets/vuln_ecommerce.py",
            "url": "http://127.0.0.1:5001/",
            "port": 5001,
            "expected_vulns": ["sql_injection", "jwt_weakness", "idor", "xss", "header_security"]
        },
        {
            "name": "Blog Platform (Port 5002)",
            "script": "test_targets/vuln_blog.py",
            "url": "http://127.0.0.1:5002/",
            "port": 5002,
            "expected_vulns": ["ssrf", "rce", "open_redirect", "lfi", "git_exposure", "debug_exposure"]
        }
    ]
    
    results = []
    
    for scenario in scenarios:
        print_header(f"TESTING: {scenario['name']}")
        
        # Start the vulnerable app
        app_proc = start_app(scenario['script'], scenario['port'], scenario['name'])
        
        try:
            # Test 1: Basic scan
            print_header("Test 1: Basic Scan (Default Settings)")
            cmd = f".venv\\Scripts\\python -m breakpoint {scenario['url']} --env dev"
            result = run_command(cmd, "Running basic scan")
            
            test_result = {
                "scenario": scenario['name'],
                "test": "Basic Scan",
                "output": result.stdout + result.stderr,
                "return_code": result.returncode
            }
            results.append(test_result)
            
            # Save output
            output_file = f"test_results_{scenario['port']}_basic.txt"
            with open(output_file, 'w') as f:
                f.write(test_result['output'])
            print(f"    Output saved to: {output_file}")
            
            # Test 2: Verbose scan
            print_header("Test 2: Verbose Scan (All Features)")
            cmd = f".venv\\Scripts\\python -m breakpoint {scenario['url']} --env dev --verbose"
            result = run_command(cmd, "Running verbose scan")
            
            test_result = {
                "scenario": scenario['name'],
                "test": "Verbose Scan",
                "output": result.stdout + result.stderr,
                "return_code": result.returncode
            }
            results.append(test_result)
            
            # Save output
            output_file = f"test_results_{scenario['port']}_verbose.txt"
            with open(output_file, 'w') as f:
                f.write(test_result['output'])
            print(f"    Output saved to: {output_file}")
            
            # Test 3: Thorough scan
            print_header("Test 3: Thorough Scan (Maximum Coverage)")
            cmd = f".venv\\Scripts\\python -m breakpoint {scenario['url']} --env dev --thorough --verbose"
            result = run_command(cmd, "Running thorough scan")
            
            test_result = {
                "scenario": scenario['name'],
                "test": "Thorough Scan",
                "output": result.stdout + result.stderr,
                "return_code": result.returncode
            }
            results.append(test_result)
            
            # Save output
            output_file = f"test_results_{scenario['port']}_thorough.txt"
            with open(output_file, 'w') as f:
                f.write(test_result['output'])
            print(f"    Output saved to: {output_file}")
            
        finally:
            # Stop the app
            stop_app(app_proc, scenario['name'])
            time.sleep(2)
    
    # Generate summary report
    print_header("TEST SUMMARY")
    
    for result in results:
        print(f"\n{result['scenario']} - {result['test']}")
        print(f"  Return Code: {result['return_code']}")
        
        # Count findings
        output = result['output']
        confirmed = output.count('CONFIRMED')
        vulnerable = output.count('VULNERABLE')
        errors = output.count('ERROR')
        skipped = output.count('SKIPPED')
        
        print(f"  CONFIRMED: {confirmed}")
        print(f"  VULNERABLE: {vulnerable}")
        print(f"  ERRORS: {errors}")
        print(f"  SKIPPED: {skipped}")
        
        # Check for advanced features
        if 'OOB Service: ENABLED' in output:
            print(f"  ✅ OOB Service Active")
        if 'Adaptive Throttling: ENABLED' in output:
            print(f"  ✅ Adaptive Throttling Active")
        if 'Attack Graph: ENABLED' in output:
            print(f"  ✅ Attack Graph Active")
        if 'EXPLOITATION PATHS' in output:
            print(f"  ✅ Exploitation Paths Generated")
        if 'Target Stability Report' in output:
            print(f"  ✅ Stability Report Generated")
    
    print_header("TESTING COMPLETE")
    print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\nTotal Tests Run: {len(results)}")
    print(f"Output Files: test_results_*.txt")

if __name__ == '__main__':
    main()
