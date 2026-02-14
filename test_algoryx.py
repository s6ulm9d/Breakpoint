import os
import sys
import json
# Add current dir to path to import breakpoint
sys.path.append(os.getcwd())

from breakpoint.ai_analyzer import AIAnalyzer
from breakpoint.licensing import get_openai_key

def test_algoryx_analysis():
    path = r"C:\Users\soulmad\projects\Algoryx"
    print(f"=== TESTING AI ANALYSIS FOR: {path} ===")
    
    if not os.path.exists(path):
        print(f"[-] ERROR: Path {path} does not exist or is inaccessible.")
        return

    analyzer = AIAnalyzer()
    
    # 1. Test Summarization
    print(f"[*] Analyzing project footprint...")
    summary_data = analyzer._summarize_directory(path)
    
    print(f"[+] AI summarized {summary_data['count']} relevant source files from Algoryx.")
    print("\n--- CODEBASE SUMMARY (First 500 chars) ---")
    print(summary_data['summary'][:500] + "...")
    print("-" * 40)
    
    # 2. Show Prompt
    available_modules = ["sql_injection", "broken_auth", "rce", "xss", "ssrf"]
    prompt = (
        f"You are a senior security researcher. Given the following summary of a project's source code, "
        f"determine which of these security attack modules are most applicable to test this project: {available_modules}.\n\n"
        f"Project Summary:\n{summary_data['summary']}\n\n"
        f"Respond with ONLY a JSON list of module IDs that should be enabled. "
        f"Explain nothing else."
    )
    
    print("\n[*] GENERATED PROMPT:")
    # We won't print the whole prompt here to avoid cluttering, but let's confirm it's ready.
    print(f"[+] Prompt Length: {len(prompt)} characters.")
    print("[+] Status: READY FOR AI SUBMISSION.")

if __name__ == "__main__":
    test_algoryx_analysis()
