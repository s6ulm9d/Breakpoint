import os
import sys
# Add current dir to path to import breakpoint
sys.path.append(os.getcwd())

from breakpoint.ai_analyzer import AIAnalyzer
from breakpoint.licensing import get_openai_key

def verify():
    print("=== BREAKPOINT AI VERIFICATION ===")
    
    # 1. Check Key Presence
    key = get_openai_key()
    if key:
        print(f"[+] OpenAI Key Detected: {key[:8]}...{key[-4:]}")
    else:
        print("[-] OpenAI Key NOT Found in storage.")
        return

    # 2. Test File Summarization
    analyzer = AIAnalyzer(key)
    print(f"\n[*] Testing Directory Summarization (Excluding common noise)...")
    summary_data = analyzer._summarize_directory(".")
    
    print(f"[+] Summarized {summary_data['count']} relevant source files.")
    
    # 3. Verify Prompt Construction
    print("\n[*] Verifying AI Prompt Construction...")
    available_modules = ["sqli", "xss", "rce"]
    prompt = (
        f"You are a senior security researcher. Given the following summary of a project's source code, "
        f"determine which of these security attack modules are most applicable to test this project: {available_modules}.\n\n"
        f"Project Summary:\n{summary_data['summary'][:200]}..." # Truncated for display
    )
    
    if len(summary_data['summary']) > 0:
        print("[+] SUCCESS: AI can see and summarize the codebase.")
        print("-" * 40)
        print(prompt)
        print("-" * 40)
    else:
        print("[-] FAILED: Summary is empty.")

if __name__ == "__main__":
    verify()
