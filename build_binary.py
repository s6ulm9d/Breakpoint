import PyInstaller.__main__
import os
import shutil
import sys

def build():
    print("[-] Initializing BREAKPOINT Binary Build...")
    
    # Define hidden imports for dynamic loading in engine.py
    hidden_imports = [
        "breakpoint.attacks.xxe",
        "breakpoint.attacks.sqli",
        "breakpoint.attacks.rce",
        "breakpoint.attacks.web_exploits",
        "breakpoint.attacks.dos_extreme",
        "breakpoint.attacks.cve_classics",
        "breakpoint.attacks.brute",
        "breakpoint.attacks.crlf",
        "breakpoint.reporting.html_reporting",
        "breakpoint.reporting.sarif_reporting",
        "breakpoint.reporting.console_reporting"
    ]
    
    args = [
        "breakpoint/cli.py",       # Entry Point
        "--paths=.",               # Ensure root is in path to find 'breakpoint' package
        "--onefile",               # Single Executable
        "--name=breakpoint",       # Output Name
        "--clean",                 # Clean Cache
        "--noconfirm",             # Overwrite existing
        "--console",               # Console App (No GUI)
        # "--log-level=WARN",      # Reduce noise
    ]
    
    # Append hidden imports
    for hidden in hidden_imports:
        args.append(f"--hidden-import={hidden}")

    print(f"[-] Running PyInstaller with: {' '.join(args)}")
    
    try:
        PyInstaller.__main__.run(args)
        print("\n[+] Build Success!")
        print(f"[+] Binary located at: {os.path.abspath('dist')}")
    except Exception as e:
        print(f"\n[!] Build Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    build()
