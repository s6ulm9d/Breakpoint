import PyInstaller.__main__
import os
import sys

def build():
    # 1. Create temporary entry point in ROOT
    # This ensures 'breakpoint' is treated as a package, resolving all import issues.
    with open("run_breakpoint.py", "w") as f:
        f.write("from breakpoint.cli import main\n")
        f.write("if __name__ == '__main__':\n")
        f.write("    main()\n")
        
    print("[-] Created temporary entry point: run_breakpoint.py")
    
    # 2. Build
    sep = os.pathsep
    args = [
        "run_breakpoint.py",       # USE ROOT ENTRY POINT
        "--onefile",
        "--name=breakpoint",
        "--clean",
        "--noconfirm",
        "--console",
        # Explicitly bundle the default scenarios file into 'breakpoint' folder in bundle
        f"--add-data=breakpoint/default_scenarios.yaml{sep}breakpoint",
        # Use simple hidden imports for known dynamic loaders, but root entry usually fixes most
        "--hidden-import=breakpoint.attacks",
        "--collect-all=breakpoint", # Force collect everything in package
    ]
    
    print(f"[-] Running PyInstaller...")
    try:
        PyInstaller.__main__.run(args)
        print("\n[+] Build Success!")
        print(f"[+] Binary located at: {os.path.abspath('dist')}")
    except Exception as e:
        print(f"[!] Build Failed: {e}")
        sys.exit(1)
    finally:
        # Cleanup
        if os.path.exists("run_breakpoint.py"):
            os.remove("run_breakpoint.py")

if __name__ == "__main__":
    build()
