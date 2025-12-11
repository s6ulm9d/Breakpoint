import sys
import os
import shutil
import subprocess
import ctypes
import time

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def install():
    print("==========================================")
    print("   BREAKPOINT ENTERPRISE INSTALLER")
    print("==========================================")
    
    if not is_admin():
        print("[-] Error: Administrator privileges required.")
        print("    The installer will restart with Admin rights...")
        # Re-run with Admin
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

    target_dir = r"C:\Program Files\BreakPoint"
    target_exe = os.path.join(target_dir, "breakpoint.exe")
    
    # 1. Create Dir
    if not os.path.exists(target_dir):
        try:
            os.makedirs(target_dir)
            print(f"[+] Created directory: {target_dir}")
        except Exception as e:
            print(f"[-] Failed to create directory: {e}")
            input("Press Enter to exit...")
            sys.exit(1)

    # 2. Extract Binary
    print("[*] Installing engine...")
    src = resource_path("breakpoint_embedded.exe") 
    
    if not os.path.exists(src):
        # Fallback for dev mode
        src = "dist/breakpoint.exe" 
        
    if not os.path.exists(src):
        print("[-] Fatal: Installation payload missing.")
        input("Press Enter to exit...")
        sys.exit(1)
        
    try:
        shutil.copy(src, target_exe)
        print(f"[+] Engine installed to {target_exe}")
    except Exception as e:
        print(f"[-] Copy failed: {e}")
        input("Press Enter to exit...")
        sys.exit(1)

    # 3. Update PATH
    print("[*] Configuring environment variables...")
    try:
        ps_check = f'[Environment]::GetEnvironmentVariable("Path", "Machine") -like "*{target_dir}*"'
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_check], capture_output=True, text=True)
        
        if "True" not in res.stdout:
            ps_add = f'[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "Machine") + ";{target_dir}", "Machine")'
            subprocess.run(["powershell", "-NoProfile", "-Command", ps_add], check=True)
            print("[+] System PATH updated.")
        else:
            print("[*] PATH already configured.")
            
    except Exception as e:
        print(f"[-] PATH update failed: {e}")

    print("\n[SUCCESS] Installation Complete.")
    print("You can now open a terminal and run: breakpoint")
    print("Closing in 3 seconds...")
    time.sleep(3)

if __name__ == "__main__":
    try:
        install()
    except Exception as e:
        print(f"Critial Error: {e}")
        input("Error. Press Enter...")
