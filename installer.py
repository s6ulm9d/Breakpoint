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
        # Check Machine Path
        ps_check_machine = f'[Environment]::GetEnvironmentVariable("Path", "Machine") -like "*{target_dir}*"'
        res_machine = subprocess.run(["powershell", "-NoProfile", "-Command", ps_check_machine], capture_output=True, text=True)
        
        if "True" not in res_machine.stdout:
            ps_add_machine = f'[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "Machine") + ";{target_dir}", "Machine")'
            subprocess.run(["powershell", "-NoProfile", "-Command", ps_add_machine], check=True)
            print("[+] System PATH updated.")
        
        # Check User Path
        ps_check_user = f'[Environment]::GetEnvironmentVariable("Path", "User") -like "*{target_dir}*"'
        res_user = subprocess.run(["powershell", "-NoProfile", "-Command", ps_check_user], capture_output=True, text=True)
        
        if "True" not in res_user.stdout:
            ps_add_user = f'[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";{target_dir}", "User")'
            subprocess.run(["powershell", "-NoProfile", "-Command", ps_add_user], check=True)
            print("[+] User PATH updated.")
            
    except Exception as e:
        print(f"[-] PATH update failed: {e}")

    print("\n[SUCCESS] Installation Complete.")
    print("-" * 50)
    print("IMPORTANT: To use 'breakpoint' in the current terminal, run:")
    print('  $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")')
    print("Or simply open a new terminal window.")
    print("-" * 50)
    print("Closing in 3 seconds...")
    time.sleep(3)

if __name__ == "__main__":
    try:
        install()
    except Exception as e:
        print(f"Critial Error: {e}")
        input("Error. Press Enter...")
