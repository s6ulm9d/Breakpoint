import PyInstaller.__main__
import shutil
import os

print("[*] Building Breakpoint Engine...")

# 1. Build Core Engine
# We use ; for Windows separator in add-data
PyInstaller.__main__.run([
    'breakpoint/cli.py',
    '--name', 'breakpoint',
    '--onefile',
    '--add-data', 'breakpoint/default_scenarios.yaml;breakpoint',
    '--hidden-import', 'breakpoint',
    '--clean',
    '--log-level', 'WARN',
    '--distpath', 'dist',
    '-y'
])

# 2. Rename for Embedding
# Check dist root
if os.path.exists('dist/breakpoint.exe'):
    src_exe = 'dist/breakpoint.exe'
    embed_exe = 'dist/breakpoint_embedded.exe'
    
    if os.path.exists(embed_exe):
        os.remove(embed_exe)
        
    shutil.copy(src_exe, embed_exe)
    print(f"[+] Prepared payload: {embed_exe}")
else:
    print("[-] Error: breakpoint.exe not found in dist/")
    exit(1)

print("[*] Building Windows Installer...")

# 3. Build Installer (Bundling the engine)
PyInstaller.__main__.run([
    'installer.py',
    '--name', 'breakpoint-installer',
    '--onefile',
    '--add-data', 'dist/breakpoint_embedded.exe;.',
    '--uac-admin',
    '--clean',
    '--log-level', 'WARN',
    '--distpath', 'dist',
    '-y'
])

print("\n[SUCCESS] Build Pipeline Complete.")
print(f"[+] Installer: dist/breakpoint-installer.exe")
