# Breakpoint Uninstaller
# Usage: Right-click > Run with PowerShell

# 1. Check Administrator Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[-] Error: You must run this script as Administrator." -ForegroundColor Red
    Write-Host "    Right-click the script and select 'Run with PowerShell'."
    Start-Sleep -Seconds 5
    Exit
}

$InstallDir = "C:\Program Files\BreakPoint"

Write-Host "[*] Starting Uninstallation..." -ForegroundColor Cyan

# 2. Remove from PATH
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($CurrentPath -like "*$InstallDir*") {
    # Remove the entry ensuring we don't leave double semicolons
    $NewPath = $CurrentPath.Replace(";$InstallDir", "").Replace("$InstallDir;", "").Replace($InstallDir, "")
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "Machine")
    Write-Host "[+] Removed from System PATH." -ForegroundColor Green
}
else {
    Write-Host "[*] PATH clean." -ForegroundColor Yellow
}

# 3. Delete Files
if (Test-Path $InstallDir) {
    try {
        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction Stop
        Write-Host "[+] Removed files from: $InstallDir" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Error deleting files: $_" -ForegroundColor Red
        Write-Host "    Make sure 'breakpoint.exe' is not currently running."
    }
}
else {
    Write-Host "[*] Directory not found." -ForegroundColor Yellow
}

Write-Host "`n[SUCCESS] Breakpoint has been uninstalled." -ForegroundColor Green
Start-Sleep -Seconds 3
