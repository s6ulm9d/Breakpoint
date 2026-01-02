# Breakpoint Professional Installer
# Usage: Right-click > Run with PowerShell

param (
    [string]$InstallDir = "C:\Program Files\BreakPoint",
    [string]$BinaryName = "breakpoint_windows.exe",
    [string]$TargetName = "breakpoint.exe"
)

# 1. Check Administrator Privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[-] Error: You must run this script as Administrator." -ForegroundColor Red
    Write-Host "    Right-click the script and select 'Run with PowerShell', then accept the UAC prompt if asked."
    Start-Sleep -Seconds 5
    Exit
}

$SourcePath = Join-Path $PSScriptRoot $BinaryName
if (!(Test-Path $SourcePath)) {
    # Fallback to alternative names
    $AltName = "breakpoint_windows_x64.exe"
    $SourcePath = Join-Path $PSScriptRoot $AltName
}

if (!(Test-Path $SourcePath)) {
    Write-Host "[-] Error: Could not find Breakpoint binary ('$BinaryName' or '$AltName') in the current directory." -ForegroundColor Red
    Write-Host "    Ensure you downloaded both the installer script and the executable to the same folder."
    Start-Sleep -Seconds 5
    Exit
}

Write-Host "[*] Starting Installation..." -ForegroundColor Cyan

# 2. Create Directory
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Write-Host "[+] Created directory: $InstallDir" -ForegroundColor Green
}

# 3. Copy and Rename Binary
$DestPath = Join-Path $InstallDir $TargetName

try {
    Copy-Item -Path $SourcePath -Destination $DestPath -Force
    Write-Host "[+] Installed binary to: $DestPath" -ForegroundColor Green
}
catch {
    Write-Host "[-] Error copying file: $_" -ForegroundColor Red
    Exit
}

# 4. Add to PATH (Machine & User for redundancy)
$PathsChanged = $false

# System Path
$CurrentMachinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($CurrentMachinePath -notlike "*$InstallDir*") {
    $NewMachinePath = $CurrentMachinePath + ";$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $NewMachinePath, "Machine")
    $PathsChanged = $true
    Write-Host "[+] Added '$InstallDir' to System PATH." -ForegroundColor Green
}

# User Path
$CurrentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($CurrentUserPath -notlike "*$InstallDir*") {
    $NewUserPath = $CurrentUserPath + ";$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
    $PathsChanged = $true
    Write-Host "[+] Added '$InstallDir' to User PATH." -ForegroundColor Green
}

if (!$PathsChanged) {
    Write-Host "[*] PATH already configured." -ForegroundColor Yellow
}

Write-Host "`n[SUCCESS] Breakpoint installed successfully!" -ForegroundColor Green
Write-Host "--------------------------------------------------------"
Write-Host "IMPORTANT: To use 'breakpoint' in THIS terminal, run:"
Write-Host '$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")' -ForegroundColor Cyan
Write-Host "Otherwise, please open a NEW terminal window."
Write-Host "--------------------------------------------------------"
Start-Sleep -Seconds 3
