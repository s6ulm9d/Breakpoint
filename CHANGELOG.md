# 📜 Changelog

All notable changes to the "BREAKPOINT" engine will be documented in this file.

## [2.3.0-ELITE] - 2025-12-11

### 🚀 Major Features
- **Full Spectrum Weaponization**: Enabled 18+ attack modules covering the entire OWASP Top 10 (Recon, Auth, Injection, BAC, Components, Logic, DoS).
- **Aggressive Mode**: New `--aggressive` flag unlocks destructive payloads:
    - **SQLi**: `DROP`, `TRUNCATE`, `xp_cmdshell`.
    - **RCE**: Fork bombs, File writes, Reverse Shells.
    - **DoS**: Uncapped concurrency and memory exhaustion.
- **Zero Config**: No initialization required. Just run `breakpoint <URL>`. Config and reports are auto-managed.

### 🛠️ Improvements
- **Installers**: Release includes `breakpoint-installer.exe` (Windows) and self-contained Linux/Mac binaries.
- **Force Attack**: Aggressive mode now explicitly ignores 404/405 "Safe" checks to force attacks on hidden endpoints.

## [2.0.0-ELITE] - 2025-12-11
- Initial Enterprise Release.
- Forensics, Safety Locks, and HTML Reporting.

---
*Based on Keep a Changelog.*
