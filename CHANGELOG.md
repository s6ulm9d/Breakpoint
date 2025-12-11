# 📜 Changelog

All notable changes to the "BREAKPOINT" engine will be documented in this file.

## [2.0.0-ELITE] - 2025-12-11

### 🚀 Major Features
- **Engine**: Rewrite of the core orchestrator for higher concurrency (20+ threads).
- **Attacks**: Added "Death Suite" (SQLi, DoS, Log4Shell, JWT Forgery).
- **Forensics**: Immutable audit logging system (`audit_UUID.log`).
- **Safety**: Added `STOP.lock` kill switch and interactive consent.
- **Reporting**: New HTML Executive Dashboard and SARIF output.

### 🛠️ Improvements
- **CLI**: Added `init` and `update` commands.
- **Installer**: Automated PowerShell installer (`install.ps1`) for Windows.
- **Docs**: Comprehensive professional documentation suite.

### 🐛 Bug Fixes
- Fixed race conditions in socket handling.
- Resolved path issues for Windows binary builds.

---
*Based on Keep a Changelog.*
