# 📜 Changelog

All notable changes to the "BREAKPOINT" engine will be documented in this file.

## [2.5.1-ELITE] - 2025-12-11
### 🐛 Bug Fixes
- **Critical Crash Fix**: Resolved "unhashable type: slice" error caused by attempting to slice dictionary details in console output.
- **JWT**: Now uses a dummy token for simulation if no token is provided, preventing the test from being skipped.
- **Function Names**: Fixed function name mismatches for Deserialization and IDOR checks.

## [2.5.0-ELITE] - 2025-12-11

### 🚀 Features
- **In-Place Updates**: Added `--update` flag (and enhanced `update` command) to automatically pull the latest changes via Git if available, enabling seamless upgrades without reinstallation.

## [2.4.0-ELITE] - 2025-12-11

### 🛠️ Fixes
- **Attack Registry**: Fixed "Unknown check type" errors by properly registering all 15+ attack modules in the engine dispatcher.
- **Error Handling**: Internal execution errors are now correctly marked as `LOW/ERROR` instead of `HIGH/VULNERABLE`.
- **Legacy Compatibility**: Fixed `ForensicLogger` attribute errors in legacy header checks.
- **Safe DoS**: The Slowloris module now defaults to a low-impact mode (Safe) if `--aggressive` is not provided, rather than skipping.

## [2.3.0-ELITE] - 2025-12-11

### 🚀 Major Features
- **Strict CLI Validation**: The tool now exits immediately if unknown flags or typos are detected.
- **Aggressive DoS Scaling**: Hostile/Aggressive mode now forces 10,000 sockets and auto-scales threads (up to 200).
- **Liveness Checks**: DoS module verifies if the server was dropped.

### 🛠️ Improvements
- **Installers**: Release includes `breakpoint-installer.exe` (Windows) and self-contained Linux/Mac binaries.
- **Force Attack**: Aggressive mode now explicitly ignores 404/405 "Safe" checks.

## [2.0.0-ELITE] - 2025-12-11
- Initial Enterprise Release.
- Forensics, Safety Locks, and HTML Reporting.

---
*Based on Keep a Changelog.*
