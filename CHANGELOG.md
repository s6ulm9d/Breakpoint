# 📜 Changelog

All notable changes to the "BREAKPOINT" engine will be documented in this file.

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
