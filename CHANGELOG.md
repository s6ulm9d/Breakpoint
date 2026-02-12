# 📜 Changelog

All notable changes to the "BREAKPOINT" engine will be documented in this file.
    
## [3.0.0-ELITE] - 2026-02-12
### 🧹 Major Cleanup & Optimization
- **File System Purge**: Removed outdated documentation, legacy QA checklists, and empty test directories to stream-line the codebase.
- **Dependency Consolidation**: Synchronized versioning across `setup.py`, `cli.py`, and `README.md`.
- **Performance**: Removed redundant `__pycache__` and optimized engine initialization.
- **Consistency**: Removed legacy command references (`register`, `init`) that have been replaced by the unified `--login` and `--license-key` workflow.

## [2.7.0-ELITE] - 2026-01-18
### 🌟 New Features
- **Account Connection**: Integrated explicit account connection flow (`--login`) to sync with the Breakpoint-Web subscription engine.
- **License Key Activation**: Added `--license-key <KEY>` flag for non-interactive activation and persistence, ideal for CI/CD or scripted deployments.
- **Enterprise Validation**: Robust server-side verification for premium features (Aggressive mode, Production environment targeting).

### 🛠️ Improvements
- **Security Gates**: Hardened access control for destructive features, requiring verified ELITE/PREMIUM status.
- **Localhost Optimization**: Improved thread management and safety locks for local testing to prevent dev-server crashes.

## [2.6.3-ELITE] - 2025-12-21
### 🛠️ Fixes
- **Configuration Persistence**: The installation process now explicitly bundles the omni-attack suite (`default_scenarios.yaml`) and correctly overwrites any stale user configuration files in `%APPDATA%` or `~/.config`. This ensures all 60+ attacks (instead of the legacy 22) are available immediately upon update for all users.

## [2.6.2-ELITE] - 2025-12-21
### 🐛 Bug Fixes
- **Scenario integrity**: Manually overwrote `default_scenarios.yaml` to ensure the exact, complete "Omni Attack" suite is used as the default. This guarantees all 60+ attack vectors are included and properly formatted, resolving prior issues with incomplete execution.

## [2.6.1-ELITE] - 2025-12-21
### 🐛 Bug Fixes
- **Scenario loading**: Fixed a critical YAML syntax error in the `omni_attack_all` scenario that caused the parser to abort early, resulting in only a subset of attacks running. All 60+ modules now execute correctly.

## [2.6.0-ELITE] - 2025-12-21
### 🌟 New Features
- **Resource Exhaustion Attacks**: Added dedicated modules for XML Bomb (Billion Laughs), ReDoS (Regular Expression DoS), and JSON recursion depth attacks to identify crash vulnerabilities.
- **Data Integrity Checks**: New `malformed_json` module to test parser robustness against truncated or invalid JSON inputs.
- **Traffic Simulation**: Added `traffic_spike` module to simulate load spikes and measure performance degradation (p50/p95 latencies).

### 🛠️ Improvements
- **Engine Dispatcher**: Fully integrated all new attack modules into the core execution engine.
- **Scenarios**: Updated `default_scenarios.yaml` with the latest elite attack vectors.

## [2.5.2] - 2025-12-12
### 🌟 New Features
- **Proof of Exploitation**: All attack modules (SQLi, XSS, XXE, LFI, IDOR, etc.) now capture and report **actual leaked data** (e.g., config snippets, file contents, reflection contexts) to definitively verify vulnerabilities.
- **Improved Reporting**: Reports now include a `leaked_data` section for each finding, differentiating between theoretical risks and proven exploits.

### 🐛 Bug Fixes
- **Critical Crash Fix**: Resolved "unhashable type: slice" error in console reporting.
- **JWT**: Added dummy token support for robust testing.
- **Function Names**: Fixed dispatcher mismatches for Deserialization and IDOR.
- **In-Place Updates**: Added `--update` flag support.

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
