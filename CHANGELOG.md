# 📜 Changelog

All notable changes to the "BREAKPOINT" engine will be documented in this file.

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
