# ⚡ BREAKPOINT Installation Guide

Welcome to the official installation guide for **BREAKPOINT (Elite Edition)**. This document provides professional, step-by-step instructions for deploying the BREAKPOINT engine on your system.

---

## 📦 For End Users (Binary Release)

The recommended installation method for security auditors and penetration testers who simply want to run the tool.

### 1. Download & Install (Zero Config)

#### 🪟 Windows (Recommended)
1.  Download **`breakpoint-installer.exe`** from the [Releases Page](https://github.com/soulmad/breakpoint/releases).
2.  **Double-click** the file.
3.  Click "Yes" on the Administrator Prompt.
    -   The installer extracts the engine to `C:\Program Files\BreakPoint`.
    -   It automatically configures your System `PATH`.
4.  **Done**. Open a terminal and run `breakpoint`.

#### 🐧 Linux / macOS
Download the monolithic binary and move it to your bin path:

```bash
# Linux
wget https://github.com/soulmad/breakpoint/releases/latest/download/breakpoint-linux-x86_64
chmod +x breakpoint-linux-x86_64
sudo mv breakpoint-linux-x86_64 /usr/local/bin/breakpoint

# macOS
wget https://github.com/soulmad/breakpoint/releases/latest/download/breakpoint-macos-x86_64
chmod +x breakpoint-macos-x86_64
sudo mv breakpoint-macos-x86_64 /usr/local/bin/breakpoint
```

### 2. Verification
Open a terminal and run:
```bash
breakpoint --version
```
Output: `Breakpoint v2.3.0-ELITE`

---

## 🗑️ Uninstallation

To remove BREAKPOINT from your system:

### Windows
1.  Run `uninstall.ps1` as Administrator (Right-click > Run with PowerShell).
2.  This will remove the program files and clean your System PATH.

### Linux / macOS
Run the uninstaller script:
```bash
sudo ./uninstall.sh
```

---

## 🛠️ For Developers (Source Code)

Instructions for contributors and engineers who wish to modify or build upon the BREAKPOINT engine.

### Prerequisites

- **Python**: Version 3.8 or higher.
- **Git**: Version control system.

### 1. Clone Repository

Retrieve the source code from the repository.

```bash
git clone https://github.com/soulmad/breakpoint.git
cd breakpoint
```

### 2. Environment Setup

It is highly recommended to run BREAKPOINT in an isolated virtual environment to avoid dependency conflicts.

**Windows:**
```powershell
python -m venv .venv
.\.venv\Scripts\activate
```

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

Install the package in "editable" mode. This allows changes in the source code to be immediately reflected when running the tool.

```bash
pip install -e .
```

### 4. Usage

Immeditaly verify your development setup:

```bash
breakpoint --help
```

---
## 🔌 CLI Reference

Complete list of command-line arguments and flags.

### Targeting
| Flag | Description | Required | Example |
| :--- | :--- | :---: | :--- |
| `--base-url` | The target URL to audit. This is the entry point for all tests. | **Yes** | `--base-url http://localhost:3000` |
| `--scenarios` | Path to a custom YAML scenarios file. Defaults to the built-in Elite Suite if omitted. | No | `--scenarios my_tests.yaml` |
| `--force-live-fire` |  Bypasses interactive safety checks. Use this for CI/CD pipelines. | No | `--force-live-fire` |

### Configuration
| Flag | Description | Required | Example |
| :--- | :--- | :---: | :--- |
| `--aggressive` | Enables **DESTRUCTIVE** mode. Increases concurrency (20 threads) and uses heavier payloads. | No | `--aggressive` |
| `--concurrency` | Manually set the number of concurrent threads. | No | `--concurrency 50` |
| `--continuous` | Runs the audit loop indefinitely. Useful for stress testing over time. | No | `--continuous` |
| `--interval` | Seconds to wait between iterations when using `--continuous`. | No | `--interval 60` |
| `--verbose` | Output full network traffic and debug details to the console. | No | `--verbose` |

### Reporting
| Flag | Description | Required | Example |
| :--- | :--- | :---: | :--- |
| `--html-report` | Generates a comprehensive HTML executive dashboard. | No | `--html-report audit.html` |
| `--json-report` | Exports raw results to a JSON file for machine parsing. | No | `--json-report data.json` |
| `--sarif-report` | Exports results in SARIF format for GitHub Security integration. | No | `--sarif-report security.sarif` |

### System Commands
| Command | Description |
| :--- | :--- |
| `breakpoint init` | Initializes the current directory with `breakpoint_config.yaml` and sets up the workspace. |
| `breakpoint update` | Connects to the release channel to check for the latest version. |

---
*BREAKPOINT - Weaponized Resilience Engine. Use responsibly.*
