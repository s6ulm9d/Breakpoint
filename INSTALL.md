# ⚡ BREAKPOINT Installation Guide

Welcome to the official installation guide for **BREAKPOINT (Elite Edition)**. This document provides professional, step-by-step instructions for deploying the BREAKPOINT engine on your system.

---

## 📦 For End Users (Binary Release)

The recommended installation method for security auditors and penetration testers who simply want to run the tool.

### 1. Download the Latest Release

Navigate to the official Releases page and download the executable binary corresponding to your operating system.

- **Current Version:** `2.0.0-ELITE`
- **File:** `breakpoint_windows.exe`

### 2. Automated Installation (Windows)

We provide a PowerShell script to automate the setup process (requires Administrator privileges).

1.  Download `install.ps1` to the same folder as your `breakpoint_windows.exe`.
2.  Right-click `install.ps1` and select **Run with PowerShell**.
3.  The script will:
    - Create `C:\Program Files\BreakPoint`.
    - Rename and move the binary to `C:\Program Files\BreakPoint\breakpoint.exe`.
    - Add the directory to your System PATH.
4.  Once complete, restart your terminal.

> **Manual Method:** If you prefer manual installation, create the folder `C:\Program Files\BreakPoint`, move/rename the file, and edit your System Environment Variables manually.

### 5. Verification

1.  Open a **new** Command Prompt (cmd) or PowerShell window.
2.  Type the following command and press Enter:
    ```bash
    breakpoint --version
    ```
3.  You should see the BREAKPOINT version information, confirming a successful installation.

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
