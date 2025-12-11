 ____  _____  ______          _   _  __ _____   ____  _____ _   _ _______ 
 |  _ \|  __ \|  ____|   /\   | |/ /|  __ \ / __ \|_   _| \ | |__   __|
 | |_) | |__) | |__     /  \  | ' / | |__) | |  | | | | |  \| |  | |   
 |  _ <|  _  /|  __|   / /\ \ |  <  |  ___/| |  | | | | | . ` |  | |   
 | |_) | | \ \| |____ / ____ \| . \ | |    | |__| |_| |_| |\  |  | |   
 |____/|_|  \_\______/_/    \_\_|\_\|_|     \____/|_____|_| \_|  |_|


# 💀 BREAKPOINT (Elite Edition)

**Version:** 2.0.0-ELITE  
**Status:** Weaponized / Audit-Grade  
**Classification:** Offensive Security Tool (OST)

> "Production is already broken. You just haven't proved it yet."

---

## 🚫 DANGER: READ BEFORE USE
This engine is **NOT A TOY**. **BREAKPOINT** contains modules designed to:
- **Crash Services** (DoS, XML Bomb, Memory Exhaustion).
- **Compromise Servers** (RCE, SQLi, Log4Shell).
- **Corrupt Data** (Race Conditions, Logic Flaws).

It includes **Force-Multipliers** like Forensic Logging and Financial Liability Estimation.  
**DO NOT RUN** on targets you do not own or have written consent to test.

---

## 🔥 Capabilities

### 1. The "Death Suite" (Attack Modules)
- **Injection**: SQLi (Union/Blind), NoSQL, RCE, LDAP, XPath, SSTI.
- **Infrastructure**: HTTP Desync (Smuggling), SSRF (Cloud Metadata), LFI/Path Traversal.
- **Denial of Service (DoS)**: Slowloris (Connection Exhaustion), XML Bomb (Billion Laughs), Body/Header Bombs, ReDoS.
- **Authentication**: JWT Forgery ("None" Alg), IDOR, Brute Force, Credential Stuffing.
- **Web & Logic**: XSS, Prototype Pollution, CRLF Injection, Race Conditions, OTP Reuse.
- **CVE Classics**: Log4Shell, Spring4Shell, Struts2 RCE.

### 2. Enterprise audit Features
- **Forensic Chain-of-Custody**: Immutable, cryptographically signed audit logs (`audit_UUID.log`).
- **Failure Economics**: Estimates financial liability per run (Downtime Costs + Data Breach Fines).
- **Safety Locks**: Interactive consent enforcement and Kill-Switch (`STOP.lock`) support.
- **Reporting**: 
  - **HTML**: Executive Dashboards with Risk Heatmaps.
  - **SARIF**: CI/CD integration for GitHub Security.

---

## 🚀 Installation

### 1. End Users (Binary Release) - Recommended
**No Python or Git required.** Follow these steps to run `breakpoint` from anywhere.

#### Step A: Download
1. Download the latest binary for your OS from the [Releases Page](https://github.com/soulmad/breakpoint/releases).
2. Rename the file to `breakpoint.exe` (Windows) or `breakpoint` (Linux/Mac) for convenience.

#### Step B: Install Globally (Add to PATH)

**🪟 Windows**
1. **Create a Folder**: Create a permanent folder (e.g., `C:\Tools\Breakpoint\`) and move `breakpoint.exe` inside it.
2. **Add to PATH**:
   * Press `Win + R`, type `sysdm.cpl`, and hit Enter.
   * Go to **Advanced** tab -> **Environment Variables**.
   * Under **User variables**, find `Path` -> Select it -> Click **Edit**.
   * Click **New** -> Paste your folder path (`C:\Tools\Breakpoint\`).
   * Click **OK** on all windows.

**🐧 Linux / macOS**
Move the binary to your executable path:
```bash
chmod +x breakpoint
sudo mv breakpoint /usr/local/bin/
```

#### Step C: Verify Installation
Open a **new** terminal window and type `breakpoint` (without `.\`).

```bash
# You should see the help menu appears immediately:
user@pc:~$ breakpoint --help
```

### 2. Developers (Source Code)
For contributors or those who want to run from source.
**Prerequisites:** Python 3.8+, Git.

1. Clone the repository:
   ```bash
   git clone https://github.com/soulmad/breakpoint.git
   cd breakpoint
   ```

2. Create a virtual environment (Recommended):
   ```bash
   # Windows
   python -m venv .venv
   .\.venv\Scripts\activate

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install as an editable package:
   ```bash
   pip install -e .
   ```

---

## ⚔️ Usage

Once installed (or downloaded), use the `breakpoint` command.

> **Tip:** If using the downloaded binary without adding it to your PATH, run it as `.\breakpoint.exe` (Windows) or `./breakpoint` (Linux/Mac).

### 1. Basic Audit
Run the Elite Scenarios against a target:
```bash
breakpoint \
  --base-url http://localhost:3000 \
  --scenarios examples/elite_scenarios.yaml \
  --html-report audit.html
```

### 2. Aggressive Mode
Enable **DESTRUCTIVE** tests (RCE File Writes, Server Crash Payloads) and high concurrency:
```bash
breakpoint \
  --base-url http://localhost:3000 \
  --scenarios examples/elite_scenarios.yaml \
  --aggressive \
  --verbose
```

### 3. CI/CD Integration (Unattended)
Bypass interactive safety prompts for automated pipelines:
```bash
breakpoint \
  --base-url https://staging-api.com \
  --scenarios examples/elite_scenarios.yaml \
  --json-report results.json \
  --sarif-report security.sarif \
  --force-live-fire
```

### 4. Continuous Attack Loop (Persistence)
Run the attack suite in an infinite loop to stress test resilience over time:
```bash
breakpoint \
  --base-url http://localhost:3000 \
  --scenarios examples/elite_scenarios.yaml \
  --continuous \
  --interval 10 \
  --aggressive
```
*(This will run indefinitely, waiting 10 seconds between each full attack cycle.)*

> **Note for Developers:** If running from source without installing, you can use `python -m breakpoint ...` instead of `breakpoint ...`.


---

---

## 🧱 Architecture

The engine is built on a modular, plugin-based architecture:
- **`breakpoint/engine.py`**: The core orchestrator.
- **`breakpoint/attacks/`**: Individual attack plugins (e.g., `sqli.py`, `dos_extreme.py`).
- **`breakpoint/scenarios.py`**: YAML parser for defining attack flows.
- **`breakpoint/forensics.py`**: Cryptographic logger.

---

## ⚖️ Legal Disclaimer
The authors of BREAKPOINT are not responsible for any damage, data loss, or legal consequences caused by the use of this tool. By using this software, you agree to assume all liability and to adhere to all applicable local, state, and federal laws regarding unauthorized access to computer systems.

**OWN YOUR TARGETS.**
