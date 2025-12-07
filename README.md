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

```bash
# Clone Repository
git clone https://github.com/soulmad/broke_prod_engine.git
cd broke_prod_engine

# Install Dependencies
pip install -r requirements.txt
```

*(Note: Requires Python 3.8+)*

---

## ⚔️ Usage

### 1. Basic Audit
Run the Elite Scenarios against a target:
```bash
python -m breakpoint \
  --base-url http://localhost:3000 \
  --scenarios examples/elite_scenarios.yaml \
  --html-report audit.html
```

### 2. Live-Fire (Unattended)
Bypass interactive safety prompts (Only for CI/CD):
```bash
python -m breakpoint \
  --base-url https://staging-api.com \
  --scenarios examples/elite_scenarios.yaml \
  --html-report stage_audit.html \
  --force-live-fire
```

### 3. CI/CD Gating
Fail the build if HIGH or CRITICAL issues are found:
```bash
python -m breakpoint ... --fail-on HIGH
```

---

## 🧱 Architecture
The engine is built on a modular, plugin-based architecture:
- **`broke_prod/engine.py`**: The core orchestrator.
- **`broke_prod/attacks/`**: Individual attack plugins (e.g., `sqli.py`, `dos_extreme.py`).
- **`broke_prod/scenarios.py`**: YAML parser for defining attack flows.
- **`broke_prod/forensics.py`**: Cryptographic logger.

---

## ⚖️ Legal Disclaimer
The authors of Broke Prod Engine are not responsible for any damage, data loss, or legal consequences caused by the use of this tool. By using this software, you agree to assume all liability and to adhere to all applicable local, state, and federal laws regarding unauthorized access to computer systems.

**OWN YOUR TARGETS.**
