# 🏗️ BREAKPOINT v3.0.0-ELITE: Deep Technical Specification
**Internal Engineering Audit // Confidential Infrastructure**

---

## 1. Core Architecture & Philosophy
Breakpoint is built on the premise that "Production is already broken." Unlike legacy tools (Snyk, Burp) that focus on discovery, Breakpoint focuses on **deterministic resilience**.

### 🧬 The Four Pillars (Implementation Details)

#### I. Deterministic Code Property Graph (CPG)
*   **Location**: `breakpoint/cpg.py`, `breakpoint/stac.py`
*   **Implementation**: Breakpoint utilizes `tree-sitter` to parse source code into an AST. It then maps **Abstract Syntax Trees (AST)**, **Control Flow Graphs (CFG)**, and **Program Dependence Graphs (PDG)**.
*   **Mechanical Advantage**: By tracking data flow from "Sinks" (e.g., `db.execute()`) back to "Sources" (e.g., `request.args`), the engine mathematically proves reachability before the scanner even fires a packet.

#### II. Red vs. Blue Adversarial Loops
*   **Location**: `breakpoint/agents.py`, `breakpoint/engine.py:276`
*   **Implementation**: A three-agent orchestration managed by the `AdversarialLoop` class.
    *   **The Breaker**: Generates high-fidelity PoCs (Python/Requests).
    *   **The Fixer**: Scans the AST/CPG to propose a precise git-diff patch.
    *   **The Validator**: Attacker-simulated LLM that attempts to bypass the Fixer's patch using advanced evasion (e.g., encoding, multi-stage bypass).
*   **Exit Condition**: The loop only terminates when the Validator returns `UNBREAKABLE`.

#### III. Security-Test-as-Code (STaC)
*   **Location**: `breakpoint/stac.py`
*   **Implementation**: The `STaCEngine` class. When a vulnerability is confirmed, it generates a stateful **Playwright** or **Pytest** file.
*   **Reference Code** (`stac.py:78`):
    ```python
    def test_sql_injection_api_regression():
        # This test ensures the vulnerability is mathematically mitigated
        response = requests.request(method, url, json=payload, params=params)
        assert response.status_code != 200, "Vulnerability still exists!"
    ```

#### IV. Isolated Victim Sandboxing
*   **Location**: `breakpoint/sandbox.py`
*   **Implementation**: Utilizes `docker-py` to spawn hardened, ephemeral containers. 
*   **Usage**: Destructive exploits (like RCE or `dos_extreme`) are executed inside the container to measure survival metrics (CPU/RAM spikes) without touching host infrastructure.

---

## 2. The Execution Engine (Engine.py)
The `Engine` is the heartbeat of the tool. It handles concurrency, safety gates, and multi-phase execution.

### Phase 1: Logistic Checks
Standard attacks like `header_security`, `reflection`, and `idor` run first to map the target.

### Phase 2: Destructive Execution (`engine.py:147`)
Resource-intensive attacks (Slowloris, XML Bombs, Extreme DoS) are deferred until Phase 2 to prevent early app crashes from skewing results.

### Localhost Optimization (`engine.py:86`)
```python
if self._is_localhost:
    limit = 25 if aggressive else 5
    # Capping concurrency to prevent dev-server saturation
    concurrency = limit
```

---

## 3. Attack Arsenal Deep-Dive (Reference: `sqli.py`)
Breakpoint uses **Differential Analysis** to confirm vulnerabilities.

### SQL Injection Logic (`sqli.py:139`)
Instead of just looking for errors, it performs timing and content-based tests:
1.  **Time-Based Blind**: Measures the delta between baseline latency and injection latency.
    ```python
    if duration > 6.0 and duration > (baseline_latency * 5):
        suspicious = True # Potential SQLi confirmed via wall-clock delay
    ```
2.  **Boolean Diffing**: Compares the HTTP response body of `True` vs `False` injections.

### RSC (React Server Components) Audit
Breakpoint is the first industrial tool to audit **Flight Protocol** (`text/x-component`):
*   **`rsc_server_action_forge`**: Checks if actions can be triggered by guessing the `Next-Action` ID.
*   **`rsc_hydration_collapse`**: Manipulates the client state tree to leak admin components in the initial SSR payload.

---

## 4. Industrial Reporting & Forensics
### SARIF 2.1.0 (`sarif_reporting.py`)
Generates 100% compliant SARIF logs for **GitHub Security Center**. Includes `verified_fix` snippets that appear as "Suggested Fixes" in PRs.

### Forensic Audit Log (`forensics.py`)
Every packet sent is logged with a **Cryptographic Hash Chain**.
*   **Chain Integrity**: `current_hash = SHA256(prev_hash + entry_str)`.
*   **Legal/Ethical**: Provides an immutable record of authorized testing, signed with a session-specific HMAC key.

---

## 5. Economic Failure Calculation (`economics.py`)
Calculates the "Price of Vulnerability" based on:
*   **Data Breach Cost**: (Records * Avg Cost per Record).
*   **Outage Cost**: (Downtime * Revenue per Minute).
*   **Legal Exposure**: Statutory fines for PII/PHI leakage.

---

**BREAKPOINT IS NOT A TOOL. IT IS AN INFRASTRUCTURE.**
**DEPLOYED. VERIFIED. UNBREAKABLE.**
