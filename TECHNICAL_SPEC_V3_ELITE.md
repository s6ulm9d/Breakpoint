# 🏗️ BREAKPOINT v3.0.0-ELITE: Deep Technical Specification
**Internal Engineering Audit // Confidential Infrastructure**

---

## 1. Core Architecture & Philosophy
Breakpoint is built on the premise that "Production is already broken." Unlike legacy tools (Snyk, Burp) that focus on discovery, Breakpoint focuses on **deterministic verification** and **high-velocity auditing**.

### 🧬 The Core Pillars (Implementation Details)

#### I. High-Velocity Execution Engine
*   **Location**: `breakpoint/engine.py`
*   **Implementation**: Utilizes an adaptive `ThreadPoolExecutor` with phase-based execution.
*   **Mechanical Advantage**: Parallelizes hundred of probes per second while maintaining target integrity through intelligent concurrency capping for sensitive environments (e.g., localhost).

#### II. Differential Vulnerability Analysis
*   **Location**: `breakpoint/attacks/`
*   **Implementation**: Instead of simple status-code checking, Breakpoint performs **Differential Analysis**:
    *   **Timing Deltas**: Measuring millisecond-level variances between baseline and injected payloads.
    *   **Content Divergence**: Byte-level comparison of response bodies to detect subtle boolean state changes.
    *   **Heuristic Confirmation**: Re-verifying findings with alternative payloads to ensure zero false positives.

#### III. Forensic Audit Chain
*   **Location**: `breakpoint/forensics.py` (Implementation intended for v3.1)
*   **Philosophy**: Every packet is logged with a session-specific trace.
*   **Legal/Ethical**: Provides an immutable record of authorized testing, ensuring full chain-of-custody for enterprise compliance audits.

#### IV. Industrial-Grade Reporting
*   **Location**: `breakpoint/sarif_reporting.py`, `breakpoint/html_reporting.py`
*   - **SARIF 2.1.0**: Perfect compliance for GitHub Security Center integration.
*   - **Interactive HTML**: Provides deep-dive evidence, including leaked data samples and reproduction payloads.

---

## 2. The Execution Engine (Engine.py)
The `Engine` is the heartbeat of the tool. It handles concurrency, safety gates, and multi-phase execution.

### Phase 1: Logistic Checks
Standard attacks like `header_security`, `reflection`, and `idor` run first to map the target.

### Phase 2: Destructive Execution
Resource-intensive attacks (Slowloris, XML Bombs, High-Concurrency Stress Mode) are deferred until Phase 2 to prevent early app crashes from skewing results.

---

## 3. Attack Arsenal Deep-Dive (Reference: `sqli.py`)
Breakpoint uses **Differential Analysis** to confirm vulnerabilities.

### SQL Injection Logic
Instead of just looking for errors, it performs timing and content-based tests:
1.  **Time-Based Blind**: Measures the delta between baseline latency and injection latency.
2.  **Boolean Diffing**: Compares the HTTP response body of `True` vs `False` injections.

### RSC (React Server Components) Audit
Breakpoint is the first industrial tool to audit **Flight Protocol** (`text/x-component`):
*   **Server Action Forgery**: Checks if actions can be triggered by guessing the `Next-Action` ID.
*   **Hydration Collapse**: Manipulates the client state tree to leak admin components in the initial SSR payload.

---

## 4. Operational Safety Gates
Breakpoint implements three tiers of safety to prevent accidental infrastructure damage:

1.  **Mandatory Environment Context**: Scans MUST specify `--env <dev|staging|production>`.
2.  **Production Hard-Gate**: Targeting "production" with `--aggressive` requires verified **PREMIUM** status.
3.  **Localhost Optimization**: When scanning `localhost`, the engine automatically caps concurrency to **5 threads** to keep dev-servers from hanging.

---

**BREAKPOINT IS NOT A TOOL. IT IS AN INFRASTRUCTURE.**
**DEPLOYED. VERIFIED. UNBREAKABLE.**
