# 🛡️ BREAKPOINT: The Ultimate Technical Manual
**Next-Generation Autonomous Offensive Security Infrastructure**

---

## 1. Executive Summary
**Breakpoint** is not just a scanner; it is a **Weaponized Resilience Engine**. Built for high-concurrency enterprise targeting, it moves beyond legacy pattern matching to provide deterministic, actionable, and reproducible security audits. By combining **Code Property Graphs (CPG)** with **AI-Driven Adversarial Loops**, Breakpoint identifies vulnerabilities that traditional tools miss.

---

## 2. Structural Architecture
Breakpoint is built on a modular, asynchronous foundation designed for extreme scalability.

### A. The Deterministic Engine (`engine.py`)
At the heart of Breakpoint is a multi-phase orchestration pipeline:
-   **Phase 1: Discovery & Fingerprinting**: Passive reconnaissance using recursive crawling and tech-stack signature matching.
-   **Phase 2: Baseline Stabilization**: Normalizes dynamic response regions (timestamps, session tokens) to ensure stable comparison during fuzzing.
-   **Phase 3: Active Vulnerability Probing**: Concurrent execution of injection, logic, and infrastructure attacks.
-   **Phase 4: Destructive Validation**: High-intensity resource exhaustion tests (only in `--aggressive` mode).

### B. CPG Foundation (`breakpoint/cpg.py`)
Moving beyond simple regex, Breakpoint utilizes a mathematical model of the target:
-   **AST**: Abstract Syntax Tree analysis.
-   **CFG**: Control Flow Graph mapping.
-   **PDG**: Program Dependence Graph for data flow slicing.
*Result: Near-zero false positive rates through mathematical verification.*

---

## 3. Intelligent Orchestration Layer

### 🧠 AI-Driven Footprinting (`ai_analyzer.py`)
Breakpoint uses OpenAI (GPT-4o) to perform context-aware analysis:
-   **Endpoint Discovery**: Heuristically extracts API routes and parameters from source code.
-   **Source Match Verification**: Dynamically validates if the provided source code matches the target's behavior.
-   **Context Injection**: Tailors payload selection based on the detected framework (e.g., Node.js, Django, React).

### ⛓️ Attack Graph Chaining (`attack_graph.py`)
Real attackers don't stop at one bug. Breakpoint's **Attack Graph** simulates real-world kill chains:
1.  **Reconnaissance** (e.g., Git exposure)
2.  **Initial Access** (e.g., Credential leak)
3.  **Privilege Escalation** (e.g., Horizontal/Vertical IDOR)
4.  **Lateral Movement** (e.g., SSRF to internal metadata)
5.  **Exfiltration** (e.g., Data dumping)

---

## 4. Industrial Features & Safety

### ⚔️ Adversarial Loops (`agents.py`)
Breakpoint employs a trio of specialized agents for self-correcting security:
-   **BreakerAgent**: Finds the vulnerability.
-   **FixerAgent**: Proposes a code-level patch.
-   **ValidatorAgent**: Attempts to *break the fix* to ensure industrial-grade patches.

### 📦 Hardened Sandboxing (`sandbox.py`)
Execute destructive payloads safely. Breakpoint spawns **Isolated Victim Containers** (using Docker) to verify exploits like RCE or Logic Bombs without risking production data.

### 🧪 Security-Test-as-Code (STaC)
Every finding is converted into a reproducible artifact:
-   **Pytest/Playwright Generators**: Automatic generation of regression tests.
-   **SARIF 2.1.0 Integration**: Native support for GitHub/GitLab Security dashboards.

---

## 5. CLI & Deployment Reference

### Standard Deployment
```bash
# Non-destructive audit
breakpoint https://target.enterprise --env production

# Aggressive validation (Destructive + High Concurrency)
breakpoint https://target.enterprise --aggressive --concurrency 50
```

### Essential Flags
| Flag | Description | Recommendation |
| :--- | :--- | :--- |
| `--aggressive` | Enables destructive payloads and 20+ threads. | Use in Staging only. |
| `--continuous` | Infinite audit loop with variance tracking. | Use for soak tests. |
| `--sarif-report` | Exports to SARIF for CI/CD integration. | Default for DevOps. |
| `--verbose` | Full network forensic details. | Debugging only. |

---

## 6. Strategic Roadmap (V2 Evolution)
-   **Scanner → Autonomous Validation Engine**: Shifting to a dynamic Attack Registry system.
-   **Differential Scanning**: Mapping Git changes to specific endpoints for 10x faster PR audits.
-   **Async IO overhaul**: Transitioning to `asyncio` for 1,000+ concurrent worker support.
-   **Offensive Policy Engine**: Defining "Pass/Fail" security criteria as code.

---
**Build Unbreakable Infrastructure. Deploy Breakpoint.**
