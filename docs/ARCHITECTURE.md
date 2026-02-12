# 🏗️ System Architecture

**BREAKPOINT** is built on a modular, plugin-based architecture designed for high concurrency and extensibility.

---

## 1. High-Level Design

The system operates in a **Producer-Consumer** model:

1.  **Orchestrator (`engine.py`)**: The central nervous system. It parses Scenarios and distributes tasks.
2.  **Attack Plugins (`attacks/`)**: Stateless modules that implement specific attack vectors (SQLi, DoS, etc.).
3.  **Forensic Ledger (`forensics.py`)**: A write-only, cryptographically signed audit log.
4.  **Reporting Engine**: Converts raw results into human-readable formats (HTML, JSON, SARIF).

```mermaid
graph TD
    CLI[CLI / Entry Point] -->|Load| S[Scenarios (YAML)]
    CLI -->|Init| E[Engine Orchestrator]
    E -->|Dispatch| T[Thread Pool]
    T -->|Execute| A1[Attack: SQLi]
    T -->|Execute| A2[Attack: DoS]
    T -->|Execute| A3[Attack: XSS]
    A1 & A2 & A3 -->|Result| R[Result Queue]
    R -->|Stream| F[Forensic Logger]
    R -->|Batch| REP[Reporting Engine]
    REP --> HTML[Audit.html]
    REP --> JSON[Results.json]
```

---

## 2. Core Components

### A. The Engine
- **Responsibility**: Manages the thread pool (`ThreadPoolExecutor`), handles graceful shutdowns, and aggregates results.
- **Concurrency**: Adaptive scaling. Standard mode uses 5 threads; Aggressive mode uses 20+.

### B. Attack Plugins
Located in `breakpoint/attacks/`. Each plugin must implement a `check()` or `attack()` interface.
- **Isolation**: Crashes in one plugin do not affect the engine.
- **Protocol**: HTTP/1.1 and HTTP/2 support via `requests`.

### C. Forensic Logger
- **File**: `audit_UUID.log`
- **Integrity**: Each entry is hashed (SHA-256) and chained to the previous entry, creating a tamper-evident blockchain-like structure.

### D. Safety Locks
- **Kill Switch**: Checks for `STOP.lock` file presence to immediately abort key operations.

---

## 3. Data Flow

1.  **Initialization (Zero Config)**:
    -   If `~/.config/breakpoint/config.yaml` is missing, the Engine **auto-generates** it using embedded defaults.
    -   This allows immediate execution without manual setup.
2.  **Discovery**:
    -   Scenarios are validated against the internal Schema.
    -   **Aggressive Gates**: Attack modules check for the `aggressive: true` flag. Destructive payloads (e.g., `DROP TABLE`) are **only** loaded if this flag is present.
3.  **Execution Scheme**:
    -   **Standard**: Sequential execution of scenario blocks, parallel execution of payloads within blocks.
    -   **Continuous**: Infinite loop with statistical deviation tracking.
4.  **Output**: Atomic writes to disk (Auto-generated `Documents/Reports` folder) to prevent corruption.

---

## 4. Security Considerations

- **No Persistence**: The engine does not install agents on the target.
- **Memory Safety**: Python's memory management minimizes buffer overflow risks within the tool itself.
- **Secrets Management**: Credentials in YAML files should be injected via Environment Variables.

---

*For contribution guidelines, see CONTRIBUTING.md.*
