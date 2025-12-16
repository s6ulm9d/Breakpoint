
### ⚡ RSC / Next.js Specific Arsenal
Advanced audit modules targeting logic and architectural flaws in modern React Server Components:

- **`rsc_server_action_forge`**:  
    - **Concept**: "Safe RPC" premise violation.  
    - **Mechanism**: Fuzzes `Next-Action` headers to find unauthenticated actions. Checks for "Async Context Bleed" (User B seeing User A's data) during high-concurrency requests or error states.
    - **Impact**: Account Takeover (without creds), Unauthorized Data Mutation.

- **`rsc_ssr_ssrf`**:  
    - **Concept**: Framework-level SSRF bypassing WAFs.
    - **Mechanism**: Injects Cloud Metadata URLs into Image Optimization endpoints (`/_next/image`) and Server Action return values.
    - **Impact**: AWS/GCP Metadata theft (`169.254.169.254`), Internal Network Access.

- **`rsc_flight_trust_boundary_violation`**:  
    - **Concept**: Deserialization Logic Collapse.
    - **Mechanism**: Infinite recursion payloads (`children: ...`) to exhaust server stack.
    - **Impact**: DoS, Information Leak (Stack Traces), Potential RCE.

- **`rsc_cache_poisoning`**:  
    - **Concept**: Flight Protocol Cache Desync.
    - **Mechanism**: Detects if CDNs cache authenticated Flight blobs ("text/x-component") ignoring `Vary: Cookie`.
    - **Impact**: PII Leakage (User B logic rendered for User A).

- **`rsc_hydration_collapse`**:  
    - **Concept**: Partial Hydration Trust Bypass.
    - **Mechanism**: Manipulates `Next-Router-State-Tree` to force server-side rendering of client-protected routes (e.g., `/admin`) without authentication.
    - **Impact**: Authorization Bypass, Silent Rule Failure.
