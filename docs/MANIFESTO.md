# The BREAKPOINT Philosophy: "Break It To Fix It"

## 1. Manifesto
We believe that **production is already broken**; you just haven't proved it yet.
Soft assertions and happy-path tests provide a false sense of security.
Only by subjecting applications to **hostile, adversarial conditions** can we guarantee resilience.

## 2. Threat Model
This engine assumes an **Internal Adversary** or **Compromised User** perspective.
- **Scope**: Authenticated and Unauthenticated Web Endpoints.
- **Exclusions**: Physical Access, Social Engineering, DDoS (unless explicitly configured).
- **Assumptions**: The target is a web application accessible via HTTP/HTTPS.

## 3. What This Tool Will NOT Do
- It will NOT auto-exploit and pivot (worm behavior).
- It will NOT perform distributed processing (Botnet).
- It will NOT hide its tracks (Stealth Mode). It is loud by design.

## 4. Safety & Ethics
- **Consent**: Only run this on systems YOU own or have explicit permission to test.
- **Production**: Use extreme caution. "Crash" modules can cause outages.
- **Liability**: The user assumes all liability for damage caused by this tool.

## 5. Limits
- **False Positives**: High confidence attacks may still hallucinate on custom 404 pages.
- **State**: The engine does not reset DB state between runs; manual cleanup required.

## 6. Case Studies (Before/After)
- **FinTech App**: 
  - *Before*: Passed 100% Unit Tests.
  - *After*: Found Race Condition in Transfer (Double Spend) and IDOR in Invoices.
- **Legacy API**:
  - *Before*: "Stable".
  - *After*: Crushed by XML Bomb (DoS) and leaked AWS Keys via SSRF.
