import requests
from ..models import CheckResult

def check(base_url, scenario, logger):
    url = f"{base_url}{scenario.target}"
    param = scenario.config.get("param", "q")
    
    # Real-world XSS Payloads (Polyglots, Context Breaking, Event Handlers)
    payloads = [
        # 1. Standard Reflected
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        
        # 2. Context Breaking (for when strictly inside attributes or JS variables)
        "\"><script>alert(1)</script>",
        "';alert(1)//",
        
        # 3. Polyglots (The "Killer" - breaks out of almost anything)
        # Based on 0xSobky's Polyglot
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/'/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        
        # 4. URI Schemes (Bypass naive tag filters)
        "javascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        
        # 5. HTML5 Auto-Focus (No user interaction needed)
        "<input onfocus=alert(1) autofocus>",
        "<video src=x onerror=alert(1)>"
    ]
    
    import concurrent.futures
    
    def check_payload(payload):
        try:
            p = {param: payload}
            # Short timeout
            resp = requests.get(url, params=p, timeout=2)
            logger.log_request("GET", url, None, p, resp)
            
            # Check if payload is reflected literally
            if payload in resp.text:
                 return CheckResult(scenario.id, scenario.type, "VULNERABLE", "MEDIUM", f"Reflected XSS detected. Payload returned unsanitized: {payload}")
        except:
             pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_payload, p) for p in payloads]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                return res
            
    return CheckResult(scenario.id, scenario.type, "SECURE", None, "XSS payloads were escaped or filtered.")
