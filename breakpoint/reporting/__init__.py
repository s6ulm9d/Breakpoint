import json
import os
import datetime
from typing import List
from colorama import Fore, Style, init
from ..models import CheckResult

init(autoreset=True)

class ConsoleReporter:
    def print_summary(self, results):
        print("\n" + "="*60)
        print("BREAKPOINT AUDIT SUMMARY")
        print("="*60)
        
        vulnerable = [r for r in results if r.status in ["VULNERABLE", "CONFIRMED"]]
        suspect = [r for r in results if r.status == "SUSPECT"]
        secure = [r for r in results if r.status == "SECURE"]
        skipped = [r for r in results if r.status == "SKIPPED"]
        blocked = [r for r in results if r.status == "BLOCKED"]
        error = [r for r in results if r.status == "ERROR"]
        inconclusive = [r for r in results if r.status == "INCONCLUSIVE"]
        
        print(f"Total Checks: {len(results)}")
        print(f"SECURE:       {Fore.GREEN}{len(secure)}{Style.RESET_ALL} (Passed)")
        print(f"VULNERABLE:   {Fore.RED}{len(vulnerable)}{Style.RESET_ALL} (Confirmed/High Risk)")
        if suspect:
            print(f"SUSPECT:      {Fore.YELLOW}{len(suspect)}{Style.RESET_ALL} (Requires Review)")
        if skipped:
            print(f"SKIPPED:      {Fore.CYAN}{len(skipped)}{Style.RESET_ALL} (Throttling/Prerequisites)")
        if blocked:
            print(f"BLOCKED:      {Fore.MAGENTA}{len(blocked)}{Style.RESET_ALL} (WAF/Rate Limited)")
        if error:
            print(f"ERROR:        {Fore.RED}{len(error)}{Style.RESET_ALL} (Crashes/Unreachable)")
        
        if vulnerable:
            print("\n[!] CRITICAL FINDINGS:")
            for f in vulnerable:
                 print(f" - {Fore.RED}[{f.type.upper()}]{Style.RESET_ALL} {f.description}")
        
        if suspect:
            print("\n[?] SUSPICIOUS FINDINGS:")
            for f in suspect:
                 print(f" - {Fore.YELLOW}[{f.type.upper()}]{Style.RESET_ALL} {f.description}")
        print("="*60 + "\n")

def generate_json_report(results, filename):
    data = [{"id": r.id, "type": r.type, "status": r.status, "severity": r.severity} for r in results]
    with open(filename, 'w') as f: json.dump(data, f, indent=2)

class EliteHTMLReporter:
    """State-of-the-Art HTML Reporting Engine consolidated into the reporting hub."""
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        findings_html = ""
        for r in v_results:
            artifacts_html = ""
            if hasattr(r, 'artifacts') and r.artifacts:
                artifacts_html += "<details style='margin-top:15px;'><summary style='cursor:pointer; color:#a855f7; font-weight:bold;'>Exploitation Evidence (Leaked Data)</summary>"
                for art in r.artifacts:
                    req = art.get('request', 'N/A')
                    res = art.get('response', 'N/A')
                    artifacts_html += f"<div style='background:#0f0f13; padding:15px; margin-top:10px; border-radius:8px; overflow-x:auto; border:1px solid #333;'><div style='color:#a855f7; font-weight:bold; margin-bottom:5px;'>Request Payload:</div><pre style='color:#e2e8f0; font-size:0.9em;'>{req}</pre><div style='color:#a855f7; font-weight:bold; margin-bottom:5px; margin-top:15px;'>Response Evidence:</div><pre style='color:#e2e8f0; font-size:0.9em;'>{res}</pre></div>"
                artifacts_html += "</details>"
            
            description = r.description or r.details or "No details provided."
            findings_html += f'<div class="card"><div style="display:flex; justify-content:space-between; align-items:center;"><h3>{r.type.upper()}</h3><span style="background:#a855f7; color:white; padding:4px 8px; border-radius:4px; font-size:0.8em; font-weight:bold;">{r.severity}</span></div><p>{description}</p><p><b>Status:</b> {r.status} | <b>Confidence:</b> {r.confidence}</p>{artifacts_html}</div>'

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>BreakPoint Elite Audit</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        body {{ background: #050507; color: #e2e8f0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 40px; }}
        .card {{ background: #16161c; border: 1px solid #23232b; padding: 25px; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        .header {{ border-bottom: 2px solid #a855f7; padding-bottom: 20px; margin-bottom: 40px; }}
        .stat {{ font-size: 2.5rem; font-weight: 800; color: #a855f7; margin-bottom: 5px; }}
        h1 {{ margin: 0; font-size: 2rem; color: #fff; }}
        h2 {{ color: #a855f7; margin-top: 40px; margin-bottom: 20px; }}
        h3 {{ margin-top: 0; color: #e2e8f0; }}
        pre {{ white-space: pre-wrap; word-wrap: break-word; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>BreakPoint Elite Audit Report</h1>
        <p style="color:#888;">Target: {self.target_url} | Date: {self.timestamp}</p>
    </div>
    <div style="display: flex; gap: 20px; margin-bottom: 40px;">
        <div class="card" style="flex:1; text-align:center;"><div class="stat">{stats['critical']}</div><div style="color:#aaa;">Critical Risks</div></div>
        <div class="card" style="flex:1; text-align:center;"><div class="stat">{stats['high']}</div><div style="color:#aaa;">High Risks</div></div>
        <div class="card" style="flex:1; text-align:center;"><div class="stat">{stats['secure']}</div><div style="color:#aaa;">Secure Checks</div></div>
    </div>
    
    <h2>Vulnerability Findings ({len(v_results)})</h2>
    {findings_html if findings_html else '<div class="card"><p>No vulnerabilities found.</p></div>'}
</body>
</html>
"""
        with open(output_file, 'w', encoding='utf-8') as f: f.write(html)

    def generate_individual_report(self, result: CheckResult, output_file: str):
        """Generates a detailed, standalone report for a single attack execution."""
        status_color = "#ef4444" if result.status in ["VULNERABLE", "CONFIRMED"] else "#f59e0b" if result.status == "SUSPECT" else "#10b981"
        
        artifacts_html = ""
        if result.artifacts:
            artifacts_html += "<h2>Exploitation Evidence & Leaked Data</h2>"
            for art in result.artifacts:
                req = art.get('request', 'N/A')
                res = art.get('response', 'N/A')
                artifacts_html += f"""
                <div class="card">
                    <div style='color:#a855f7; font-weight:bold; margin-bottom:10px;'>Proof of Exploit (Request):</div>
                    <pre style='background:#0f0f13; padding:15px; border-radius:8px; border:1px solid #333;'>{req}</pre>
                    <div style='color:#a855f7; font-weight:bold; margin-bottom:10px; margin-top:20px;'>Proof of Success (Response/Leaked Data):</div>
                    <pre style='background:#0f0f13; padding:15px; border-radius:8px; border:1px solid #333;'>{res}</pre>
                </div>"""

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>BreakPoint Attack Evidence - {result.attack_id}</title>
    <style>
        body {{ background: #050507; color: #e2e8f0; font-family: 'Segoe UI', sans-serif; padding: 40px; line-height: 1.6; }}
        .card {{ background: #16161c; border: 1px solid #23232b; padding: 25px; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        .badge {{ padding: 6px 12px; border-radius: 6px; font-weight: 800; font-size: 0.9em; text-transform: uppercase; }}
        .header {{ border-bottom: 2px solid #a855f7; padding-bottom: 20px; margin-bottom: 40px; display: flex; justify-content: space-between; align-items: center; }}
        h1, h2, h3 {{ color: #fff; }}
        h2 {{ color: #a855f7; border-left: 4px solid #a855f7; padding-left: 15px; margin-top: 40px; }}
        pre {{ white-space: pre-wrap; word-wrap: break-word; color: #cbd5e1; font-family: 'Consolas', monospace; font-size: 0.9em; }}
        .metadata-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Attack Execution Report</h1>
            <p style="color:#888;">Attack ID: {result.attack_id} | Timestamp: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        <span class="badge" style="background:{status_color}; color:white;">{result.status}</span>
    </div>

    <div class="metadata-grid">
        <div class="card">
            <h3 style="margin-top:0;">Attack Context</h3>
            <p><b>Target URL:</b> {self.target_url}</p>
            <p><b>Vulnerability:</b> {result.type.upper()}</p>
            <p><b>Severity:</b> <span style="color:#ef4444;">{result.severity}</span></p>
        </div>
        <div class="card">
            <h3 style="margin-top:0;">Risk Summary</h3>
            <p><b>Impact:</b> {result.description}</p>
            <p><b>CWE:</b> {result.cwe}</p>
            <p><b>OWASP:</b> {result.owasp}</p>
        </div>
    </div>

    <div class="card">
        <h3>Remediation Advice</h3>
        <p>{result.remediation}</p>
    </div>

    {artifacts_html}

</body>
</html>
"""
        with open(output_file, 'w', encoding='utf-8') as f: f.write(html)
