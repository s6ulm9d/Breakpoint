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

    def generate_global_report(self, results: List[CheckResult], output_file: str):
        """Generates the definitive, high-fidelity executive audit report."""
        v_results = [r for r in results if r.status in ["VULNERABLE", "CONFIRMED", "SUSPECT"]]
        stats = {
            'critical': len([r for r in v_results if r.severity == "CRITICAL"]),
            'high': len([r for r in v_results if r.severity == "HIGH"]),
            'medium': len([r for r in v_results if r.severity == "MEDIUM"]),
            'secure': len([r for r in results if r.status == "SECURE"]),
            'total': len(results)
        }
        
        findings_html = ""
        for r in v_results:
            artifacts_html = ""
            if hasattr(r, 'artifacts') and r.artifacts:
                artifacts_html += "<div class='evidence-section'>"
                artifacts_html += "<h4 style='color:#a855f7; margin-bottom:15px; font-size:1.1em;'>⚡ EXPLOITATION EVIDENCE & PAYLOAD PROOF</h4>"
                for idx, art in enumerate(r.artifacts):
                    req = art.get('request', 'N/A')
                    res = art.get('response', 'N/A')
                    # Sanitize for HTML
                    req = req.replace("<", "&lt;").replace(">", "&gt;")
                    res = res.replace("<", "&lt;").replace(">", "&gt;") if isinstance(res, str) else str(res)
                    
                    artifacts_html += f"""
                    <div class="artifact-card">
                        <div class="artifact-header">Exploit Execution #{idx+1} [Trace: {r.attack_id}]</div>
                        <div class="payload-box">
                            <div class="payload-label">EXPLOIT PAYLOAD (PRECISE)</div>
                            <pre><code>{req}</code></pre>
                        </div>
                        <div class="payload-box" style="border-color: #22c55e33;">
                            <div class="payload-label" style="color:#22c55e;">SUCCESS INDICATOR (RESPONSE)</div>
                            <pre><code>{res}</code></pre>
                        </div>
                    </div>"""
                artifacts_html += "</div>"
            
            description = r.description or r.details or "No details provided."
            severity_color = "#ef4444" if r.severity in ["CRITICAL", "HIGH"] else "#f59e0b" if r.severity == "MEDIUM" else "#3b82f6"
            
            findings_html += f"""
            <div class="card finding-card border-{r.severity.lower()}">
                <div class="finding-header">
                    <div>
                        <div class="finding-type">{r.type.upper()}</div>
                        <div class="finding-meta">ID: {r.id} | Attack Context: {r.attack_id}</div>
                    </div>
                    <div class="severity-badge" style="background:{severity_color}22; color:{severity_color}; border: 1px solid {severity_color}44;">{r.severity}</div>
                </div>
                <div class="finding-body">
                    <p style="color:#94a3b8; font-size:1.1em; margin-bottom:20px;">{description}</p>
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:15px; margin-bottom:25px;">
                        <div class="meta-item"><b>STATUS:</b> <span style="color:#fff;">{r.status}</span></div>
                        <div class="meta-item"><b>CONFIDENCE:</b> <span style="color:#fff;">{r.confidence}</span></div>
                        <div class="meta-item"><b>CWE:</b> <span style="color:#fff;">{r.cwe}</span></div>
                        <div class="meta-item"><b>OWASP:</b> <span style="color:#fff;">{r.owasp}</span></div>
                    </div>
                    
                    <div class="remediation-box">
                        <div style="color:#a855f7; font-weight:bold; margin-bottom:8px; display:flex; align-items:center;">
                            <span style="margin-right:8px;">🛠️</span> REMEDIATION STRATEGY
                        </div>
                        <p style="margin:0; font-size:0.95em; color:#cbd5e1;">{r.remediation}</p>
                    </div>

                    {artifacts_html}
                </div>
            </div>"""

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BreakPoint Elite Audit - {self.target_url}</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #050508;
            --card-bg: #0c0c14;
            --accent: #a855f7;
            --text-main: #e2e8f0;
            --text-dim: #94a3b8;
            --border: #1e1e2e;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            background: var(--bg); 
            color: var(--text-main); 
            font-family: 'Plus Jakarta Sans', sans-serif; 
            padding: 50px 10%; 
            line-height: 1.6;
            background-image: radial-gradient(circle at 50% -20%, #a855f715, transparent);
        }}
        .header {{ 
            display: flex; 
            justify-content: space-between; 
            align-items: flex-end;
            margin-bottom: 60px;
            padding-bottom: 30px;
            border-bottom: 1px solid var(--border);
        }}
        h1 {{ font-size: 2.5rem; font-weight: 800; letter-spacing: -1px; background: linear-gradient(to right, #fff, var(--accent)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); overflow: hidden; }}
        
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 60px; }}
        .stat-card {{ padding: 30px; text-align: center; position: relative; }}
        .stat-card::after {{ content: ''; position: absolute; top: 20%; right: 0; height: 60%; width: 1px; background: var(--border); }}
        .stat-card:last-child::after {{ display: none; }}
        .stat-value {{ font-size: 3rem; font-weight: 800; color: var(--accent); line-height: 1; margin-bottom: 10px; }}
        .stat-label {{ font-size: 0.8rem; font-weight: 700; color: var(--text-dim); text-transform: uppercase; letter-spacing: 2px; }}

        .finding-card {{ margin-bottom: 40px; transition: transform 0.3s ease; }}
        .finding-card:hover {{ transform: scale(1.01); }}
        .finding-header {{ padding: 25px 35px; background: rgba(255,255,255,0.02); display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); }}
        .finding-type {{ font-size: 1.4rem; font-weight: 800; color: #fff; }}
        .finding-meta {{ font-size: 0.85rem; color: var(--text-dim); margin-top: 5px; }}
        .severity-badge {{ padding: 6px 14px; border-radius: 8px; font-size: 0.75rem; font-weight: 900; letter-spacing: 1px; }}
        
        .finding-body {{ padding: 35px; }}
        .meta-item {{ font-size: 0.9rem; color: var(--text-dim); }}
        .remediation-box {{ background: rgba(168, 85, 247, 0.05); border: 1px solid rgba(168, 85, 247, 0.15); padding: 20px; border-radius: 12px; margin-bottom: 30px; }}
        
        .evidence-section {{ margin-top: 30px; padding-top: 30px; border-top: 1px dashed var(--border); }}
        .artifact-card {{ background: #08080c; border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
        .artifact-header {{ font-size: 0.8rem; font-weight: 700; color: var(--accent); margin-bottom: 15px; border-bottom: 1px solid #1e1e2e; padding-bottom: 10px; }}
        
        .payload-box {{ margin-bottom: 15px; border-left: 3px solid var(--accent); background: #030305; padding: 15px; border-radius: 0 8px 8px 0; }}
        .payload-label {{ font-size: 0.7rem; font-weight: 800; color: var(--accent); margin-bottom: 8px; }}
        pre {{ font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; white-space: pre-wrap; word-break: break-all; color: #cbd5e1; }}
        
        .footer {{ text-align: center; margin-top: 100px; color: var(--text-dim); font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>BreakPoint <span style="font-weight:400; color:var(--text-dim);">Elite Audit</span></h1>
            <p style="color:var(--text-dim); margin-top:10px; font-weight:600;">TARGET: <span style="color:var(--accent);">{self.target_url}</span></p>
        </div>
        <div style="text-align:right;">
            <p style="color:var(--text-dim); font-size:0.9rem;">GENERATED ON</p>
            <p style="font-weight:700;">{self.timestamp}</p>
        </div>
    </div>

    <div class="card stats-grid">
        <div class="stat-card">
            <div class="stat-value">{stats['total']}</div>
            <div class="stat-label">Total Checks</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{stats['critical'] + stats['high']}</div>
            <div class="stat-label">High/Critical</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{stats['medium']}</div>
            <div class="stat-label">Medium Risk</div>
        </div>
        <div class="stat-card" style="border:none;">
            <div class="stat-value" style="color:#22c55e;">{stats['secure']}</div>
            <div class="stat-label">Secure Pass</div>
        </div>
    </div>

    <h2 style="margin-bottom:30px; font-weight:800; font-size:1.8rem;">Dossier of Findings ({len(v_results)})</h2>
    {findings_html if findings_html else '<div class="card" style="padding:50px; text-align:center;"><p style="font-size:1.2rem; color:var(--text-dim);">Excellent posture. No vulnerabilities detected in this vector.</p></div>'}

    <div class="footer">
        <p>BreakPoint Adversarial Logic Engine v4.0.0-Elite</p>
        <p style="margin-top:5px; opacity:0.5;">Proprietary & Confidential Audit Data</p>
    </div>
</body>
</html>
"""
        with open(output_file, 'w', encoding='utf-8') as f: f.write(html)
