import json
import datetime
from .metadata import get_metadata, SEVERITY_SCORES

class HtmlReporter:
    def __init__(self, filename="report.html"):
        self.filename = filename

    def generate(self, results, damage_estimate, forensic_data):
        """
        Generates the Unified Comprehensive Report.
        Combines Executive Summary with Forensic/Technical Details.
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        total = len(results)
        passed = sum(1 for r in results if r.get("passed"))
        failed = total - passed
        resilience_score = (passed / total * 100) if total > 0 else 0

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>BREAKPOINT — Comprehensive Audit</title>
    <style>
        :root {{ --bg: #0f1115; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --crit: #da3633; --high: #d29922; --pass: #238636; --leak: #d2a8ff; }}
        body {{ font-family: 'Segoe UI', Inter, sans-serif; background: var(--bg); color: var(--text); padding: 40px; margin: 0; }}
        h1, h2, h3 {{ margin-top: 0; color: #fff; }}
        
        .header {{ border-bottom: 2px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: end; }}
        .header h1 {{ font-size: 2.5rem; margin: 0; }}
        .meta {{ font-family: monospace; opacity: 0.7; font-size: 0.9rem; text-align: right; }}
        
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 40px; }}
        .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 20px; }}
        
        .score {{ font-size: 3rem; font-weight: 800; }}
        .pass-col {{ color: var(--pass); }}
        .fail-col {{ color: var(--crit); }}
        
        .finding {{ margin-bottom: 20px; background: var(--card); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }}
        .finding-head {{ padding: 15px; background: rgba(255,255,255,0.03); display: flex; align-items: center; border-bottom: 1px solid var(--border); }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; margin-right: 10px; color: #fff; }}
        .bg-CRITICAL {{ background: var(--crit); }}
        .bg-HIGH {{ background: var(--high); }}
        .bg-MEDIUM {{ background: #ffc107; color: #000; }}
        .finding-body {{ padding: 15px; }}
        
        .leak-box {{ margin-top: 15px; border: 1px dashed var(--leak); background: rgba(210, 168, 255, 0.05); padding: 10px; }}
        .leak-head {{ color: var(--leak); font-weight: bold; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; }}
        pre {{ background: #0d1117; padding: 10px; overflow-x: auto; border-radius: 4px; border: 1px solid var(--border); margin: 0; font-family: 'Courier New', monospace; font-size: 0.9rem; }}
        
        details summary {{ cursor: pointer; color: var(--accent); margin-top: 10px; font-weight: 600; }}
    </style>
</head>
<body>

    <div class="header">
        <div>
            <h1>BREAKPOINT // REPORT</h1>
            <div style="color: var(--crit); font-weight: bold; margin-top: 5px;">CONFIDENTIAL SECURITY AUDIT</div>
        </div>
        <div class="meta">
            <div>Target: {forensic_data['target']}</div>
            <div>Run By: {forensic_data['run_id']}</div>
            <div>{timestamp}</div>
            <div title="{forensic_data['signature']}">Sig: {forensic_data['signature'][:16]}...</div>
        </div>
    </div>

    <!-- METRICS -->
    <div class="grid">
        <div class="card" style="text-align: center;">
            <h3>Resilience Score</h3>
            <div class="score { 'pass-col' if resilience_score > 80 else 'fail-col' }">
                {resilience_score:.1f}%
            </div>
        </div>
        <div class="card">
            <h3>Damage Assessment</h3>
            <div style="font-size: 1.5rem; color: var(--crit); font-weight: bold; margin-bottom: 5px;">
                {damage_estimate['total_estimated_damage']}
            </div>
            <div style="opacity: 0.8; font-size: 0.9rem;">
                Est. Financial Liability
            </div>
            <div style="margin-top: 10px; font-size: 0.9rem;">
                Downtime: <strong>{damage_estimate['downtime_minutes']} min</strong>
            </div>
        </div>
        <div class="card">
             <h3>Severity Breakdown</h3>
             <small>Failed Scenarios: {failed}</small>
             <div style="margin-top: 10px;">
                <!-- Simple bar viz -->
                <div style="height: 10px; background: #333; border-radius: 5px; overflow: hidden; display: flex;">
                    <div style="width: {resilience_score}%; background: var(--pass);"></div>
                    <div style="width: {100-resilience_score}%; background: var(--crit);"></div>
                </div>
             </div>
        </div>
    </div>
    
    <h2>Findings</h2>
    """
    
        for r in results:
            if not r.get("passed"):
                atype = r.get("attack_type", "unknown")
                meta = get_metadata(atype)
                details = r.get("details", {})
                
                if isinstance(details, dict):
                    leaked = details.get("leaked_data", [])
                    issues = details.get("issues", [])
                else:
                    leaked = []
                    issues = [str(details)]
                
                html += f"""
        <div class="finding">
            <div class="finding-head">
                <span class="badge bg-{meta['severity']}">{meta['severity']}</span>
                <strong>{meta['name']}</strong>
                <span style="margin-left: auto; opacity: 0.6; font-size: 0.8rem;">{r['scenario_id']}</span>
            </div>
            <div class="finding-body">
                <p style="margin-top: 0;">{meta['description']}</p>
                
                <!-- LEAKED DATA (FORENSIC PROOF) -->
                { f'''
                <div class="leak-box">
                    <div class="leak-head">⚠️ EXFILTRATED EVIDENCE</div>
                    <pre>{'\\n'.join(str(l) for l in leaked)}</pre>
                </div>
                ''' if leaked else '' }
                
                <details open>
                    <summary>Technical Details</summary>
                    <ul style="margin-bottom: 0;">{''.join(f'<li>{i}</li>' for i in issues)}</ul>
                </details>
            </div>
        </div>
        """
        
        html += """
    <div style="text-align: center; margin-top: 50px; opacity: 0.5; font-size: 0.8rem;">
        Generated by BREAKPOINT v2.0-ELITE. contains sensitive vulnerability data. 
    </div>
</body>
</html>
"""
        with open(self.filename, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"Report generated: {self.filename}")
