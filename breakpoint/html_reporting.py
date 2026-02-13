import json
import datetime
from .metadata import get_metadata, SEVERITY_SCORES

class HtmlReporter:
    def __init__(self, filename="report.html"):
        self.filename = filename

    def generate(self, results, forensic_data):
        """
        Generates the Unified Comprehensive Report.
        Combines Executive Summary with Forensic/Technical Details.
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        passed = sum(1 for r in results if hasattr(r, 'status') and r.status in ["SECURE", "PASSED"])
        failed = sum(1 for r in results if hasattr(r, 'status') and r.status == "VULNERABLE")
        inconclusive = sum(1 for r in results if hasattr(r, 'status') and r.status in ["SKIPPED", "INCONCLUSIVE", "ERROR"])
        
        # TRUSTWORTHY SCORE: Only count valid tests (Passed + Failed)
        valid_total = passed + failed
        resilience_score = (passed / valid_total * 100) if valid_total > 0 else 0

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
             <h3>Severity Breakdown</h3>
             <small>Confirmed: {sum(1 for r in results if r.status == 'CONFIRMED')} | Suspect: {sum(1 for r in results if r.status == 'SUSPECT')}</small>
             <div style="margin-top: 10px;">
                <div style="height: 10px; background: #333; border-radius: 5px; overflow: hidden; display: flex;">
                    <div style="width: {resilience_score}%; background: var(--pass);"></div>
                    <div style="width: {100-resilience_score}%; background: var(--crit);"></div>
                </div>
             </div>
        </div>
             
             <div style="margin-top: 20px; border-top: 1px solid var(--border); padding-top: 10px; font-size: 0.8rem; opacity: 0.6;">
                <strong>Scoring Thresholds:</strong><br>
                CRITICAL (9.0-10.0) &bull; HIGH (7.0-8.9)<br>
                MEDIUM (4.0-6.9) &bull; LOW (0.1-3.9)
             </div>
        </div>
        
        <!-- ENGINE HEALTH CARD -->
        <div class="card">
            <h3>Engine Health</h3>
            <div style="font-size: 1.2rem; font-weight: bold; margin-bottom: 5px;">
                {'🔴 CRASHED' if any(r.id == 'SYSTEM_CRASH' for r in results) else '🟢 STABLE'}
            </div>
            <div style="opacity: 0.8; font-size: 0.9rem;">
                System Integrity
            </div>
             <div style="margin-top: 10px; font-size: 0.9rem; color: #888;">
                Errors: {sum(1 for r in results if r.status == 'ERROR' and r.id != 'SYSTEM_CRASH')}
            </div>
        </div>
    </div>
    """

    
        # COMPLIANCE CALCULATIONS
        compliance_map = {
            "OWASP_2021": {"tested": set(), "failed": set()},
            "NIST_800_53": {"tested": set(), "failed": set()},
            "PCI_DSS_4.0": {"tested": set(), "failed": set()}
        }
        
        for r in results:
            atype = r.type if hasattr(r, 'type') else r.get("attack_type", "unknown")
            meta = get_metadata(atype)
            comp_data = meta.get("compliance", {})
            
            # Count anything not explicitly SECURE/PASSED as a fail for compliance visibility unless skipped
            is_fail = (r.status in ["VULNERABLE", "CONFIRMED", "SUSPECT"])
            
            for std, control in comp_data.items():
                if std in compliance_map:
                    compliance_map[std]["tested"].add(control)
                    if is_fail:
                        compliance_map[std]["failed"].add(control)

        # Generate Compliance HTML
        compliance_html = """
        <h2>⚖️ Compliance Lens (Beta)</h2>
        <div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));">
        """
        
        for std, data in compliance_map.items():
            total = len(data["tested"])
            failed = len(data["failed"])
            passed = total - failed
            score = 100
            if total > 0:
                score = (passed / total) * 100
            
            # Icon selection
            icon = "🛡️"
            if std == "OWASP_2021": icon = "🦉"
            if std == "PCI_DSS_4.0": icon = "💳"
            if std == "NIST_800_53": icon = "🏛️"

            # Create failure list HTML safely
            fail_list_html = ""
            if failed > 0:
                fails = ", ".join(list(data["failed"])[:5])
                if len(data['failed']) > 5: fails += "..."
                fail_list_html = f'<div style="color: var(--crit);">❌ Failed: {fails}</div>'
            else:
                fail_list_html = '<div style="color: var(--pass);">✅ All Mapped Controls Passed</div>'

            compliance_html += f"""
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h3 style="margin:0;">{icon} {std.replace('_', ' ')}</h3>
                    <div style="font-size: 1.2rem; font-weight: bold; color: {'var(--pass)' if score == 100 else 'var(--crit)'};">
                        {score:.0f}%
                    </div>
                </div>
                <div style="font-size: 0.9rem; opacity: 0.8; margin-bottom: 8px;">
                     Controls Tested: <strong>{total}</strong>
                </div>
                 <div style="height: 6px; background: #333; border-radius: 3px; overflow: hidden; display: flex; margin-bottom: 15px;">
                    <div style="width: {score}%; background: var(--pass);"></div>
                    <div style="width: {100-score}%; background: var(--crit);"></div>
                </div>
                
                <div style="font-size: 0.85rem;">
                    {fail_list_html}
                </div>
            </div>
            """
        compliance_html += "</div>"
    
        html += compliance_html
        
        html += """
    <!-- CRITICAL FINDINGS SECTION -->
    <h2>🔥 Critical Findings</h2>
    """
    
        vulnerabilities = [r for r in results if r.status in ["VULNERABLE", "CONFIRMED", "SUSPECT"]]
        
        if not vulnerabilities:
             html += """<div class="card" style="text-align: center; color: var(--pass);"><h3>✅ No Critical Vulnerabilities Found</h3></div>"""
        else:
            for r in vulnerabilities:
                atype = r.type if hasattr(r, 'type') else r.get("attack_type", "unknown")
                sev = r.severity if hasattr(r, 'severity') and r.severity else "HIGH"
                scenario_id = r.id if hasattr(r, 'id') else r.get("scenario_id", "unknown")
                
                # Metadata & Details Parsing
                try: meta = get_metadata(atype)
                except: meta = {"name": atype, "severity": sev, "description": f"Vulnerability detected in {atype}"}
                
                # Parse Details
                import ast
                raw_details = r.details if hasattr(r, 'details') else r.get("details", "")
                final_details = raw_details
                if isinstance(raw_details, str) and raw_details.startswith("{"):
                    try: final_details = ast.literal_eval(raw_details)
                    except: pass
                
                issues = []
                leaked = []
                if isinstance(final_details, dict):
                    issues = final_details.get("issues", [])
                    leaked = final_details.get("leaked_data", [])
                    if isinstance(issues, str): issues = [issues]
                    if not issues and not leaked: issues = [str(final_details)]
                else:
                    issues = [str(final_details)]

                leaked_section = ""
                if leaked:
                    joined_leaked = "\n".join(str(l) for l in leaked)
                    leaked_section = f'''
                    <div class="leak-box">
                        <div class="leak-head">⚠️ EXFILTRATED EVIDENCE / LEAKED DATA</div>
                        <pre>{joined_leaked}</pre>
                    </div>'''
                
                issues_section = ""
                if issues:
                     issues_list = "".join(f"<li>{i}</li>" for i in issues)
                     issues_section = f"<ul style='margin-bottom: 0;'>{issues_list}</ul>"

                # Compliance Badges
                comp_badges = ""
                comp_data = meta.get("compliance", {})
                if comp_data:
                    comp_badges = "<div style='margin-top: 8px; margin-bottom: 12px; display: flex; gap: 8px; flex-wrap: wrap;'>"
                    for std, code in comp_data.items():
                        short_std = std.split('_')[0]
                        comp_badges += f"<span style='background: rgba(88, 166, 255, 0.15); color: #58a6ff; border: 1px solid rgba(88, 166, 255, 0.3); padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-family: monospace;'><strong>{short_std}</strong> {code}</span>"
                    comp_badges += "</div>"

                html += f"""
            <div class="finding">
                <div class="finding-head">
                    <span class="badge bg-{sev}">{sev}</span>
                    <strong>{meta.get('name', atype)}</strong>
                    <span style="margin-left: auto; opacity: 0.6; font-size: 0.8rem;">{scenario_id}</span>
                </div>
                <div class="finding-body">
                    <p style="margin-top: 0; margin-bottom: 5px;">{meta.get('description', '')}</p>
                    {comp_badges}
                    {leaked_section}
                    <details open>
                        <summary>Technical Details</summary>
                        {issues_section}
                    </details>
                </div>
            </div>
            """

        # FULL AUDIT LOG
        html += """
        <h2 style="margin-top: 60px;">📋 Full Audit Log</h2>
        <div class="card" style="padding: 0; overflow: hidden;">
            <table style="width: 100%; border-collapse: collapse; font-size: 0.9rem;">
                <thead>
                    <tr style="background: rgba(255,255,255,0.05); text-align: left; border-bottom: 1px solid var(--border);">
                        <th style="padding: 12px 20px;">ID</th>
                        <th style="padding: 12px 20px;">Type</th>
                        <th style="padding: 12px 20px;">Status</th>
                        <th style="padding: 12px 20px;">Details</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for r in results:
            status = r.status
            color_style = ""
            if status == "CONFIRMED": color_style = "color: var(--crit); font-weight: bold; text-shadow: 0 0 10px rgba(218, 54, 51, 0.4);"
            elif status == "SUSPECT": color_style = "color: var(--high); font-weight: bold;"
            elif status == "VULNERABLE": color_style = "color: var(--crit);" # Legacy/Unverified
            elif status == "PASSED": color_style = "color: var(--pass);"
            elif status == "SKIPPED": color_style = "color: #888;"
            elif status == "SECURE": color_style = "color: var(--pass);"
            
            # Clean details for table
            d_txt = str(r.details)
            if len(d_txt) > 100: d_txt = d_txt[:100] + "..."
            
            html += f"""
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <td style="padding: 10px 20px; font-family: monospace;">{r.id}</td>
                    <td style="padding: 10px 20px;">{r.type}</td>
                    <td style="padding: 10px 20px; {color_style}">{status}</td>
                    <td style="padding: 10px 20px; opacity: 0.7;">{d_txt}</td>
                </tr>
            """
            
        html += """
                </tbody>
            </table>
        </div>

    <div style="text-align: center; margin-top: 50px; opacity: 0.5; font-size: 0.8rem;">
        Generated by BREAKPOINT v3.0.0-ELITE. contains sensitive vulnerability data. 
    </div>
</body>
</html>
"""
        with open(self.filename, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"Report generated: {self.filename}")
