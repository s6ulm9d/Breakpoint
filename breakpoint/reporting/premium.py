import json
import datetime
import os
from typing import List, Dict, Any, Optional
from ..models import CheckResult, VulnerabilityStatus

class PremiumReportGenerator:
    """
    Premium Corporate-Grade Reporting Engine for BREAKPOINT.
    Implements the 'Shannon' structured reporting architecture with professional aesthetics.
    """
    def __init__(self, engine_instance):
        self.engine = engine_instance
        self.base_url = getattr(engine_instance, 'base_url', 'http://juice-shop.sandbox.local:3001')
        self.timestamp = datetime.datetime.now().strftime("%B %Y")
        self.full_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.results = []
        self.scan_id = getattr(engine_instance, 'scan_id', "BRK-" + datetime.datetime.now().strftime("%Y%m%d%H%M%S"))

    def generate(self, results: List[CheckResult], output_file: str):
        self.results = results
        
        # Categorize results for sections
        categorized = self._categorize_results(results)
        
        # Section data preparation
        sections = {
            "metadata": self._get_metadata(),
            "summary": self._get_summary_stats(results, categorized),
            "vulnerabilities": categorized
        }

        html_content = self._render_html(sections)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file

    def _get_metadata(self) -> Dict[str, Any]:
        # Derive a human-readable name from the URL or source path
        target_name = self.base_url
        if hasattr(self.engine, 'source_path') and self.engine.source_path:
            target_name = os.path.basename(self.engine.source_path.rstrip('/'))
        
        # Fallback if URL is generic localhost
        if "localhost" in target_name.lower() or "127.0.0.1" in target_name.lower():
            if hasattr(self.engine, 'source_path') and self.engine.source_path:
                target_name = os.path.basename(self.engine.source_path.rstrip('/'))
            else:
                target_name = self.base_url.replace("http://", "").replace("https://", "").split(":")[0]

        return {
            "target": target_name or "Standard Target",
            "date": self.timestamp,
            "full_date": self.full_timestamp,
            "scan_id": self.scan_id
        }

    def _categorize_results(self, results: List[CheckResult]) -> Dict[str, List[CheckResult]]:
        mapping = {
            "Authentication": ["auth", "login", "brute", "credential", "jwt", "password", "session", "oauth"],
            "Authorization": ["idor", "access_control", "tenant", "privilege", "role", "permissions", "acl", "bypass"],
            "Injection": ["sqli", "sql", "nosql", "command", "rce", "ssti", "xxe", "yaml", "injection", "blind", "time", "os_", "eval", "pickle", "deserialization", "path_traversal", "lfi", "rfi"],
            "XSS": ["xss", "cross-site", "scripting", "jsonp", "reflected", "stored", "dom_"],
            "SSRF": ["ssrf", "internal_scan", "request_forgery", "metadata"]
        }
        
        categorized = {k: [] for k in mapping.keys()}
        categorized["Miscellaneous"] = []
        
        for r in results:
            found = False
            r_type_lower = r.type.lower()
            for cat, keywords in mapping.items():
                if any(kw in r_type_lower for kw in keywords):
                    categorized[cat].append(r)
                    found = True
                    break
            if not found:
                categorized["Miscellaneous"].append(r)
                
        return categorized

    def _get_summary_stats(self, results: List[CheckResult], categorized: Dict[str, List[CheckResult]]) -> Dict[str, Any]:
        findings = [r for r in results if r.status not in ["SECURE", "SKIPPED", "ERROR", "INCONCLUSIVE"]]
        
        stats = {
            "total": len(findings),
            "counts": {
                "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
            },
            "highest_risk": "No major risks identified."
        }
        
        for r in findings:
            stats["counts"][r.severity.upper()] = stats["counts"].get(r.severity.upper(), 0) + 1
            
        # Add category summaries for the breakdown section
        for cat, recs in categorized.items():
            valid_recs = [r for r in recs if r.status not in ["SECURE", "SKIPPED", "ERROR", "INCONCLUSIVE"]]
            if valid_recs:
                top_sev = "LOW"
                sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                top_r = sorted(valid_recs, key=lambda x: sev_map.get(x.severity.upper(), 0), reverse=True)[0]
                stats[cat] = f"{len(valid_recs)} findings including {top_r.severity} severity vulnerabilities. Detailed exploitation evidence provided below."
            else:
                stats[cat] = "No findings identified in this category."

        if findings:
            sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            sorted_findings = sorted(findings, key=lambda x: sev_map.get(x.severity.upper(), 0), reverse=True)
            top = sorted_findings[0]
            stats["highest_risk"] = f"{top.type.replace('_', ' ').upper()}: {top.description or top.details}"
            if len(stats["highest_risk"]) > 150:
                stats["highest_risk"] = stats["highest_risk"][:147] + "..."
                
        return stats

    def _render_html(self, sections: Dict[str, Any]) -> str:
        style = """
        :root {
            /* Color Palette - Professional Slate & Steel */
            --color-bg: #f1f5f9;
            --color-surface: #ffffff;
            --color-surface-dim: #f8fafc;
            --color-text-primary: #0f172a;
            --color-text-secondary: #334155;
            --color-text-muted: #64748b;
            --color-accent: #1e293b;
            --color-border: #e2e8f0;
            --color-border-soft: #f1f5f9;
            
            /* Functional Colors */
            --color-critical: #991b1b;
            --color-critical-bg: #fef2f2;
            --color-high: #9a3412;
            --color-high-bg: #fff7ed;
            --color-medium: #92400e;
            --color-medium-bg: #fffbeb;
            --color-low: #166534;
            --color-low-bg: #f0fdf4;
            --color-info: #0369a1;
            --color-info-bg: #f0f9ff;
            
            /* Spacing System */
            --space-1: 0.25rem;
            --space-2: 0.5rem;
            --space-3: 0.75rem;
            --space-4: 1rem;
            --space-6: 1.5rem;
            --space-8: 2rem;
            --space-10: 2.5rem;
            --space-12: 3rem;
            --space-16: 4rem;
            
            /* Component Radius */
            --radius-sm: 4px;
            --radius-md: 8px;
            --radius-lg: 12px;
            
            /* Shadow */
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body { 
            background: var(--color-bg); 
            color: var(--color-text-primary); 
            font-family: 'Inter', system-ui, -apple-system, sans-serif; 
            line-height: 1.6; 
            font-size: 15px;
            -webkit-font-smoothing: antialiased;
        }
        
        .container {
            max-width: 1000px;
            margin: var(--space-8) auto;
            background: var(--color-surface);
            padding: var(--space-12) var(--space-16);
            box-shadow: var(--shadow-md);
            border-radius: var(--radius-lg);
        }
        
        header { 
            border-bottom: 3px solid var(--color-text-primary); 
            padding-bottom: var(--space-6); 
            margin-bottom: var(--space-10); 
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }
        
        h1 { font-size: 2.5rem; font-weight: 800; letter-spacing: -0.03em; color: var(--color-text-primary); }
        h2 { font-size: 1.75rem; font-weight: 700; color: var(--color-text-primary); margin: var(--space-12) 0 var(--space-6) 0; border-bottom: 2px solid var(--color-border-soft); padding-bottom: var(--space-2); }
        h3 { font-size: 1.25rem; font-weight: 600; color: var(--color-accent); margin: var(--space-8) 0 var(--space-4) 0; }
        
        /* Table of Contents */
        .toc {
            background: var(--color-surface-dim);
            padding: var(--space-6);
            border-radius: var(--radius-md);
            margin-bottom: var(--space-10);
            border: 1px solid var(--color-border);
        }
        .toc h4 { font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--color-text-muted); margin-bottom: var(--space-3); }
        .toc ul { list-style: none; display: grid; grid-template-columns: repeat(2, 1fr); gap: var(--space-2); }
        .toc a { text-decoration: none; color: var(--color-info); font-size: 0.9rem; font-weight: 500; }
        .toc a:hover { text-decoration: underline; }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: var(--space-4);
            margin-bottom: var(--space-10);
        }
        
        .stat-card {
            background: var(--color-surface);
            padding: var(--space-4);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-md);
            text-align: center;
            box-shadow: var(--shadow-sm);
        }
        .stat-card .label { font-size: 0.75rem; font-weight: 600; color: var(--color-text-muted); text-transform: uppercase; margin-bottom: var(--space-1); }
        .stat-card .value { font-size: 1.5rem; font-weight: 800; }

        .vuln-card {
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-lg);
            margin-bottom: var(--space-8);
            overflow: hidden;
            box-shadow: var(--shadow-sm);
        }
        
        .vuln-header {
            padding: var(--space-4) var(--space-6);
            background: var(--color-surface-dim);
            border-bottom: 1px solid var(--color-border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .vuln-title { font-size: 1.1rem; font-weight: 700; color: var(--color-text-primary); text-transform: uppercase; }
        
        .severity-badge {
            padding: var(--space-1) var(--space-3);
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 800;
            text-transform: uppercase;
        }
        
        .vuln-body { padding: var(--space-6); }
        
        .meta-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: var(--space-6);
            margin-bottom: var(--space-6);
            padding-bottom: var(--space-6);
            border-bottom: 1px solid var(--color-border-soft);
        }
        
        .meta-item .label { font-size: 0.7rem; font-weight: 700; color: var(--color-text-muted); text-transform: uppercase; margin-bottom: var(--space-1); }
        .meta-item .value { font-size: 0.9rem; font-weight: 600; color: var(--color-text-secondary); }
        
        .code-block {
            background: #0f172a;
            color: #e2e8f0;
            padding: var(--space-4);
            border-radius: var(--radius-md);
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.85rem;
            overflow-x: auto;
            margin-top: var(--space-2);
            border: 1px solid #1e293b;
            line-height: 1.5;
        }
        
        .evidence-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: var(--space-4);
            margin-top: var(--space-4);
        }
        
        .remediation-box {
            background: var(--color-info-bg);
            color: var(--color-info);
            padding: var(--space-4);
            border-radius: var(--radius-md);
            margin-top: var(--space-6);
            font-size: 0.9rem;
            border-left: 4px solid var(--color-info);
        }

        .confidence-bar-container {
            width: 100%;
            height: 6px;
            background: var(--color-border-soft);
            border-radius: 3px;
            margin-top: var(--space-2);
            overflow: hidden;
        }
        .confidence-bar-fill {
            height: 100%;
            background: var(--color-info);
            transition: width 0.5s ease-in-out;
        }

        .verification-callout {
            background: var(--color-high-bg);
            border: 1px dashed var(--color-high);
            color: var(--color-high);
            padding: var(--space-3);
            border-radius: var(--radius-md);
            font-size: 0.85rem;
            margin-bottom: var(--space-4);
            font-weight: 500;
        }

        .footer { 
            text-align: center; 
            margin-top: var(--space-16); 
            padding-top: var(--space-8); 
            border-top: 1px solid var(--color-border); 
            color: var(--color-text-muted); 
            font-size: 0.75rem; 
        }
        
        @media (min-width: 768px) {
            .evidence-grid { grid-template-columns: 1fr 1fr; }
        }

        @media print {
            body { background: white; font-size: 11pt; }
            .container { box-shadow: none; border: none; max-width: 100%; margin: 0; padding: 0.5in; }
            .vuln-card { break-inside: avoid; border: 1px solid #ccc; }
        }
        """


        # Generate HTML sections
        metadata = sections["metadata"]
        summary = sections["summary"]
        vulnerabilities = sections["vulnerabilities"]

        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Assessment Report: {metadata['target']}</title>
            <style>{style}</style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>Security Audit Report</h1>
                    <div style="text-align: right; color: var(--color-text-muted); font-size: 0.8rem;">
                        Scan ID: {metadata['scan_id']}<br>
                        {metadata['full_date']}
                    </div>
                </header>

                <section id="executive-summary">
                    <h2>Executive Summary</h2>
                    
                    <div style="margin-bottom: var(--space-8); display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-8);">
                        <div>
                            <p style="font-size: 0.75rem; font-weight: 700; color: var(--color-text-muted); text-transform: uppercase;">Assessment Target</p>
                            <p style="font-size: 1.25rem; font-weight: 700; color: var(--color-text-primary);">{metadata['target']}</p>
                        </div>
                        <div>
                            <p style="font-size: 0.75rem; font-weight: 700; color: var(--color-text-muted); text-transform: uppercase;">Report Date</p>
                            <p style="font-size: 1.25rem; font-weight: 700; color: var(--color-text-primary);">{metadata['date']}</p>
                        </div>
                    </div>

                    <div class="toc">
                        <h4>Table of Contents</h4>
                        <ul>
                            <li><a href="#summary-stats">Risk Summary</a></li>
                            {"".join([f'<li><a href="#{cat.lower().replace(" ", "-")}">Findings: {cat}</a></li>' for cat in vulnerabilities.keys() if vulnerabilities[cat]])}
                        </ul>
                    </div>

                    <h3 id="summary-stats">Advisory Risk Summary</h3>
                    <div class="summary-grid">
                        <div class="stat-card">
                            <div class="label">Total Findings</div>
                            <div class="value">{summary['total']}</div>
                        </div>
                        <div class="stat-card" style="border-top: 4px solid var(--color-critical);">
                            <div class="label" style="color: var(--color-critical);">Critical</div>
                            <div class="value">{summary['counts']['CRITICAL']}</div>
                        </div>
                        <div class="stat-card" style="border-top: 4px solid var(--color-high);">
                            <div class="label" style="color: var(--color-high);">High</div>
                            <div class="value">{summary['counts']['HIGH']}</div>
                        </div>
                        <div class="stat-card" style="border-top: 4px solid var(--color-medium);">
                            <div class="label" style="color: var(--color-medium);">Medium</div>
                            <div class="value">{summary['counts']['MEDIUM']}</div>
                        </div>
                        <div class="stat-card" style="border-top: 4px solid var(--color-low);">
                            <div class="label" style="color: var(--color-low);">Low</div>
                            <div class="value">{summary['counts']['LOW']}</div>
                        </div>
                        <div class="stat-card" style="border-top: 4px solid var(--color-info);">
                            <div class="label" style="color: var(--color-info);">Info</div>
                            <div class="value">{summary['counts']['INFO']}</div>
                        </div>
                    </div>

                    <div style="background: var(--color-surface-dim); padding: var(--space-6); border-radius: var(--radius-md); border-left: 4px solid var(--color-critical); margin-bottom: var(--space-12);">
                        <p style="font-size: 0.75rem; color: var(--color-text-muted); font-weight: 700; text-transform: uppercase;">Highest Risk Detected</p>
                        <p style="color: var(--color-critical); font-weight: 800; font-size: 1.1rem; margin-top: var(--space-1);">{summary['highest_risk']}</p>
                    </div>
                <section id="detailed-findings">
                    <h2>Detailed Audit Findings</h2>
                    
                    {"".join([f'''
                    <section id="{cat.lower().replace(" ", "-")}" style="margin-top: var(--space-8);">
                        <h3 style="border-left: 4px solid var(--color-accent); padding-left: var(--space-3);">{cat} Findings</h3>
                        {self._render_exploitation_records(vulnerabilities.get(cat, []), cat)}
                    </section>
                    ''' for cat in vulnerabilities.keys() if vulnerabilities[cat]])}
                </section>

                <div class="footer">
                    BREAKPOINT AUDIT ENGINE | {metadata['scan_id']} | {metadata['full_date']}
                </div>
            </div>
        </body>
        </html>
        """
        return html

    def _render_exploitation_records(self, records: List[CheckResult], category: str) -> str:
        records = [r for r in records if r.status not in ["SECURE", "SKIPPED", "ERROR", "INCONCLUSIVE"]]
        if not records:
            return "<p style='color: var(--color-text-muted); font-style: italic; font-size: 0.9rem;'>No vulnerabilities identified in this category.</p>"
            
        from ..engine import ATTACK_IMPACTS
        html = f'<div id="{category.lower().replace(" ", "-")}">'
        for r in records:
            # Visual distinction for unverified findings
            is_muted = not r.is_verified and r.confidence_score < 0.5
            sev_class = f"sev-{r.severity.lower()}"
            card_style = "opacity: 0.7; border-left: 4px solid #cbd5e1;" if is_muted else f"border-left: 4px solid var(--color-{r.severity.lower()});"
            
            # Evidence extraction
            payload = "N/A"
            response = "N/A"
            if r.artifacts:
                for art in r.artifacts:
                    if art.get("payload") and art.get("payload") != "N/A":
                        payload = art.get("payload")
                    if art.get("response") and art.get("response") != "N/A":
                        response = art.get("response")
            
            impact_confirmation = response or "Not captured — payload delivered, response not conclusive"
            tech_summary = r.description or ATTACK_IMPACTS.get(r.type, 'Technical vulnerability identified.')
            
            conf_percent = int(getattr(r, 'confidence_score', 0.5) * 100)
            conf_label = "Confirmed" if r.is_verified else r.confidence
            
            # Verification Callout
            verification_html = ""
            if getattr(r, 'verification_msg', None):
                verification_html = f'''
                <div class="verification-callout">
                    <strong>Exploit Proof:</strong> {r.verification_msg}
                </div>
                '''

            html += f"""
            <div class="vuln-card" style="{card_style}">
                <div class="vuln-header">
                    <div>
                        <span class="vuln-title">{r.type.replace('_', ' ').upper()}</span>
                        {f'<span style="margin-left: 10px; background: var(--color-high); color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.65rem; vertical-align: middle;">VERIFIED EXPLOIT</span>' if r.is_verified else ''}
                    </div>
                    <div>
                        {f'<span style="font-size: 0.7rem; color: var(--color-text-muted); margin-right: var(--space-2);">[{r.status}]</span>' if is_muted else ''}
                        <span class="severity-badge {sev_class}">{r.severity}</span>
                    </div>
                </div>

                <div class="vuln-body">
                    {verification_html}
                    
                    <p style="font-weight: 500; font-size: 1rem; color: var(--color-text-primary); margin-bottom: var(--space-4);">{tech_summary}</p>

                    <div class="meta-grid">
                        <div class="meta-item">
                            <div class="label">Affected Endpoint</div>
                            <div class="value">{r.method} {r.endpoint}</div>
                        </div>
                        <div class="meta-item">
                            <div class="label">Vulnerable Parameter</div>
                            <div class="value" style="font-family: monospace; color: var(--color-critical);">{r.parameter}</div>
                        </div>
                        <div class="meta-item">
                            <div class="label">Confidence Score ({conf_label})</div>
                            <div class="value">
                                {conf_percent}%
                                <div class="confidence-bar-container">
                                    <div class="confidence-bar-fill" style="width: {conf_percent}%; background: {'var(--color-critical)' if conf_percent >= 90 else ('var(--color-high)' if conf_percent >= 70 else 'var(--color-info)')}"></div>
                                </div>
                            </div>
                        </div>
                        <div class="meta-item">
                            <div class="label">Standards & Mapping</div>
                            <div class="value">{r.cwe} | {r.owasp}</div>
                        </div>
                    </div>

                    <div class="evidence-grid">
                        <div>
                            <p style="font-size: 0.7rem; font-weight: 700; color: var(--color-text-muted); text-transform: uppercase;">Reproduction Payload</p>
                            <div class="code-block">{payload}</div>
                        </div>
                        <div>
                            <p style="font-size: 0.7rem; font-weight: 700; color: var(--color-text-muted); text-transform: uppercase;">Verification Evidence</p>
                            <div class="code-block">{str(impact_confirmation)[:800] + ('...' if len(str(impact_confirmation)) > 800 else '')}</div>
                        </div>
                    </div>

                    <div class="remediation-box">
                        <p style="font-weight: 700; margin-bottom: 2px;">Recommendation</p>
                        {r.remediation}
                    </div>
                </div>
            </div>
            """
        html += '</div>'
        return html
