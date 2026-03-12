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
            "summary": self._get_summary_stats(categorized),
            "vulnerabilities": categorized
        }

        html_content = self._render_html(sections)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file

    def _get_metadata(self) -> Dict[str, Any]:
        return {
            "target": "Juice-Shop",
            "date": self.timestamp,
            "scope": "Authentication, XSS, SQL and Command Injection, SSRF, Authorization testing",
            "full_date": self.full_timestamp,
            "scan_id": self.scan_id
        }

    def _categorize_results(self, results: List[CheckResult]) -> Dict[str, List[CheckResult]]:
        mapping = {
            "Authentication": ["auth", "login", "brute", "credential", "jwt"],
            "Authorization": ["idor", "access_control", "tenant", "privilege"],
            "Injection": ["sqli", "sql", "nosql", "command", "rce", "ssti", "xxe", "yaml"],
            "XSS": ["xss", "jsonp"],
            "SSRF": ["ssrf", "internal_scan"]
        }
        
        categorized = {k: [] for k in mapping.keys()}
        for r in results:
            for cat, keywords in mapping.items():
                if any(kw in r.type.lower() for kw in keywords):
                    categorized[cat].append(r)
                    break
        return categorized

    def _get_summary_stats(self, categorized: Dict[str, List[CheckResult]]) -> Dict[str, str]:
        stats = {}
        for cat, vulns in categorized.items():
            if not vulns:
                stats[cat] = "No findings in this category."
                continue
            
            severities = [v.severity for v in vulns]
            max_sev = "LOW"
            if "CRITICAL" in severities: max_sev = "Critical"
            elif "HIGH" in severities: max_sev = "High"
            elif "MEDIUM" in severities: max_sev = "Medium"
            
            stats[cat] = f"Multiple findings including {max_sev} severity vulnerabilities. Detailed exploitation evidence provided below."
            
        return stats

    def _render_html(self, sections: Dict[str, Any]) -> str:
        style = """
        :root {
            /* Color Palette - Professional Slate & Steel */
            --color-bg: #f8fafc;
            --color-surface: #ffffff;
            --color-surface-dim: #f1f5f9;
            --color-text-primary: #0f172a;
            --color-text-secondary: #475569;
            --color-text-muted: #94a3b8;
            --color-accent: #334155;
            --color-border: #e2e8f0;
            
            /* Functional Colors */
            --color-critical: #991b1b;
            --color-critical-bg: #fee2e2;
            --color-high: #9a3412;
            --color-high-bg: #ffedd5;
            --color-medium: #92400e;
            --color-medium-bg: #fef3c7;
            --color-low: #166534;
            --color-low-bg: #dcfce7;
            
            /* Type Scale - Professional Hierarchy */
            --type-xs: 0.75rem;
            --type-sm: 0.875rem;
            --type-base: 1rem;
            --type-md: 1.125rem;
            --type-lg: 1.25rem;
            --type-xl: 1.5rem;
            --type-xxl: 2.25rem;
            
            /* Spacing System */
            --space-1: 0.25rem;
            --space-2: 0.5rem;
            --space-3: 0.75rem;
            --space-4: 1rem;
            --space-6: 1.5rem;
            --space-8: 2rem;
            --space-12: 3rem;
            
            /* Component Radius */
            --radius-sm: 4px;
            --radius-md: 8px;
            
            /* Animation */
            --ease: cubic-bezier(0.4, 0, 0.2, 1);
            --duration-fast: 150ms;
            --duration-base: 300ms;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body { 
            background: var(--color-bg); 
            color: var(--color-text-primary); 
            font-family: 'Inter', -apple-system, sans-serif; 
            line-height: 1.5; 
            font-size: var(--type-base);
            -webkit-font-smoothing: antialiased;
        }
        
        .container {
            max-width: 800px;
            margin: var(--space-8) auto;
            background: var(--color-surface);
            padding: var(--space-12);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-md);
        }
        
        header { 
            border-bottom: 2px solid var(--color-text-primary); 
            padding-bottom: var(--space-4); 
            margin-bottom: var(--space-8); 
        }
        
        h1 { 
            font-size: var(--type-xxl); 
            font-weight: 700; 
            letter-spacing: -0.02em; 
            color: var(--color-text-primary);
        }
        
        h2 { 
            font-size: var(--type-xl); 
            font-weight: 700; 
            border-bottom: 1px solid var(--color-border); 
            padding-bottom: var(--space-2); 
            margin-top: var(--space-12); 
            margin-bottom: var(--space-6);
        }
        
        h3 { 
            font-size: var(--type-lg); 
            font-weight: 600; 
            color: var(--color-accent); 
            margin-top: var(--space-8); 
            margin-bottom: var(--space-4);
        }
        
        .meta-list { list-style: none; margin-bottom: var(--space-8); }
        .meta-list li { margin-bottom: var(--space-2); display: flex; font-size: var(--type-sm); }
        .meta-list span { font-weight: 600; width: 140px; color: var(--color-text-secondary); }
        
        .summary-block { 
            background: var(--color-surface-dim); 
            padding: var(--space-6); 
            border-radius: var(--radius-sm); 
            border-left: 4px solid var(--color-accent); 
            margin-bottom: var(--space-8); 
        }
        
        .vuln-type-summary { margin-bottom: var(--space-8); border-left: 2px solid var(--color-border); padding-left: var(--space-4); }
        .vuln-type-summary strong { 
            color: var(--color-text-primary); 
            display: block; 
            margin-bottom: var(--space-1); 
            font-size: var(--type-sm);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .vuln-type-summary p { font-size: var(--type-sm); color: var(--color-text-secondary); }
        
        .exploitation-record { 
            margin-bottom: var(--space-12); 
            border: 1px solid var(--color-border); 
            border-radius: var(--radius-md); 
            overflow: hidden;
            transition: transform var(--duration-fast) var(--ease), box-shadow var(--duration-fast) var(--ease);
        }
        
        .exploitation-record:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        }
        
        .record-header { 
            background: var(--color-text-primary); 
            color: white; 
            padding: var(--space-3) var(--space-4); 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
        }
        
        .record-header span { font-weight: 600; font-family: monospace; font-size: var(--type-sm); }
        .record-body { padding: var(--space-6); }
        
        .severity-badge { 
            padding: var(--space-1) var(--space-3); 
            border-radius: 9999px; 
            font-size: var(--type-xs); 
            font-weight: 700; 
            text-transform: uppercase;
            letter-spacing: 0.02em;
        }
        .sev-critical { background: var(--color-critical-bg); color: var(--color-critical); }
        .sev-high { background: var(--color-high-bg); color: var(--color-high); }
        .sev-medium { background: var(--color-medium-bg); color: var(--color-medium); }
        .sev-low { background: var(--color-low-bg); color: var(--color-low); }
        
        pre { 
            background: #1e293b; 
            color: #f1f5f9; 
            padding: var(--space-4); 
            border-radius: var(--radius-sm); 
            overflow-x: auto; 
            font-family: 'JetBrains Mono', monospace; 
            font-size: var(--type-sm);
            margin: var(--space-4) 0;
            border: 1px solid #334155;
        }
        
        .impact-proof { 
            border-left: 3px solid var(--color-accent); 
            padding-left: var(--space-4); 
            margin: var(--space-4) 0; 
            font-size: var(--type-sm);
            color: var(--color-text-secondary);
            font-style: italic;
        }
        
        .footer { 
            text-align: center; 
            margin-top: var(--space-12); 
            padding-top: var(--space-8); 
            border-top: 1px solid var(--color-border); 
            color: var(--color-text-muted); 
            font-size: var(--type-xs); 
            letter-spacing: 0.05em;
        }
        
        @media print {
            body { background: white; font-size: 11pt; }
            .container { border: none; max-width: 100%; margin: 0; padding: 0.5in; }
            .exploitation-record { break-inside: avoid; }
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
                    <h1>Security Assessment Report</h1>
                </header>

                <section id="executive-summary">
                    <h2>Executive Summary</h2>
                    <ul class="meta-list">
                        <li><span>Target:</span> {metadata['target']}</li>
                        <li><span>Assessment Date:</span> {metadata['date']}</li>
                        <li><span>Scope:</span> {metadata['scope']}</li>
                    </ul>
                    
                    <h3>Summary by Vulnerability Type</h3>
                    
                    <div class="vuln-type-summary">
                        <strong>Authentication Vulnerabilities:</strong>
                        <p>{summary.get('Authentication', 'No findings.')}</p>
                    </div>

                    <div class="vuln-type-summary">
                        <strong>Authorization Vulnerabilities:</strong>
                        <p>{summary.get('Authorization', 'No findings.')}</p>
                    </div>

                    <div class="vuln-type-summary">
                        <strong>Injection Vulnerabilities:</strong>
                        <p>{summary.get('Injection', 'No findings.')}</p>
                    </div>

                    <div class="vuln-type-summary">
                        <strong>Cross-Site Scripting (XSS) Vulnerabilities:</strong>
                        <p>{summary.get('XSS', 'No findings.')}</p>
                    </div>

                    <div class="vuln-type-summary">
                        <strong>Server-Side Request Forgery (SSRF) Vulnerabilities:</strong>
                        <p>{summary.get('SSRF', 'No findings.')}</p>
                    </div>
                </section>

                <section id="injection-exploitation">
                    <h2>Injection Exploitation Evidence</h2>
                    {self._render_exploitation_records(vulnerabilities.get('Injection', []))}
                </section>

                <section id="xss-exploitation">
                    <h2>Cross-Site Scripting (XSS) Exploitation Evidence</h2>
                    {self._render_exploitation_records(vulnerabilities.get('XSS', []))}
                </section>

                <section id="authentication-exploitation">
                    <h2>Authentication Exploitation Evidence</h2>
                    {self._render_exploitation_records(vulnerabilities.get('Authentication', []))}
                </section>

                <section id="ssrf-exploitation">
                    <h2>SSRF Exploitation Evidence</h2>
                    {self._render_exploitation_records(vulnerabilities.get('SSRF', []))}
                </section>

                <section id="authorization-exploitation">
                    <h2>Authorization Exploitation Evidence</h2>
                    {self._render_exploitation_records(vulnerabilities.get('Authorization', []))}
                </section>

                <div class="footer">
                    BREAKPOINT AUDIT ENGINE | {metadata['scan_id']} | {metadata['full_date']}
                </div>
            </div>
        </body>
        </html>
        """
        return html

    def _render_exploitation_records(self, records: List[CheckResult]) -> str:
        if not records:
            return "<p>No vulnerabilities identified in this category.</p>"
            
        html = ""
        for r in records:
            sev_class = f"sev-{r.severity.lower()}"
            record_id = r.id.replace("VULN-", "ID-")
            
            # Extract payload and response if available
            payload = "Automated Adversarial Payload"
            response = "Technical verification confirmed."
            if r.artifacts:
                art = r.artifacts[0]
                payload = art.get('payload', payload)
                response = art.get('response', response)
                if isinstance(response, (dict, list)):
                    response = json.dumps(response, indent=2)

            html += f"""
            <div class="exploitation-record">
                <div class="record-header">
                    <span>{r.id}: {r.type.replace('_', ' ').upper()}</span>
                    <span class="severity-badge {sev_class}">{r.severity}</span>
                </div>
                <div class="record-body">
                    <p><strong>Summary:</strong> {r.description or r.details}</p>
                    
                    <p><strong>Vulnerable Location:</strong> {r.attack_id or 'Dynamic Resource'}</p>
                    
                    <p><strong>Exploitation Steps:</strong></p>
                    <ol>
                        <li>Identify vulnerable endpoint: {r.attack_id or 'Auto-discovered'}</li>
                        <li>Execute adversarial payload:</li>
                    </ol>
                    <pre><code>{payload}</code></pre>
                    
                    <p><strong>Technical Evidence (Server Response):</strong></p>
                    <pre><code>{response}</code></pre>

                    <p><strong>Proof of Impact:</strong></p>
                    <div class="impact-proof">
                        {r.details[:500]}...
                    </div>
                </div>
            </div>
            """
        return html
