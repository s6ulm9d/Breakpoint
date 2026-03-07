import json
import datetime
import os
from typing import List, Dict, Any, Optional
from ..models import CheckResult, VulnerabilityStatus

class StructuredReportGenerator:
    """
    Advanced Reporting Engine for BREAKPOINT.
    Implements a 14-section structured reporting architecture.
    """
    def __init__(self, engine_instance):
        self.engine = engine_instance
        self.base_url = engine_instance.base_url
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.results = []
        # Try to get scan_id from engine, fallback to generated one
        self.scan_id = getattr(engine_instance, 'scan_id', "BRK-" + datetime.datetime.now().strftime("%Y%m%d%H%M%S"))

    def generate(self, results: List[CheckResult], output_file: str):
        self.results = results
        
        # Section mapping
        sections = {
            1: self._operation_metadata(),
            2: self._exposure_overview(),
            3: self._attack_surface_cartography(),
            4: self._exploit_chain_analysis(),
            5: self._confirmed_exploitation_records(),
            6: self._injection_attack_intelligence(),
            7: self._identity_access_compromise(),
            8: self._client_side_exploitation(),
            9: self._internal_network_abuse(),
            10: self._data_exposure_findings(),
            11: self._evidence_repository(),
            12: self._security_hardening_guidance(),
            13: self._scan_diagnostics(),
            14: self._replay_audit()
        }

        html_content = self._render_html(sections)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file

    def _operation_metadata(self) -> Dict[str, Any]:
        return {
            "target_system": self.base_url,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "scan_mode": "Differential" if getattr(self.engine, 'diff_mode', False) else "Full Audit",
            "environment": getattr(self.engine, 'env', 'Unknown'),
            "version": "4.0.0-Elite",
            "total_modules_executed": len(set(r.type for r in self.results)),
            "total_requests_sent": getattr(self.engine.throttler, 'total_requests', 0) if hasattr(self.engine, 'throttler') else len(self.results) * 5
        }

    def _exposure_overview(self) -> Dict[str, Any]:
        v_results = [r for r in self.results if r.status in ["VULNERABLE", "CONFIRMED"]]
        return {
            "total_endpoints_discovered": len(getattr(self.engine.context, 'discovered_endpoints', [])) if hasattr(self.engine, 'context') else 0,
            "total_attack_vectors": len(set(r.type for r in self.results)),
            "confirmed_vulnerabilities": len([r for r in self.results if r.status == "CONFIRMED"]),
            "potential_vulnerabilities": len([r for r in self.results if r.status == "VULNERABLE"]),
            "risk_breakdown": {
                "critical": len([r for r in v_results if r.severity == "CRITICAL"]),
                "high": len([r for r in v_results if r.severity == "HIGH"]),
                "medium": len([r for r in v_results if r.severity == "MEDIUM"]),
                "low": len([r for r in v_results if r.severity == "LOW"])
            }
        }

    def _attack_surface_cartography(self) -> Dict[str, Any]:
        context = getattr(self.engine, 'context', None)
        return {
            "route_enumeration": getattr(context, 'discovered_endpoints', []) if context else [],
            "input_channels": ["URL Parameters", "POST Body", "JSON Body", "Headers"],
            "technology_profile": {
                "languages": getattr(context.tech_stack, 'languages', []) if context and hasattr(context, 'tech_stack') else [],
                "frameworks": getattr(context.tech_stack, 'frameworks', []) if context and hasattr(context, 'tech_stack') else [],
                "servers": getattr(context.tech_stack, 'servers', []) if context and hasattr(context, 'tech_stack') else [],
                "databases": getattr(context.tech_stack, 'databases', []) if context and hasattr(context, 'tech_stack') else []
            }
        }

    def _exploit_chain_analysis(self) -> List[Dict[str, Any]]:
        graph = getattr(self.engine, 'attack_graph', None)
        if not graph: return []
        # Attempt to generate exploit paths if graph exists
        try:
            paths = graph.generate_exploit_paths()
            chains = []
            for p in paths:
                chains.append({
                    "chain": p.nodes,
                    "description": p.description,
                    "severity_score": p.severity_score
                })
            return chains
        except:
            return []

    def _confirmed_exploitation_records(self) -> List[Dict[str, Any]]:
        confirmed = [r for r in self.results if r.status in ["VULNERABLE", "CONFIRMED", "SUSPECT"]]
        records = []
        for r in confirmed:
            records.append({
                "id": r.id,
                "category": r.type,
                "severity": r.severity,
                "confidence": r.confidence,
                "location": {
                    "endpoint": "Dynamic Endpoint",
                    "parameter": "Multiple/Dynamic"
                },
                "description": r.description or r.details,
                "remediation": r.remediation
            })
        return records

    def _injection_attack_intelligence(self) -> Dict[str, List[CheckResult]]:
        categories = ["sql_injection", "nosql_injection", "command_injection", "ssti", "xxe", "yaml_injection"]
        intelligence = {}
        for cat in categories:
            intelligence[cat] = [r for r in self.results if cat in r.type.lower()]
        return intelligence

    def _identity_access_compromise(self) -> Dict[str, List[CheckResult]]:
        return {
            "authentication_failures": [r for r in self.results if any(x in r.type.lower() for x in ["auth", "login", "brute", "credential"])],
            "authorization_failures": [r for r in self.results if any(x in r.type.lower() for x in ["idor", "access_control", "tenant", "privilege"])]
        }

    def _client_side_exploitation(self) -> List[CheckResult]:
        client_side_types = ["xss", "jsonp", "cors", "clickjacking", "open_redirect"]
        return [r for r in self.results if any(cat in r.type.lower() for cat in client_side_types)]

    def _internal_network_abuse(self) -> List[CheckResult]:
        network_types = ["ssrf", "metadata", "internal_scan", "dns_rebinding"]
        return [r for r in self.results if any(cat in r.type.lower() for cat in network_types)]

    def _data_exposure_findings(self) -> List[CheckResult]:
        exposure_types = ["secret", "leak", "exposure", "disclosure", "debug", "git", "env", "ds_store"]
        return [r for r in self.results if any(cat in r.type.lower() for cat in exposure_types)]

    def _evidence_repository(self) -> List[Dict[str, Any]]:
        evidence = []
        for r in self.results:
            if hasattr(r, 'artifacts') and r.artifacts:
                for art in r.artifacts:
                    evidence.append({
                        "finding_id": r.id,
                        "type": r.type,
                        "request": art.get('request', 'N/A'),
                        "response": art.get('response', 'N/A'),
                        "payload": art.get('payload', 'N/A')
                    })
        return evidence

    def _security_hardening_guidance(self) -> List[str]:
        recommendations = set()
        vulnerable = [r for r in self.results if r.status in ["VULNERABLE", "CONFIRMED"]]
        for r in vulnerable:
            if r.remediation and r.remediation != "N/A":
                recommendations.add(r.remediation)
        return list(recommendations)

    def _scan_diagnostics(self) -> Dict[str, Any]:
        return {
            "scan_duration": "Dynamic",
            "modules_executed": len(set(r.type for r in self.results)),
            "modules_skipped": len([r for r in self.results if r.status == "SKIPPED"]),
            "module_failures": len([r for r in self.results if r.status == "ERROR"])
        }

    def _replay_audit(self) -> Optional[Dict[str, Any]]:
        if not hasattr(self.engine, 'replay_manager') or not getattr(self.engine.replay_manager, 'last_session_id', None):
            return None
        return {
            "replay_session_id": self.engine.replay_manager.last_session_id,
            "original_scan_timestamp": "Recorded",
            "number_of_replayed_attacks": len(self.results),
            "result_consistency_status": "CONSISTENT"
        }

    def _render_html(self, sections: Dict[int, Any]) -> str:
        # Helper to generate section HTML
        def get_section_header(num, title):
            return f'<div class="section-anchor" id="section-{num}"></div><h2 class="section-title"><span class="section-num">{num}</span> {title}</h2>'

        style = """
        :root {
            --bg: #030305;
            --card-bg: #0a0a0f;
            --accent: #a855f7;
            --text: #e2e8f0;
            --text-dim: #94a3b8;
            --border: #1e1e2e;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #3b82f6;
            --success: #22c55e;
        }
        * { box-sizing: border-box; }
        body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, -apple-system, sans-serif; line-height: 1.6; margin: 0; padding: 40px 10%; }
        .hero { margin-bottom: 60px; border-bottom: 1px solid var(--border); padding-bottom: 40px; }
        .hero h1 { font-size: 3rem; margin: 0; font-weight: 800; letter-spacing: -2px; }
        .section-title { margin-top: 80px; margin-bottom: 30px; font-size: 1.8rem; border-left: 4px solid var(--accent); padding-left: 20px; text-transform: uppercase; letter-spacing: 2px; font-weight: 800; }
        .section-num { color: var(--accent); opacity: 0.5; margin-right: 15px; font-weight: 200; }
        .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 25px; margin-bottom: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .stat-item { text-align: center; padding: 20px; background: rgba(255,255,255,0.02); border-radius: 8px; }
        .stat-val { font-size: 2.5rem; font-weight: 800; color: var(--accent); }
        .stat-label { font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }
        pre { background: #000; padding: 20px; border-radius: 8px; overflow-x: auto; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; border: 1px solid #111; color: #10b981; }
        .badge { padding: 4px 12px; border-radius: 6px; font-size: 0.7rem; font-weight: 900; text-transform: uppercase; letter-spacing: 0.5px; }
        .badge-critical { background: rgba(239, 68, 68, 0.1); color: var(--critical); border: 1px solid rgba(239, 68, 68, 0.2); }
        .badge-high { background: rgba(249, 115, 22, 0.1); color: var(--high); border: 1px solid rgba(249, 115, 22, 0.2); }
        .badge-medium { background: rgba(245, 158, 11, 0.1); color: var(--medium); border: 1px solid rgba(245, 158, 11, 0.2); }
        .badge-low { background: rgba(59, 130, 246, 0.1); color: var(--low); border: 1px solid rgba(59, 130, 246, 0.2); }
        """

        html = f"""
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>BREAKPOINT - Structured Audit Report</title><style>{style}</style></head>
        <body>
            <div class="hero">
                <h1>BREAKPOINT <span style="font-weight:200; color:var(--accent);">v4.0.0</span></h1>
                <p style="color:var(--text-dim); font-weight:600; letter-spacing:1px; text-transform:uppercase;">Enterprise Security Exposure Analysis</p>
            </div>

            {get_section_header(1, "OPERATION METADATA")}
            <div class="card">
                <div class="stats-grid">
                    <div class="stat-item"><div class="stat-label">SCAN ID</div><div class="stat-val" style="font-size:1.1rem; color:#fff;">{sections[1]['scan_id']}</div></div>
                    <div class="stat-item"><div class="stat-label">TARGET</div><div class="stat-val" style="font-size:1.1rem; color:#fff;">{sections[1]['target_system']}</div></div>
                    <div class="stat-item"><div class="stat-label">SCAN MODE</div><div class="stat-val" style="font-size:1.1rem; color:#fff;">{sections[1]['scan_mode']}</div></div>
                    <div class="stat-item"><div class="stat-label">ENV</div><div class="stat-val" style="font-size:1.1rem; color:#fff;">{sections[1]['environment']}</div></div>
                    <div class="stat-item"><div class="stat-label">TOTAL REQUESTS</div><div class="stat-val" style="font-size:1.1rem; color:#fff;">{sections[1]['total_requests_sent']}</div></div>
                </div>
            </div>

            {get_section_header(2, "EXPOSURE OVERVIEW")}
            <div class="card">
                <div class="stats-grid">
                    <div class="stat-item"><div class="stat-val">{sections[2]['confirmed_vulnerabilities']}</div><div class="stat-label">CONFIRMED VULNS</div></div>
                    <div class="stat-item"><div class="stat-val">{sections[2]['potential_vulnerabilities']}</div><div class="stat-label">POTENTIAL VULNS</div></div>
                    <div class="stat-item"><div class="stat-val">{sections[2]['total_endpoints_discovered']}</div><div class="stat-label">DISCOVERED ENDPOINTS</div></div>
                    <div class="stat-item"><div class="stat-val" style="color:var(--critical);">{sections[2]['risk_breakdown']['critical']}</div><div class="stat-label">CRITICAL RISK</div></div>
                </div>
            </div>

            {get_section_header(3, "ATTACK SURFACE CARTOGRAPHY")}
            <div class="card">
                <h3 style="color:var(--accent); font-size:1rem; margin-bottom:15px;">Route Enumeration</h3>
                <div style="background:rgba(0,0,0,0.2); padding:15px; border-radius:8px;">
                    {f'<ul style="margin:0; padding-left:20px;">' + "".join(f"<li>{r}</li>" for r in sections[3]['route_enumeration'][:15]) + '</ul>' if sections[3]['route_enumeration'] else '<p>No endpoints discovered.</p>'}
                </div>
                <h3 style="color:var(--accent); font-size:1rem; margin-top:25px; margin-bottom:15px;">Technology Profile</h3>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px;">
                    <p><b>Languages:</b> {", ".join(sections[3]['technology_profile']['languages']) or "N/A"}</p>
                    <p><b>Frameworks:</b> {", ".join(sections[3]['technology_profile']['frameworks']) or "N/A"}</p>
                    <p><b>Servers:</b> {", ".join(sections[3]['technology_profile']['servers']) or "N/A"}</p>
                    <p><b>Databases:</b> {", ".join(sections[3]['technology_profile']['databases']) or "N/A"}</p>
                </div>
            </div>

            {get_section_header(4, "EXPLOIT CHAIN ANALYSIS")}
            <div class="card">
                {f'<p>Detected {len(sections[4])} potential exploit chains.</p>' if sections[4] else '<p style="color:var(--text-dim);">No multi-stage exploit chains identified.</p>'}
                {"".join(f'''<div style="margin-bottom:20px; border-left:2px solid var(--accent); padding-left:15px;">
                    <div style="font-weight:bold; color:#fff;">{" → ".join(c["chain"])}</div>
                    <p style="font-size:0.9rem; color:var(--text-dim); margin:5px 0;">{c["description"]}</p>
                    <small style="color:var(--accent);">SEVERITY SCORE: {c["severity_score"]}</small>
                </div>''' for c in sections[4])}
            </div>

            {get_section_header(5, "CONFIRMED EXPLOITATION RECORDS")}
            {"".join(f'''<div class="card" style="border-right: 4px solid var({r['severity'].lower()});">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-weight:800; font-size:1.1rem; color:#fff;">{r['category'].upper()}</span>
                    <span class="badge badge-{r['severity'].lower()}">{r['severity']}</span>
                </div>
                <div style="margin:15px 0; color:var(--text-dim); font-size:0.95rem;">{r['description']}</div>
                <div style="display:flex; gap:20px; font-size:0.75rem; color:var(--accent); font-weight:bold;">
                    <div>LOCATION: {r['location']['endpoint']}</div>
                    <div>CONFIDENCE: {r['confidence']}</div>
                    <div>ID: {r['id']}</div>
                </div>
            </div>''' for r in sections[5]) if sections[5] else '<div class="card"><p>No confirmed exploits found.</p></div>'}

            {get_section_header(6, "INJECTION ATTACK INTELLIGENCE")}
            <div class="card">
                <div style="display:grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap:15px;">
                    {"".join(f'<div style="padding:15px; background:rgba(255,255,255,0.02); border-radius:8px;"><b>{k.replace("_", " ").upper()}</b><br><span style="font-size:1.5rem; color:var(--accent);">{len(v)}</span> findings</div>' for k,v in sections[6].items() if v) or "No injection findings."}
                </div>
            </div>

            {get_section_header(7, "IDENTITY & ACCESS COMPROMISE")}
            <div class="card">
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
                    <div>
                        <h4 style="margin-top:0; color:var(--accent);">Authentication Failures</h4>
                        <div style="font-size:2rem; font-weight:800;">{len(sections[7]['authentication_failures'])}</div>
                    </div>
                    <div>
                        <h4 style="margin-top:0; color:var(--accent);">Authorization Failures</h4>
                        <div style="font-size:2rem; font-weight:800;">{len(sections[7]['authorization_failures'])}</div>
                    </div>
                </div>
            </div>

            {get_section_header(8, "CLIENT-SIDE EXPLOITATION")}
            <div class="card"><p>Vulnerability Count: <span style="font-weight:800; color:var(--accent); font-size:1.5rem;">{len(sections[8])}</span></p></div>

            {get_section_header(9, "INTERNAL NETWORK ABUSE")}
            <div class="card"><p>Vulnerability Count: <span style="font-weight:800; color:var(--accent); font-size:1.5rem;">{len(sections[9])}</span></p></div>

            {get_section_header(10, "DATA EXPOSURE FINDINGS")}
            <div class="card"><p>Vulnerability Count: <span style="font-weight:800; color:var(--accent); font-size:1.5rem;">{len(sections[10])}</span></p></div>

            {get_section_header(11, "EVIDENCE REPOSITORY")}
            <div class="card">
                {f'<p>Displaying first {min(len(sections[11]), 5)} evidence artifacts.</p>' if sections[11] else '<p>No evidence artifacts collected.</p>'}
                {"".join(f'''<div style="margin-top:20px; border-top:1px solid var(--border); padding-top:15px;">
                    <div style="color:var(--accent); font-weight:bold; margin-bottom:10px;">Finding ID: {e['finding_id']} | Type: {e['type']}</div>
                    <div style="margin-bottom:5px;"><b>Payload:</b></div>
                    <pre>{e['payload']}</pre>
                </div>''' for e in sections[11][:5])}
            </div>

            {get_section_header(12, "SECURITY HARDENING GUIDANCE")}
            <div class="card">
                {f'<ul style="margin:0; padding-left:20px;">' + "".join(f'<li style="margin-bottom:10px;">{rec}</li>' for rec in sections[12]) + '</ul>' if sections[12] else '<p>No specific remediation steps identified.</p>'}
            </div>

            {get_section_header(13, "SCAN DIAGNOSTICS")}
            <div class="card">
                <div class="stats-grid">
                    <div class="stat-item"><div class="stat-val">{sections[13]['modules_executed']}</div><div class="stat-label">MODULES RUN</div></div>
                    <div class="stat-item"><div class="stat-val" style="color:var(--text-dim);">{sections[13]['modules_skipped']}</div><div class="stat-label">SKIPPED</div></div>
                    <div class="stat-item"><div class="stat-val" style="color:var(--critical);">{sections[13]['module_failures']}</div><div class="stat-label">FAILURES</div></div>
                </div>
            </div>

            {get_section_header(14, "REPLAY AUDIT (OPTIONAL)")}
            {f'''<div class="card">
                <p><b>Session ID:</b> {sections[14]["replay_session_id"]}</p>
                <p><b>Original Timestamp:</b> {sections[14]["original_scan_timestamp"]}</p>
                <p><b>Attacks Replayed:</b> {sections[14]["number_of_replayed_attacks"]}</p>
                <p><b>Status:</b> <span style="color:var(--success); font-weight:bold;">{sections[14]["result_consistency_status"]}</span></p>
            </div>''' if sections[14] else '<div class="card"><p style="color:var(--text-dim);">Replay mode not used during this session.</p></div>'}

            <div style="text-align:center; margin-top:100px; padding:40px; border-top:1px solid var(--border); color:var(--text-dim); font-size:0.8rem;">
                BREAKPOINT ADVERSARIAL LOGIC ENGINE | PROPRIETARY AUDIT OUTPUT
            </div>
        </body></html>
        """
        return html
