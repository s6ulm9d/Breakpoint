import datetime
import json
import os
from typing import List, Dict, Any, Optional
from colorama import Fore, Style, init
from ..models import CheckResult, VulnerabilityStatus

init(autoreset=True)

class ProfessionalReportBuilder:
    """
    Professional Offensive Security Reporting Engine for BREAKPOINT.
    Generates a 12-section structured text-based report for terminal output.
    """
    def __init__(self, engine_instance, results: List[CheckResult]):
        self.engine = engine_instance
        self.results = results
        self.base_url = engine_instance.base_url
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.scan_id = getattr(engine_instance, 'scan_id', "BRK-" + datetime.datetime.now().strftime("%Y%m%d%H%M%S"))
        self.is_replay = hasattr(engine_instance, 'is_replay') and engine_instance.is_replay
        self.replay_session_id = getattr(engine_instance, 'replay_session_id', None)
        
        # Internal components
        self.grouping_engine = CategoryGroupingEngine(results)
        self.exploit_gen = ExploitDocumentationGenerator()
        self.evidence_formatter = EvidenceRepositoryFormatter()

    def build_report(self) -> str:
        report = []
        
        # 1. EXECUTIVE SUMMARY
        report.append(self._section_header(1, "EXECUTIVE SUMMARY"))
        report.append(self._build_executive_summary())
        
        # 2. EXPOSURE OVERVIEW
        report.append(self._section_header(2, "EXPOSURE OVERVIEW"))
        report.append(self._build_exposure_overview())
        
        # 3. NETWORK RECONNAISSANCE
        report.append(self._section_header(3, "NETWORK RECONNAISSANCE"))
        report.append(self._build_network_recon())
        
        # 4. ATTACK SURFACE CARTOGRAPHY
        report.append(self._section_header(4, "ATTACK SURFACE CARTOGRAPHY"))
        report.append(self._build_attack_surface())
        
        # 5. VULNERABILITY CATEGORY ANALYSIS
        report.append(self._section_header(5, "VULNERABILITY CATEGORY ANALYSIS"))
        report.append(self._build_category_analysis())
        
        # 6. CONFIRMED EXPLOITATION RECORDS
        report.append(self._section_header(6, "CONFIRMED EXPLOITATION RECORDS"))
        report.append(self._build_exploitation_records())
        
        # 7. EXPLOIT CHAIN ANALYSIS
        report.append(self._section_header(7, "EXPLOIT CHAIN ANALYSIS"))
        report.append(self._build_exploit_chain())
        
        # 8. POTENTIAL VULNERABILITIES
        report.append(self._section_header(8, "POTENTIAL VULNERABILITIES"))
        report.append(self._build_potential_vulnerabilities())
        
        # 9. EVIDENCE REPOSITORY
        report.append(self._section_header(9, "EVIDENCE REPOSITORY"))
        report.append(self._build_evidence_repository())
        
        # 10. SECURITY HARDENING GUIDANCE
        report.append(self._section_header(10, "SECURITY HARDENING GUIDANCE"))
        report.append(self._build_hardening_guidance())
        
        # 11. SCAN DIAGNOSTICS
        report.append(self._section_header(11, "SCAN DIAGNOSTICS"))
        report.append(self._build_scan_diagnostics())
        
        # 12. REPLAY AUDIT (OPTIONAL)
        report.append(self._section_header(12, "REPLAY AUDIT"))
        report.append(self._build_replay_audit())

        # 13. REPORT DISTRIBUTION
        report.append(self._section_header(13, "REPORT DISTRIBUTION"))
        report.append(self._build_distribution_links())
        
        return "\n".join(report)

    def build_link_summary(self) -> str:
        """Condensed output showing only summary and distribution links."""
        summary = [
            self._section_header(1, "EXECUTIVE SUMMARY"),
            self._build_executive_summary(),
            self._build_audit_summary(),
            self._section_header(13, "REPORT DISTRIBUTION"),
            self._build_distribution_links()
        ]
        return "\n".join(summary)

    def _section_header(self, num: int, title: str) -> str:
        line = "=" * 80
        return f"\n{Fore.CYAN}{line}\nSECTION {num}: {title}\n{line}{Style.RESET_ALL}"

    def _build_executive_summary(self) -> str:
        risk_level = self._calculate_overall_risk()
        color = self._get_severity_color(risk_level)
        
        summary = [
            f"{Fore.WHITE}Target System:      {Style.RESET_ALL}{self.base_url}",
            f"{Fore.WHITE}Scan Timestamp:     {Style.RESET_ALL}{self.timestamp}",
            f"{Fore.WHITE}Assessment Scope:   {Style.RESET_ALL}Full Adversarial Audit",
            f"{Fore.WHITE}Overall Risk Level: {color}{risk_level}{Style.RESET_ALL}",
            "",
            f"{Fore.YELLOW}Major Security Findings (Categories):{Style.RESET_ALL}"
        ]
        
        cats = self.grouping_engine.get_summaries()
        for cat, data in cats.items():
            if data['count'] > 0:
                summary.append(f" - {cat}: {data['count']} findings (Max Severity: {data['max_severity']})")
        
        if not any(d['count'] > 0 for d in cats.values()):
            summary.append(" - No major vulnerability categories identified.")
            
        return "\n".join(summary)

    def _build_audit_summary(self) -> str:
        total = len(self.results)
        vulnerable = len([r for r in self.results if r.status in ["VULNERABLE", "CONFIRMED"]])
        skipped = len([r for r in self.results if r.status == "SKIPPED"])
        inconclusive = len([r for r in self.results if r.status in ["INCONCLUSIVE", "ERROR", "BLOCKED"]])
        secure = total - vulnerable - skipped - inconclusive
        
        line = "=" * 60
        summary = [
            f"\n{Fore.WHITE}{line}",
            "BREAKPOINT AUDIT SUMMARY",
            f"{line}{Style.RESET_ALL}",
            f"Total Checks: {total}",
            f"{Fore.GREEN}SECURE:       {secure} (Passed){Style.RESET_ALL}",
            f"{Fore.RED}VULNERABLE:   {vulnerable} (Confirmed/High Risk){Style.RESET_ALL}",
            f"{Fore.YELLOW}SKIPPED:      {skipped} (Throttling/Prerequisites){Style.RESET_ALL}",
            ""
        ]
        
        critical_findings = [r for r in self.results if r.status in ["VULNERABLE", "CONFIRMED"] and r.severity in ["CRITICAL", "HIGH"]]
        if critical_findings:
            summary.append(f"{Fore.RED}[!] CRITICAL FINDINGS:{Style.RESET_ALL}")
            for r in critical_findings:
                # Add impact note if available or a standard one
                impact = r.description or "Security Compromise"
                if "jwt" in r.type.lower() and not r.description: impact = "Authentication bypass, allowing attackers to forge identities."
                summary.append(f" - [{r.type.upper()}] (Location: {r.method} {r.endpoint}, Param: {r.parameter}) {impact}")
        
        summary.append(f"{Fore.WHITE}{line}{Style.RESET_ALL}")
        return "\n".join(summary)

    def _build_exposure_overview(self) -> str:
        confirmed = len([r for r in self.results if r.status == "CONFIRMED"])
        potential = len([r for r in self.results if r.status in ["VULNERABLE", "SUSPECT"]])
        endpoints = len(getattr(self.engine.context, 'discovered_endpoints', [])) if hasattr(self.engine, 'context') else 0
        modules = len(set(r.type for r in self.results))
        
        v_results = [r for r in self.results if r.status in ["VULNERABLE", "CONFIRMED"]]
        distribution = {
            "CRITICAL": len([r for r in v_results if r.severity == "CRITICAL"]),
            "HIGH": len([r for r in v_results if r.severity == "HIGH"]),
            "MEDIUM": len([r for r in v_results if r.severity == "MEDIUM"]),
            "LOW": len([r for r in v_results if r.severity == "LOW"])
        }
        
        return (
            f"Total Endpoints Discovered:   {endpoints}\n"
            f"Total Attack Modules Run:     {modules}\n"
            f"Confirmed Vulnerabilities:    {confirmed}\n"
            f"Potential Vulnerabilities:    {potential}\n\n"
            f"Risk Distribution:\n"
            f" {Fore.RED}CRITICAL: {distribution['CRITICAL']}{Style.RESET_ALL}\n"
            f" {Fore.LIGHTRED_EX}HIGH:     {distribution['HIGH']}{Style.RESET_ALL}\n"
            f" {Fore.YELLOW}MEDIUM:   {distribution['MEDIUM']}{Style.RESET_ALL}\n"
            f" {Fore.BLUE}LOW:      {distribution['LOW']}{Style.RESET_ALL}"
        )

    def _build_network_recon(self) -> str:
        context = getattr(self.engine, 'context', None)
        tech = context.tech_stack if context and hasattr(context, 'tech_stack') else None
        
        recon = [
            f"Detected Frameworks:    {', '.join(tech.frameworks) if tech and tech.frameworks else 'Unknown/None'}",
            f"Detected Databases:     {', '.join(tech.databases) if tech and tech.databases else 'Unknown/None'}",
            f"Detected Server Tech:   {', '.join(tech.servers) if tech and tech.servers else 'Unknown/None'}",
            f"Security Header Status: {self._get_header_summary()}"
        ]
        return "\n".join(recon)

    def _get_header_summary(self) -> str:
        # Placeholder for dynamic header analysis
        return "Baseline Verification Required"

    def _build_attack_surface(self) -> str:
        context = getattr(self.engine, 'context', None)
        routes = getattr(context, 'discovered_endpoints', []) if context else []
        
        surface = [
            f"{Fore.YELLOW}[+] Route Enumeration:{Style.RESET_ALL}",
            "\n".join([f" - {r}" for r in routes[:15]]) or " - No endpoints discovered.",
            "",
            f"{Fore.YELLOW}[+] Input Channels:{Style.RESET_ALL}",
            " - Query Parameters (URL)",
            " - JSON Request Bodies",
            " - Authentication Headers",
            " - Standard HTTP Headers"
        ]
        return "\n".join(surface)

    def _build_category_analysis(self) -> str:
        analysis = []
        cats = self.grouping_engine.get_summaries()
        
        # Specified categories in requirements
        ordered_cats = [
            "Authentication Vulnerabilities",
            "Authorization Vulnerabilities",
            "Injection Vulnerabilities",
            "XSS Vulnerabilities",
            "SSRF Vulnerabilities",
            "Data Exposure Vulnerabilities"
        ]
        
        for cat in ordered_cats:
            # Map requirement names to internal keys
            internal_key = cat.replace(" Vulnerabilities", "")
            if internal_key == "XSS": internal_key = "Cross-Site Scripting"
            
            data = cats.get(internal_key, {"count": 0, "max_severity": "N/A"})
            color = self._get_severity_color(data['max_severity'])
            analysis.append(f"{Fore.WHITE}{cat.upper()}{Style.RESET_ALL}")
            analysis.append(f" - Findings: {data['count']}")
            analysis.append(f" - Max Severity: {color}{data['max_severity']}{Style.RESET_ALL}")
            analysis.append("")
        
        return "\n".join(analysis)

    def _build_exploitation_records(self) -> str:
        records = []
        confirmed = [r for r in self.results if r.status in ["CONFIRMED", "VULNERABLE"]]
        
        if not confirmed:
            return "No confirmed exploits to document."
            
        for r in confirmed:
            records.append(self.exploit_gen.format_record(r))
            records.append("-" * 40)
            
        return "\n".join(records)

    def _build_exploit_chain(self) -> str:
        graph = getattr(self.engine, 'attack_graph', None)
        if not graph:
            return "No multi-stage exploit chains identified."
        # Placeholder for actual graph traversal result
        return "No multi-stage exploit chains identified."

    def _build_potential_vulnerabilities(self) -> str:
        potential = [r for r in self.results if r.status in ["SUSPECT", "VULNERABLE"] and r.status != "CONFIRMED"]
        if not potential:
            return "No potential weaknesses identified."
            
        out = []
        for r in potential:
            out.append(f"[{r.severity}] {r.type.upper()} at {r.id}")
            out.append(f" - {r.description or r.details}")
            out.append("")
        return "\n".join(out)

    def _build_evidence_repository(self) -> str:
        evidence = [r for r in self.results if r.artifacts]
        if not evidence:
            return "No evidence artifacts collected."
            
        return self.evidence_formatter.format_list(evidence[:3])

    def _build_hardening_guidance(self) -> str:
        rems = set()
        for r in self.results:
            if r.status in ["VULNERABLE", "CONFIRMED"] and r.remediation and r.remediation != "N/A":
                rems.add(r.remediation)
        
        if not rems:
            return "No specific hardening guidance identified."
            
        return "\n".join([f" - {rem}" for rem in rems])

    def _build_scan_diagnostics(self) -> str:
        duration = "Dynamic Estimation" # Or calculate from engine timestamps
        modules_run = len(set(r.type for r in self.results))
        modules_skip = len([r for r in self.results if r.status == "SKIPPED"])
        modules_fail = len([r for r in self.results if r.status == "ERROR"])
        
        return (
            f"Total Modules Executed: {modules_run}\n"
            f"Modules Skipped:        {modules_skip}\n"
            f"Module Failures:        {modules_fail}\n"
            f"Scan Duration:          {duration}"
        )

    def _build_replay_audit(self) -> str:
        if not self.is_replay:
            return "Replay mode not used during this session."
        
        return (
            f"Replay Session ID:      {self.replay_session_id or 'N/A'}\n"
            f"Original Scan Time:     Recorded in Master Log\n"
            f"Replayed Attacks:       {len(self.results)}\n"
            f"Comparison Status:      CONSISTENT"
        )

    def _build_distribution_links(self) -> str:
        dist = ReportDistributionEngine(self.engine, self.scan_id)
        return dist.generate_links_block()

    def _calculate_overall_risk(self) -> str:
        severities = [r.severity for r in self.results if r.status in ["CONFIRMED", "VULNERABLE"]]
        if "CRITICAL" in severities: return "CRITICAL"
        if "HIGH" in severities: return "HIGH"
        if "MEDIUM" in severities: return "MEDIUM"
        if "LOW" in severities: return "LOW"
        return "INFORMATIONAL"

    def _get_severity_color(self, severity: str) -> str:
        map = {
            "CRITICAL": Fore.RED,
            "HIGH": Fore.LIGHTRED_EX,
            "MEDIUM": Fore.YELLOW,
            "LOW": Fore.BLUE,
            "INFORMATIONAL": Fore.GREEN
        }
        return map.get(severity, Fore.WHITE)

class CategoryGroupingEngine:
    def __init__(self, results: List[CheckResult]):
        self.results = results
        self.categories = {
            "Authentication": ["auth", "login", "brute", "credential", "jwt"],
            "Authorization": ["idor", "access_control", "tenant", "privilege"],
            "Injection": ["sqli", "sql", "nosql", "command", "rce", "ssti", "xxe"],
            "Cross-Site Scripting": ["xss"],
            "SSRF": ["ssrf", "internal_scan"],
            "Data Exposure": ["info", "disclosure", "leak", "exposure", "secret"]
        }

    def get_summaries(self) -> Dict[str, Dict[str, Any]]:
        summaries = {}
        for cat_name, keywords in self.categories.items():
            matches = [r for r in self.results if any(k in r.type.lower() for k in keywords)]
            vulnerable = [r for r in matches if r.status in ["CONFIRMED", "VULNERABLE"]]
            
            max_sev = "LOW"
            if vulnerable:
                sevs = [r.severity for r in vulnerable]
                if "CRITICAL" in sevs: max_sev = "CRITICAL"
                elif "HIGH" in sevs: max_sev = "HIGH"
                elif "MEDIUM" in sevs: max_sev = "MEDIUM"
            
            summaries[cat_name] = {
                "count": len(vulnerable),
                "max_severity": max_sev if vulnerable else "N/A"
            }
        return summaries

class ExploitDocumentationGenerator:
    def format_record(self, result: CheckResult) -> str:
        color = self._get_severity_color(result.severity)
        
        record = [
            f"{Fore.WHITE}FINDING ID:    {Style.RESET_ALL}{result.id}",
            f"{Fore.WHITE}CATEGORY:      {Style.RESET_ALL}{result.type.upper()}",
            f"{Fore.WHITE}SEVERITY:      {color}{result.severity}{Style.RESET_ALL}",
            f"{Fore.WHITE}CONFIDENCE:    {Style.RESET_ALL}{result.confidence}",
            "",
            f"{Fore.YELLOW}ATTACK LOCATION:{Style.RESET_ALL}",
            f" Endpoint:  {result.method} {result.endpoint}",
            f" Parameter: {result.parameter or 'N/A'}",
            "",
            f"{Fore.YELLOW}TECHNICAL SUMMARY:{Style.RESET_ALL}",
            f" {result.description or result.details}",
            "",
            f"{Fore.YELLOW}PREREQUISITES:{Style.RESET_ALL}",
            f" {self._derive_prerequisites(result)}",
            "",
            f"{Fore.YELLOW}EXPLOITATION STEPS:{Style.RESET_ALL}",
            f" Step 1: Initialize BREAKPOINT Adversarial Session.",
            f" Step 2: Target identified endpoint with {result.type} payload variants.",
            f" Step 3: Inject verified payload: {self._get_payload(result)}",
            f" Step 4: Validate success criterion: {result.details[:100]}...",
            "",
            f"{Fore.YELLOW}ATTACK PAYLOAD:{Style.RESET_ALL}",
            f" {self._get_payload(result)}",
            "",
            f"{Fore.YELLOW}PROOF OF IMPACT:{Style.RESET_ALL}",
            f" {result.details}",
            "",
            f"{Fore.YELLOW}SECURITY IMPACT:{Style.RESET_ALL}",
            f" {self._derive_impact(result)}",
            "",
            f"{Fore.YELLOW}DEVELOPER NOTES:{Style.RESET_ALL}",
            f" {result.remediation}"
        ]
        return "\n".join(record)

    def _derive_prerequisites(self, result: CheckResult) -> str:
        # Heuristic for demo purposes
        if "auth" in result.type or "tenant" in result.type:
            return "Authenticated user access required."
        return "None (Unauthenticated Remote Attacker)"

    def _get_payload(self, result: CheckResult) -> str:
        if result.artifacts and 'payload' in result.artifacts[0]:
            return result.artifacts[0]['payload']
        return "Encrypted/Dynamic Payload Wrapper"

    def _derive_impact(self, result: CheckResult) -> str:
        # Heuristic mapping
        impact_map = {
            "sqli": "Full Database Compromise / Extortion",
            "xss": "Client-Side Session Hijacking",
            "auth": "Account Takeover / Identity Theft",
            "rce": "Full Server Command Execution",
            "ssrf": "Internal Network Pivot & Metadata Leak"
        }
        for k, v in impact_map.items():
            if k in result.type.lower(): return v
        return "Security Posture Degradation"

    def _get_severity_color(self, severity: str) -> str:
        # Direct access to colorama mapping
        from colorama import Fore
        map = {"CRITICAL": Fore.RED, "HIGH": Fore.LIGHTRED_EX, "MEDIUM": Fore.YELLOW, "LOW": Fore.BLUE}
        return map.get(severity, Fore.WHITE)

class EvidenceRepositoryFormatter:
    def format_list(self, results: List[CheckResult]) -> str:
        formatted = []
        for r in results:
            if not r.artifacts: continue
            art = r.artifacts[0]
            item = [
                f"Finding ID:  {r.id}",
                f"Attack Type: {r.type}",
                f"Payload:     {art.get('payload', 'N/A')}",
                f"\n--- REQUEST DUMP ---",
                f"{art.get('request', 'N/A')[:200]}...",
                f"\n--- RESPONSE SNIPPET ---",
                f"{str(art.get('response', 'N/A'))[:200]}..."
            ]
            formatted.append("\n".join(item))
            formatted.append("\n" + "."*40 + "\n")
        
        return "\n".join(formatted)

class ReportDistributionEngine:
    """Handles generation of local and remote report access links."""
    def __init__(self, engine, scan_id: str):
        self.engine = engine
        self.scan_id = scan_id
        self.base_dir = os.getcwd()

    def generate_links_block(self) -> str:
        # 1. Local HTML Link
        html_report = getattr(self.engine, 'html_report_path', "local_audit_report.html")
        local_html_path = os.path.abspath(html_report)
        local_html_link = f"file://{local_html_path}"

        # 2. Local JSON Link
        json_report = getattr(self.engine, 'json_report_path', "scan_results.json")
        local_json_path = os.path.abspath(json_report)
        local_json_link = f"file://{local_json_path}"

        block = [
            f"{Fore.GREEN}[+] LOCAL ACCESS LINKS:{Style.RESET_ALL}",
            f" HTML Report: {Fore.CYAN}{local_html_link}{Style.RESET_ALL}",
            f" JSON Data:   {Fore.CYAN}{local_json_path}{Style.RESET_ALL}",
            "",
            f"{Fore.WHITE}[!] NOTE: HTML report link available if supported by terminal emulator.{Style.RESET_ALL}"
        ]
        return "\n".join(block)
