
import sys
import subprocess
import datetime

# Install FPDF if not present
try:
    from fpdf import FPDF
except ImportError:
    print("Installing requirements for Documentation generation...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "fpdf"])
    from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 10)
        self.cell(0, 10, 'BREAKPOINT - Official Technical Documentation', 0, 1, 'R')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 14)
        self.set_fill_color(0, 0, 0)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, title, 0, 1, 'L', 1)
        self.ln(4)
        self.set_text_color(0, 0, 0)

    def chapter_body(self, body):
        self.set_font('Arial', '', 11)
        self.multi_cell(0, 6, body)
        self.ln()
    
    def section_title(self, title):
         self.set_font('Arial', 'B', 12)
         self.cell(0, 10, title, 0, 1, 'L')

def sanitize(text):
    return text.encode('latin-1', 'replace').decode('latin-1')

def generate_full_pdf():
    pdf = PDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # PAGE 1: TITLE
    pdf.set_font('Arial', 'B', 36)
    pdf.ln(60)
    pdf.cell(0, 10, "BREAKPOINT", 0, 1, 'C')
    pdf.set_font('Arial', '', 18)
    pdf.cell(0, 10, "Elite Chaos & Security Audit Engine", 0, 1, 'C')
    pdf.ln(10)
    pdf.set_font('Courier', '', 12)
    pdf.cell(0, 10, "Version: 2.0.0-ELITE", 0, 1, 'C')
    pdf.ln(40)
    pdf.set_font('Arial', '', 10)
    pdf.multi_cell(0, 5, "CONFIDENTIAL // OFFENSIVE SECURITY TOOL\n\nGenerated: " + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 0, 'C')
    pdf.add_page()

    # SECTION 1: EXECUTIVE SUMMARY
    pdf.chapter_title('1. Executive Overview')
    body_exec = (
        "BREAKPOINT is an advanced offensive security engine designed to prove the fragility of production systems. "
        "Unlike traditional vulnerability scanners that rely on passive checks or safe probes, BREAKPOINT is built on "
        "Adversarial Principles: it simulates a hostile actor attempting to crash, exploit, and compromise the target.\n\n"
        "Core Value Proposition:\n"
        "1. Reality-Based Testing: Uses actual historic payloads (Log4Shell, SQLi) to trigger real failures.\n"
        "2. Forensic Accountability: Every action is cryptographically signed and logged for audit trails.\n"
        "3. Financial Liability Modeling: Translates technical vulnerabilities into estimated downtime costs and data breach fines.\n"
        "4. Automation Safety: Implements hard-coded Kill Switches and Man-in-the-Loop consent constraints to prevent accidental destruction."
    )
    pdf.chapter_body(sanitize(body_exec))

    # SECTION 2: TECHNICAL ARCHITECTURE
    pdf.chapter_title('2. Technical Architecture')
    body_arch = (
        "The engine is built on a high-performance Python 3 core using a modular Plugin Architecture.\n\n"
        "2.1 Core Components:\n"
        "- Engine Orchestrator (breakpoint/engine.py): Manages the execution lifecycle, enforcing safety locks and dispatching tasks.\n"
        "- Attack Dispatcher (breakpoint/attacks/__init__.py): A dynamic registry that routes generic intent strings (e.g., 'rce') to specific implementation modules.\n"
        "- HTTP Client Layer: A custom wrapper around the 'requests' library that injects instrumentation, captures precise timing metrics, and handles raw socket manipulation for DoS attacks.\n\n"
        "2.2 Forensic Layer (breakpoint/forensics.py):\n"
        "- Implements an immutable ledger. Every event (Start, Payload, Result) is hashed into a Merkle-like chain.\n"
        "- At the end of a run, an HMAC-SHA256 signature is generated using a session key, ensuring the audit log cannot be tampered with post-execution.\n\n"
        "2.3 Reporting Layer:\n"
        "- HTML Reporter: Generates a single-file, self-contained dashboard ('report.html') containing Exfiltration Evidence, Risk Heatmaps, and Executive Summaries.\n"
        "- SARIF Generator: Outputs industry-standard static analysis results for integration with GitHub Security and CI/CD pipelines."
    )
    pdf.chapter_body(sanitize(body_arch))

    # SECTION 3: ATTACK MODULES
    pdf.chapter_title('3. The "Death Suite"')
    body_attacks = (
        "BREAKPOINT includes a comprehensive library of attack vectors, categorized by impact:\n\n"
        "3.1 Injection & RCE:\n"
        "- SQL Injection: Union-based retrieval, Boolean-Blind inference, and Error-based exfiltration.\n"
        "- Remote Code Execution (RCE): Shell metacharacter injection (; | `) targeting Linux and Windows subsystems.\n"
        "- Log4Shell (CVE-2021-44228): JNDI/LDAP injection headers to trigger remote class loading.\n"
        "- Server-Side Template Injection (SSTI): Exploits Jinja2, Thymeleaf, and Spring templates.\n\n"
        "3.2 Denial of Service (DoS):\n"
        "- Slowloris: Socket exhaustion attack holding open connections indefinitely.\n"
        "- XML Bomb (Billion Laughs): Recursive entity expansion to consume server RAM (O(2^n)).\n"
        "- Header / Body Bombs: Attempts to overflow parsing buffers with multi-megabyte payloads.\n"
        "- ReDoS: Catastrophic backtracking via malicious Regex inputs.\n\n"
        "3.3 Infrastructure & Logic:\n"
        "- SSRF: Targeting Cloud Metadata (AWS 169.254.169.254) and internal services (localhost:22).\n"
        "- LFI: Traversal attacks (../../etc/passwd) to leak configuration files.\n"
        "- JWT Forgery: Exploit of 'None' algorithm and signature stripping.\n"
        "- Race Conditions: Parallel request flooding to bypass logic checks."
    )
    pdf.chapter_body(sanitize(body_attacks))

    # SECTION 4: INSTALLATION & USAGE
    pdf.chapter_title('4. Operational Manual')
    body_ops = (
        "4.1 Prerequisites:\n"
        "- Python 3.8+ Environment.\n"
        "- 8GB+ RAM (Recommended for DoS modules).\n"
        "- Non-Production Network Access (Unless authorized).\n\n"
        "4.2 Installation:\n"
        "   git clone https://github.com/soulmad/breakpoint.git\n"
        "   cd breakpoint\n"
        "   pip install -r requirements.txt\n\n"
        "4.3 Execution Command:\n"
        "   python -m breakpoint --base-url <TARGET> --scenarios <YAML_FILE> --html-report report.html\n\n"
        "4.4 Safety Protocols:\n"
        "- Interactive Consent: The user must physically type 'I AUTHORIZE DESTRUCTION' to arm the weaponized modules.\n"
        "- Kill Switch: Creating a file named 'STOP.lock' in the working directory triggers an immediate hard-stop of the engine."
    )
    pdf.chapter_body(sanitize(body_ops))

    # SECTION 5: LEGAL & ETHICS
    pdf.chapter_title('5. Legal & Ethical Framework')
    body_legal = (
        "Use of BREAKPOINT is governed by strict ethical guidelines:\n\n"
        "1. Written Consent: You must possess explicit, written authorization from the system owner before targeting any IP address.\n"
        "2. Scope Containment: Attacks must be limited to the agreed-upon endpoints.\n"
        "3. Liability: The operator assumes full financial and legal liability for outages, data corruption, or breaches caused by this tool.\n"
        "4. No Malicious Use: Use of this tool for unauthorized access, cyber-vandalism, or extortion is a violation of federal law (CFAA in the US, CMA in the UK).\n\n"
        "The project maintainers provide this software 'AS IS' without warranty of any kind."
    )
    pdf.chapter_body(sanitize(body_legal))

    pdf.output("documentation.pdf")
    print("SUCCESS: Full Technical Documentation generated as 'documentation.pdf'")

if __name__ == "__main__":
    generate_full_pdf()
