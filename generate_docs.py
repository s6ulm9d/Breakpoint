
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
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Broke Prod Engine - Official Documentation', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 14)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 10, title, 0, 1, 'L', 1)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Arial', '', 11)
        self.multi_cell(0, 6, body)
        self.ln()

def sanitize(text):
    return text.encode('latin-1', 'replace').decode('latin-1')

def generate_pdf():
    pdf = PDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # TITLE PAGE
    pdf.set_font('Arial', 'B', 24)
    pdf.ln(40)
    pdf.cell(0, 10, "BREAKPOINT", 0, 1, 'C')
    pdf.set_font('Arial', '', 16)
    pdf.cell(0, 10, "Professional Documentation (v2.0 Elite)", 0, 1, 'C')
    pdf.ln(20)
    pdf.set_font('Arial', 'I', 12)
    pdf.cell(0, 10, f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d')}", 0, 1, 'C')
    pdf.add_page()

    # SECTION 1: INTRODUCTION
    pdf.chapter_title('1. Why It Is Built (Philosophy)')
    text_intro = (
        "BREAKPOINT was born from a singular truth: Production is already broken; you just haven't proved it yet.\n\n"
        "Traditional testing tools (Unit, Integration, E2E) focus on the 'Happy Path' -- ensuring users can log in, buy items, and save data. "
        "However, they fail to test the 'Adversarial Path' -- what happens when a user tries to crash the database, exhaust memory, or steal secrets?\n\n"
        "This tool is built to democratize 'Chaos Engineering' and 'Red Teaming'. It is designed to act as a hostile attacker, rigorously proving the resilience of an application "
        "before it faces real-world threats. It seamlessly shifts from simple checks to military-grade audits."
    )
    pdf.chapter_body(sanitize(text_intro))

    # SECTION 2: HOW IT IS BUILT
    pdf.chapter_title('2. Architecture & Design')
    text_arch = (
        "The engine utilizes a modular, plugin-based architecture written in Python. Key components include:\n\n"
        "1. Core Engine (breakpoint/engine.py): The iterator that loads Scenarios (YAML) and dispatches them to Attack Handlers.\n"
        "2. Attack Dispatcher: A dynamic registry mapping intent (e.g., 'sql_injection') to Python logic modules.\n"
        "3. HTTP Client Layer: A wrapper around 'requests' that injects metrics tracking, timeout handling, and payload instrumentation.\n"
        "4. Forensic Logger: A cryptographic ledger that hashes every action to ensure audit integrity.\n"
        "5. Safety Locks: Pre-flight checks that enforce consent and verify target scope to prevent unauthorized damage."
    )
    pdf.chapter_body(sanitize(text_arch))

    # SECTION 3: ATTACK COVERAGE
    pdf.chapter_title('3. Attack Capabilities')
    text_attacks = (
        "The engine covers the full OWASP Top 10 and beyond:\n\n"
        "- Injection: SQLi (Union/Blind), NoSQL, RCE, LDAP, XPath, SSTI.\n"
        "- Denial of Service: Slowloris, XML Bomb, Body/Header Bombs, ReDoS.\n"
        "- Authentication: JWT Forgery ('None' alg), Brute Force, Credential Stuffing.\n"
        "- Logic Flaws: Race Conditions, OTP Reuse, IDOR.\n"
        "- Infrastructure: SSRF, LFI, HTTP Desync (Smuggling), Log4Shell.\n"
        "- Client-Side: XSS, Prototype Pollution, Open Redirect."
    )
    pdf.chapter_body(sanitize(text_attacks))

    # SECTION 4: REQUIREMENTS
    pdf.chapter_title('4. System Requirements')
    text_reqs = (
        "Hardware Requirements:\n"
        "- CPU: Multi-core processor (4+ cores recommended) to handle threaded attacks like Traffic Spikes and Slowloris.\n"
        "- RAM: 8GB minimum recommended. The XML Bomb and Large Payload modules process data in memory.\n"
        "- Network: Gigabit Ethernet or stable broadband. DoS attacks leverage available bandwidth.\n\n"
        "Software Requirements:\n"
        "- OS: Windows, Linux, or macOS.\n"
        "- Python: Version 3.8 or higher.\n"
        "- Python Packages: requests, pyyaml, colorama, fpdf (for docs)."
    )
    pdf.chapter_body(sanitize(text_reqs))
    
    # SECTION 5: SAFETY
    pdf.chapter_title('5. Safety & Forensics')
    text_safety = (
        "To ensure professional usage:\n"
        "- Chain of Custody: Every run creates a cryptographically signed log file.\n"
        "- Financial Modeling: The engine calculates estimated liability based on downtime and severity of findings.\n"
        "- Kill Switch: The presence of a 'STOP.lock' file forces an immediate abort.\n"
        "- Consent: Interactive prompts verify ownership before destructive modules arm themselves."
    )
    pdf.chapter_body(sanitize(text_safety))

    pdf.output("documentation.pdf")
    print("Successfully generated documentation.pdf")

if __name__ == "__main__":
    generate_pdf()
