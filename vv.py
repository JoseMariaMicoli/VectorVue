import cmd
import sqlite3
import os
import csv
import shutil
from fpdf import FPDF
from fpdf.enums import XPos, YPos

import colorama
from colorama import Fore, Style

# Add these to your existing imports
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import asyncio
import aiosqlite

console = Console()

# Initialize colorama for Windows/Linux compatibility
colorama.init(autoreset=True)

library_data = {
    "Web App (OWASP Top 10)": [
        ("A01", "Broken Access Control", "Implement centralized access control; use 'Deny by Default'."),
        ("A02", "Security Misconfiguration", "Automate hardening; remove default accounts and verbose error pages."),
        ("A03", "Software/Data Integrity", "Use digital signatures for updates; verify CI/CD pipeline security."),
        ("A04", "Cryptographic Failures", "Encrypt data at rest/transit (AES-256/TLS 1.3); disable old protocols."),
        ("A05", "Injection (SQLi, XSS)", "Use parameterized queries and context-aware output encoding."),
        ("A06", "Insecure Design", "Shift-left security; perform Threat Modeling during the design phase."),
        ("A07", "Authentication Failures", "Implement Phishing-resistant MFA (FIDO2); enforce account lockouts."),
        ("A08", "Integrity Failures", "Verify plugins/libraries; use Subresource Integrity (SRI) for CDN assets."),
        ("A09", "Logging & Alerting", "Log all auth failures/high-value transactions; use a SIEM for alerts."),
        ("A10", "SSRF / Exception Handling", "Sanitize inputs for URLs; implement strict allowlists for outbound calls.")
    ],
    "API Security (OWASP API)": [
        ("API1", "BOLA (Object Level)", "Validate that the logged-in user owns the resource requested in the URL."),
        ("API2", "Broken Authentication", "Use standard OAuth2/OpenID Connect; secure tokens with short TTLs."),
        ("API3", "BOPLA (Property Level)", "Use Data Transfer Objects (DTOs) to prevent 'Mass Assignment' of fields."),
        ("API4", "Unrestricted Consumption", "Set Rate Limits (TPS) and quotas for CPU/Memory/Payload size."),
        ("API5", "Broken Function Level", "Enforce RBAC (Role-Based Access Control) on all admin endpoints."),
        ("API6", "Unrestricted Business Logic", "Validate workflow sequences to prevent bypassing payment or approval steps."),
        ("API7", "SSRF (API Specific)", "Block API access to internal metadata services (e.g., AWS IMDS)."),
        ("API8", "Security Misconfiguration", "Disable unnecessary HTTP methods (PUT/PATCH/DELETE) and CORS wildcards."),
        ("API9", "Improper Inventory", "Maintain OpenAPI/Swagger docs; sunset 'Zombie' (old) API versions."),
        ("API10", "Unsafe Consumption", "Sanitize data from third-party APIs before processing; use strict schema validation.")
    ],
    "Mobile Security (OWASP Mobile)": [
        ("M1", "Improper Credentials", "Use Android Keystore/iOS Keychain; never hardcode API keys."),
        ("M2", "Inadequate Supply Chain", "Verify third-party SDKs; use Software Bill of Materials (SBOM) tracking."),
        ("M3", "Insecure Authentication", "Implement MFA and biometric backing; avoid local-only auth bypasses."),
        ("M4", "Insufficient Input Validation", "Sanitize data from IPC, URLs, and QR codes to prevent deep-link attacks."),
        ("M5", "Insecure Communication", "Enforce TLS; implement Certificate Pinning to stop MitM attacks."),
        ("M6", "Inadequate Privacy", "Limit PII collection; use 'Purpose Limitation' and data minimization."),
        ("M7", "Binary Protection", "Use Obfuscation (DexGuard/ProGuard) and Anti-Tampering checks."),
        ("M8", "Security Misconfiguration", "Disable Debug mode; set 'allowBackup=false' in Android Manifest."),
        ("M9", "Insecure Data Storage", "Encrypt local SQLite/Realm databases using SQLCipher."),
        ("M10", "Insufficient Cryptography", "Use modern primitives (AES-GCM/Argon2); avoid hardcoded salts.")
    ],
    "AD & Infrastructure (Red Team)": [
        ("AD-01", "Kerberoasting", "Use gMSAs or passwords with >25 characters for Service Accounts."),
        ("AD-02", "AS-REP Roasting", "Enable 'Do not require Kerberos preauthentication' only where necessary."),
        ("AD-03", "BloodHound Path", "Audit High-Privileged groups (Domain Admins); reduce 'Nested' permissions."),
        ("AD-04", "GPO Misconfiguration", "Restrict 'SeDebugPrivilege' and 'SeImpersonatePrivilege' to Admins."),
        ("NET-01", "LLMNR/NBNS", "Disable via GPO; enable SMB Signing to prevent relaying."),
        ("NET-02", "SNMP Public String", "Disable SNMP v1/v2c; use v3 with authPriv or restrict to allowlists."),
        ("INF-01", "Unquoted Service Path", "Wrap service executables in quotes: 'C:\\Program Files\\App\\srv.exe'."),
        ("INF-02", "Cleartext in Shares", "Automate scanning of SYSVOL and File Shares for secrets."),
        ("INF-03", "Weak TLS/SSL", "Disable SSLv3, TLS 1.0/1.1; enforce TLS 1.2+ with Strong Ciphers."),
        ("INF-04", "Default Credentials", "Enforce a 'Change Password on First Login' policy for all appliances.")
    ]
}

# --- MITRE ATT&CK DATA ---
MITRE_TACTICS_DATA = [
    ("TA0043", "Reconnaissance", "Gathering information to plan future operations."),
    ("TA0042", "Resource Development", "Establishing infrastructure or resources to support operations."),
    ("TA0001", "Initial Access", "Entry vectors like phishing or supply chain compromise."),
    ("TA0002", "Execution", "Running malicious code, such as using a CLI."),
    ("TA0003", "Persistence", "Maintaining a foothold so access is not lost."),
    ("TA0004", "Privilege Escalation", "Gaining higher-level permissions (e.g., Root/SYSTEM)."),
    ("TA0005", "Defense Evasion", "Avoiding detection by security controls."),
    ("TA0006", "Credential Access", "Stealing account names and passwords."),
    ("TA0007", "Discovery", "Figuring out what resources are available."),
    ("TA0008", "Lateral Movement", "Moving through the network to other systems."),
    ("TA0009", "Collection", "Gathering data of interest to meet objectives."),
    ("TA0011", "Command and Control", "Communicating with compromised systems."),
    ("TA0010", "Exfiltration", "Stealing data by removing it from the network."),
    ("TA0040", "Impact", "Manipulating, interrupting, or destroying systems.")
]

# --- HELPER UTILITIES ---
def get_icon(key):
    """Returns a symbolic icon for categories and severities."""
    icons = {
        "Web": "(W)", "API": "(/)", "Mobile": "(M)", "AD": "(K)", "Infra": "(I)",
        "Critical": "[!!!]", "High": "[!!]", "Medium": "[!]", "Low": "[+]", "Info": "[i]"
    }
    return icons.get(str(key), "(*)")

# --- DATABASE LAYER ---

def load_mitre_reference():
    """Reads the cleaned reference file and populates the DB."""
    if not os.path.exists('mitre_reference.txt'):
        print("[!] mitre_reference.txt not found. Skipping library update.")
        return

    conn = sqlite3.connect('vectorvue.db', timeout=10)
    c = conn.cursor()
    
    # Create the reference table
    c.execute('''CREATE TABLE IF NOT EXISTS mitre_reference (
                    id TEXT PRIMARY KEY,
                    name TEXT,
                    description TEXT)''')

    with open('mitre_reference.txt', 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split('|')
            if len(parts) == 3:
                c.execute("INSERT OR REPLACE INTO mitre_reference VALUES (?, ?, ?)", 
                          (parts[0], parts[1], parts[2]))
    
    conn.commit()
    conn.close()
    print("[+] MITRE Intelligence Library updated.")

def init_db():
    """Ensures the findings table exists with the correct schema."""
    conn = sqlite3.connect('adversary.db')
    c = conn.cursor()
    # Create the table if it doesn't exist
    c.execute('''CREATE TABLE IF NOT EXISTS findings
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  company TEXT, 
                  category TEXT, 
                  title TEXT, 
                  severity TEXT, 
                  description TEXT, 
                  remediation TEXT, 
                  mitre_id TEXT, 
                  tactic_id TEXT, 
                  source TEXT)''')
    conn.commit()
    conn.close()

def do_seed(self, arg):
        """Seeds the DB with heavy dummy text for the Technical Anatomy and MITRE sections."""
        init_db()
        load_mitre_reference()
        
        # Comprehensive data payload to fill all pages including Technical Anatomy
        ghost_hydra_chain = [
            ("TargetCorp", "API", "Phase I: External Shadow API Discovery", "Medium", 
             "During the initial Reconnaissance phase, VaporTrace identified several orphaned OIDC endpoints. "
             "These 'Shadow APIs' were legacy integrations that remained active but unmonitored. "
             "The team successfully mapped 12 distinct entry points that allowed for unauthorized "
             "metadata harvesting without triggering standard API gateway alerts.", 
             "Implement strict service mesh entry points and deprecate unused OIDC endpoints.", 
             "T1580", "TA0043", "VaporTrace"),

            ("TargetCorp", "Infra", "Phase II: Supply Chain Hijack", "Critical", 
             "In the Pivot phase, the Ghost-Pipeline interceptor was deployed. By exploiting a "
             "vulnerability in the CI/CD runner, we injected the 'Weaver' agent directly into the "
             "production container images. This allowed for code execution inside the trusted "
             "environment, bypassing perimeter firewalls and image signing protocols.", 
             "Implement mandatory Infrastructure as Code (IaC) scanning and build integrity checks.", 
             "T1195", "TA0001", "Ghost-Pipeline"),

            ("TargetCorp", "AD", "Phase III: Hydra-C2 Persistence", "High", 
             "For the Persistence phase, custom-engineered Rust and Kotlin server agents were installed. "
             "These agents utilized Hydra-C2 for command and control, employing AES-256-GCM encrypted "
             "heartbeats. The agents remained dormant for 48 hours to evade initial behavioral "
             "analysis before establishing a stable backchannel to the adversary infrastructure.", 
             "Deploy eBPF-based behavioral monitoring to detect non-standard binary execution.", 
             "T1505", "TA0003", "Hydra-C2"),

            ("TargetCorp", "Web", "The Diversion: APEX PRO", "High", 
             "To mask the exfiltration, we executed APEX PRO. This involved running 'noisy' "
             "PowerShell scripts across non-critical workstations. These scripts were designed to "
             "mimic a commodity ransomware outbreak, successfully diverting the SOC's attention "
             "toward containment while the actual data theft occurred silently in the background.", 
             "Enhance SOC training to distinguish between diversionary noise and actual exfiltration.", 
             "T1059", "TA0002", "APEX PRO"),

            ("TargetCorp", "API", "Exfiltration: Stealth Channel", "Critical", 
             "The final objective involved the exfiltration of 50GB of core intellectual property. "
             "This was achieved using a proprietary 'Stealth Channel' that fragmented data into "
             "small packets disguised as standard HTTPS heartbeat traffic. This method effectively "
             "bypassed the organization's Data Loss Prevention (DLP) thresholds.", 
             "Restrict outbound C2 communication and implement granular traffic inspection.", 
             "T1041", "TA0010", "Stealth Channel")
        ]

        conn = sqlite3.connect('adversary.db')
        c = conn.cursor()
        try:
            # Clear existing data for TargetCorp to avoid duplicates
            c.execute("DELETE FROM findings WHERE company='TargetCorp'")
            
            # Injecting extensive data
            c.executemany("INSERT INTO findings (company, category, title, severity, description, remediation, mitre_id, tactic_id, source) VALUES (?,?,?,?,?,?,?,?,?)", ghost_hydra_chain)
            conn.commit()
            
            print(f"{Fore.GREEN}[+] Data injection successful: we have too much info for all pages.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Database Error: {e}{Style.RESET_ALL}")
        finally:
            conn.close()

def add_finding_full(data):
    """Inserts a high-fidelity finding into the database."""
    conn = sqlite3.connect('vectorvue.db')
    c = conn.cursor()
    c.execute("""INSERT INTO findings 
                 (company, category, title, severity, likelihood, impact, description, remediation, steps, evidence) 
                 VALUES (?,?,?,?,?,?,?,?,?,?)""", data)
    conn.commit()
    conn.close()

def query_findings(column, value):
    conn = sqlite3.connect('vectorvue.db')
    c = conn.cursor()
    # Explicitly including 'status' as the last column (index 11)
    c.execute(f"""SELECT id, company, category, title, severity, likelihood, impact, 
                  description, remediation, steps, evidence, status 
                  FROM findings WHERE {column} = ?""", (value,))
    res = c.fetchall()
    conn.close()
    return res

# --- PDF ENGINE ---
class VectorVuePDF(FPDF):
    """Professional PDF class with diagonal watermark and logo support."""
    def header(self):
        # 1. CLASSIFIED WATERMARK (Appears on every page)
        self.set_font('Courier', 'B', 50)
        self.set_text_color(240, 240, 240)
        with self.rotation(45, self.w / 2, self.h / 2):
            self.text(self.w / 4, self.h / 2, "C L A S S I F I E D")
        
        # 2. HEADER BRANDING [cite: 313]
        self.set_font('Courier', 'B', 10)
        self.set_text_color(180, 0, 0)
        self.cell(0, 10, '[ INTERNAL USE ONLY - RESTRICTED ACCESS ]', align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def footer(self):
        self.set_y(-15)
        self.set_font('Courier', 'I', 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f'Page {self.page_no()} | VectorVue Adversary System v1.3', align='R')

    def cover_page(self, company):
        self.add_page()
        
        # 1. TOP SECTION: TITLES
        self.set_y(35)
        self.set_font("Helvetica", "B", 36)
        self.set_text_color(0, 0, 0)
        self.cell(0, 15, "OPERATION GHOST-HYDRA", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        self.set_font("Helvetica", "B", 20)
        self.set_text_color(180, 0, 0)
        self.cell(0, 12, "MISSION DEBRIEF", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        self.ln(5)
        self.set_font("Helvetica", "I", 12)
        self.set_text_color(100, 100, 100)
        self.cell(0, 7, "Anatomy of a modern cyber attack", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # 2. MIDDLE SECTION: LOGO (Keeping your preferred large size)
        if os.path.exists("logo.png"):
            self.image("logo.png", x=15, y=80, w=180)

        # 3. BOTTOM SECTION: SMALLER TARGET & RESEARCHER
        self.set_y(255) # Pushed slightly lower
        self.set_font("Courier", "B", 14) # Reduced from 18/20 to 14
        self.set_text_color(0, 0, 0)
        # Using a smaller cell height (8) for a tighter look
        self.cell(0, 8, f"TARGET: {str(company).upper()}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        self.ln(2)
        self.set_font("Helvetica", "B", 9) # Smaller font for researcher
        self.set_text_color(120, 120, 120)
        self.cell(0, 4, "LEAD RESEARCHER: Jose Maria Micoli", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.cell(0, 4, "DATE: January 19, 2026", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        # LOGO - FORCED DEAD CENTER [cite: 192]
        if os.path.exists("logo.png"):
            self.image("logo.png", x=15, y=80, w=180)

        # TARGET & RESEARCHER AT THE VERY BOTTOM [cite: 199, 317]
        self.set_y(250) 
        self.set_font("Courier", "B", 18)
        self.cell(0, 10, f"TARGET: {str(company).upper()}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)


class GhostHydraReport(FPDF):
    """7-Page Tactical Suite Engine."""
    def header(self):
        # CLASSIFIED WATERMARK [cite: 321]
        self.set_font('Courier', 'B', 50)
        self.set_text_color(242, 242, 242)
        with self.rotation(45, self.w / 2, self.h / 2):
            self.text(self.w / 4, self.h / 2, "C L A S S I F I E D")

        self.set_font("Courier", "B", 8)
        self.set_text_color(200, 0, 0)
        self.cell(0, 10, "[ LEVEL 4 TOP SECRET ] // RED TEAM OPERATIONS", align="L")
        self.set_text_color(0, 0, 0)
        self.cell(0, 10, "VECTORVUE v2.0", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def footer(self):
        self.set_y(-15)
        self.set_font("Courier", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()} // Confidential For Executive Review Only", align="R")

    def cover_page(self, company):
        self.add_page()
        
        # 1. TOP SECTION: TITLES
        self.set_y(35)
        self.set_font("Helvetica", "B", 36)
        self.set_text_color(0, 0, 0)
        self.cell(0, 15, "OPERATION GHOST-HYDRA", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        self.set_font("Helvetica", "B", 20)
        self.set_text_color(180, 0, 0)
        self.cell(0, 12, "MISSION DEBRIEF", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        self.ln(5)
        self.set_font("Helvetica", "I", 12)
        self.set_text_color(100, 100, 100)
        self.cell(0, 7, "Anatomy of a modern cyber attack", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # 2. MIDDLE SECTION: LOGO (Keeping your preferred large size)
        if os.path.exists("logo.png"):
            self.image("logo.png", x=15, y=80, w=180)

        # 3. BOTTOM SECTION: SMALLER TARGET & RESEARCHER
        self.set_y(255) # Pushed slightly lower
        self.set_font("Courier", "B", 14) # Reduced from 18/20 to 14
        self.set_text_color(0, 0, 0)
        # Using a smaller cell height (8) for a tighter look
        self.cell(0, 8, f"TARGET: {str(company).upper()}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        self.ln(2)
        self.set_font("Helvetica", "B", 9) # Smaller font for researcher
        self.set_text_color(120, 120, 120)
        self.cell(0, 4, "LEAD RESEARCHER: Jose Maria Micoli", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.cell(0, 4, "DATE: January 19, 2026", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def executive_summary(self):
        self.add_page()
        self.set_font("Helvetica", "B", 18)
        self.cell(0, 10, "Executive Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font("Times", "", 11)
        self.multi_cell(0, 7, text="To demonstrate critical vulnerabilities in hybrid-cloud architectures... [cite: 205]")

    def technical_anatomy(self, findings):
        """Page 3: Populates the attack chain from the database."""
        self.add_page()
        self.set_font("Helvetica", "B", 18)
        self.cell(0, 10, "The Technical Anatomy", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        for title, desc in findings:
            if "Phase" in title: # Only print the attack chain findings here
                self.ln(5)
                self.set_font("Helvetica", "B", 12)
                self.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                self.set_font("Times", "", 11)
                self.multi_cell(0, 7, text=desc)

    def mitre_mapping(self):
        """MITRE ATT&CK Table Generation[cite: 272, 357]."""
        self.add_page()
        # Insert your table logic here using the mapping provided in the debrief [cite: 274, 358]

    def remediation_plan(self):
        """Strategic Remediation and Golden Library of Defense[cite: 278, 364]."""
        self.add_page()
        self.set_font("Helvetica", "B", 18)
        self.cell(0, 10, "Strategic Remediation", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        # List items 1-4: Zero Trust, IaC, Behavioral Monitoring, Response [cite: 281, 282, 283, 288]

    def back_cover(self):
        """Final authentication page[cite: 296, 378]."""
        self.add_page()
        self.set_y(100)
        self.cell(0, 10, "[AUTHENTICATED BY VECTORVUE ENGINE]", align="C")
        self.cell(0, 10, "Status: MISSION COMPLETE", align="C") # [cite: 310, 379]

    def executive_summary(self):
        # Keep the rest of your executive_summary and other methods as they are...
        pass

    def remediation_plan(self):
        self.add_page()
        self.set_font("Helvetica", "B", 18)
        self.cell(0, 10, "Strategic Remediation", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(5)
        self.set_font("Courier", "B", 12)
        self.cell(0, 10, "The Golden Library of Defense:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        self.set_font("Times", "", 11)
        rems = [
            "1. Zero Trust APIs: Transition from broad OIDC tokens to strictly scoped, short-lived credentials.",
            "2. Infrastructure as Code (IaC) Scanning: Implement automated 'Weaver' detection within the CI/CD pipeline.",
            "3. Behavioral Monitoring: Shift focus from signature-based AV to eBPF-based behavioral monitoring to catch custom-compiled binaries.",
            "4. Incident Response: Enhance SOC training to distinguish between 'noise' diversions and actual data exfiltration."
        ]
        for r in rems:
            self.multi_cell(w=0, h=8, text=r, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.ln(2)

    def back_cover(self):
        self.add_page()
        self.ln(100)
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 10, "[AUTHENTICATED BY VECTORVUE ENGINE]", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font("Courier", "B", 12)
        self.cell(0, 10, "Status: MISSION COMPLETE", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(10)
        self.set_font("Times", "I", 10)
        self.cell(0, 10, "Lead Researcher: Jose Maria Micoli", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.cell(0, 10, "Senior Red Team Operator / Offensive R&D", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

# --- THE SHELL INTERFACE ---
class VectorVueShell(cmd.Cmd):
    intro = "\033[31m" + r"""
  __      __         _              __   __            
  \ \    / /        | |             \ \ / /            
   \ \  / /__   ___ | |_  ___   _ __ \ V / _   _   ___ 
    \ \/ / _ \ / __|| __|/ _ \ | '__| \ / | | | | / _ \
     \  /  __/| (__ | |_| (_) || |    | | | |_| ||  __/
      \/ \___| \___| \__|\___/ |_|    \_/  \__,_| \___|
             >> ADVERSARY REPORTING FRAMEWORK <<
""" + "\033[0m\nSystem ready. Type 'usage' for commands.\n"
    prompt = '(VectorVue) > '

    def do_init(self, arg):
        """Initializes folders and repairs/creates the database."""
        folders = ["01-Pre-Engagement", "02-Executive-Summary", "03-Risk-Assessment", 
                   "04-Technical-Details", "05-Delivery"]
        for f in folders: os.makedirs(f, exist_ok=True)
        init_db()
        print("[+] Environment and Database initialized/repaired.")

    def do_new(self, arg):
        """Interactive Wizard for deep finding entry."""
        print("\n" + "="*30 + "\n[ NEW FINDING WIZARD ]\n" + "="*30)
        data = (
            input("Target Company: ").strip(),
            input("Category (Web/API/Mobile/AD/Infra): ").strip(),
            input("Finding Title: ").strip(),
            input("Severity: ").capitalize().strip(),
            input("Likelihood: ").capitalize().strip(),
            input("Impact: ").capitalize().strip(),
            input("Technical Description: ").strip(),
            input("Remediation Strategy: ").strip(),
            input("Steps to Reproduce: ").strip(),
            input("Evidence: ").strip()
        )
        add_finding_full(data)
        print("\n[+] Data synchronized to database.")

    def do_seed(self, arg):
        """Seeds the DB with Ghost-Hydra chain findings mapped to MITRE Tactics."""
        init_db()
        load_mitre_reference()
        # Format: (Company, Category, Title, Sev, Desc, Rem, MitreID, TacticID, Source)
        ghost_hydra_chain = [
            ("TargetCorp", "API", "External Shadow API Discovery", "Medium", 
             "Exposed OIDC endpoints discovered via VaporTrace.", "Implement strict service mesh entry points.", 
             "T1580", "TA0043", "VaporTrace"),
            ("TargetCorp", "Infra", "Supply Chain Hijack", "Critical", 
             "CI/CD interceptor injected Weaver agent into production.", "Implement IaC scanning and build integrity checks.", 
             "T1195", "TA0001", "Ghost-Pipeline"),
            ("TargetCorp", "AD", "Hydra-C2 Persistence", "High", 
             "Rust-based server agents established multi-vector C2.", "Deploy eBPF-based behavioral monitoring.", 
             "T1505", "TA0003", "Hydra-C2"),
            ("TargetCorp", "Web", "APEX PRO Diversion", "High", 
             "Noisy PowerShell scripts triggered standard SOC alerts.", "Enhance SOC training for diversionary tactics.", 
             "T1059", "TA0002", "APEX PRO"),
            ("TargetCorp", "API", "Stealth Data Exfiltration", "Critical", 
             "Core IP exfiltrated over encrypted AES-256 channel.", "Restrict outbound C2 communication.", 
             "T1041", "TA0010", "Stealth Channel")
        ]

        conn = sqlite3.connect('adversary.db')
        c = conn.cursor()
        c.executemany("INSERT INTO findings (company, category, title, severity, description, remediation, mitre_id, tactic_id, source) VALUES (?,?,?,?,?,?,?,?,?)", ghost_hydra_chain)
        conn.commit()
        conn.close()

        print(f"{Fore.GREEN}[+] Data injection successful: we have too much info.{Style.RESET_ALL}")
        
        conn = sqlite3.connect('vectorvue.db', timeout=10)
        c = conn.cursor()
        c.execute("DELETE FROM findings")
        
        for f in ghost_hydra_chain:
            full_record = (
                f[0], f[1], f[2], f[3], "High", "High", 
                f[4], f[5], "1. Run VaporTrace\n2. Execute Payload", "See Mission Debrief",
                f[6], f[7], f[8]
            )
            c.execute("""INSERT INTO findings 
                         (company, category, title, severity, likelihood, impact, 
                          description, remediation, steps, evidence, mitre_id, tactic_id, discovery_source) 
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", full_record)
        conn.commit()
        conn.close()
        print("[+] VectorVue: Ghost-Hydra attack chain seeded with MITRE mapping.")

    def do_report_roe(self, company):
        """Generates the RoE Checklist PDF (Folder 01)."""
        if not company: print("Error: Company name required."); return
        pdf = VectorVuePDF(); pdf.add_page(); pdf.set_font('Courier', 'B', 16)
        pdf.cell(0, 15, "Pre-Engagement & RoE Checklist", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        sections = [
            ("I. Administrative & Legal", [
                "MSA/SOW: Master Service Agreement and Statement of Work signed.",
                "Permission to Audit: Explicit written 'Get Out of Jail Free' card signed.",
                "Insurance: Professional liability insurance is active.",
                "Emergency Contact: 24/7 technical contact provided."
            ]),
            ("II. Technical Scope", [
                "Target List: Finalized list of IPs, URLs, and App Bundle IDs.",
                "Exclusion List: Explicitly defined 'Out of Bounds' assets.",
                "Testing Windows: Defined times (Business vs After hours).",
                "Data Handling: Agreement on sensitive findings transmission."
            ]),
            ("III. Execution Boundaries", [
                "Social Engineering: Phishing allowed? (Yes/No).",
                "Physical Security: Tailgating allowed? (Yes/No).",
                "Exploitation Level: PoC vs Post-Exploitation pivoting.",
                "DoS: Stress tests or buffer overflows permitted?"
            ])
        ]
        for title, items in sections:
            pdf.ln(5); pdf.set_font('Courier', 'B', 12); pdf.set_fill_color(240, 240, 240)
            pdf.cell(0, 10, f" {title}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font('Courier', '', 10)
            for item in items:
                pdf.cell(10, 8, " [ ]")
                pdf.multi_cell(180, 8, item, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.output(f"01-Pre-Engagement/{company}_ROE.pdf")
        print("[+] ROE PDF delivered to Folder 01.")

    def do_report_executive(self, company):
        """Generates the Executive Summary (Folder 02)."""
        if not company: print("Error: Company name required."); return
        findings = query_findings('company', company)
        pdf = VectorVuePDF(); pdf.cover_page("EXECUTIVE SUMMARY", company)
        pdf.add_page(); pdf.set_font('Courier', 'B', 16)
        pdf.cell(0, 15, "Key Findings & Business Impact", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font('Courier', 'B', 10)
        
        # Increase width to 130 to prevent overlap
        pdf.cell(130, 10, " Vulnerability", 1, new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.cell(50, 10, " Severity", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.set_font('Courier', '', 10)
        for f in findings:
            icon = get_icon(f[4]) # index 4 = severity
            title_text = str(f[3] or "Untitled Finding")[:55] # index 3 = title
            severity_text = str(f[4] or "N/A")
            
            pdf.cell(130, 8, f" {title_text}", 1, new_x=XPos.RIGHT, new_y=YPos.TOP)
            pdf.cell(50, 8, f" {icon} {severity_text}", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.output(f"02-Executive-Summary/{company}_Executive.pdf")
        print("[+] Executive Summary delivered to Folder 02.")

    def do_report_risk(self, company):
        """Generates Risk Assessment Matrix (Folder 03)."""
        if not company: print("Error: Company name required."); return
        pdf = VectorVuePDF(); pdf.add_page(); pdf.set_font('Courier', 'B', 16)
        pdf.cell(0, 15, "Risk Assessment Matrix & Methodology", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.set_font('Courier', 'B', 11); pdf.cell(0, 10, "I. Risk Rating Methodology", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.set_fill_color(230, 230, 230)
        pdf.cell(45, 10, " LIKELIHOOD/IMPACT", 1, new_x=XPos.RIGHT, new_y=YPos.TOP, fill=True)
        pdf.cell(45, 10, "Low", 1, fill=True); pdf.cell(45, 10, "Medium", 1, fill=True); pdf.cell(45, 10, "High", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        
        matrix = [("High Likelihood", "Medium", "High", "CRITICAL"), ("Med Likelihood", "Low", "Medium", "High"), ("Low Likelihood", "Low", "Low", "Medium")]
        for row in matrix:
            pdf.set_font('Courier', 'B', 10); pdf.cell(45, 10, f" {row[0]}", 1, new_x=XPos.RIGHT, new_y=YPos.TOP, fill=True)
            pdf.set_font('Courier', '', 10)
            for cell in row[1:]:
                pdf.cell(45, 10, cell, 1, new_x=XPos.RIGHT if row.index(cell) < 3 else XPos.LMARGIN, new_y=YPos.TOP if row.index(cell) < 3 else YPos.NEXT)
        
        pdf.ln(5); pdf.set_font('Courier', 'B', 11); pdf.cell(0, 10, "II. Findings Heatmap", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font('Courier', 'B', 9); pdf.set_fill_color(240, 240, 240)
        pdf.cell(85, 8, " Finding Title", 1, fill=True)
        pdf.cell(30, 8, " Likelihood", 1, fill=True)
        pdf.cell(30, 8, " Impact", 1, fill=True)
        pdf.cell(35, 8, " Risk Level", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        
        findings = query_findings('company', company)
        if not findings:
            pdf.cell(180, 8, " No findings recorded for heatmap.", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        else:
            pdf.set_font('Courier', '', 9)
            for f in findings:
                title_text = str(f[3] or "")[:40] # index 3
                pdf.cell(85, 8, f" {title_text}", 1)
                pdf.cell(30, 8, f" {str(f[5] or 'N/A')}", 1) # index 5 = likelihood
                pdf.cell(30, 8, f" {str(f[6] or 'N/A')}", 1) # index 6 = impact
                pdf.cell(35, 8, f" {str(f[4] or 'N/A')}", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT) # index 4 = severity

        pdf.output(f"03-Risk-Assessment/{company}_Risk_Matrix.pdf")
        print("[+] Risk Methodology delivered to Folder 03.")

    def do_report_library(self, arg):
        """Generates THE FULL MASTER REMEDIATION LIBRARY (Golden Library)."""
        pdf = VectorVuePDF(); pdf.add_page(); pdf.set_font('Courier', 'B', 18)
        pdf.cell(0, 15, "MASTER REMEDIATION LIBRARY", align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        library_data = {
            "Web App (OWASP Top 10)": [
                ("A01", "Broken Access Control", "Implement centralized access control; use 'Deny by Default'."),
                ("A02", "Security Misconfiguration", "Automate hardening; remove default accounts and verbose error pages."),
                ("A03", "Software/Data Integrity", "Use digital signatures for updates; verify CI/CD pipeline security."),
                ("A04", "Cryptographic Failures", "Encrypt data at rest/transit (AES-256/TLS 1.3); disable old protocols."),
                ("A05", "Injection (SQLi, XSS)", "Use parameterized queries and context-aware output encoding."),
                ("A06", "Insecure Design", "Shift-left security; perform Threat Modeling during the design phase."),
                ("A07", "Authentication Failures", "Implement Phishing-resistant MFA (FIDO2); enforce account lockouts."),
                ("A08", "Integrity Failures", "Verify plugins/libraries; use Subresource Integrity (SRI) for CDN assets."),
                ("A09", "Logging & Alerting", "Log all auth failures/high-value transactions; use a SIEM for alerts."),
                ("A10", "SSRF / Exception Handling", "Sanitize inputs for URLs; implement strict allowlists for outbound calls.")
            ],
            "API Security (OWASP API)": [
                ("API1", "BOLA (Object Level)", "Validate that the logged-in user owns the resource requested in the URL."),
                ("API2", "Broken Authentication", "Use standard OAuth2/OpenID Connect; secure tokens with short TTLs."),
                ("API3", "BOPLA (Property Level)", "Use Data Transfer Objects (DTOs) to prevent 'Mass Assignment' of fields."),
                ("API4", "Unrestricted Consumption", "Set Rate Limits (TPS) and quotas for CPU/Memory/Payload size."),
                ("API5", "Broken Function Level", "Enforce RBAC (Role-Based Access Control) on all admin endpoints."),
                ("API6", "Unrestricted Business Logic", "Validate workflow sequences to prevent bypassing payment or approval steps."),
                ("API7", "SSRF (API Specific)", "Block API access to internal metadata services (e.g., AWS IMDS)."),
                ("API8", "Security Misconfiguration", "Disable unnecessary HTTP methods (PUT/PATCH/DELETE) and CORS wildcards."),
                ("API9", "Improper Inventory", "Maintain OpenAPI/Swagger docs; sunset 'Zombie' (old) API versions."),
                ("API10", "Unsafe Consumption", "Sanitize data from third-party APIs before processing; use strict schema validation.")
            ],
            "Mobile Security (OWASP Mobile)": [
                ("M1", "Improper Credentials", "Use Android Keystore/iOS Keychain; never hardcode API keys."),
                ("M2", "Inadequate Supply Chain", "Verify third-party SDKs; use Software Bill of Materials (SBOM) tracking."),
                ("M3", "Insecure Authentication", "Implement MFA and biometric backing; avoid local-only auth bypasses."),
                ("M4", "Insufficient Input Validation", "Sanitize data from IPC, URLs, and QR codes to prevent deep-link attacks."),
                ("M5", "Insecure Communication", "Enforce TLS; implement Certificate Pinning to stop MitM attacks."),
                ("M6", "Inadequate Privacy", "Limit PII collection; use 'Purpose Limitation' and data minimization."),
                ("M7", "Binary Protection", "Use Obfuscation (DexGuard/ProGuard) and Anti-Tampering checks."),
                ("M8", "Security Misconfiguration", "Disable Debug mode; set 'allowBackup=false' in Android Manifest."),
                ("M9", "Insecure Data Storage", "Encrypt local SQLite/Realm databases using SQLCipher."),
                ("M10", "Insufficient Cryptography", "Use modern primitives (AES-GCM/Argon2); avoid hardcoded salts.")
            ],
            "AD & Infrastructure (Red Team)": [
                ("AD-01", "Kerberoasting", "Use gMSAs or passwords with >25 characters for Service Accounts."),
                ("AD-02", "AS-REP Roasting", "Enable 'Do not require Kerberos preauthentication' only where necessary."),
                ("AD-03", "BloodHound Path", "Audit High-Privileged groups (Domain Admins); reduce 'Nested' permissions."),
                ("AD-04", "GPO Misconfiguration", "Restrict 'SeDebugPrivilege' and 'SeImpersonatePrivilege' to Admins."),
                ("NET-01", "LLMNR/NBNS", "Disable via GPO; enable SMB Signing to prevent relaying."),
                ("NET-02", "SNMP Public String", "Disable SNMP v1/v2c; use v3 with authPriv or restrict to allowlists."),
                ("INF-01", "Unquoted Service Path", "Wrap service executables in quotes: 'C:\\Program Files\\App\\srv.exe'."),
                ("INF-02", "Cleartext in Shares", "Automate scanning of SYSVOL and File Shares for secrets."),
                ("INF-03", "Weak TLS/SSL", "Disable SSLv3, TLS 1.0/1.1; enforce TLS 1.2+ with Strong Ciphers."),
                ("INF-04", "Default Credentials", "Enforce a 'Change Password on First Login' policy for all appliances.")
            ]
        }
        for section, rows in library_data.items():
            if pdf.get_y() > 250: pdf.add_page()
            pdf.ln(5); pdf.set_font('Courier', 'B', 12); pdf.cell(0, 10, f" {section}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font('Courier', 'B', 10); pdf.cell(25, 10, "ID", 1); pdf.cell(60, 10, "Finding", 1); pdf.cell(100, 10, "Strategy", 1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font('Courier', '', 9)
            for cid, title, rem in rows:
                if pdf.get_y() > 260: pdf.add_page()
                start_y = pdf.get_y()
                pdf.multi_cell(25, 7, cid, 1); end_y_id = pdf.get_y()
                pdf.set_xy(35, start_y); pdf.multi_cell(60, 7, title, 1); end_y_title = pdf.get_y()
                pdf.set_xy(95, start_y); pdf.multi_cell(100, 7, rem, 1); end_y_rem = pdf.get_y()
                pdf.set_y(max(end_y_id, end_y_title, end_y_rem))
        pdf.output("04-Technical-Details/Golden_Remediation_Library.pdf")
        print("[+] Master Golden Remediation Library Generated.")

    def do_library(self, arg):
        target_cats = [arg] if arg in library_data else library_data.keys()
        
        for cat in target_cats:
            table = Table(title=f"Golden Remediation: {cat}", box=box.ROUNDED, header_style="bold magenta")
            table.add_column("ID", style="cyan", width=6)
            table.add_column("Finding", style="white", b=True)
            table.add_column("Strategic Remediation", style="green")
            
            for code, title, rem in library_data[cat]:
                table.add_row(code, title, rem)
                
            console.print(table)

    def do_report_technical(self, company):
        """Generates Technical Deep Dive (Folder 04)."""
        if not company: print("Error: Company name required."); return
        findings = query_findings('company', company)
        if not findings: print(f"No findings found for {company}."); return
        
        pdf = VectorVuePDF(); pdf.cover_page("TECHNICAL FINDINGS REPORT", company)
        for f in findings:
            pdf.add_page(); pdf.set_font('Courier', 'B', 14)
            icon_cat = get_icon(f[2]); icon_sev = get_icon(f[4])
            title_text = str(f[3] or "Untitled Finding")
            pdf.cell(0, 10, f"{icon_cat} TECH-{f[0]}: {title_text}", border='B', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font('Courier', 'B', 9); pdf.cell(0, 8, f"Severity: {icon_sev} {str(f[4] or 'N/A')} | Impact: {str(f[6] or 'N/A')} | Likelihood: {str(f[5] or 'N/A')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            sections = [
                ("DESCRIPTION", f[7]), 
                ("REPRODUCTION", f[9]), 
                ("EVIDENCE", f[10]), 
                ("REMEDIATION", f[8])
            ]
            for label, content in sections:
                pdf.ln(4); pdf.set_font('Courier', 'B', 11); pdf.cell(0, 8, f"{label}:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                pdf.set_font('Courier', '', 10)
                if label == "EVIDENCE": 
                    pdf.set_fill_color(245, 245, 245); pdf.set_font('Courier', '', 9)
                    pdf.multi_cell(0, 5, str(content or "No evidence provided."), border=1, fill=True)
                else: 
                    pdf.multi_cell(0, 6, str(content or "N/A"))
        pdf.output(f"04-Technical-Details/{company}_Technical_Deep_Dive.pdf")
        print("[+] Technical Report delivered to Folder 04.")

    def do_report_csv(self, company):
        """Generates CSV Evidence Export (Folder 05)."""
        if not company: print("Error: Company name required."); return
        findings = query_findings('company', company)
        path = f"05-Delivery/{company}_Findings_Export.csv"
        with open(path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Company", "Category", "Title", "Severity", "Likelihood", "Impact", "Description", "Remediation", "Steps", "Evidence"])
            writer.writerows(findings)
        print(f"[+] CSV Evidence Exported to Folder 05.")

    def do_report_full(self, company):
        """Generates the full 7-page Ghost-Hydra Tactical Suite with dynamic data."""
        if not company:
            print("[!] Usage: report_full <Company>")
            return

        # 1. DATABASE FETCH: Ensure we use vectorvue.db (matching your seed)
        conn = sqlite3.connect('vectorvue.db', timeout=10)
        c = conn.cursor()
        # Fetching title and description for the Technical Anatomy page
        c.execute("SELECT title, description FROM findings WHERE company = ?", (company,))
        db_findings = c.fetchall()

        # 2. PDF INITIALIZATION
        pdf = GhostHydraReport()
        
        # Page 1: Cover
        pdf.cover_page(company)
        
        # Page 2: Executive Summary (Internal hardcoded summary)
        pdf.executive_summary()
        
        # Page 3: Technical Anatomy (DYNAMIC - Uses db_findings)
        pdf.technical_anatomy(db_findings)
        
        # Page 4: Escalation & Sabotage (Internal logic)
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 10, "Escalation & Sabotage", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, "Lateral Movement", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Times", "", 11)
        pdf.multi_cell(0, 7, text="Leveraged Log4shell (POC) and local privilege escalation to achieve NT AUTHORITY\\SYSTEM and Root across sensitive database clusters.")
        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, "The Diversion (APEX PRO)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Times", "", 11)
        pdf.multi_cell(0, 7, text="Executed high-volume, 'noisy' PowerShell scripts in memory to trigger standard ransomware alerts, forcing the SOC into 'Containment Mode' while low-and-slow exfiltration occurred.")

        # Page 5: MITRE Tactical Mapping (DYNAMIC - Uses SQL Join)
        c.execute("""
            SELECT f.tactic_id, m.name, f.mitre_id, f.discovery_source
            FROM findings f
            LEFT JOIN mitre_reference m ON f.mitre_id = m.id
            WHERE f.company = ?
        """, (company,))
        mitre_results = c.fetchall()
        
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "MITRE ATT&CK Mapping", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(5)
        
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(200, 0, 0); pdf.set_text_color(255, 255, 255)
        pdf.cell(40, 10, "Tactic", border=1, fill=True)
        pdf.cell(60, 10, "Technique", border=1, fill=True)
        pdf.cell(30, 10, "ID (Txxxx)", border=1, fill=True)
        pdf.cell(50, 10, "Discovery", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.set_text_color(0, 0, 0); pdf.set_font("Courier", "", 9)
        for row in mitre_results:
            pdf.cell(40, 10, str(row[0]), border=1)
            pdf.cell(60, 10, str(row[1])[:30], border=1)
            pdf.cell(30, 10, str(row[2]), border=1)
            pdf.cell(50, 10, str(row[3]), border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        # Page 6: Strategic Remediation
        pdf.remediation_plan()
        
        # Page 7: Back Cover
        pdf.back_cover()
        
        # 3. OUTPUT & CLEANUP
        final_path = f"05-Delivery/{company}_Full_Ghost_Hydra_Debrief.pdf"
        pdf.output(final_path)
        conn.close()
        print(f"[+] Full 7-page Mission Debrief generated at {final_path}")

    def do_list(self, company):
        """Displays a summary table of findings: list <company>"""
        if not company:
            print("Usage: list <company>"); return
        
        findings = query_findings('company', company)
        if not findings:
            print(f"[-] No findings found for {company}."); return

        print(f"\n[ ENGAGEMENT DATA: {company.upper()} ]")
        print(f"{'ID':<4} | {'SEV':<10} | {'VULNERABILITY TITLE':<40} | {'STATUS':<12}")
        print("-" * 75)
        
        for f in findings:
            f_id, _, _, title, sev, _, _, _, _, _, _, status = f
            # Defaults to 'Open' if status is None
            current_status = status if status else "Open"
            print(f"{f_id:<4} | {sev:<10} | {title[:40]:<40} | {current_status:<12}")
        print("-" * 75 + "\n")

    def do_status(self, arg):
        """Update finding status: status <id> <NewStatus>"""
        try:
            finding_id, new_status = arg.split(None, 1)
            conn = sqlite3.connect('vectorvue.db')
            c = conn.cursor()
            c.execute("UPDATE findings SET status = ? WHERE id = ?", (new_status, finding_id))
            conn.commit()
            if c.rowcount > 0:
                print(f"[+] Finding {finding_id} updated to: {new_status}")
            else:
                print(f"[-] Finding ID {finding_id} not found.")
            conn.close()
        except ValueError:
            print("Usage: status <id> <NewStatus> (e.g., status 1 Fixed)")

    def do_delete(self, arg):
        """Permanent removal: delete <id>"""
        if not arg:
            print("Usage: delete <id>"); return
        confirm = input(f"[*] Confim deletion of ID {arg}? (y/n): ")
        if confirm.lower() == 'y':
            conn = sqlite3.connect('vectorvue.db')
            c = conn.cursor()
            c.execute("DELETE FROM findings WHERE id = ?", (arg,))
            conn.commit()
            conn.close()
            print(f"[!] Finding {arg} purged from database.")

    def do_query(self, sql):
        """Execute custom SQL queries: query SELECT * FROM findings WHERE severity='High'"""
        if not sql:
            print("Usage: query <SQL_STATEMENT>"); return
        
        try:
            conn = sqlite3.connect('vectorvue.db', timeout=10)
            c = conn.cursor()
            c.execute(sql)
            rows = c.fetchall()
            
            # Fetch column names for the header
            colnames = [description[0] for description in c.description]
            print(f"\n[ SQL RESULTS ]\n{' | '.join(colnames)}")
            print("-" * (len(' | '.join(colnames)) + 5))
            
            for row in rows:
                print(" | ".join(str(item) for item in row))
            
            conn.close()
            print(f"\n[+] Total records returned: {len(rows)}")
        except Exception as e:
            print(f"[-] Database Error: {e}")

    def do_usage(self, arg):
            """Displays perfectly aligned command interface for v1.6."""
            # Define colors
            c, y, g, r, b = "\033[36m", "\033[33m", "\033[32m", "\033[0m", "\033[1m"
            
            # Internal width of the box (excluding borders and 1-space padding)
            W = 62 

            def p_line(text, color_content=r):
                # Formats the text to the fixed width first, THEN adds color
                content = f"{text:<{W}}"
                print(f"│ {color_content}{content}{r}{b} │")

            # Top Border
            print(f"\n{b}┌{'─' * (W + 2)}┐")
            
            # Header
            p_line(f"VECTORVUE COMMAND SPECIFICATION v1.6", c)
            print(f"├{'─' * (W + 2)}┤")
            
            # Sections
            p_line("SETUP & DATA ENTRY", y)
            p_line("  init             - Prepare folders & repair database")
            p_line("  new              - Interactive Finding Wizard")
            p_line("  seed             - Populate DB with 10 Demo Findings")
            print(f"├{'─' * (W + 2)}┤")
            
            # MANAGEMENT & QUERY
            p_line("MANAGEMENT & QUERY", y)
            p_line("  list <target>    - Table of Findings, IDs & Statuses")
            p_line("  library          - View 40-Point Golden Remediation Lib")
            p_line("  status <id> <val> - Update state (e.g. status 1 Fixed)")
            p_line("  delete <id>      - Permanent removal by Finding ID")
            p_line("  query <sql>      - Raw SQL search (e.g. SELECT *...)")
            print(f"├{'─' * (W + 2)}┤")
            
            # REPORT GENERATION
            p_line("REPORT GENERATION", y)
            p_line("  report_executive - High-level Summary (F02)")
            p_line("  report_technical - Technical Deep Dive (F04)")
            p_line("  report_full      - One-click Suite Generation (F05)")
            print(f"├{'─' * (W + 2)}┤")
            
            # FULL WORKFLOW EXAMPLE
            p_line("FULL WORKFLOW EXAMPLE: TargetCorp", y)
            p_line("  init                 -> Setup workspace")
            p_line("  seed                 -> Seed initial data")
            p_line("  list \"TargetCorp\"     -> Identify IDs")
            p_line("  status 1 \"Fixed\"      -> Update lifecycle")
            p_line("  library \"API\"        -> Lookup remediations")
            p_line("  query SELECT * FROM findings WHERE company='TargetCorp'")
            p_line("  report_full \"TargetCorp\" -> Final Delivery")
            
            # Bottom Border
            print(f"└{'─' * (W + 2)}┘{r}")

    def do_exit(self, arg):
        """Exits the shell."""
        print("Shutting down VectorVue...")
        return True

if __name__ == '__main__':
    init_db()
    VectorVueShell().cmdloop()