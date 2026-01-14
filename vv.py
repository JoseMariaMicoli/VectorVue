import cmd
import sqlite3
import os
import csv
import shutil
from fpdf import FPDF
from fpdf.enums import XPos, YPos

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

# --- HELPER UTILITIES ---
def get_icon(key):
    """Returns a symbolic icon for categories and severities."""
    icons = {
        "Web": "(W)", "API": "(/)", "Mobile": "(M)", "AD": "(K)", "Infra": "(I)",
        "Critical": "[!!!]", "High": "[!!]", "Medium": "[!]", "Low": "[+]", "Info": "[i]"
    }
    return icons.get(str(key), "(*)")

# --- DATABASE LAYER ---
def init_db():
    """Initializes and repairs the backend SQLite database schema to ensure all columns exist."""
    conn = sqlite3.connect('vectorvue.db')
    c = conn.cursor()
    
    # Ensure the table exists
    c.execute('''CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY AUTOINCREMENT)''')
    
    # Required columns for the full technical and executive reports
    required_columns = [
        ("company", "TEXT"),
        ("category", "TEXT"),
        ("title", "TEXT"),
        ("severity", "TEXT"),
        ("likelihood", "TEXT"),
        ("impact", "TEXT"),
        ("description", "TEXT"),
        ("remediation", "TEXT"),
        ("steps", "TEXT"),
        ("evidence", "TEXT"),
        ("status", "TEXT DEFAULT 'Open'")  # <--- ADD THIS LINE
    ]
    
    # Check for missing columns (to repair older database versions)
    c.execute("PRAGMA table_info(findings)")
    existing_cols = [info[1] for info in c.fetchall()]
    
    for col_name, col_type in required_columns:
        if col_name not in existing_cols:
            c.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}")
            
    conn.commit()
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
    """Professional PDF class with classified branding and modern FPDF2 positioning."""
    def header(self):
        self.set_font('Courier', 'B', 10)
        self.set_text_color(180, 0, 0)
        self.cell(0, 10, '[ INTERNAL USE ONLY - RESTRICTED ACCESS ]', align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        if self.page_no() > 1:
            self.set_font('Courier', 'B', 45); self.set_text_color(245, 245, 245)
            with self.rotation(45, self.w / 2, self.h / 2):
                self.text(self.w / 4, self.h / 2, "C L A S S I F I E D")

    def footer(self):
        self.set_y(-15); self.set_font('Courier', 'I', 8); self.set_text_color(100, 100, 100)
        self.cell(0, 10, f'Page {self.page_no()} | VectorVue Adversary System v1.3', align='R')

    def cover_page(self, title, company):
        self.add_page()
        self.set_font('Courier', 'B', 35); self.set_text_color(150, 0, 0); self.set_draw_color(150, 0, 0)
        with self.rotation(15, self.w / 2, self.h / 2):
            self.rect(55, 135, 100, 22); self.text(61, 151, " CLASSIFIED ")
        self.set_text_color(0, 0, 0); self.set_font('Courier', 'B', 28); self.ln(60)
        self.cell(0, 20, title, align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font('Courier', '', 18)
        self.cell(0, 15, f"TARGET: {str(company).upper()}", align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

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
        """Seeds the database with professional Golden Library findings."""
        init_db()
        findings = [
            ("TargetCorp", "Web", "Blind SQL Injection", "Critical", "Time-based injection in /login", "Use Parameterized Queries"),
            ("TargetCorp", "API", "BOLA on Invoice ID", "Critical", "Unauthorized access to global invoices", "Implement resource-level auth"),
            ("TargetCorp", "AD", "Kerberoasting", "High", "SPNs allow offline hash cracking", "Rotate to 25+ char passwords"),
            ("TargetCorp", "Mobile", "Hardcoded API Keys", "High", "Secrets leaked in binary strings", "Use Secure Vault/Proxy"),
            ("TargetCorp", "Infra", "Unquoted Service Path", "High", "Privilege escalation via Windows services", "Wrap paths in double quotes"),
            ("TargetCorp", "Web", "Insecure IDOR", "High", "User data leak via parameter tampering", "Validate session ownership"),
            ("TargetCorp", "API", "Mass Assignment", "Medium", "Self-promotion to Admin via JSON", "Whitelist input with DTOs"),
            ("TargetCorp", "AD", "LLMNR/NBNS Active", "Medium", "Responder-based MitM potential", "Disable via GPO"),
            ("TargetCorp", "Mobile", "PII in Logcat", "Medium", "Sensitive tokens leaked to system logs", "Disable production logging"),
            ("TargetCorp", "Infra", "SNMP Public String", "Low", "Recon enabled via default string", "Switch to SNMP v3")
        ]
        
        conn = sqlite3.connect('vectorvue.db')
        c = conn.cursor()
        c.execute("DELETE FROM findings")
        
        for f in findings:
            full_record = (
                f[0], f[1], f[2], f[3], 
                "High" if f[3] in ["Critical", "High"] else "Medium",
                "High" if f[3] in ["Critical", "High"] else "Medium",
                f[4], f[5], 
                "1. Run automated scan.\n2. Verify manually.", 
                "See attached proof_of_concept.png"
            )
            c.execute("""INSERT INTO findings 
                         (company, category, title, severity, likelihood, impact, description, remediation, steps, evidence) 
                         VALUES (?,?,?,?,?,?,?,?,?,?)""", full_record)
        conn.commit()
        conn.close()
        print("[+] VectorVue: 10 Findings seeded successfully.")

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
        """Displays the Golden Remediation Library: library <category>"""
        c, y, g, r, b = "\033[36m", "\033[33m", "\033[32m", "\033[0m", "\033[1m"
        
        # If no category is specified, show all categories
        target_cats = [arg] if arg in library_data else library_data.keys()

        for cat in target_cats:
            print(f"\n{b}{y}[ {cat.upper()} ]{r}")
            print(f"{b}{'ID':<6} | {'VULNERABILITY':<30} | {'REMEDIATION'}{r}")
            print("-" * 90)
            
            for code, title, rem in library_data[cat]:
                # Truncate remediation for terminal view if it's too long
                clean_rem = (rem[:50] + '..') if len(rem) > 50 else rem
                print(f"{c}{code:<6}{r} | {title:<30} | {g}{clean_rem}{r}")
            print("-" * 90)

        print(f"\n{b}Tip:{r} Use 'library \"Web App (OWASP Top 10)\"' to filter for a specific set.")

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
        """One-click generation of the complete delivery suite (Folder 05)."""
        if not company: print("Error: Company name required."); return
        self.do_report_roe(company)
        self.do_report_executive(company)
        self.do_report_risk(company)
        self.do_report_library(None)
        self.do_report_technical(company)
        self.do_report_csv(company)
        
        # Delivery Aggregation
        for folder in ["01-Pre-Engagement", "02-Executive-Summary", "03-Risk-Assessment", "04-Technical-Details"]:
            if os.path.exists(folder):
                for file in os.listdir(folder):
                    if company in file or "Library" in file:
                        shutil.copy(f"{folder}/{file}", f"05-Delivery/{file}")
                        
        print(f"\n[***] ALL ASSETS DELIVERED FOR {company.upper()}")

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
            conn = sqlite3.connect('vectorvue.db')
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
            
            p_line("MANAGEMENT & QUERY", y)
            p_line("  list <target>    - Table of Findings, IDs & Statuses")
            p_line("  library          - View 40-Point Golden Remediation Lib")
            p_line("  status <id> <val> - Update state (e.g. status 1 Fixed)")
            p_line("  delete <id>      - Permanent removal by Finding ID")
            p_line("  query <sql>      - Raw SQL search (e.g. SELECT *...)")
            print(f"├{'─' * (W + 2)}┤")
            
            p_line("REPORT GENERATION", y)
            p_line("  report_executive - High-level Summary (F02)")
            p_line("  report_technical - Technical Deep Dive (F04)")
            p_line("  report_full      - One-click Suite Generation (F05)")
            print(f"├{'─' * (W + 2)}┤")
            
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