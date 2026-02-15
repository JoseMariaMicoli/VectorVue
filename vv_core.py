import sqlite3
import math
import os
import sys
from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple
from pathlib import Path

# --- CRYPTOGRAPHY LAYER ---
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("WARNING: 'cryptography' module not found. DB encryption disabled (Plaintext mode).")
    print("INSTALL: pip install cryptography")

# --- NIST REPORTING TEMPLATE ---
NIST_800_115_SKELETON = """# PENTEST REPORT: [TARGET_NAME]
**Date:** [DATE]
**Methodology:** NIST SP 800-115
**Classification:** CONFIDENTIAL

## 1. Executive Summary
[High-level overview of risk for management. Do not include technical jargon here.]

## 2. Assessment Methodology
The assessment followed the NIST SP 800-115 standard:
1. **Planning:** Rules of Engagement defined.
2. **Discovery:** Asset identification and scanning.
3. **Attack:** Exploit validation (evidence-based).
4. **Reporting:** Analysis and remediation planning.

## 3. Summary of Findings
| ID | Severity | Title |
|----|----------|-------|
| 01 | CRITICAL | [Example Title] |

## 4. Technical Findings & Evidence

### 4.1 [Finding Title]
**CVSS:** 9.8 (Critical) | **ID:** VUE-01
**Description:**
[Technical description]

**Evidence:**
```bash
[Paste Evidence Here]
```

**Remediation:**
[Specific technical fix]

## 5. Appendices
"""

class CryptoManager:
    """Handles Column-Level Encryption for the Database"""
    KEY_FILE = "vector.key"

    def __init__(self):
        self.cipher = None
        if CRYPTO_AVAILABLE:
            self.load_or_generate_key()

    def load_or_generate_key(self):
        if os.path.exists(self.KEY_FILE):
            with open(self.KEY_FILE, "rb") as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.KEY_FILE, "wb") as f:
                f.write(key)
        self.cipher = Fernet(key)

    def encrypt(self, text: str) -> str:
        if not self.cipher or not text: return text
        try:
            return self.cipher.encrypt(text.encode()).decode()
        except Exception:
            return text  # Fallback if already corrupted/string issues

    def decrypt(self, text: str) -> str:
        if not self.cipher or not text: return text
        try:
            # Check if it looks like a Fernet token (basic check)
            if text.startswith("gAAAA"):
                return self.cipher.decrypt(text.encode()).decode()
            return text
        except Exception:
            return text  # Return raw if decryption fails (legacy data)

# --- BUILT-IN INTELLIGENCE (Golden Remediation Library) ---
GOLDEN_LIBRARY = {
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
        ("A10", "SSRF", "Sanitize inputs for URLs; implement strict allowlists for outbound calls.")
    ],
    "API Security (OWASP API)": [
        ("API1", "BOLA (Object Level)", "Validate that the logged-in user owns the resource requested."),
        ("API2", "Broken Authentication", "Use standard OAuth2/OpenID Connect; secure tokens with short TTLs."),
        ("API3", "BOPLA (Property Level)", "Use Data Transfer Objects (DTOs) to prevent 'Mass Assignment'."),
        ("API4", "Unrestricted Consumption", "Set Rate Limits (TPS) and quotas for CPU/Memory/Payload size."),
        ("API5", "Broken Function Level", "Enforce RBAC (Role-Based Access Control) on all admin endpoints.")
    ],
    "AD & Infrastructure": [
        ("AD-01", "Kerberoasting", "Use gMSAs or passwords with >25 characters for Service Accounts."),
        ("AD-02", "AS-REP Roasting", "Enable 'Do not require Kerberos preauthentication' only where necessary."),
        ("NET-01", "LLMNR/NBNS", "Disable via GPO; enable SMB Signing to prevent relaying.")
    ]
}

# --- CVSS CALCULATOR LOGIC ---
class CVSSCalculator:
    METRICS = {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR": {
            "N": {"U": 0.85, "C": 0.85},
            "L": {"U": 0.62, "C": 0.68},
            "H": {"U": 0.27, "C": 0.50}
        },
        "UI": {"N": 0.85, "R": 0.62},
        "S":  {"U": 6.42, "C": 7.52},
        "C":  {"N": 0.0, "L": 0.22, "H": 0.56},
        "I":  {"N": 0.0, "L": 0.22, "H": 0.56},
        "A":  {"N": 0.0, "L": 0.22, "H": 0.56}
    }

    @staticmethod
    def calculate(vector_str: str) -> float:
        try:
            parts = vector_str.upper().split('/')
            d = {}
            for p in parts:
                if ':' in p:
                    k, v = p.split(':')
                    d[k] = v

            scope = d.get("S", "U")
            av = CVSSCalculator.METRICS["AV"][d.get("AV", "N")]
            ac = CVSSCalculator.METRICS["AC"][d.get("AC", "L")]
            ui = CVSSCalculator.METRICS["UI"][d.get("UI", "N")]
            pr = CVSSCalculator.METRICS["PR"][d.get("PR", "N")][scope]
            c = CVSSCalculator.METRICS["C"][d.get("C", "N")]
            i = CVSSCalculator.METRICS["I"][d.get("I", "N")]
            a = CVSSCalculator.METRICS["A"][d.get("A", "N")]

            iss = 1 - ((1 - c) * (1 - i) * (1 - a))
            
            if scope == 'U':
                impact = 6.42 * iss
            else:
                impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

            if impact <= 0: return 0.0

            exploitability = 8.22 * av * ac * pr * ui
            
            if scope == 'U':
                base_score = min((impact + exploitability), 10)
            else:
                base_score = min(1.08 * (impact + exploitability), 10)

            return math.ceil(base_score * 10) / 10.0
        except Exception:
            return 0.0

# --- DATA MODELS ---

@dataclass
class Finding:
    """Core Finding Model"""
    id: Optional[int]
    title: str
    description: str
    cvss_score: float = 0.0
    mitre_id: str = ""
    tactic_id: str = ""
    status: str = "Open"
    evidence: str = "" 
    remediation: str = ""
    project_id: str = "DEFAULT"
    cvss_vector: str = ""

@dataclass
class MitreTechnique:
    """Intel Model"""
    id: str
    name: str
    description: str

# --- INTELLIGENCE ENGINE ---

class IntelligenceEngine:
    """
    Manages knowledge base. 
    1. Loads mitre_reference.txt if available.
    2. Provides built-in Golden Library lookups.
    """
    REFERENCE_FILE = "mitre_reference.txt"

    def __init__(self):
        self.mitre_cache: Dict[str, MitreTechnique] = {}
        self.techniques_list: List[MitreTechnique] = [] 
        self._load_mitre_reference()

    def _load_mitre_reference(self):
        path = Path(self.REFERENCE_FILE)
        if not path.exists():
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    if "|" in line:
                        parts = line.strip().split("|")
                        if len(parts) >= 2:
                            tid = parts[0].strip()
                            name = parts[1].strip()
                            desc = parts[2].strip() if len(parts) > 2 else "No description."
                            
                            tech = MitreTechnique(tid, name, desc)
                            self.mitre_cache[tid.upper()] = tech
                            self.techniques_list.append(tech)
        except Exception:
            pass

    def lookup_mitre(self, technique_id: str) -> Optional[MitreTechnique]:
        return self.mitre_cache.get(technique_id.upper())

    def search_techniques(self, query: str) -> List[MitreTechnique]:
        q = query.upper()
        return [t for t in self.techniques_list if q in t.id.upper() or q in t.name.upper()]

    def get_remediation_suggestion(self, category: str) -> List[Tuple[str, str, str]]:
        results = []
        for key, items in GOLDEN_LIBRARY.items():
            if category.lower() in key.lower() or key.lower() in category.lower():
                results.extend(items)
        return results

# --- CORE DATABASE MANAGER ---

class Database:
    """Primary SQLite Database with Encryption and Migration"""
    DB_NAME = "vectorvue.db"

    def __init__(self):
        self.crypto = CryptoManager()
        self.conn = sqlite3.connect(self.DB_NAME, check_same_thread=False)
        self.check_schema()

    def check_schema(self):
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS findings
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      title TEXT NOT NULL,
                      description TEXT, 
                      cvss_score REAL DEFAULT 0.0,
                      mitre_id TEXT DEFAULT '',
                      tactic_id TEXT DEFAULT '',
                      status TEXT DEFAULT 'Open',
                      evidence TEXT DEFAULT '',
                      remediation TEXT DEFAULT '',
                      project_id TEXT DEFAULT 'DEFAULT',
                      cvss_vector TEXT DEFAULT '')''')
        
        # Migrations for existing DBs
        try:
            c.execute("ALTER TABLE findings ADD COLUMN project_id TEXT DEFAULT 'DEFAULT'")
        except sqlite3.OperationalError:
            pass 
        
        try:
            c.execute("ALTER TABLE findings ADD COLUMN cvss_vector TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass 

        self.conn.commit()

    def get_findings(self, project_id: str = "DEFAULT") -> List[Finding]:
        """Returns findings for project, decrypts sensitive fields"""
        # Safety check for None
        if project_id is None: project_id = "DEFAULT"
        
        c = self.conn.cursor()
        c.execute("SELECT * FROM findings WHERE project_id=? ORDER BY cvss_score DESC", (project_id,))
        rows = c.fetchall()
        
        results = []
        for r in rows:
            try:
                # Decrypt sensitive text fields
                desc = self.crypto.decrypt(r[2])
                evidence = self.crypto.decrypt(r[7])
                remediation = self.crypto.decrypt(r[8])

                results.append(Finding(
                    id=r[0], title=r[1], description=desc, 
                    cvss_score=r[3], mitre_id=r[4], tactic_id=r[5], 
                    status=r[6], evidence=evidence, remediation=remediation,
                    project_id=r[9], cvss_vector=r[10]
                ))
            except IndexError:
                continue 
        return results

    def add_finding(self, f: Finding) -> int:
        c = self.conn.cursor()
        
        # Encrypt sensitive fields before storage
        enc_desc = self.crypto.encrypt(f.description)
        enc_evid = self.crypto.encrypt(f.evidence)
        enc_rem = self.crypto.encrypt(f.remediation)

        c.execute("""INSERT INTO findings 
                     (title, description, cvss_score, mitre_id, tactic_id, status, 
                      evidence, remediation, project_id, cvss_vector) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                  (f.title, enc_desc, f.cvss_score, f.mitre_id, f.tactic_id, f.status, 
                   enc_evid, enc_rem, f.project_id, f.cvss_vector))
        self.conn.commit()
        return c.lastrowid

    def update_finding(self, f: Finding):
        if not f.id: return
        c = self.conn.cursor()
        
        # Encrypt sensitive fields
        enc_desc = self.crypto.encrypt(f.description)
        enc_evid = self.crypto.encrypt(f.evidence)
        enc_rem = self.crypto.encrypt(f.remediation)

        c.execute("""UPDATE findings SET 
                     title=?, description=?, cvss_score=?, mitre_id=?, status=?, 
                     evidence=?, remediation=?, project_id=?, cvss_vector=?
                     WHERE id=?""",
                  (f.title, enc_desc, f.cvss_score, f.mitre_id, f.status, 
                   enc_evid, enc_rem, f.project_id, f.cvss_vector, f.id))
        self.conn.commit()

    def delete_finding(self, fid: int):
        c = self.conn.cursor()
        c.execute("DELETE FROM findings WHERE id=?", (fid,))
        self.conn.commit()

    def close(self):
        self.conn.close()