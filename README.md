```markdown
██▒   █▓▓█████  ▄████▄  ▄▄▄█████▓ ▒█████   ██▀███      ██▒   █▓ ██▓  ██▓ ▓█████ 
▓██░   █▒▓█   ▀ ▒██▀ ▀█  ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒    ▓██░   █▒▓██▒  ██▒ ▓█   ▀ 
 ▓██  █▒░▒███   ▒▓█    ▄ ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒     ▓██  █▒░▓██░  ██▒ ▒███   
  ▒██ █░░▒▓█  ▄ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄       ▒██ █░░▒██   ██░ ▒▓█  ▄ 
   ▒▀█░  ░▒████▒▒ ▓███▀ ░  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒      ▒▀█░  ░ ████▓▒░ ░▒████▒
   ░ ▐░  ░░ ▒░ ░░ ░▒ ▒  ░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░      ░ ▐░  ░ ▒░▒░▒░  ░░ ▒░ ░
   ░ ░░   ░ ░  ░  ░  ▒       ░      ░ ░ ▒░   ░▒ ░ ▒░      ░ ░░  ░ ░ ▒░▒░   ░ ░  ░
   ░      ░    ░    ░          ░      ░ ░ ░ ▒    ░░   ░ ░      ░        ░ ░ ▒░     ░    
          ░  ░ ░                               ░               ░ ░ ░      ░  ░  
               >> RED TEAM CAMPAIGN MANAGEMENT PLATFORM <<

# VectorVue v3.0 - Red Team Campaign Management Platform

![Status](https://img.shields.io/badge/Status-Operational-39FF14) ![Version](https://img.shields.io/badge/Version-3.0_RC1-00FFFF) ![Build](https://img.shields.io/badge/Build-Enterprise_Grade-grey) ![License](https://img.shields.io/badge/License-Proprietary-FF0000)

**VectorVue v3.0** is an enterprise-grade, terminal-based Red Team Campaign Management Platform engineered for offensive security operators. It transforms raw pentest findings into structured, auditable campaign evidence within a comprehensive operational security framework.

Designed for teams that demand precision, VectorVue integrates MITRE ATT&CK® mapping, approval workflows, evidence chain of custody, and atomic database operations—all within a unified, high-performance Text User Interface (TUI).

---

## 🚀 What's New in v3.0

### Core Campaign Management
- ✅ **Campaign Isolation:** Every finding, asset, credential, and action scoped to campaigns
- ✅ **Multi-User RBAC:** Viewer → Operator → Lead → Admin (4-level role hierarchy)
- ✅ **Approval Workflow:** pending → approved → rejected state machine for findings
- ✅ **Evidence Chain of Custody:** Immutable evidence tracking with SHA256 integrity verification

### Audit & Compliance
- ✅ **Activity Timeline:** Detailed operational audit log with severity classification
- ✅ **Enhanced Logging:** Dual-logging to activity_log (v3.0) and audit_log (backward compat)
- ✅ **Operator Attribution:** All actions tracked to username with timestamps
- ✅ **Campaign Integrity:** Verify evidence authenticity with HMAC signatures

### Advanced Features
- ✅ **Attack Path Narrative:** Auto-generate chronological timeline grouped by MITRE tactic
- ✅ **Atomic Transactions:** Multi-step database operations with rollback support
- ✅ **Semantic Theme System:** 22 colors + 50+ CSS classes for OPSEC-aware decisions
- ✅ **Evidence Dashboard:** Track collected artifacts with immutable approval status

---

## ⚡ Key Technical Features

### 1. Phosphor Cyberpunk UI/UX
Optimized for high-stress, low-light operational environments, featuring:
* **Phosphor Green (#39FF14):** Active status, success, approval indicators
* **Amber (#FFBF00):** Warnings, pending review, secondary actions
* **Electric Cyan (#00FFFF):** Navigation, active focus, timestamps
* **Red Alert (#FF0000):** Errors, critical findings, rejections
* **OPSEC Colors:** Orange (caution), Lime (evidence), Magenta (audit), Teal (approval)

### 2. Campaign-Centric Architecture
* **Global Campaign Scope:** All data (findings, assets, actions) belongs to a campaign
* **Multi-Campaign Support:** Switch between campaigns seamlessly
* **Campaign Status:** planning → active → finished → archived lifecycle
* **Team Operations:** Multi-operator assignments with shared evidence visibility

### 3. Enterprise Markdown Engine
* **Real-time Syntax Highlighting:** GFM with zero input lag
* **Tactical Layout:** Split-pane for metadata + content simultaneously
* **Atomic I/O:** Fault-tolerant saves prevent data loss during crashes
* **C2 Log Ingestion:** Parse operator logs into structured findings

### 4. Intelligence & Data Core
* **Dual-Database Orchestration:**
    * `vectorvue.db`: Campaign store (findings, assets, credentials, evidence, actions)
    * `adversary.db`: Intelligence secondary store (threat profiles, MITRE data)
* **MITRE ATT&CK Integration:** Automated technique/tactic lookups with descriptions
* **Attack Graph Visualization:** Relations between assets showing lateral movement
* **CVSS 3.1 Calculator:** Built-in CVSS scoring engine

### 5. Cryptographic Security
* **AES-256 Encryption:** All sensitive fields encrypted via Fernet
* **PBKDF2 Key Derivation:** 480,000 iterations for password hardening
* **Row-Level HMAC:** Integrity signatures on all database records
* **Secure File Operations:** Atomic writes, multi-pass wipe, crypto-aware I/O

---

## 📂 Project Structure

```text
VectorVue_Root/
├── .github/
│   ├── copilot-instructions.md         # AI agent development guide
│   ├── VV3_REFACTOR_LOG.md             # vv.py Phase 2 refactoring
│   ├── VV3_THEME_REFACTOR.md           # vv_theme.py Phase 3 refactoring
│   ├── VV3_CORE_REFACTOR.md            # vv_core.py Phase 4 refactoring
│   ├── VV3_COMPLETE.md                 # Overall v3.0 completion status
│   └── V3_DEPLOYMENT_READINESS.md      # Deployment checklist
├── docs/manuals/
│   ├── INDEX.md                        # Documentation index
│   ├── GETTING_STARTED.md              # Deployment & setup
│   ├── OPERATOR_MANUAL.md              # Field usage guide
│   ├── ARCHITECTURE_SPEC.md            # Technical deep dive
│   └── TROUBLESHOOTING_GUIDE.md        # Error diagnosis & recovery
├── vv.py                               # Main TUI controller (956 lines)
├── vv_core.py                          # Database & crypto layer (1847 lines)
├── vv_fs.py                            # Filesystem abstraction (127 lines)
├── vv_theme.py                         # Semantic theme system (745 lines)
├── vv_file_manager.py                  # File CRUD manager
├── mitre_reference.txt                 # MITRE ATT&CK lookup table
├── requirements.txt                    # Dependencies
├── vectorvue.db                        # Operational database (auto-created)
├── vectorvue.salt                      # Encryption salt (auto-created)
├── LICENSE                             # Proprietary License
└── README.md                           # This file
```

---

## 🔧 Database Schema (v3.0)

### Core Tables
- **campaigns:** Campaign metadata and status tracking
- **findings:** Vulnerabilities/weaknesses with approval workflow
- **assets:** Targets (hosts, users, services) with first/last seen
- **credentials:** Captured creds (encrypted) with source tracking
- **actions:** Operator actions with MITRE technique mapping
- **evidence_items:** Immutable evidence artifacts (v3.0)
- **activity_log:** Detailed audit trail with severity (v3.0)

### Supporting Tables
- **users:** Operators with role-based access control
- **groups:** Team/group membership
- **sessions:** Session tokens for authentication
- **audit_log:** Legacy audit trail (backward compat)
- **relations:** Attack graph edges (lateral movement)
- **loot:** File artifacts and trophies

---

## 🚀 Deployment & Installation

### System Prerequisites
* **Python:** 3.10+ (tested on 3.10, 3.11, 3.12)
* **Terminal:** TrueColor (24-bit) support required (Kitty, Alacritty, iTerm2, Windows Terminal)
* **OS:** Linux (Debian/Arch/Kali), macOS
* **Memory:** 256MB minimum (1GB recommended for large campaigns)

### Quick Start

```bash
# 1. Clone repository
git clone [internal.repo/vectorvue.git](https://internal.repo/vectorvue.git)
cd vectorvue

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch VectorVue v3.0
python3 vv.py

# 5. On first launch
# → Create admin user
# → Select or create campaign
# → Start documenting findings
```

### Dependencies
- `textual` - Terminal UI framework
- `cryptography` - AES-256 encryption
- `argon2-cffi` - Argon2id password hashing
- `pydantic` - Data validation

---

## 📖 Documentation

Complete documentation with examples and workflows:

* **[Getting Started](./docs/manuals/GETTING_STARTED.md)** - Installation, setup, first campaign
* **[Operator Manual](./docs/manuals/OPERATOR_MANUAL.md)** - Keybindings, workflows, approval process
* **[Architecture Spec](./docs/manuals/ARCHITECTURE_SPEC.md)** - v3.0 schema, crypto layer, RBAC design
* **[Troubleshooting](./docs/manuals/TROUBLESHOOTING_GUIDE.md)** - Common errors and fixes

### v3.0 Feature Documentation
* **[v3.0 Completion Report](./.github/VV3_COMPLETE.md)** - What's new, what's working
* **[Deployment Readiness](./.github/V3_DEPLOYMENT_READINESS.md)** - Pre-release checklist

---

## 🔐 Security & Compliance

✅ **Evidence Integrity:** Immutable evidence_items with SHA256 hashing  
✅ **Audit Trail:** Complete activity_log with operator attribution and timestamps  
✅ **RBAC Enforcement:** 4-level role hierarchy (Viewer/Operator/Lead/Admin)  
✅ **Encryption:** AES-256 via Fernet on all sensitive fields  
✅ **Approval Workflow:** Findings require LEAD+ approval before export  
✅ **Campaign Isolation:** No cross-campaign data leakage  

---

## 🛠 Development

### Contributing

VectorVue follows strict architectural patterns documented in `.github/copilot-instructions.md`. Key patterns:

1. **Database Access:** Always use `Database` class methods, never direct SQL
2. **Campaign Context:** Every operation requires valid campaign_id
3. **Role Checks:** Enforce RBAC at controller (vv.py) AND database (vv_core.py) layers
4. **Audit Logging:** Call `db.log_audit_event()` for all mutations
5. **Cryptography:** Use `SessionCrypto` for all sensitive data

### Testing

```bash
# Verify syntax
python3 -m py_compile vv.py vv_core.py vv_theme.py vv_fs.py

# Test imports
python3 -c "import vv_core, vv_theme, vv_fs; print('✅ All modules OK')"

# Run with test campaign
python3 vv.py
```

---

## 📊 Metrics

| Component | Lines | Status | Version |
|-----------|-------|--------|---------|
| vv.py (UI Controller) | 956 | ✅ Complete | v3.0 |
| vv_core.py (Database) | 1847 | ✅ Complete | v3.0 |
| vv_theme.py (Theme) | 745 | ✅ Complete | v3.0 |
| vv_fs.py (Filesystem) | 127 | ✅ Complete | v3.0 |
| **Total** | **3675** | ✅ v3.0 Ready | **v3.0-RC1** |

---

## 📋 Version History

### v3.0 (Current - February 2026)
- ✅ Campaign management platform
- ✅ Multi-user RBAC
- ✅ Approval workflow
- ✅ Evidence chain of custody
- ✅ Activity timeline
- ✅ Atomic transactions
- ✅ MITRE attack path narrative
- ✅ Semantic theme system (22 colors, 50+ CSS classes)

### v2.1 (Legacy)
- Pentest findings notebook
- Single-user operation
- Basic MITRE lookup
- Atomic file I/O
- Phosphor cyberpunk theme

---

## ⚖️ License & Disclaimer

**VectorVue v3.0** is proprietary software developed for Offensive Security R&D. Unauthorized distribution or reverse engineering is strictly prohibited. The developers assume no liability for misuse or damage caused by this software in non-authorized environments.

For enterprise licensing inquiries, contact the Internal Engineering Lead.

---

**VectorVue v3.0** | *Precision Intelligence. Campaign Management. Tactical Reporting.*

---

```
