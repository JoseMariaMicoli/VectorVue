
/*
Copyright (c) 2026 José María Micoli
Licensed under Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Remove copyright notices
*/

# Getting Started with VectorVue v3.8

![Setup](https://img.shields.io/badge/Setup-v3.8_Production_Ready-39FF14?style=flat-square) ![Status](https://img.shields.io/badge/Status-Phase_5.5_Complete-39FF14?style=flat-square) ![Cognition](https://img.shields.io/badge/Cognition-Operational-39FF14?style=flat-square) ![Features](https://img.shields.io/badge/Features-78_Tables_250%2B_Methods-39FF14)

This guide covers deployment of **VectorVue v3.8**, the complete Red Team Campaign Management Platform with Phases 0-5 and Phase 5.5 (Operational Cognition) implemented: campaign management, RBAC, evidence chain of custody, operational intelligence, operational cognition decision-support, reporting & export, multi-team federation, and advanced threat intelligence. Follow these steps to get operationally ready.

---

## 🎯 What is VectorVue v3.8?

VectorVue is a terminal-based (TUI) platform for red team operators to:
- **Manage campaigns** with client context, ROE, objectives, and team assignments
- **Document findings** with CVSS scoring, MITRE ATT&CK mapping, approval workflows
- **Track operations** including command execution, active sessions, persistence, detections
- **Support decisions** with deterministic analysis, risk scoring, and explainable recommendations (Phase 5.5)
- **Correlate intelligence** with threat feeds, threat actors, IoCs, enrichment data
- **Generate reports** in multiple formats with evidence manifests and compliance mapping
- **Coordinate teams** with role-based access, shared pools, performance tracking
- **Analyze threats** with automated risk scoring, behavioral analytics, defense prediction
- **Make better decisions** with operational cognition: pathfinding, objective tracking, detection pressure, confidence scoring (Phase 5.5)

**New in v3.8:** Operational Cognition (Phase 5.5) - Attack graph pathfinding, objective distance, recommendation scoring, detection pressure tracking, OpSec simulation, event replay, operator tempo analysis, infrastructure burn tracking, confidence analysis, and pattern learning.

---

## 1️⃣ System Requirements

### Operating System
- **Linux:** Debian 11+, Ubuntu 20.04+, Fedora 36+, Kali Linux, ParrotOS, Arch
- **macOS:** Monterey 12.0+ (Intel and Apple Silicon native)
- **Windows:** WSL2 (Windows 10/11) with native terminal support
- **Container:** Docker support coming in Phase 6

### Python & Runtime
- **Python:** 3.10+ (tested on 3.10, 3.11, 3.12)
- **pip:** 21.0+ (dependency management)
- **Terminal:** 256-color minimum, 24-bit TrueColor recommended (UTF-8 required)
  - ✅ **Recommended:** Kitty, Alacritty, WezTerm, iTerm2, Windows Terminal v1.5+
  - ✅ **Works:** GNOME Terminal, Konsole, Xterm with color support
  - ❌ **Not Supported:** Legacy Windows CMD, basic xterm, PuTTY

### Hardware
- **Memory:** 512MB minimum, 2GB+ recommended (for background tasks and analytics)
- **Storage:** 200MB+ free (SQLite database grows ~10MB per 1000 findings, 5MB per 500 credentials)
- **CPU:** Dual-core minimum (background executor runs on separate async task)
- **Network:** Not required (fully air-gap capable, local SQLite only)

### Optional: MITRE ATT&CK
- `mitre_reference.txt` file should exist in root directory (CSV format)
- Contains: Technique ID, Tactic, Technique Name, Description

---

## 2️⃣ Installation & Setup

### Step 1: Clone Repository
```bash
git clone https://github.com/yourorg/vectorvue.git
cd vectorvue
```

### Step 2: Create Python Virtual Environment
```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Windows (Command Prompt)
python -m venv venv
venv\Scripts\activate.bat
```

Verify activation:
```bash
which python  # Linux/macOS
where python  # Windows
# Should show: /path/to/vectorvue/venv/bin/python
```

### Step 3: Install Dependencies
```bash
# Upgrade pip (important for security)
pip install --upgrade pip setuptools wheel

# Install requirements
pip install -r requirements.txt
```

**Core Dependencies:**
- `textual>=0.90.0` - Terminal UI framework
- `cryptography>=42.0.0` - AES-256-GCM encryption
- `argon2-cffi>=23.1.0` - Password hashing (PBKDF2)
- `Pillow>=11.0.0` - Image handling for reports

**Installation troubleshooting:**
- If `pip install` fails with build errors, install system dev packages:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install python3-dev libssl-dev
  
  # Fedora/RHEL
  sudo dnf install python3-devel openssl-devel
  
  # macOS (Homebrew)
  brew install python@3.12  # If needed
  ```

### Step 4: Verify Installation
```bash
# Check Python version
python --version  # Should be 3.10+

# Check dependencies
python -c "import textual, cryptography; print('✓ Dependencies OK')"

# Check MITRE reference (if available)
ls -l mitre_reference.txt  # Should exist

# Run syntax check
python -m py_compile vv.py vv_core.py vv_theme.py vv_fs.py
echo "✓ All source files valid"
```

---

## 3️⃣ First Launch & Authentication

### IMPORTANT: Authentication is Required on Every Launch

**Security Note:** VectorVue requires fresh authentication on each startup. There is **no automatic session resumption** - you must log in each time. This prevents unauthorized access to sensitive campaign data.

### Initial Startup
```bash
python3 vv.py
```

**Expected first-time behavior:**
1. ✅ Application initializes, TUI loads
2. ✅ Database created: `vectorvue.db` (41-72 MB)
3. ✅ Salt file created: `vectorvue.salt` (256-bit random)
4. ✅ Registration screen displayed (no users yet)
5. ✅ Status bar shows: "FIRST RUN: REGISTER YOUR ADMIN ACCOUNT"
6. ✅ Terminal displays phosphor green (#39FF14) and cyan (#00FFFF) colors

### Create Admin User (First Run Only)

The **first user** created automatically becomes **ADMIN** (highest privilege level).

1. **Fill Registration Form:**
   - Username: Your operator identifier (e.g., `john.operator`, `red-lead-1`)
   - Password: Strong passphrase (12+ characters recommended)
     - Use mix of upper/lower/numbers/symbols
     - Example: `Cr1ms0n-Shadow-2026!`
   - Confirm Password: Re-enter identical password

2. **Click REGISTER** or press Enter

3. **Await confirmation:**
   - Status bar: "REGISTRATION COMPLETE — AUTHENTICATE NOW" (green)
   - Auto-redirects to login screen

4. **Log in with new credentials:**
   - Username: [same as above]
   - Password: [same as above]
   - Press LOGIN

5. **Success! You are now ADMIN:**
   - Status bar: "ACCESS GRANTED [ADMIN] — john.operator"
   - Main editor view loads
   - All buttons become enabled

### Subsequent Launches

On subsequent runs, when you execute `python3 vv.py`:

1. Application checks if users exist in database
2. If users exist: Login screen appears immediately
3. **Must authenticate with username + password**
4. No automatic login or session resumption
5. After successful login: Editor view loads

---

## 4️⃣ Create Your First Campaign

After successful authentication:

### Step 1: Initialize Campaign
Press **Ctrl+K** (or click **CAMPAIGN OPS**) to open Campaign View

### Step 2: Fill Campaign Details
- **Campaign Name:** e.g., "ACME Corp Q1 2026 Assessment"
- **Client:** Organization name (e.g., "ACME Corporation")
- **Operator Team:** Your red team identifier (e.g., "Red Team Alpha")
- **Start Date:** YYYY-MM-DD format (e.g., 2026-02-17)
- **End Date:** Optional, or leave as NULL
- **Rules of Engagement:** Operating constraints
  ```
  Operating hours: 9 AM - 5 PM EST weekdays
  Avoid: Production databases, critical systems
  Sensitive hosts: Finance servers (192.168.10.0/24)
  ```
- **Objective:** Campaign goal (e.g., "Comprehensive assessment of perimeter security")
- **Classification:** Sensitivity level (UNCLASSIFIED/CONFIDENTIAL/SECRET)

### Step 3: Click CREATE CAMPAIGN

Status bar confirms: "✓ CAMPAIGN CREATED (ID: 1)"

### Step 4: Verify Campaign is Active
- Lateral panel shows: "CAMPAIGN ACTIVE: ACME Corp Q1 2026 Assessment"
- **Ctrl+K** now shows your campaign data

---

## 5️⃣ Understanding User Roles & Permissions

VectorVue has **4 role levels** with increasing privileges:

### VIEWER (Level 0)
- Can view all findings, evidence, reports
- **Cannot** create, edit, or delete
- Use for: Observers, auditors, read-only access

### OPERATOR (Level 1)  
- Can create and edit findings
- Can ingest IoCs, create evidence items
- Can execute background tasks
- **Cannot** approve findings or delete campaigns
- Use for: Day-to-day operators entering findings

### LEAD (Level 2)
- Can do everything Operators can do
- **Can** approve findings (before export)
- Can create teams, policies, and intelligence reports
- Can configure webhooks and integrations
- **Cannot** delete campaigns or modify users
- Use for: Team leads, senior operators

### ADMIN (Level 3)
- **Full access** to all features
- Can create/delete/modify anything
- Can create user accounts and assign roles
- Can manage retention policies and compliance settings
- Use for: Lead operators, system administrators

---

## 6️⃣ Core UI Navigation

### Primary Views (Ctrl+ key)

| Key | View | Purpose |
|-----|------|---------|
| Space | File Manager | Browse, upload, manage files |
| Ctrl+M | MITRE DB | Technique/tactic search & linking |
| Ctrl+K | Campaign | Active campaign context & switching |
| Ctrl+E | Command Log | Executed commands & C2 output |
| Ctrl+J | Sessions | Active operational sessions |
| Ctrl+D | Detections | Detected by defender activity |
| Ctrl+O | Objectives | Campaign goal tracking |
| Ctrl+P | Persistence | Backdoors & persistence mechanisms |

### Analytics Views (Ctrl+1-5)

| Key | View | Purpose |
|-----|------|---------|
| Ctrl+1 | Dashboard | Real-time metrics, risk heat map |
| Ctrl+2 | Analysis | Post-engagement TTP analysis |
| Ctrl+3 | Intel (legacy) | Threat intelligence (Phase 2) |
| Ctrl+4 | Remediation | Remediation action tracking |
| Ctrl+5 | Capability | Capability assessment matrix |

### Advanced Views (Alt+1-6)

| Key | View | Purpose |
|-----|------|---------|
| Alt+1 | Collaboration | Multi-operator session mgmt |
| Alt+2 | Tasks | Background task orchestration |
| Alt+3 | Analytics | Behavioral anomaly detection |
| Alt+4 | Integration | Webhook endpoint management |
| Alt+5 | Compliance | Compliance attestation reports |
| Alt+6 | Security | TLP, audit logs, retention |

### Phase 3-5 Views

| Key | View | Purpose |
|-----|------|---------|
| Ctrl+R | Reporting | PDF/HTML reports, evidence manifests |
| Ctrl+T | Teams | Team management, coordination |
| Ctrl+Shift+I | Threat Intel | IoC management, threat actor profiles, risk scoring |

---

## 7️⃣ First Operational Tasks

### Create Your First Finding

1. Press **Escape** to return to main editor
2. Type in markdown format:
   ```markdown
   # Weak Password Policy

   ## Summary
   User passwords are not enforced to meet complexity requirements.

   ## CVSS Score
   6.5 (Medium)

   ## Impact
   Attackers can use dictionary attacks to compromise accounts.
   ```

3. Fill lateral panel:
   - **Vector Title:** "Weak Password Policy"
   - **CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
   - **MITRE ID:** T1110 (Brute Force)

4. Click **NEW ENTRY** to add to findings queue

5. Click **COMMIT DB** to save finding

### Log a Command Execution (Phase 1)

1. Press **Ctrl+E** (Command Execution Log)
2. View logged commands if any exist
3. Commands logged via database methods (not manual in UI)

### Check Campaign Coverage (Phase 2b)

1. Press **Ctrl+1** (Dashboard)
2. View metrics: assets, credentials, sessions, persistence
3. Risk score aggregated from findings

### Generate a Report (Phase 3)

1. Press **Ctrl+R** (Reporting)
2. Select report type: Technical, Executive, Client
3. Select format: PDF or HTML
4. Add executive summary
5. Click **GENERATE REPORT**
6. Report saved to `Reports/` directory

---

## 8️⃣ Background Task Execution (Phase 2c)

VectorVue runs a **background task executor** automatically after login. This handles:

- **Task Scheduler:** Executes pending scheduled tasks every 30 seconds
- **Webhook Delivery:** Sends integration payloads to external endpoints
- **Session Timeout:** Expires idle sessions after 120 minutes
- **Retention Policy:** Purges old findings/credentials/logs per policy
- **Anomaly Detection:** Analyzes operator behavior for anomalies

You don't need to manually start the executor - it's started automatically in `_post_login_setup()`.

**Stop Executor:**
- Press **Ctrl+L** (Logout) - executor stops gracefully
- Press **q** (Quit) - executor stops before exit

---

## 9️⃣ Multi-Team Setup (Phase 4)

### Create a Team

1. Press **Ctrl+T** (Team Management)
2. Enter Team Name, Description, Budget (USD)
3. Click **CREATE TEAM**
4. Team appears in team list

### Add Members to Team

1. In Team Management, select team
2. Click **ADD MEMBER**
3. Select user, assign role (team_member, team_lead)
4. Member added to team_members table

### Share Intelligence

1. Create an Intelligence Pool (Phase 4)
2. Add findings/IoCs to pool
3. Select teams with access
4. Teams can query pooled intelligence

---

## 🔟 Threat Intelligence Setup (Phase 5)

### Add Threat Feed

1. Press **Ctrl+Shift+I** (Threat Intelligence)
2. Click **Add Feed (VirusTotal/Shodan/OTX/MISP)**
3. Enter:
   - Feed URL (e.g., https://api.virustotal.com/api/v3/feeds)
   - Feed Type (VirusTotal, Shodan, OTX, MISP, Custom)
   - API Key (encrypted in database)
   - Description
4. Click **ADD FEED**

### Create Threat Actor Profile

1. In Threat Intelligence view
2. Click **Create Threat Actor Profile**
3. Enter:
   - Actor Name (e.g., "Lazarus Group")
   - Origin Country (e.g., "North Korea")
   - Organization (e.g., "APT1")
   - Known Targets (e.g., "Financial institutions")
   - Confidence (0.0-1.0)
4. Click **CREATE**

### Ingest Indicators of Compromise

1. In Threat Intelligence view
2. Click **Ingest IoC (IP/Domain/Hash/Email)**
3. Select indicator type
4. Enter value (e.g., 192.168.1.100)
5. Set threat level (LOW/MEDIUM/HIGH/CRITICAL)
6. Click **INGEST**

### Check Risk Scores

1. View Risk Scores & Threats section
2. See automated 0-10 risk scores for findings
3. Risk levels: CRITICAL (≥8.0), HIGH (≥6.0), MEDIUM (≥4.0), LOW (<4.0)

---

## 🚀 Troubleshooting Initial Setup

### Issue: "Terminal colors not displaying"
**Solution:** Ensure terminal supports 256-color or 24-bit true color
```bash
# Check color support
echo $TERM  # Should show xterm-256color, alacritty, etc.

# Force color mode
export TERM=xterm-256color
python3 vv.py
```

### Issue: "Cannot import textual"
**Solution:** Reinstall from requirements.txt with correct pip
```bash
pip install --upgrade pip
pip install -r requirements.txt --force-reinstall
```

### Issue: "No such file or directory: 'mitre_reference.txt'"
**Solution:** This is optional, but recommended
```bash
# Get MITRE ATT&CK data from upstream source
# File format: technique_id,tactic,name,description
# Create empty file if unavailable:
touch mitre_reference.txt
```

### Issue: "Authentication required on every launch"
**Solution:** This is **intentional for security**. VectorVue requires fresh login each time to prevent unauthorized access.

### Issue: "SQLite database locked"
**Solution:** Another VectorVue instance is running
```bash
# Check running processes
ps aux | grep vv.py

# Kill if needed
pkill -f vv.py

# Restart
python3 vv.py
```

---

## 📚 Next Steps

After completing first-time setup:

1. **Read [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md)** - Complete operations guide
2. **Review [COMPLETE_FEATURES.md](./COMPLETE_FEATURES.md)** - All feature reference
3. **Check [TROUBLESHOOTING_GUIDE.md](./TROUBLESHOOTING_GUIDE.md)** - Common issues
4. **Study [ARCHITECTURE_SPEC.md](./ARCHITECTURE_SPEC.md)** - Technical deep-dive

---

**VectorVue v3.7** | Production Ready | 72 Tables | 200+ Methods | Phase 5 Complete

For support: See [TROUBLESHOOTING_GUIDE.md](./TROUBLESHOOTING_GUIDE.md)
