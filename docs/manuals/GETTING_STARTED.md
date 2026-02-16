# Getting Started with VectorVue v3.0

![Setup](https://img.shields.io/badge/Setup-v3.0_Ready-39FF14?style=flat-square) ![Status](https://img.shields.io/badge/Status-Production_Ready-00FFFF?style=flat-square)

This document outlines the procedure for deploying VectorVue v3.0 and setting up your first Red Team campaign. Follow these steps carefully to ensure system stability and data integrity.

## 1. System Requirements

Before deploying VectorVue v3.0, verify your system meets these specifications:

### Operating System
- **Linux:** Debian 11+, Ubuntu 20.04+, Fedora 36+, Kali Linux, ParrotOS
- **macOS:** Monterey 12.0+
- **Windows:** PowerShell 7+ or WSL2 (Windows 10/11)

### Python & Runtime
- **Python:** 3.10+ (tested on 3.10, 3.11, 3.12)
- **Terminal:** Must support 24-bit TrueColor and UTF-8 rendering
  - ✅ **Recommended:** Kitty, Alacritty, WezTerm, iTerm2, Windows Terminal
  - ❌ **Not Supported:** Legacy Windows CMD

### Hardware
- **Memory:** 256MB minimum (1GB recommended for large campaigns)
- **Storage:** 100MB free (SQLite database grows with data)
- **Network:** Internet connection for initial setup (optional after)

## 2. Installation & Setup

### Step 1: Clone Repository
Retrieve VectorVue v3.0 from the internal repository:

```bash
git clone https://internal.repo/vectorvue.git
cd vectorvue
```

### Step 2: Create Virtual Environment
Always use a virtual environment to isolate dependencies:

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\activate
```

### Step 3: Install Dependencies
VectorVue v3.0 requires cryptography libraries and the Textual TUI framework:

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

**Key Dependencies:**
- `textual` (0.90+) - Terminal UI framework
- `cryptography` - AES-256 encryption (Fernet)
- `argon2-cffi` - Password hashing
- `pydantic` - Data validation

### Step 4: Verify MITRE Data
VectorVue uses MITRE ATT&CK® mappings for technique coverage:

```bash
# Verify mitre_reference.txt exists in root directory
ls -la mitre_reference.txt

# Expected format: T-Code | Technique | Tactic | Description
# Example: T1566 | Phishing | Initial Access | ...
```

If the file is missing, the application will still work but MITRE lookups will be unavailable.

## 3. First Launch & Initial Setup

### Launch VectorVue v3.0
```bash
python3 vv.py
```

**You should see:**
1. ✅ Application loads without errors
2. ✅ Login screen appears (blue header with "VectorVue v3.0")
3. ✅ Terminal renders colors correctly (Phosphor green #39FF14, cyan #00FFFF)
4. ✅ Status bar shows "READY"

### First-Time Initialization
On first launch, VectorVue v3.0 will:
1. Create `vectorvue.db` (operational database)
2. Create `adversary.db` (intelligence database)
3. Generate `vectorvue.salt` (encryption salt for session key derivation)
4. Prompt you to create an **admin user**

**Create Admin Account:**
```
Username: [your-username]
Password: [strong-password-16+ chars recommended]
Confirm Password: [re-enter]
Role: ADMIN
```

Save these credentials securely—you cannot recover a lost admin password without database recovery tools.

## 4. Creating Your First Campaign

### Step 1: Log In
Use the admin credentials created during first launch:
- Username: `[your-username]`
- Password: `[your-password]`

### Step 2: Create Campaign
Once logged in, create your first campaign:
1. Navigate to **Campaigns** view
2. Press `[C]` to create new campaign
3. Fill in campaign details:
   - **Name:** e.g., "Client-Corp Red Team 2026"
   - **Client:** e.g., "Client Corporation"
   - **Operator Team:** Your team name
   - **Objective:** Engagement scope, e.g., "Complete network penetration test"
   - **Rules of Engagement:** Restrictions, hours, sensitive systems
   - **Classification:** e.g., "CONFIDENTIAL"

### Step 3: Invite Operators
Add team members to the campaign:
1. In campaign settings, select **Manage Team**
2. Add operators by username:
   - **Username:** Team member's account
   - **Role:** Operator (default), Lead, or Viewer
3. They can log in and access the campaign immediately

## 5. Understanding User Roles

VectorVue v3.0 implements four-level role-based access control (RBAC):

| Role | Permissions | Use Case |
|------|-------------|----------|
| **VIEWER** | Read-only access to findings, assets, evidence | Client presentations, documentation review |
| **OPERATOR** | Create findings, collect evidence, log actions | Pentesters, exploitation engineers |
| **LEAD** | Approve findings, manage evidence, create reports | Engagement leads, quality assurance |
| **ADMIN** | User management, campaign deletion, system config | Project managers, engagement leads |

**Permission Hierarchy:** VIEWER < OPERATOR < LEAD < ADMIN

A user with LEAD role inherits all OPERATOR permissions and can approve findings before they're finalized.

## 6. Core Workflows

### Adding Your First Finding
1. Navigate to **Findings** view
2. Press `[N]` for new finding
3. Fill in details:
   - **Title:** Vulnerability title (e.g., "SQL Injection in Login Form")
   - **Severity:** CRITICAL, HIGH, MEDIUM, LOW, INFO
   - **CVSS Score:** e.g., 9.1 (auto-calculated if you prefer)
   - **Description:** Details and proof of concept
   - **MITRE Technique:** Select from dropdown (e.g., T1566 - Phishing)
4. Save finding (status: **PENDING**)
5. Wait for LEAD approval

### Collecting Evidence
1. In the finding, press `[E]` to add evidence
2. Select file or create evidence:
   - **Type:** Screenshot, log, credential, artifact
   - **File:** Upload proof (hash verified automatically)
3. System records:
   - ✅ SHA256 hash of artifact
   - ✅ Who collected it (your username)
   - ✅ When it was collected (timestamp)
   - ✅ Collection method (manual, C2, tool output)
4. Evidence is **immutable** (cannot be edited after creation)

### Approving Findings (LEAD+ Only)
1. As a LEAD, navigate to **Findings**
2. Filter by **Status: PENDING**
3. Review each finding
4. Press `[A]` to **approve** or `[R]` to **reject**
5. Approved findings are locked and ready for export

## 7. Generating Reports

### Create Campaign Report
1. Navigate to **Reports** view
2. Press `[G]` to generate report
3. Select export format:
   - **Markdown:** Default, human-readable
   - **JSON:** Machine-readable with metadata
   - **CSV:** For spreadsheet analysis
4. Report includes:
   - ✅ Only **approved** findings
   - ✅ Attack timeline (chronological activity log)
   - ✅ MITRE coverage matrix
   - ✅ Operator attribution
   - ✅ Evidence integrity verification

## 8. Troubleshooting Initial Setup

### Issue: "Not Authenticated" Error
**Cause:** User not logged in or session expired  
**Solution:** Log out and log back in using admin credentials

### Issue: "Campaign Not Found"
**Cause:** No campaign created yet  
**Solution:** Follow Step 4 above to create your first campaign

### Issue: Colors Not Rendering (Monochrome)
**Cause:** Terminal doesn't support TrueColor  
**Solution:** Use recommended terminal (Kitty, Alacritty, Windows Terminal)

### Issue: "mitre_reference.txt Not Found"
**Cause:** MITRE data file missing  
**Solution:** File is optional; MITRE lookups will be disabled but app still works

For more troubleshooting, see [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md)

---

## 🎯 Next Steps

✅ **Installation complete!** Now proceed to:

1. **[Operator Manual](./OPERATOR_MANUAL.md)** - Learn keyboard shortcuts and daily workflows
2. **[Architecture Spec](./ARCHITECTURE_SPEC.md)** - Understand database schema and RBAC design (optional)
3. Start documenting your engagement findings

**Questions?** See [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md) or contact your team lead.

---

**VectorVue v3.0** | Red Team Campaign Management Platform | v3.0-RC1
