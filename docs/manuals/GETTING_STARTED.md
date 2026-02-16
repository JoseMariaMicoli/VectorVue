# Getting Started with VectorVue v3.4

![Setup](https://img.shields.io/badge/Setup-v3.4_Production_Ready-39FF14?style=flat-square) ![Status](https://img.shields.io/badge/Status-Phase_2/8-00FFFF?style=flat-square) ![Phase](https://img.shields.io/badge/Phase-Complete-39FF14)

This guide covers deployment of VectorVue v3.4 Red Team Campaign Management Platform, which includes phases 0-2 complete with 41 database tables, 16 UI views, background task execution, and enterprise-ready security features. Follow these steps to get operationally ready.

## 1. System Requirements

### Operating System
- **Linux:** Debian 11+, Ubuntu 20.04+, Fedora 36+, Kali Linux, ParrotOS
- **macOS:** Monterey 12.0+ (Intel and Apple Silicon)
- **Windows:** WSL2 (Windows 10/11) with native terminal support

### Python & Runtime
- **Python:** 3.10+ (tested on 3.10, 3.11, 3.12)
- **Terminal:** 24-bit TrueColor (UTF-8 rendering required)
  - ✅ **Recommended:** Kitty, Alacritty, WezTerm, iTerm2, Windows Terminal v1.5+
  - ❌ **Not Supported:** Legacy Windows CMD, basic xterm

### Hardware
- **Memory:** 256MB minimum, 1GB+ recommended (for background tasks)
- **Storage:** 100MB+ free (SQLite grows ~10MB per 1000 findings)
- **Network:** Not required after initial setup (air-gap capable)

## 2. Installation & Setup

### Step 1: Clone Repository
```bash
git clone https://internal.repo/vectorvue.git
cd vectorvue
```

### Step 2: Create Virtual Environment
```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

**Required Packages:**
- `textual` (0.90+) - TUI framework
- `cryptography` - AES-256-GCM encryption
- `argon2-cffi` - Password hashing
- `pydantic` - Data validation

### Step 4: Verify MITRE Reference Data
```bash
# Check if MITRE ATT&CK lookup table exists
ls -lh mitre_reference.txt

# Expected content: CSV with Technique ID, Name, Tactic, Description
# Example: T1566,Phishing,Initial Access,Adversaries may send phishing messages...
```

## 3. First Launch & Configuration

### Initial Startup
```bash
python3 vv.py
```

**Expected behavior on first launch:**
1. ✅ Application initializes without errors
2. ✅ Registration screen appears (no users yet)
3. ✅ Terminal displays colors correctly (green #39FF14, cyan #00FFFF)
4. ✅ Status bar shows operational status

### Create Admin User
The first user created automatically becomes ADMIN:

1. Fill registration form:
   - **Username:** Your operator identifier
   - **Password:** Strong passphrase (min 12 chars recommended)
   - **Confirm:** Re-enter password
2. Press **REGISTER**
3. Auto-redirected to login screen
4. Log in with new credentials
5. **Congratulations!** You're now authenticated as ADMIN

### Create First Campaign
After login:

1. Click **INIT CAMPAIGN** (or press `Ctrl+K`)
2. Fill campaign details:
   - **Campaign Name:** e.g., "ACME Corp Red Team Q1 2026"
   - **Client:** "ACME Corporation"
   - **Operator Team:** Your team identifier
   - **Start Date:** YYYY-MM-DD format
   - **Objective:** "Comprehensive security assessment of..."
   - **Rules of Engagement:** Operating hours, restrictions, sensitive systems
   - **Classification:** CONFIDENTIAL or SECRET
3. Press **CREATE CAMPAIGN**
4. Campaign initializes with status **PLANNING**

## 4. Database Initialization

On first launch, VectorVue v3.4 automatically creates:

| File | Purpose | Size | Notes |
|------|---------|------|-------|
| `vectorvue.db` | Operational data (41 tables) | ~100KB empty | SQLite3, encrypted |
| `adversary.db` | Intelligence store | ~50KB empty | Secondary database |
| `vectorvue.salt` | Encryption salt | 16 bytes | PBKDF2 salt, keep secure |

**Important:** Back up `vectorvue.salt` immediately! Losing this file makes all encrypted data unrecoverable.

## 5. Post-Installation Verification

### Test Compilation
```bash
python3 -m py_compile vv.py vv_core.py vv_theme.py vv_fs.py
# Clean output = success
```

### Verify Database Schema
```bash
sqlite3 vectorvue.db ".tables"
# Should list 41 tables: campaigns, findings, assets, credentials, actions, evidence_items, activity_log, users, ...
```

### Test Background Executor
The RuntimeExecutor automatically starts on login and executes:
- Scheduled tasks (every 30 seconds)
- Webhook deliveries
- Session timeout enforcement (120 min inactivity)
- Data retention policies
- Anomaly detection

Monitor in status bar: `[Scheduler] 5 pending tasks executed`

## 6. Data Storage & Backups

### Backup Strategy
```bash
# Daily backup (before login)
tar czf vectorvue-backup-$(date +%Y%m%d).tar.gz vectorvue.db adversary.db vectorvue.salt requirements.txt

# Store securely (encrypted USB, cloud vault, etc.)
```

### Restore from Backup
```bash
# Stop VectorVue (logout)
# Restore files
tar xzf vectorvue-backup-YYYYMMDD.tar.gz

# Restart VectorVue
python3 vv.py
```

### Database Maintenance
Clean up old data using retention policies:
1. Press **Alt+6** (SecurityHardeningView)
2. Configure retention policies:
   - Findings: 90 days (archive)
   - Credentials: 180 days (secure delete)
   - Audit logs: 365 days (archive)
   - Detection events: 30 days (secure delete)
3. Runtime scheduler auto-executes nightly

## 7. Security Hardening (Day 1)

### Change Admin Password
```
1. Login as admin
2. Press Ctrl+L (Logout)
3. Login again with new password (prompted on next session)
```

### Create Team Users
As ADMIN, invite operators:
1. Press **Ctrl+K** → **Team Management**
2. Click **ADD OPERATOR**
3. Assign role: VIEWER, OPERATOR, or LEAD
4. Operator receives credentials
5. All actions attributed to their username in activity log

### Enable Campaign Isolation
Enforce that operators only see their assigned campaigns:
1. Campaign settings → **Visibility Mode: TEAM_SCOPED**
2. Teams only access findings/assets they create or are assigned
3. ADMIN can override for audits

### Review Audit Trail
Check all activity:
1. Press **Ctrl+1** (SituationalAwarenessView)
2. Review **Activity Timeline**
3. Verify operator attribution and timestamps

## 8. Troubleshooting First Launch

| Issue | Symptom | Solution |
|-------|---------|----------|
| Terminal colors wrong | Pink/brown instead of green/cyan | Update terminal (Alacritty recommended) |
| Database errors | "Cannot open database file" | Check write permissions in current directory |
| Import errors | ModuleNotFoundError: cryptography | Run `pip install -r requirements.txt` |
| Encryption fails | "CRYPTO_AVAILABLE = False" | Install `cryptography` package |
| MITRE missing | No tactic/technique suggestions | Place mitre_reference.txt in root directory |
| Background tasks fail | Status: "Scheduler error" | Check logs in status bar, verify database connectivity |

For more issues, see **TROUBLESHOOTING_GUIDE.md**.

## 9. Next Steps

### For Operators
- [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md) - Daily workflows, keybindings, findings management

### For Developers
- [ARCHITECTURE_SPEC.md](./ARCHITECTURE_SPEC.md) - Database schema, design patterns, APIs

### For Admins
- [TROUBLESHOOTING_GUIDE.md](./TROUBLESHOOTING_GUIDE.md) - System diagnostics, recovery procedures

---

**VectorVue v3.4** | Production Ready | Phase 2/8 Complete
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
