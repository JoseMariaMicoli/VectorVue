# VectorVue v3.0 Operator Manual

![Role](https://img.shields.io/badge/Role-Operator-00FFFF?style=flat-square) ![Version](https://img.shields.io/badge/Version-3.0-39FF14?style=flat-square) ![Campaign](https://img.shields.io/badge/Context-Campaign_Centric-FFBF00?style=flat-square)

Complete operational guide for VectorVue v3.0. This manual covers daily workflows, approval processes, evidence tracking, and team collaboration within the Red Team Campaign Management Platform.

**Designed for high-velocity keyboard interaction. All major workflows are achievable without mouse input.**

---

## 1. Getting Around the UI

### Main Views
VectorVue v3.0 organizes data into four primary views:

#### **Login View**
- Initial authentication screen
- Username/password entry
- First-time user setup (admin account creation)
- **Hotkeys:**
  - `Tab` - Move between fields
  - `Enter` - Submit login

#### **Campaign View** (Main Interface)
- Central hub for all engagement data
- Manage findings, assets, credentials, evidence
- View activity timeline
- **Hotkeys:**
  - `C` - Create new finding
  - `A` - Approve finding (LEAD+ only)
  - `R` - Reject finding (LEAD+ only)
  - `E` - Add evidence to finding
  - `V` - View activity timeline
  - `G` - Generate report
  - `Ctrl+S` - Save current finding
  - `Q` - Quit (with confirmation)

#### **MITRE Intelligence View**
- Left navigation: MITRE tactics
- Right preview: Technique details
- **Hotkeys:**
  - `j/k` - Navigate tactics up/down
  - `Enter` - Expand technique details
  - `Esc` - Close preview

#### **File Manager View**
- Full-screen filesystem browser
- Atomic file I/O with vim keybindings
- Secure file deletion (multi-pass wipe)
- **Hotkeys:**
  - `j/k` - Navigate files up/down
  - `g` - Go to top
  - `G` - Go to bottom
  - `n` - Create new file
  - `d` - Delete file (⚠️ with confirmation)
  - `Esc` - Return to Campaign View

---

## 2. Campaign Management Workflows

### Creating a Campaign
**Prerequisite:** Admin or LEAD role

1. From **Login View**, log in with admin account
2. Select **Create New Campaign** (or press `Ctrl+N`)
3. Fill in campaign details:
   - **Campaign Name:** e.g., "ACME Corp Red Team Q1 2026"
   - **Client Name:** e.g., "ACME Corporation"
   - **Operator Team:** Your team name
   - **Objective:** Engagement scope (free text)
   - **Rules of Engagement:** Restrictions, hours, sensitive systems
   - **Classification:** CONFIDENTIAL, SECRET, etc.
4. Press **SAVE** (Ctrl+S)
5. Campaign is created with status **PLANNING**

### Switching Between Campaigns
1. In **Campaign View**, press `Ctrl+C` to view all campaigns
2. Select a campaign from the list
3. Current campaign changes (all views update to new campaign scope)
4. All subsequent data entries are scoped to new campaign

### Campaign Status Lifecycle
```
PLANNING → ACTIVE → FINISHED → ARCHIVED
```

- **PLANNING:** Setup phase, initial reconnaissance
- **ACTIVE:** Exploitation and data collection
- **FINISHED:** Post-exploitation wrap-up
- **ARCHIVED:** Locked, read-only (historical reference)

Press `Ctrl+U` to update campaign status.

---

## 3. Finding Workflow & Approval Process

### Creating a Finding
1. In **Campaign View**, press `C` to create new finding
2. Fill in **Finding Details:**
   - **Title:** Vulnerability name (e.g., "SQL Injection in Login Form")
   - **Severity:** CRITICAL, HIGH, MEDIUM, LOW, INFO
   - **CVSS Score:** 0.0 - 10.0 (auto-update MITRE severity label)
   - **Description:** Markdown-formatted details, POC, impact
   - **MITRE Technique:** Select from dropdown (e.g., T1566 - Phishing)
3. Press **SAVE** (Ctrl+S)
4. Finding is created with status **PENDING**

### Severity Color Coding
| Score | Severity | Color | Indicator |
|-------|----------|-------|-----------|
| 9.0-10.0 | CRITICAL | 🔴 Red (#FF0000) | Flashing border |
| 7.0-8.9 | HIGH | 🟠 Amber (#FFBF00) | Solid border |
| 4.0-6.9 | MEDIUM | 🔵 Cyan (#00FFFF) | Solid border |
| 0.0-3.9 | LOW | 🟢 Green (#39FF14) | Faint border |

### MITRE Technique Mapping
1. In finding editor, navigate to **MITRE Technique** field
2. Start typing technique ID or name:
   - Type `T1566` for "Phishing"
   - Type `exploit` to search by keyword
3. **Real-time Feedback:**
   - ✅ Green (#39FF14) = Technique found in database
   - ⚠️ Amber (#FFBF00) = Technique not found
   - Description displays in preview pane
4. Press `Enter` to confirm selection

### Approval Workflow (LEAD+ Only)
**State Machine:** `PENDING` → `APPROVED` or `REJECTED`

#### As an OPERATOR:
1. Create finding (status: PENDING)
2. Add evidence
3. Submit for approval

#### As a LEAD:
1. Navigate to **Findings** view
2. Filter by **Status: PENDING**
3. Review finding and evidence
4. Press `A` to **APPROVE** finding
   - Finding status → **APPROVED**
   - Locked (no further edits)
   - Ready for report export
5. Or press `R` to **REJECT** finding
   - Finding status → **REJECTED**
   - Can be revised and re-submitted by OPERATOR
   - Not included in final reports

#### As an ADMIN:
- Can override LEAD approval
- Can force status changes
- Use carefully (audited in activity log)

---

## 4. Evidence Collection & Chain of Custody

### Adding Evidence to a Finding
1. In finding view, press `E` to add evidence
2. Select evidence type:
   - **Screenshot:** Image artifact
   - **Log:** Text log file (C2 output, server logs)
   - **Credential:** Captured authentication (encrypted)
   - **Artifact:** Binary or structured data
3. Choose source:
   - **Upload File:** Browse and select artifact
   - **Create Evidence:** Paste output directly
4. System automatically records:
   - ✅ **SHA256 Hash:** Integrity verification
   - ✅ **Collector:** Your username
   - ✅ **Timestamp:** When collected
   - ✅ **Collection Method:** manual, c2, tool, other
5. Evidence is **IMMUTABLE** (cannot be edited)

### Evidence Verification
1. In finding, view evidence section
2. Each evidence item shows:
   - **Filename / Description**
   - **Hash:** SHA256 (clickable, compares with source)
   - **Collector:** Username who added it
   - **Timestamp:** ISO 8601 format
   - **Chain of Custody:** Verification status (✅ Valid / ⚠️ Modified)

**To verify evidence integrity:**
```bash
# Get SHA256 of original file
sha256sum /path/to/original/file

# Compare with evidence hash shown in VectorVue
# If they match: ✅ Evidence unmodified
# If different: ⚠️ Evidence tampered (alert LEAD)
```

### C2 Log Ingestion
To ingest operator logs (C2 output, terminal history):
1. In finding, press `E` → Create Evidence → Log
2. **Paste log output** (multiline supported):
   ```
   [*] 192.168.1.100 > shell whoami
   DOMAIN\Administrator
   [*] 192.168.1.100 > shell ipconfig
   IP Address: 192.168.1.100
   ...
   ```
3. System automatically:
   - Parses timestamps and operators
   - Creates structured markdown
   - Generates hash for verification
   - Records in evidence_items table

---

## 5. Asset & Credential Management

### Adding an Asset (Target)
1. In **Campaign View**, press `A` to add asset
2. Fill in asset details:
   - **Hostname:** e.g., "web-server-01.corp.local"
   - **IP Address:** e.g., "192.168.1.100"
   - **Type:** Server, Workstation, Database, Network Device
   - **OS:** e.g., "Windows Server 2019"
   - **Status:** Active, Offline, Decommissioned
   - **Sensitive:** Yes/No (triggers warning for lateral movement)
3. Press **SAVE** (Ctrl+S)

### Adding a Credential
1. In **Campaign View**, press `K` to add credential
2. Fill in credential details:
   - **Username:** e.g., "admin@corp.local"
   - **Password:** (encrypted before storage)
   - **Type:** AD, Local, SSH, API Key
   - **Source Asset:** Where credential was found
   - **Privilege Level:** User, Administrator, Domain Admin
3. **Important:** Passwords are encrypted with AES-256 before database storage
4. Press **SAVE** (Ctrl+S)

### Tracking Credential Chain
1. Credential shows **Source Asset**
2. Asset shows **Lateral Movement** paths
3. Timeline shows who used credential and when
4. Report includes credential chain narrative

---

## 6. Activity Timeline & Audit Logging

### Viewing Activity Timeline
1. In **Campaign View**, press `V` to view timeline
2. Timeline shows all campaign events:
   - Finding creation/approval/rejection
   - Evidence collection
   - Asset discovery
   - Credential capture
   - Action execution
   - User access (logins, logouts)
3. **Filters:**
   - By date range
   - By operator
   - By action type
   - By severity

### Activity Log Details
Each log entry shows:
- **Timestamp:** ISO 8601 (UTC)
- **Operator:** Username who performed action
- **Action:** Create, Approve, Reject, Collect Evidence, etc.
- **Context:** Finding ID, asset name, etc.
- **Severity:** INFO, WARNING, ERROR, CRITICAL

Example:
```
2026-02-16 14:23:45Z | alice@corp.local | APPROVED | Finding: SQL Injection | Severity: HIGH
```

### Audit Trail Security
- All actions are **immutable** (cannot be edited)
- Each log entry is **HMAC signed** (integrity verification)
- Dual-logged to:
  - `activity_log` (v3.0 structured logging)
  - `audit_log` (backward compat, legacy format)
- Exportable for compliance (SOX, ISO 27001, etc.)

---

## 7. Generating Reports

### Pre-Report Checklist
Before exporting findings:
1. ✅ All findings are **APPROVED** (LEAD+ only)
2. ✅ All evidence is **VERIFIED** (chain of custody valid)
3. ✅ All assets are **DOCUMENTED** (no unknowns)
4. ✅ All timelines are **COMPLETE** (no gaps)

### Exporting Campaign Report
1. In **Campaign View**, press `G` to generate report
2. Select export options:
   - **Format:** Markdown, JSON, CSV
   - **Include:** Executive Summary, Technical Details, Timeline, MITRE Coverage
   - **Redaction:** Client sensitive data, internal team notes
3. Report includes:
   - ✅ Title page with classification
   - ✅ Executive summary (findings by severity)
   - ✅ Technical details (each approved finding)
   - ✅ MITRE coverage matrix (tactics/techniques)
   - ✅ Activity timeline (chronological)
   - ✅ Evidence integrity verification (hashes)
   - ✅ Operator attribution (who found what)
4. File is saved to `05-Delivery/[Campaign Name]-Report-[Date].md`

### Report Security
- Only **APPROVED** findings are included
- Sensitive data is **redacted** per classification
- Evidence hashes **verify** authenticity
- Operator signatures **authenticate** findings
- Cannot be modified without invalidating HMAC

---

## 8. Multi-Operator Collaboration

### Team Workflows
**Scenario:** Three operators (Alice, Bob, Charlie) on same campaign

**Alice (OPERATOR) discovers vulnerability:**
1. Creates finding "SQL Injection"
2. Status: **PENDING**
3. Adds screenshot evidence
4. Submits for approval

**Bob (LEAD) reviews finding:**
1. Views pending findings
2. Verifies evidence
3. Approves finding
4. Status: **APPROVED**
5. Notification sent to Alice

**Charlie (OPERATOR) adds complementary evidence:**
1. Views approved findings
2. Cannot edit finding (locked)
3. Can view complete evidence chain
4. Uses in next report section

### Real-Time Notifications
- Finding approval/rejection
- Campaign status changes
- New assets/credentials discovered
- Evidence collected
- Role-based visibility

### Conflict Resolution
If multiple operators edit same finding simultaneously:
- Last writer wins (auto-merge on close)
- Previous version preserved in activity_log
- LEAD can revert to earlier version

---

## 9. Keyboard Shortcuts Reference

| Context | Hotkey | Action |
|---------|--------|--------|
| **Global** | `Q` | Quit application (with confirmation) |
| **Global** | `?` | Show help menu |
| **Campaign View** | `C` | Create new finding |
| **Campaign View** | `A` | Approve finding (LEAD+) |
| **Campaign View** | `R` | Reject finding (LEAD+) |
| **Campaign View** | `E` | Add evidence |
| **Campaign View** | `V` | View activity timeline |
| **Campaign View** | `K` | Add credential |
| **Campaign View** | `Ctrl+A` | Add asset |
| **Campaign View** | `Ctrl+C` | Switch campaign |
| **Campaign View** | `Ctrl+U` | Update campaign status |
| **Campaign View** | `G` | Generate report |
| **Campaign View** | `Ctrl+S` | Save current finding |
| **MITRE View** | `j/k` | Navigate tactics |
| **MITRE View** | `Enter` | Expand technique |
| **MITRE View** | `Esc` | Close preview |
| **File Manager** | `j/k` | Navigate files |
| **File Manager** | `g` | Top of list |
| **File Manager** | `G` | Bottom of list |
| **File Manager** | `n` | Create new file |
| **File Manager** | `d` | Delete file |
| **File Manager** | `Esc` | Return to Campaign View |
| **Text Editor** | `Ctrl+S` | Save finding |
| **Text Editor** | `Tab` | Indent block |
| **Text Editor** | `Shift+Tab` | Unindent block |

---

## 10. Best Practices

### Evidence Collection
- ✅ Collect evidence **at the moment of discovery**
- ✅ Use **descriptive filenames** (timestamps, asset names)
- ✅ Verify **hashes** before committing to database
- ✅ Screenshot **proof of concept** for every finding
- ❌ Do NOT edit evidence after collection

### Finding Documentation
- ✅ **Title:** Clear, actionable (not vague)
- ✅ **CVSS Score:** Accurate based on risk
- ✅ **MITRE Mapping:** Correct technique ID
- ✅ **Description:** Enough detail for remediation
- ✅ **Evidence:** Screenshot or log output proving finding
- ❌ Do NOT create duplicate findings

### Approval Workflow
- ✅ **OPERATOR:** Create with evidence
- ✅ **LEAD:** Review, approve/reject within 24h
- ✅ **OPERATOR:** Address rejections, re-submit
- ✅ **ADMIN:** Override only for critical cases (audited)
- ❌ Do NOT force findings through without evidence

### Campaign Hygiene
- ✅ Keep campaign status accurate (PLANNING → ACTIVE → FINISHED)
- ✅ Archive completed campaigns (FINISHED → ARCHIVED)
- ✅ Regular backups of `vectorvue.db`
- ✅ Review activity timeline weekly
- ❌ Do NOT delete campaigns (use ARCHIVE instead)

---

## 11. Troubleshooting Quick Reference

**Issue:** "Not Authenticated" error
- **Solution:** Log out (Q) and log back in with valid credentials

**Issue:** "Campaign Not Found"
- **Solution:** Create campaign first (Ctrl+N) or switch to existing campaign (Ctrl+C)

**Issue:** Finding stuck in PENDING
- **Solution:** Ensure you're logged in as LEAD role; OPERATOR role can only create, not approve

**Issue:** Evidence hash mismatch
- **Solution:** Evidence was modified after collection (immutable violation); check activity_log for who modified it

**Issue:** Can't edit approved finding
- **Solution:** This is by design (locked for audit trail); ask LEAD to reject and re-open if needed

**Issue:** Report export fails
- **Solution:** Ensure all findings are APPROVED; check disk space; try again with smaller report

For more help, see [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md).

---

## 📚 Related Documentation

- [Getting Started](./GETTING_STARTED.md) - Deployment and initial setup
- [Architecture Spec](./ARCHITECTURE_SPEC.md) - Database schema, RBAC, crypto details
- [Troubleshooting](./TROUBLESHOOTING_GUIDE.md) - Error diagnosis and recovery

---

**VectorVue v3.0** | Red Team Campaign Management Platform | v3.0-RC1
