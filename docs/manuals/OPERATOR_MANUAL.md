# VectorVue v3.4 Operator Manual

![Operator](https://img.shields.io/badge/Operator-Manual-00FFFF?style=flat-square) ![Version](https://img.shields.io/badge/Version-v3.4-39FF14) ![Phase](https://img.shields.io/badge/Phase-2_Complete-39FF14)

This manual documents operational procedures, keybindings, workflows, and advanced features for red team operators using VectorVue v3.4. The platform now includes background task execution, advanced analytics, approval workflows, and enterprise security controls.

## 1. Authentication & Session Management

### Login & Role Assignment
VectorVue v3.4 implements strict RBAC with four role levels:

| Role | Level | Capabilities |
|------|-------|--------------|
| VIEWER | 0 | Read-only: findings, reports, evidence (no creation) |
| OPERATOR | 1 | Create findings, manage assets, upload evidence, task execution |
| LEAD | 2 | Approve findings, generate reports, team management, campaign policies |
| ADMIN | 3 | System admin, user management, encryption, retention policies, audit |

### Initial Login Flow
1. **Enter credentials** (username / password)
2. **Session crypto initialization:** Passphrase derives AES-256 encryption key (PBKDF2, 480k iterations)
3. **Campaign selection:** Choose active campaign from list
4. **Session timeout:** 120 minutes inactivity auto-logout (configurable via retention policies)
5. **Background executor starts:** RuntimeExecutor queues begin async task execution

### Session Security
- All user data encrypted with AES-256-GCM before storage
- HMAC signature on each row ensures integrity
- Session tokens stored with TTL in `users` table
- Audit logging tracks all actions with `who`, `when`, `what`

## 2. Campaign Management

### Creating a New Campaign (LEAD+ Role)
Press `Ctrl+K` to open **Campaign Initialization**:

1. **Campaign Name:** e.g., "ACME Corp Red Team Q1 2026"
2. **Client:** Organization name
3. **Operator Team:** Team identifier (all findings scoped to team)
4. **Start/End Date:** YYYY-MM-DD format
5. **Objective:** Test scope and goals
6. **Rules of Engagement:** Operating hours, excluded systems, escalation
7. **Classification:** TLP level (CLEAR, GREEN, AMBER, RED)
8. **Status:** Auto-set to PLANNING

Press **CREATE** → Campaign initializes with all 41 database tables scoped to campaign_id.

### Campaign Status Lifecycle
- **PLANNING:** Intelligence gathering, pre-test phase
- **ACTIVE:** Active testing phase (background tasks execute)
- **SUSPENDED:** Temporary hold (client request, issue discovery)
- **COMPLETE:** Testing finished, reporting phase
- **ARCHIVED:** Historical record (data retained, no new modifications)

**LEAD can change status:** Press `Ctrl+Shift+S` → Select new status

### Switching Campaigns
Press `Ctrl+Shift+K` → Select campaign from dropdown → All views refresh to show selected campaign_id

**Background behavior:** RuntimeExecutor schedules all pending tasks for new campaign context

## 3. Six Primary Views (v3.4 Complete)

### View 1: Situational Awareness Dashboard (`Ctrl+1`)
Real-time operational status and metrics:

**Left Panel:**
- Campaign name and status
- Timeline of operator actions (who/when/what)
- Task queue status (scheduled, running, completed)
- Background executor heartbeat

**Right Panel:**
- Assets summary (total, active, compromised)
- Credentials summary (valid, expired, high-privilege)
- Findings summary (by severity: CRITICAL, HIGH, MEDIUM, LOW, INFO)
- MITRE coverage (% techniques tested)

**Keybindings:**
| Key | Action |
|-----|--------|
| `r` | Refresh all panels |
| `t` | Toggle activity timeline details |
| `s` | Show task scheduler queue |
| `e` | Export dashboard snapshot |
| `q` | Close view |

### View 2: Campaign Management (`Ctrl+2`)
Assets, credentials, and evidence in unified interface:

**Three Tabs:**
1. **Assets Tab** (default)
   - IP/hostname, OS, role, status (alive, dead, compromised)
   - Vim keybindings: j/k navigate, Enter to inspect, i to insert, d to delete
2. **Credentials Tab**
   - Account, domain, privilege level, source (discovery method)
   - Hash/plaintext status, last logon, lateral movement potential
3. **Evidence Tab**
   - SHA256 hash, timestamp, collection method
   - File type, size, encrypted status
   - Chain of custody metadata

**Keybindings:**
| Key | Action |
|-----|--------|
| `Tab` | Switch between tabs |
| `j/k` | Navigate rows (vim) |
| `g/G` | Jump to top/bottom |
| `Enter` | View/edit selected item |
| `i` | Insert new asset/credential/evidence |
| `d` | Delete (requires LEAD+ for destructive ops) |
| `y` | Copy hash to clipboard |
| `v` | View content (read-only) |
| `/` | Search within tab |
| `q` | Close view |

### View 3: MITRE ATT&CK Intelligence (`Ctrl+3`)
Technique mapping and coverage analysis:

**Left Pane (Tactics Tree):**
- Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command & Control, Exfiltration, Impact
- Navigate with j/k, expand/collapse with Enter

**Right Pane (Technique Details):**
- Technique ID, name, description
- Sub-techniques and detection methods
- Related tactics and procedures
- Detection status (tested, discovered, covered)

**Keybindings:**
| Key | Action |
|-----|--------|
| `j/k` | Navigate tactics |
| `Enter` | View technique details |
| `l` | Link finding to technique |
| `L` | Show all linked findings |
| `c` | Show coverage matrix (% complete) |
| `e` | Export MITRE report |
| `q` | Close view |

### View 4: File Manager (`Ctrl+4`)
Evidence and artifact management with atomic I/O:

**Directory Structure:**
```
campaign-name/
├── findings/          # Finding markdown files
├── evidence/          # Raw evidence (logs, dumps, captures)
├── reports/           # Generated reports
├── c2-logs/          # C2 operator logs (auto-ingested)
└── archive/          # Old evidence (encrypted)
```

**Operations:**
| Key | Action |
|-----|--------|
| `i` | Create file/folder (atomic write) |
| `d` | Secure delete (multi-pass overwrite) |
| `v` | View file content |
| `e` | Open in external editor |
| `y` | Copy file path |
| `p` | Paste (duplicate) |
| `h` | Show file hash (SHA256) |
| `m` | Show file metadata (timestamp, size) |
| `q` | Close view |

**Atomic I/O:** All writes use temp file + fsync + atomic replace (crash-safe)

### View 5: Task Orchestrator (`Ctrl+5`)
Monitor and manage background task execution:

**Active Tasks List:**
- Task ID, name, status (scheduled, running, completed, failed)
- Execution time, next scheduled run
- Executor type (scheduler, webhooks, sessions, retention, anomaly)

**Operations:**
| Key | Action |
|-----|--------|
| `j/k` | Navigate task list |
| `Enter` | View task details/logs |
| `c` | Cancel scheduled task |
| `r` | Retry failed task |
| `p` | Pause task executor |
| `R` | Resume task executor |
| `l` | Show task logs |
| `q` | Close view |

**Background Tasks (Automatic):**
- **Scheduler:** Every 30 seconds, executes scheduled actions
- **Webhooks:** Delivers integration payloads (Slack, webhook endpoints)
- **Sessions:** Enforces 120-min timeout, logs expirations
- **Retention:** Nightly purge per configured policies
- **Anomaly:** Detects unusual activity (suspicious logins, mass exports)

### View 6: Security Hardening (`Ctrl+6`)
Encryption, policies, and compliance controls:

**Tabs:**
1. **Encryption Tab**
   - Current crypto cipher (AES-256-GCM)
   - Session key derivation (PBKDF2, 480k iterations)
   - Salt status (backed up: yes/no)
   - Re-key option (ADMIN only)

2. **Policies Tab**
   - Retention rules (findings, credentials, audit logs)
   - Classification enforcement (TLP levels)
   - Approval workflow requirements
   - Client-safe-mode toggle

3. **Compliance Tab**
   - Audit log retention (365 days default)
   - Evidence integrity checks (SHA256 verification)
   - User access logs (who accessed what, when)
   - Export audit trail (for external review)

**Keybindings:**
| Key | Action |
|-----|--------|
| `Tab` | Switch tabs |
| `e` | Edit selected policy |
| `v` | View current settings |
| `r` | Reset to defaults (ADMIN only) |
| `x` | Export compliance report |
| `q` | Close view |

## 4. Core Workflows

### Workflow: Document a Vulnerability Finding

**Core Process (OPERATOR Role):**

1. **Press `Ctrl+E`** to open Finding Editor
2. **Fill in Fields:**
   ```
   Title: SQL Injection in Login Form
   Description: The login form accepts SQL commands in the username field
   Impact: CRITICAL
   Affected Assets: web-prod-01, web-prod-02
   MITRE Technique: T1190 (Exploit Public-Facing Application)
   Tags: authentication, sqli, t1190
   ```
3. **Attach Evidence:**
   - Screenshot: login-bypass.png (Hash: a1b2c3...)
   - PoC Script: sqli-exploit.py (Hash: d4e5f6...)
   - Network Capture: http-requests.pcap (Hash: g7h8i9...)
4. **Add Remediation:**
   ```
   Use parameterized queries or prepared statements.
   Current: SELECT * FROM users WHERE username='$input'
   Corrected: SELECT * FROM users WHERE username=?
   ```
5. **Press `Ctrl+S`** to save finding (encrypted in database)
6. **Press `Ctrl+Shift+A`** to submit for approval

**What Happens After Submit:**
- Finding marked as PENDING_APPROVAL
- LEAD receives notification
- RuntimeExecutor logs action in activity_log with operator name + timestamp
- HMAC signature added for integrity verification

### Workflow: LEAD Approval & Finalization

**Core Process (LEAD Role):**

1. **Press `Ctrl+1`** (Situational Awareness)
2. **Navigate to pending findings**
3. **Review each finding:**
   - Evidence chain of custody (who collected, when, hash)
   - Technical accuracy (impact, remediation)
   - MITRE mapping (technique coverage)
4. **Take Action:**
   - **Approve:** `Ctrl+A` → Finding moves to APPROVED (included in report)
   - **Reject:** `Ctrl+Shift+R` → Returned to OPERATOR with comment
   - **Request Changes:** `Ctrl+M` → Marked for OPERATOR to revise
5. **Final Report Generation:**
   - Press `Ctrl+Shift+G` (Generate Report)
   - Select format: PDF, DOCX, JSON, HTML
   - Choose scope: All approved findings, by tactic, by severity
   - RuntimeExecutor generates report asynchronously (status in View 5)

### Workflow: Track & Link a Compromised Credential

**Core Process (OPERATOR Role):**

1. **Create new credential entry** (`Ctrl+2` → Credentials Tab → `i`)
2. **Document Details:**
   ```
   Account: ACME\domain-admin
   Domain: ACME.LOCAL
   Source: Memory dump from web-prod-01 (DCSync attack)
   Hash Type: NTLM
   Hash Value: 8846f7eaee8fb117ad06bdd830b7586c
   Plaintext: (not known, hash only)
   Privilege Level: Domain Admin (CRITICAL)
   Last Logon: 2026-01-15 09:23:04 UTC
   Lateral Movement: Can access 47/50 in-scope assets
   ```
3. **Link to Finding:**
   - Reference finding ID in credentials comment
   - `Ctrl+L` to link bidirectionally
4. **Flag if Sensitive:**
   - Mark as RED (sensitive host credential)
   - Apply data minimization: Don't include plaintext in reports
5. **Submit for Approval:** `Ctrl+Shift+A`
6. **LEAD Reviews & Approves:**
   - Verifies hash correctness (NTLM, bcrypt, etc.)
   - Confirms privilege escalation impact
   - Approves for inclusion in final report

### Workflow: Manage Evidence Chain of Custody

**Core Process (Any Role):**

1. **Capture Evidence** (manual discovery)
   - Execute exploit, capture screenshot or output
   - Save to file: `exploit-output.txt` or `screenshot.png`
2. **Upload to Evidence Manager** (`Ctrl+4`)
   - Navigate to `evidence/` folder
   - Press `i` to upload new file
   - Select file from filesystem
3. **System Automatically:**
   - Calculates SHA256 hash
   - Records timestamp, operator name
   - Encrypts file content (at rest)
   - Stores metadata in `evidence_items` table
4. **Immutable After Upload:**
   - Evidence cannot be edited or deleted by OPERATOR
   - LEAD can soft-delete (archive) with reason recorded
   - All deletions logged in activity_log with HMAC signature
5. **Chain of Custody Report:**
   - Press `Ctrl+6` → Compliance Tab → Export audit trail
   - Shows: who uploaded, when, from which source, hash, signature

## 5. Collaborative Multi-Operator Campaigns

### Shared Team Workflows
VectorVue v3.4 supports entire red team working on same campaign:

**Team Synchronization:**
- All operators on same team → Auto-see findings from all members
- Real-time activity timeline shows action attribution (operator name + timestamp)
- Task orchestrator queues work across team

**Task Assignment & Tracking:**
1. **LEAD** opens Campaign Management (`Ctrl+2`)
2. **Assigns finding** to specific OPERATOR (e.g., "Research SQL injection variants")
3. **OPERATOR** receives task in their Task Orchestrator (`Ctrl+5`)
4. **OPERATOR** executes task, updates finding with results
5. **LEAD** sees status change in real-time
6. **All activity logged** with operator attribution

**Approval Workflow:**
1. **OPERATOR** completes work, submits finding (`Ctrl+Shift+A`)
2. **System Status:** Finding moves to PENDING_APPROVAL
3. **LEAD Notification:** RuntimeExecutor queues webhook delivery (Slack, webhook endpoint)
4. **LEAD Reviews** in Situational Awareness view
5. **LEAD Decision:**
   - ✅ **Approve:** Included in final report
   - ❌ **Reject:** Deleted with reason recorded
   - 🔄 **Request Changes:** Returned to OPERATOR with comment

### Conflict Prevention
- **Lock Mechanism:** Only one operator can edit a finding at a time
- **Concurrent Edits:** If two operators try to edit, system locks for first, shows message to second
- **Merge Detection:** If both edit simultaneously (offline), RuntimeExecutor shows conflict resolution dialog

## 6. Advanced Features (Phase 2 Complete)

### Background Task Execution
RuntimeExecutor system automatically runs tasks in 5 executor threads:

**Scheduler Executor:**
- Runs every 30 seconds
- Executes all scheduled actions (webhooks, retention policies)
- Logs execution in activity_log with timestamp and status

**Webhook Executor:**
- Delivers integration payloads (Slack, generic webhook)
- Retries on failure (exponential backoff)
- Logs integration events (success/failure) for audit

**Session Executor:**
- Monitors user session TTL (120 min inactivity)
- Auto-logout if timeout exceeded
- Logs session expirations in activity_log

**Retention Executor:**
- Runs nightly at configured time (default: 2 AM UTC)
- Purges old findings/credentials/audit logs per retention policies
- Secure-deletes files (multi-pass overwrite)
- Logs all purges with reason and count

**Anomaly Executor:**
- Analyzes activity patterns in real-time
- Detects suspicious activity (unusual login times, mass export attempts)
- Alerts ADMIN if anomaly threshold exceeded
- Logs detection events for investigation

**Monitor Task Execution:**
1. Press `Ctrl+5` (Task Orchestrator)
2. View all 5 executor threads and their status
3. Check "Last Run" and "Next Run" times
4. View logs and error messages

### Report Generation & Export
Advanced reporting in multiple formats (Phase 2 feature):

**Formats Supported:**
- **PDF:** Professional formatted report with findings, evidence links
- **DOCX:** Editable Word document (for client customization)
- **JSON:** Machine-readable for integration pipelines
- **HTML:** Web viewable (standalone, no dependencies)
- **XLSX:** Spreadsheet with findings, metrics, timeline

**Generation Process:**
1. **Press `Ctrl+Shift+G`** (Generate Report)
2. **Select Scope:**
   - All approved findings
   - By tactic (only Initial Access findings, etc.)
   - By severity (only CRITICAL findings)
   - By date range
3. **Configure Options:**
   - Include evidence links (yes/no)
   - Include remediation (yes/no)
   - Include MITRE coverage matrix (yes/no)
   - Classification level (affects redaction)
4. **Submit:**
   - RuntimeExecutor generates report asynchronously
   - Monitor in Task Orchestrator (`Ctrl+5`)
   - Completion notification sent to operator

### Approval & Sign-Off Workflows
Multi-stage approval ensures quality and authorization:

**Stage 1: OPERATOR Submission**
- Operator completes finding with evidence
- Clicks `Ctrl+Shift+A` to submit
- Finding status: PENDING_APPROVAL
- Activity logged with operator name + timestamp

**Stage 2: LEAD Review & Approval**
- LEAD opens Situational Awareness (`Ctrl+1`)
- Reviews pending findings (with evidence)
- Takes action:
  - **Approve:** ✅ Moves to APPROVED
  - **Reject:** ❌ Deleted with reason
  - **Request Changes:** 🔄 Returned with comment
- All decisions logged in activity_log with LEAD name + timestamp

**Stage 3: Final Report Generation**
- Only APPROVED findings included in final report
- Report generation logged with who requested, when, what format
- Export audit trail shows full approval chain for each finding

## 7. Security & OPSEC Controls

### Client Safe Mode
Restrict sensitive operations when client is present:

**Enable Client Safe Mode:**
1. Press `Ctrl+6` (Security Hardening)
2. Toggle "Client Safe Mode"

**Effects:**
- ✅ Operators can create findings and view evidence
- ❌ Disable: Export reports, view credential hashes, access audit logs
- ❌ Hide: Technical details (MITRE technique IDs)
- ❌ Redact: IP addresses, system names (replaced with generic labels)

### Sensitive Host Warnings
Flag production/critical systems to prevent accidental disclosure:

**Mark Sensitive Host:**
1. Press `Ctrl+2` (Campaign Management) → Assets Tab
2. Select asset
3. Press `T` (Toggle sensitive)
4. Confirm warning before lateral movement on sensitive hosts

**Effect:** Before documenting lateral movement to sensitive host, system warns:
```
⚠️  WARNING: dc-01.acme.local is flagged as PRODUCTION DC
    Target: Domain Controller (CRITICAL INFRASTRUCTURE)
    Continue? (y/N)
```

### Restricted Action Warnings
Destructive operations require LEAD+ role and confirmation:

**Protected Actions:**
- Delete campaign (requires ADMIN)
- Delete approved finding (requires LEAD)
- Export audit logs (requires ADMIN)
- Purge old evidence (requires LEAD)
- Change encryption key (requires ADMIN)

**Confirmation Prompt:**
```
⚠️  DESTRUCTIVE: This action cannot be undone
    Action: Delete campaign "ACME-Q1-2026"
    Findings: 47 (will be archived, not deleted)
    Evidence: 234 files (will be secure-deleted)
    
    Type "DELETE" to confirm:
```

## 8. Keybinding Quick Reference

### Navigation
| Key | Command |
|-----|---------|
| `Ctrl+1` | Situational Awareness View |
| `Ctrl+2` | Campaign Management View |
| `Ctrl+3` | MITRE Intelligence View |
| `Ctrl+4` | File Manager View |
| `Ctrl+5` | Task Orchestrator View |
| `Ctrl+6` | Security Hardening View |
| `Ctrl+Tab` | Cycle through views |

### Campaign Operations
| Key | Command |
|-----|---------|
| `Ctrl+K` | Initialize new campaign |
| `Ctrl+Shift+K` | Switch to different campaign |
| `Ctrl+Shift+S` | Change campaign status |

### Finding Management
| Key | Command |
|-----|---------|
| `Ctrl+E` | Open finding editor |
| `Ctrl+S` | Save finding |
| `Ctrl+Shift+A` | Submit finding for approval (OPERATOR) |
| `Ctrl+Shift+R` | Approve/reject finding (LEAD) |
| `Ctrl+Shift+M` | Request changes on finding (LEAD) |

### Report & Export
| Key | Command |
|-----|---------|
| `Ctrl+Shift+G` | Generate report |
| `Ctrl+Shift+E` | Export audit trail (ADMIN) |

### Utility
| Key | Command |
|-----|---------|
| `Ctrl+L` | Logout |
| `Ctrl+J` | Jump to item by ID |
| `Ctrl+D` | Duplicate selected item |
| `Ctrl+O` | Open selected item (external editor) |
| `Ctrl+P` | Print/display selected item |
| `Ctrl+?` | Show help (keybindings) |

### Vim Navigation (in Tables)
| Key | Action |
|-----|--------|
| `j` | Move down |
| `k` | Move up |
| `g` | Jump to top (first row) |
| `G` | Jump to bottom (last row) |
| `Enter` | Select/open item |
| `/` | Search within table |
| `n` | Next search result |
| `N` | Previous search result |
| `q` | Close view |

## 9. RBAC & Role-Specific Operations

### VIEWER Permissions
✅ **Can Do:**
- View all findings, assets, credentials, evidence
- Search and filter findings
- View MITRE technique mappings
- Download evidence files (encrypted)
- View activity timeline
- Export findings as PDF (read-only)

❌ **Cannot Do:**
- Create, edit, or delete findings
- Upload new evidence
- Access credential hashes or plaintext
- Approve findings
- Change campaign status
- Export audit logs

### OPERATOR Permissions
✅ **Can Do:**
- All VIEWER capabilities
- Create new findings with evidence
- Edit own findings (until approved)
- Upload and manage evidence
- Add/modify assets and credentials
- Submit findings for approval
- View task orchestration queue
- Execute background tasks (subject to policies)

❌ **Cannot Do:**
- Edit other operators' findings
- Delete any finding
- Approve findings
- Change campaign status
- Access audit logs
- Modify system policies

### LEAD Permissions
✅ **Can Do:**
- All OPERATOR capabilities
- Delete any finding (with reason logged)
- Approve/reject/request changes on findings
- Change campaign status (PLANNING → ACTIVE, etc.)
- Generate and export reports (all formats)
- Manage team members (assign tasks, revoke access)
- Configure approval workflows
- View activity timeline with filtering
- Access task orchestrator (pause/resume)

❌ **Cannot Do:**
- Manage encryption keys
- Modify system-wide policies
- Access other teams' campaigns
- Manage user roles (VIEWER↔OPERATOR promotion)

### ADMIN Permissions
✅ **Can Do:**
- All LEAD capabilities
- Manage users: create, delete, promote/demote roles
- Configure system-wide policies (retention, encryption, approval requirements)
- Manage encryption keys (rotate, re-derive)
- Access complete audit logs
- Configure background task executors
- Enable/disable integrations (Slack webhooks, etc.)
- Perform database maintenance
- Export compliance reports

## 10. Troubleshooting & Common Issues

| Issue | Symptom | Solution |
|-------|---------|----------|
| **Finding Won't Save** | Press Ctrl+S, no response | Check campaign status is ACTIVE. Verify disk space. Restart session. |
| **Approval Stuck** | Finding still PENDING after LEAD clicked approve | Check RuntimeExecutor status (Ctrl+5). May be queued. Refresh view (r key). |
| **Evidence Hash Mismatch** | Hash shows different value on re-upload | Evidence is immutable. If hash differs, old evidence corrupted. Check backup. |
| **Task Executor Error** | Status shows "Scheduler Failed" | Check database connectivity. Verify all 41 tables exist. Restart app. |
| **Audit Log Missing Entry** | Action performed but not in activity log | System may be buffering. Wait 30 seconds for scheduler to flush. |
| **Background Task Timeout** | Report generation started but never completes | Check RuntimeExecutor logs (Ctrl+5, press l). Increase task timeout in policies. |
| **Can't Delete Finding** | LEAD presses d, "Permission Denied" | Only LEAD/ADMIN can delete. Ensure you're LEAD+. Check client-safe-mode. |
| **MITRE View Empty** | No techniques visible | Verify mitre_reference.txt exists and is readable. Check file format. |
| **Session Timeout Unexpected** | Logged out after 30 mins (not 120) | Custom retention policy may override default. Check Ctrl+6 Policies tab. |

---

**VectorVue v3.4** | Phase 2/8 Complete | Background Task Runtime | Enterprise RBAC | Production Ready
