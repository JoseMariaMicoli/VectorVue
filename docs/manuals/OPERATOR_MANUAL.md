
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

# VectorVue v3.7 Operator Manual

![Version](https://img.shields.io/badge/Version-v3.7_Production-39FF14) ![Phase](https://img.shields.io/badge/Phase-5/8_Complete-00FFFF) ![Tables](https://img.shields.io/badge/Database-72_Tables-FF00FF)

Complete operational reference for VectorVue v3.7 red team campaign management platform. This manual covers all phases from campaign setup through advanced threat intelligence analysis and multi-team coordination.

---

## Table of Contents

1. [Phase 0: Foundation & Core](#phase-0)
2. [Phase 1: Campaign Management](#phase-1)
3. [Phase 2: Operational Intelligence](#phase-2)
4. [Phase 3: Reporting & Evidence](#phase-3)
5. [Phase 4: Team Federation & Coordination](#phase-4)
6. [Phase 5: Advanced Threat Intelligence](#phase-5)
7. [Cryptography & Security](#crypto)
8. [Advanced Operations](#advanced)
9. [Quick Reference](#reference)

---

## <a name="phase-0"></a>Phase 0: Foundation & Core

### Authentication & Session Management

VectorVue implements **mandatory authentication on every launch** to prevent unauthorized access.

**Authentication Flow:**
```
Application Start
    ↓
Database Initialize (vectorvue.db + vectorvue.salt)
    ↓
Check: Has Users?
    ├─ NO → Registration View (create admin)
    └─ YES → Login View (required)
         ↓
    Validate Credentials (username + password)
         ↓
    Derive Encryption Key (PBKDF2, 480k iterations)
         ↓
    Post-Login Setup
         ├─ Initialize Background Task Executor
         ├─ Load Current User Context
         ├─ Set RBAC Permissions
         └─ Launch Main Editor
```

**Key Points:**
- ✅ **No auto-login:** Session tokens NOT resumed; fresh login required
- ✅ **Key derivation:** Password → AES-256-GCM encryption key
- ✅ **RBAC enforcement:** All database operations checked against user role
- ✅ **Session timeout:** Auto-logout after 120 minutes inactivity

### User Roles & Permissions Matrix

| Operation | VIEWER | OPERATOR | LEAD | ADMIN |
|-----------|--------|----------|------|-------|
| View findings | ✅ | ✅ | ✅ | ✅ |
| Create findings | ❌ | ✅ | ✅ | ✅ |
| Approve findings | ❌ | ❌ | ✅ | ✅ |
| Create campaigns | ❌ | ❌ | ✅ | ✅ |
| Delete campaigns | ❌ | ❌ | ❌ | ✅ |
| Manage teams | ❌ | ❌ | ✅ | ✅ |
| Manage users | ❌ | ❌ | ❌ | ✅ |
| Configure webhooks | ❌ | ❌ | ✅ | ✅ |
| Access threat intel | ✅ | ✅ | ✅ | ✅ |
| Ingest IoCs | ❌ | ✅ | ✅ | ✅ |

---

## <a name="phase-1"></a>Phase 1: Campaign Management

### Creating & Switching Campaigns

**Press Ctrl+K to open Campaign View**

**Campaign Fields:**
- **Campaign Name:** Unique identifier for engagement
- **Client:** Organization being assessed
- **Operator Team:** Red team assignment
- **Start Date:** Campaign kickoff (YYYY-MM-DD)
- **End Date:** Campaign conclusion (optional)
- **Rules of Engagement (ROE):** Operating constraints
  ```
  Example:
  ✓ Operating hours: 9 AM - 5 PM EST weekdays
  ✓ Approved systems: DEV environment only
  ✗ Off-limits: Production databases, medical records
  ```
- **Objective:** What are you trying to prove/assess?
  ```
  Example:
  - Perimeter penetration resistance
  - Social engineering susceptibility
  - Incident response capability
  ```
- **Classification:** UNCLASSIFIED | CONFIDENTIAL | SECRET
- **Status:** Planning | Active | Paused | Concluded

**Creating a Campaign:**
1. In Campaign View, click **CREATE CAMPAIGN**
2. Fill all required fields
3. Click **CONFIRM**
4. Campaign becomes active context
5. Status bar shows: "CAMPAIGN ACTIVE: [Name]"

**Switching Between Campaigns:**
- Click campaign name in lateral panel
- View updates to show selected campaign's data
- All subsequent operations belong to active campaign

### Asset Management

**Press Ctrl+K → Assets Tab**

Assets represent targets within a campaign:

**Asset Types:**
- **Host:** IP, FQDN, hostname (e.g., web01.acme.local)
- **Network:** CIDR range (e.g., 192.168.10.0/24)
- **Service:** Running application (e.g., Apache 2.4.41)
- **Account:** User account (e.g., john.admin@acme.local)
- **Database:** Data repository (e.g., mssql-prod-01)

**Asset Properties:**
- **OS/Version:** Operating system + patch level
- **Criticality:** LOW | MEDIUM | HIGH | CRITICAL
- **Sensitivity Tags:** Production, Finance, Healthcare, DC (Data Center)
- **Owner:** Responsible team/person
- **Status:** Discovered | Targeting | Compromised | Remediated

**Adding Assets:**
```
1. Click NEW ASSET
2. Fill:
   - Name: 192.168.1.10 (or hostname)
   - Type: Host | Network | Service | Account | Database
   - OS: Windows 10, CentOS 8, etc.
   - Criticality: LOW/MEDIUM/HIGH/CRITICAL
   - Tags: (optional) prod, finance, sensitive
3. Click CREATE
```

**Warning on Sensitive Hosts:**
If asset tagged as "Production" or "Finance" or "Healthcare":
- Status bar shows ⚠️ warning before lateral movement
- Must confirm: "Really pivot to [sensitive host]?"
- Audit logged to activity_log for compliance

### Credential Management

**Press Ctrl+K → Credentials Tab**

Track compromised credentials with integrity tracking.

**Credential Types:**
- **Password:** Username + plaintext password
- **Hash:** Domain, username, NTLM/LM hash
- **Token:** API key, OAuth token, JWT
- **SSH Key:** Private key file hash
- **MFA Bypass:** MFA bypass method (TOTP seed, backup code)

**Credential Fields:**
- **Type:** (above types)
- **Username/Account:** User identifier
- **Secret:** Encrypted in database (NEVER plaintext on disk)
- **Source:** Where was credential obtained? (T-number, phishing, dump file)
- **Strength:** Weak | Normal | Strong (entropy estimate)
- **Harvested On:** Timestamp
- **Status:** Active | Expired | Rotated | Invalidated

**Adding Credentials:**
```
1. Click NEW CREDENTIAL
2. Select Type (password, hash, token, etc.)
3. Enter Username
4. Enter Secret (automatically encrypted)
5. Select Source (T1110 Brute Force, T1040 Network Sniffing, etc.)
6. Set Status
7. Click CREATE
```

**Security:** Credentials are **encrypted with AES-256-GCM** before storage. They are **never logged or printed**. To reveal: open Credentials tab, view encrypted blobs.

### Asset-Credential Linking

After creating credentials, link them to assets:

```
1. In Credentials tab, select credential
2. Click LINK TO ASSET
3. Select target asset
4. Enter access level (guest, user, admin)
5. Enter access type (local, domain, service)
6. Click LINK
```

This creates `asset_credentials` association for tracking which accounts access which systems.

---

## <a name="phase-2"></a>Phase 2: Operational Intelligence

### Finding Management

**Main Editor View (default)**

Create markdown findings with automatic MITRE ATT&CK mapping.

**Finding Structure:**
```markdown
# Finding Title

## Summary
Brief description of the vulnerability/misconfiguration.

## Description
Detailed technical explanation.

## CVSS Vector
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

## Remediation
What needs to be fixed?

## References
- https://cwe.mitre.org/data/definitions/...
- OWASP: ...
```

**Creating a Finding:**
1. Type markdown in main editor
2. Fill lateral panel:
   - **Title:** Short name
   - **CVSS Vector:** Full CVSS string
   - **MITRE Technique:** T1110, T1040, etc.
   - **Severity:** CRITICAL | HIGH | MEDIUM | LOW
3. Click **NEW ENTRY**
4. Click **COMMIT DB** to save

**Finding Status Workflow:**
```
Created → Reviewed → Approved → Exported → Archived

- Created: Initial entry, no review
- Reviewed: Operator verified accuracy
- Approved: Lead approved for client report
- Exported: Included in final report
- Archived: Campaign concluded, finding archived
```

### Command Execution Logging (Phase 2a)

**Press Ctrl+E to view Command Execution Log**

Automatically logs all commands executed during engagement:

**What Gets Logged:**
- Successful command execution
- Command output (stdout)
- Execution time, PID, working directory
- User who ran command
- Campaign context

**Example Log Entry:**
```
[2026-02-18 14:32:15] john.operator @ 192.168.1.10:4444
Command: whoami
Output: ACME\Administrator
Status: SUCCESS (exit 0)
MITRE: T1033 (System Owner/User Discovery)
```

**Interpreting Logs:**
- All timestamps in UTC
- Output is sanitized (credentials redacted if detected)
- MITRE mapping done automatically if available
- Can export logs to markdown report

### Session & Persistence Tracking (Phase 2b)

**Press Ctrl+J to view Active Sessions**

Track command execution sessions, reverse shells, meterpreter callbacks.

**Session Fields:**
- **Session ID:** Unique identifier
- **Type:** Meterpreter | Reverse Shell | SSH | WinRM | Custom
- **Target:** IP + port
- **User:** Executing user (DOMAIN\username)
- **Host:** Compromised system name
- **Opened At:** Session start time
- **Last Activity:** Most recent command execution
- **Status:** Active | Idle | Dead | Ended

**Creating Session Records:**
```
1. Click NEW SESSION
2. Enter:
   - Type (shell, meterpreter, etc.)
   - Target (192.168.1.10:4444)
   - User (ACME\jsmith)
   - Host (web01.acme.local)
   - Status (Active)
3. Click CREATE
```

**Persistence Tracking:**

**Press Ctrl+P to view Persistence Mechanisms**

Track installed backdoors, persistence methods.

**Persistence Types:**
- **Registry Run Keys:** HKLM\Software\Microsoft\Windows\CurrentVersion\Run
- **Scheduled Task:** Windows Task Scheduler
- **Cron Job:** Linux /etc/cron.d
- **Service Installation:** Windows service created
- **Webshell:** ASP.NET/PHP shell deployed
- **SSH Key:** Authorized_keys entry
- **Sudo Rule:** /etc/sudoers modification

**Persistence Fields:**
- **Type:** (above types)
- **Target:** Host where persistence installed
- **Method:** How was it installed? (T-number)
- **Installed At:** Timestamp
- **Status:** Active | Disabled | Detected | Removed
- **Description:** Technical details
- **Recovery:** How to remove?

---

## <a name="phase-2b"></a>Phase 2: Real-Time Analytics

### Dashboard (Ctrl+1)

Real-time operational metrics and threat heat map.

**Metrics Displayed:**
- **Campaign Summary:** Name, client, team, status
- **Finding Count:** Total, by severity (CRITICAL/HIGH/MEDIUM/LOW)
- **Asset Coverage:** Assets discovered, compromised, remediated
- **Credential Count:** Compromised accounts, types
- **Session Count:** Active sessions, idle
- **Risk Score:** Aggregate 0-10 score
- **Persistence Count:** Active backdoors

**Heat Map:**
```
Green  (0-3.9):   LOW       - Minor issues
Yellow (4.0-5.9): MEDIUM    - Concerning
Orange (6.0-7.9): HIGH      - Serious
Red    (8.0-10):  CRITICAL  - Urgent
```

### Detection Log (Ctrl+D)

Track defensive actions detected during engagement.

**Detection Types:**
- **Antivirus Alert:** AVG, McAfee, Defender, etc.
- **IDS Alert:** Snort, Suricata, Zeek
- **EDR Alert:** CrowdStrike, Sentinel One, Carbon Black
- **SIEM Alert:** Splunk, QRadar, ArcSight
- **Log Anomaly:** Suspicious entries in security event log
- **Manual Detection:** Defender discovered activity manually

**Detection Fields:**
- **Type:** (above types)
- **Timestamp:** When detected
- **Alert ID:** From defensive system
- **Triggered By:** What action triggered detection?
- **Technique:** MITRE technique used (e.g., T1547 Boot/Logon Autostart)
- **Severity:** From defensive system
- **Response:** What action did defender take?

**Why Track Detections:**
- Shows defensive monitoring capability
- Identifies gaps in detection
- Helps operators avoid further detection
- Evidence of security posture

### Objective Tracking (Ctrl+O)

Track campaign objectives and achievement status.

**Objective Fields:**
- **Objective:** What needs to be achieved?
  ```
  Example: "Demonstrate ability to access customer databases"
  ```
- **Evidence Needed:** What proof is required?
  ```
  Example: "Screenshot of SELECT query + data exfiltration log"
  ```
- **Status:** Not Started | In Progress | Achieved | Failed
- **Completion %:** 0-100
- **Notes:** Progress updates

---

## <a name="phase-2c"></a>Phase 2c: Background Task Execution

VectorVue runs a **background task executor** automatically after login.

**Executor Functions:**
1. **Task Scheduler** - Executes pending scheduled tasks (30-second intervals)
2. **Webhook Delivery** - Sends integration payloads to external endpoints
3. **Session Timeout** - Expires idle sessions after 120 minutes
4. **Retention Policy** - Purges old findings/credentials per policy
5. **Anomaly Detection** - Behavioral analytics on operator activity

**Background Tasks Tab (Alt+2):**
- View queued tasks
- Monitor executor health
- Cancel long-running tasks
- Adjust executor thread count (1-8)

**Task Types:**
- **Scheduled Task:** Run at specific time
- **Webhook:** Send data to external system
- **Retention Purge:** Delete expired records
- **Anomaly Analysis:** Detect unusual behavior
- **Report Generation:** Create PDF/HTML output

**Executor Health:**
- Green = Running, no backlog
- Yellow = Running, some backlog
- Red = Error or executor down
- Restart: Logout + re-login

---

## <a name="phase-3"></a>Phase 3: Reporting & Evidence Chain of Custody

### Evidence Management

**Press Ctrl+R → Evidence Tab**

VectorVue implements strict chain of custody for all evidence.

**Evidence Fields:**
- **ID:** Unique identifier (auto-generated)
- **Title:** Brief description (e.g., "SAM Registry Dump")
- **Description:** Detailed content
- **Collection Method:** How was evidence collected?
  - T1005 (Data Staged)
  - T1113 (Screen Capture)
  - T1005 (Data from Local System)
  - T1056 (Input Capture)
  - Manual/Custom
- **Who Collected:** Operator username
- **Timestamp:** When collected (UTC)
- **Source Host:** Where was it collected from?
- **File Hash (SHA256):** Integrity verification
- **Classification:** UNCLASSIFIED | CONFIDENTIAL | SECRET
- **Status:** Collected | Verified | Approved | Reported | Archived

**Immutability Guarantee:**
- Evidence **cannot be edited** after creation
- Attempts to modify trigger audit log alert
- Hash verification on every read
- Prevents tampering/falsification

**Collecting Evidence:**
```
1. Click NEW EVIDENCE
2. Enter:
   - Title: "Registry Export HKLM\Security"
   - Description: [multiline]
   - Collection Method: T1005 (Data Staged)
   - Source Host: 192.168.1.10
   - Content: [paste data/attach file]
3. Click COLLECT
   → File written atomically
   → SHA256 computed automatically
   → Timestamp recorded
   → Audit logged
```

### Report Generation

**Press Ctrl+R → Generate Report**

VectorVue supports multiple report formats and audiences.

**Report Types:**

#### 1. Technical Report
**Audience:** Defenders, architects  
**Contents:**
- Executive summary
- All findings (detailed)
- Asset inventory
- Credential list (redacted)
- MITRE ATT&CK coverage matrix
- Timeline of activities
- Recommendations by severity

**Format Options:**
- PDF (formatted, with headers/footers)
- HTML (interactive, searchable)
- Markdown (for internal wiki)

#### 2. Executive Summary
**Audience:** C-suite, management  
**Contents:**
- High-level findings (CRITICAL + HIGH only)
- Risk rating (0-10 scale)
- Key recommendations
- Compliance mapping (if applicable)
- Timeline (attack progression)
- Next steps

#### 3. Compliance Report
**Audience:** Auditors, compliance teams  
**Contents:**
- CVSS scores for all findings
- CWE/OWASP mapping
- PCI-DSS / HIPAA / SOC2 compliance gaps
- Evidence artifacts
- Attestation statements
- Remediation SLAs

### Evidence Manifest

VectorVue automatically generates evidence manifest with:
- Hash of all artifacts
- Chain of custody (who collected, when, how)
- Classification levels
- Legal admissibility notes

**Manifest Example:**
```
EVIDENCE MANIFEST
Campaign: ACME Corp Q1 2026
Generated: 2026-02-18 15:30:00 UTC
Approver: john.lead [LEAD]

[E001] SAM Registry Dump
  Hash: a1b2c3d4e5f6...
  Collected: 2026-02-17 10:15:00
  Method: T1005 (Data Staged)
  Source: 192.168.1.10
  Status: APPROVED

[E002] Network Traffic Capture
  Hash: f6e5d4c3b2a1...
  Collected: 2026-02-17 11:20:00
  Method: T1041 (Exfiltration Over C2 Channel)
  Source: 192.168.0.0/24
  Status: APPROVED
```

### Report Delivery

Reports automatically saved to **05-Delivery/** directory:
- `ACME_Corp_Q1_2026_Technical_Report.pdf`
- `ACME_Corp_Q1_2026_Executive_Summary.html`
- `ACME_Corp_Q1_2026_Compliance_Report.pdf`
- `ACME_Corp_Q1_2026_Evidence_Manifest.txt`

---

## <a name="phase-4"></a>Phase 4: Team Federation & Coordination

### Team Management

**Press Ctrl+T to open Team Management**

Multi-operator coordination with shared intelligence and approval workflows.

**Creating Teams:**
```
1. Click CREATE TEAM
2. Enter:
   - Team Name: "Red Team Alpha"
   - Description: "Primary red team"
   - Budget (USD): 50000
   - Team Lead: [select user]
3. Click CREATE
```

**Team Fields:**
- **Name:** Unique identifier
- **Description:** Purpose, scope
- **Budget:** USD allocation for engagement
- **Team Lead:** LEAD+ role user
- **Created At:** Timestamp
- **Members Count:** Active team size
- **Status:** Active | On-Hold | Disbanded

### Team Membership

**Add Members:**
```
1. Select team in Team Management
2. Click ADD MEMBER
3. Select user
4. Assign role:
   - team_member: Standard operator
   - team_lead: Lead operator (can approve findings)
5. Click ADD
```

**Team Roles:**
- **team_member:** Create/edit findings in shared campaign
- **team_lead:** Approve findings, manage team settings
- **team_observer:** View-only access

**Permissions in Team Context:**
- team_members can see all team findings
- Non-team members cannot see team findings
- Approval required from any team_lead
- Audit log tracks all team activity

### Intelligence Sharing (Phase 4)

**Intelligence Pools:**

Create shared pools of findings, credentials, IoCs for team access.

```
1. In Threat Intelligence view, click NEW POOL
2. Enter:
   - Pool Name: "Critical Vulns"
   - Description: "High-impact findings"
   - Sharing: Select teams with access
3. Add findings to pool
4. Teams with access can query pool
```

**Data Sharing Policies:**

Define what data team members can see:

```
1. Click CREATE POLICY
2. Set:
   - Policy Name: "Dev-Only Access"
   - Applies To: [select teams]
   - Can View: Findings, Assets, Credentials
   - Can Modify: No
   - Can Export: No
3. Click CREATE
```

### Operator Performance Tracking

VectorVue tracks operator metrics automatically:

**Metrics Captured:**
- Findings submitted per operator
- Average CVSS score of findings
- Findings approved/rejected ratio
- Commands executed
- Session duration
- Credential harvested count

**View Operator Dashboard:**
```
1. Press Alt+6 (Compliance & Security)
2. Click OPERATOR METRICS
3. View performance across team
```

---

## <a name="phase-5"></a>Phase 5: Advanced Threat Intelligence

### Threat Intelligence View

**Press Ctrl+Shift+I to open Threat Intelligence**

Advanced threat actor profiling, IoC management, and automated risk correlation.

### Threat Feeds

**Adding Threat Feeds:**

Integrate with external threat intelligence services.

```
1. Click ADD FEED
2. Select source:
   - VirusTotal (https://www.virustotal.com)
   - Shodan (https://www.shodan.io)
   - OTX/AlienVault (https://otx.alienvault.com)
   - MISP (https://www.misp-project.org)
   - Custom (any JSON endpoint)
3. Enter:
   - Feed Name: "VirusTotal IP Reputation"
   - Feed URL: https://api.virustotal.com/api/v3/feeds
   - API Key: [encrypted in DB]
   - Update Interval: 24 hours
   - Description: "IP reputation scoring"
4. Click ADD FEED
```

**Feed Data Integration:**

Threat feeds automatically populate:
- **IP Reputation:** Malicious IP scores
- **Domain Reputation:** Phishing/malware domains
- **Hash Reputation:** Known malware/tools
- **Email Reputation:** Known phishing senders

**Refresh Feeds:**
- Manual: Click REFRESH ALL FEEDS
- Automatic: Background executor refreshes on schedule
- Status: Shows "Last updated: 2 hours ago"

### Threat Actor Profiles

**Create Threat Actor Profile:**

```
1. Click CREATE THREAT ACTOR
2. Enter:
   - Actor Name: "Lazarus Group"
   - Aliases: "APT-C-39, Hidden Cobra, TEMP.Hermit"
   - Origin: "North Korea"
   - Organization: "Reconnaissance General Bureau (RGB)"
   - Founded: 2009
   - Known Targets: "Financial institutions, cryptocurrency exchanges"
   - Confidence: 0.95 (1.0 = certain)
   - Description: [detailed background]
3. Click CREATE
```

**Add Tactics & Techniques (TTP):**

```
1. Select threat actor
2. Click ADD TTP
3. Select technique:
   - T1110: Brute Force
   - T1566: Phishing
   - T1040: Network Sniffing
4. Add details:
   - How used: "Spear-phishing with malicious Excel macros"
   - Tools: "Custom implant 'MATA'"
   - Observed: 2026-01-15
5. Click ADD
```

### Indicators of Compromise (IoC) Management

**Ingest IoC:**

Add indicators of compromise with automatic enrichment.

```
1. Click INGEST IoC
2. Select type:
   - IPv4 Address (e.g., 192.168.1.100)
   - Domain (e.g., malware.com)
   - File Hash (MD5, SHA1, SHA256)
   - Email Address
   - URL
3. Enter value
4. Set threat level:
   - LOW: Suspicious, monitor
   - MEDIUM: Likely malicious, investigate
   - HIGH: Confirmed malicious, block
   - CRITICAL: Known active attack, immediate action
5. Add context:
   - Found in: (campaign, alert, feed)
   - Technique: T-number
   - Actor: (if known)
6. Click INGEST
```

**IoC Enrichment (Automatic):**

VectorVue enriches all IoCs with:
- VirusTotal verdict (malicious, suspicious, clean)
- Shodan data (if IP)
- Whois/DNS data
- Passive DNS history
- Correlation with known campaigns

**IoC Linking:**

Link IoCs to:
- Threat actors
- Campaigns
- Techniques
- Assets (detected on host)
- Sessions (seen in network traffic)

**IoC Status:**
- **Active:** Currently monitored
- **Blocked:** On firewall/EDR blocklist
- **Remediated:** No longer detected
- **False Positive:** Legitimate traffic/tool
- **Archived:** Campaign ended

### Risk Scoring (Automated)

VectorVue automatically computes risk scores for findings:

**Risk Score Formula:**
```
Risk Score = (CVSS_Base × Weight_Severity) 
           + (Exploitability × Weight_Exploit)
           + (Prevalence × Weight_Prevalence)
           + (IoC_Count × Weight_IoC)

Where:
- CVSS_Base: 0-10 (from CVSS vector)
- Exploitability: 0-1 (public PoC available?)
- Prevalence: 0-1 (how many orgs affected?)
- IoC_Count: number of indicators tied to finding
```

**Risk Levels:**
- **CRITICAL:** 8.0 - 10.0 (immediate remediation)
- **HIGH:** 6.0 - 7.9 (remediate within 30 days)
- **MEDIUM:** 4.0 - 5.9 (remediate within 90 days)
- **LOW:** 0 - 3.9 (remediate within 1 year)

**View Risk Scores:**
1. Press Ctrl+Shift+I (Threat Intelligence)
2. Click RISK SCORES
3. Sort by risk level
4. Click finding to see score breakdown

### Threat Correlation Engine

**Automatic Correlation:**

VectorVue correlates findings with:
1. Known threat actors (from profiles)
2. Known techniques (MITRE ATT&CK)
3. Known tools (from threat feeds)
4. Similar campaigns (from history)

**Correlation Example:**
```
Finding: "Lateral movement via T1570 (Lateral Tool Transfer)"
Assets: web01, db01, dc01
Technique: T1570
IoCs: malware.exe, attacker_ip.txt

System finds:
✓ T1570 used by: Lazarus Group (confidence 0.85)
✓ Similar campaign: "ACME Corp 2025 Assessment"
  - Used T1570, T1110, T1566
✓ Correlated findings:
  - Phishing email (T1566)
  - Password spraying (T1110)
  - Lateral movement (T1570)

→ Likely attack chain discovered
→ Risk score elevated to CRITICAL
```

### Threat Timeline & Attack Progression

**View Attack Timeline:**

```
1. Press Ctrl+Shift+I
2. Click TIMELINE
3. See chronological progression:
   09:15 - Phishing email sent (T1566)
   09:45 - User clicks link, downloads malware (T1566)
   10:20 - Malware executes, establishes C2 (T1071)
   11:30 - Reconnaissance commands (T1033, T1087, T1010)
   12:45 - Lateral movement begins (T1570)
   14:00 - Data exfiltration detected (T1041)
   15:30 - Persistence installed (T1547)
```

**Timeline Features:**
- Chronological ordering
- MITRE ATT&CK mapping
- IoC correlation
- Detection timeline (when defender detected each step)
- Time-to-detect metric

---

## <a name="crypto"></a>Cryptography & Security

### Encryption

**AES-256-GCM Encryption:**

All sensitive data encrypted at rest:

```
Plaintext → Encryption Key → AES-256-GCM → Ciphertext (DB)

Key Derivation:
Password → PBKDF2 (480,000 iterations) → 32-byte key
           ↓
        vectorvue.salt (256-bit random)
           ↓
        Encryption key (never stored)
```

**Encrypted Fields:**
- Passwords (user passwords, API keys)
- Credentials (harvested usernames/passwords)
- Private keys (SSH, certificates)
- API keys (threat feeds, webhooks)
- Comments (can contain sensitive info)

**Non-Encrypted Fields (But Audited):**
- Usernames (logged for audit)
- IP addresses (needed for asset tracking)
- Domain names (needed for asset tracking)
- MITRE techniques (needed for reporting)

### Integrity

**HMAC Signing:**

All database rows signed with HMAC:

```
Row Data → HMAC-SHA256 → Signature (stored with row)

Verification:
DB Read → Recalculate HMAC → Compare with stored

Result:
✓ Match: Row is authentic
✗ Mismatch: Row has been tampered with → Alert
```

**Chain of Custody:**

Evidence items tracked with:
- Collection timestamp
- Operator username
- Source host
- Collection method
- SHA256 file hash
- Immutable after creation

### Access Control

**Role-Based Access Control (RBAC):**

All database operations check user role:

```python
if role_gte(current_user.role, LEAD):
    allow("Approve finding")
else:
    deny("Only LEAD+ can approve")
```

**Campaign Isolation:**

Every finding, asset, credential belongs to a campaign:

```
Finding → Campaign (1:many)
           ↓
       Only users in that campaign can see finding
       
Queries always filtered:
SELECT * FROM findings 
WHERE campaign_id = current_campaign_id
```

---

## <a name="advanced"></a>Advanced Operations

### Keybindings Reference

**File Management:**
- **Space** - File Manager
- **Ctrl+N** - New File
- **Ctrl+W** - Close File
- **Ctrl+S** - Save File

**Campaign & Intelligence:**
- **Ctrl+K** - Campaign Management
- **Ctrl+E** - Command Execution Log
- **Ctrl+J** - Active Sessions
- **Ctrl+D** - Detection Log
- **Ctrl+O** - Objectives
- **Ctrl+P** - Persistence
- **Ctrl+Shift+I** - Threat Intelligence (Phase 5)

**Analytics:**
- **Ctrl+1** - Dashboard
- **Ctrl+2** - Analysis
- **Ctrl+3** - Legacy Intelligence
- **Ctrl+4** - Remediation
- **Ctrl+5** - Capability Matrix

**Advanced:**
- **Ctrl+R** - Reporting
- **Ctrl+T** - Team Management (Phase 4)
- **Ctrl+M** - MITRE ATT&CK Database
- **Alt+1** - Collaboration
- **Alt+2** - Background Tasks
- **Alt+3** - Analytics/Anomalies
- **Alt+4** - Integrations/Webhooks
- **Alt+5** - Compliance
- **Alt+6** - Security/Audit

**General:**
- **Ctrl+L** - Logout
- **Ctrl+Q** - Quit
- **q** - Quit
- **?** - Help
- **Escape** - Back to main editor

### Vim Navigation in Tables

All VectorVue data tables support Vim keybindings:

- **j/k** - Move down/up
- **g** - Jump to top
- **G** - Jump to bottom
- **/** - Search
- **Enter** - Select/edit row
- **d** - Delete row (with confirmation)
- **e** - Edit row
- **o** - New row

### Webhook Integration

**Set Up Webhook:**

```
1. Press Alt+4 (Integrations)
2. Click ADD WEBHOOK
3. Configure:
   - Name: "Slack Notifications"
   - URL: https://hooks.slack.com/services/[token]
   - Trigger: Finding created, Finding approved, Report generated
   - Format: JSON
   - Headers: Authorization: Bearer [token]
4. Click CREATE
```

**Webhook Payloads:**

When triggered, VectorVue sends JSON:

```json
{
  "event": "finding.created",
  "campaign": "ACME Corp Q1 2026",
  "finding": {
    "title": "Weak Password Policy",
    "severity": "HIGH",
    "cvss": 6.5,
    "mitre_technique": "T1110"
  },
  "operator": "john.operator",
  "timestamp": "2026-02-18T15:30:00Z"
}
```

### Export Formats

**Press Ctrl+R → Export**

**Supported Formats:**
- **PDF** - Professional formatted report (uses ReportLab)
- **HTML** - Interactive web report (searchable)
- **Markdown** - Internal wiki format
- **JSON** - Structured data format
- **CSV** - Spreadsheet compatible
- **NESSUS** - Import findings into Nessus
- **Splunk** - Send to Splunk SIEM

**Export Options:**
- Include/exclude findings by severity
- Include/exclude credentials
- Include/exclude evidence
- Anonymize IP addresses
- Redact sensitive data
- Add watermark/classification

---

## <a name="reference"></a>Quick Reference

### Command Cheat Sheet

| Task | Command |
|------|---------|
| Create finding | Type in editor → NEW ENTRY → COMMIT DB |
| Switch campaign | Ctrl+K → Click campaign name |
| Add asset | Ctrl+K → Assets → NEW ASSET |
| Log credential | Ctrl+K → Credentials → NEW CREDENTIAL |
| View threat intel | Ctrl+Shift+I |
| Create team | Ctrl+T → CREATE TEAM |
| Approve finding | Ctrl+R → Select finding → APPROVE |
| Generate report | Ctrl+R → SELECT TYPE → GENERATE |
| Logout | Ctrl+L |
| Quit | Ctrl+Q |

### Database Tables (72 Total)

**Phase 0-1: Foundation (12 tables)**
- users, user_roles, user_preferences, sessions
- campaigns, campaign_participants, campaign_audit_log
- roles, permissions, role_permissions
- system_settings, audit_log

**Phase 2: Operations (15 tables)**
- findings, assets, credentials, asset_credentials
- commands, command_output, command_artifacts
- sessions, persistence_mechanisms, detections
- objectives, campaign_metrics, finding_approvals
- activity_log, scheduled_tasks, webhook_deliveries

**Phase 3: Reporting (8 tables)**
- reports, report_sections, evidence_items
- evidence_artifacts, evidence_manifest
- campaign_reports, evidence_chains, compliance_mappings

**Phase 4: Teams (16 tables)**
- teams, team_members, team_roles, team_permissions
- campaign_team_assignments, data_sharing_policies
- team_metrics, operator_performance, team_intelligence_pools
- coordination_logs, team_approvals, team_audit_log
- intelligence_pool_findings, team_notifications
- capability_assessments, remediation_tracking

**Phase 5: Threat Intelligence (21 tables)**
- threat_feeds, threat_feed_refresh_log
- threat_actors, actor_aliases, actor_ttps
- indicators_of_compromise (IoC), ioc_enrichment
- threat_correlations, risk_scores, risk_scoring_rules
- enrichment_data, threat_intelligence_archive
- behavioral_analytics, anomaly_rules, detected_anomalies
- attack_patterns, attack_timeline, technique_coverage
- intelligence_sharing, feed_data_cache

---

## Support & Troubleshooting

For common issues, see [TROUBLESHOOTING_GUIDE.md](./TROUBLESHOOTING_GUIDE.md)

**VectorVue v3.7** | Phase 5 Complete | 72 Tables | 200+ Methods
