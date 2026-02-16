# VectorVue v3.4 Architecture Specification

![Architecture](https://img.shields.io/badge/Architecture-v3.4-39FF14?style=flat-square) ![Status](https://img.shields.io/badge/Status-Production_Ready-00FFFF?style=flat-square) ![Phase](https://img.shields.io/badge/Phase-2_Complete-39FF14)

Comprehensive technical specification for VectorVue v3.4 Red Team Campaign Management Platform. Covers database schema, system design patterns, cryptography, and runtime architecture with background task execution.

## 1. System Overview

VectorVue v3.4 is organized around **Five Core Pillars** plus a new **Runtime Execution Layer**:

### The Six Pillars of VectorVue v3.4

```
┌─────────────────────────────────────────────────────┐
│  Layer 6: UI Controller (vv.py)                     │
│  - 16 TUI Views, 30+ Keybindings, Tab Navigation   │
├─────────────────────────────────────────────────────┤
│  Layer 5: Runtime Executor (vv_core.py)            │
│  - 5 Background Executors, Async Task Queuing      │
├─────────────────────────────────────────────────────┤
│  Layer 4: File System Abstraction (vv_fs.py)       │
│  - Atomic I/O, Secure Wipe, SHA256 Hashing         │
├─────────────────────────────────────────────────────┤
│  Layer 3: Database Orchestration (vv_core.py)      │
│  - 41 Tables, Campaign Isolation, RBAC             │
├─────────────────────────────────────────────────────┤
│  Layer 2: Session Crypto (vv_core.py)              │
│  - AES-256-GCM, PBKDF2 (480k), HMAC Signing        │
├─────────────────────────────────────────────────────┤
│  Layer 1: Theme System (vv_theme.py)               │
│  - Phosphor Cyberpunk CSS, Color Variables         │
└─────────────────────────────────────────────────────┘
```

## 2. Database Architecture (41 Tables)

### Phase 0: Core Foundation (15 Tables)
**Campaign, Role, RBAC & Core Data**

```sql
-- Campaign Management
campaigns              -- Campaign metadata (id, name, client, status, tactic)
findings              -- Vulnerabilities (id, campaign_id, title, impact, mitre_technique)
assets                -- Target systems (id, campaign_id, ip, hostname, os)
credentials           -- Discovered accounts (id, campaign_id, account, hash)
actions               -- Operator activities (id, campaign_id, who, when, what)

-- User & Role Management
users                 -- User accounts (id, username, passhash, role)
roles                 -- RBAC definitions (id, name, level: VIEWER/OPERATOR/LEAD/ADMIN)
permissions           -- Role capabilities (id, role_id, can_create_finding, etc.)

-- Operational Tracking
activity_log          -- Audit trail (id, campaign_id, operator, timestamp, action, hmac)
sessions              -- User sessions (id, user_id, token, expires_at, last_active)

-- Intelligence
teams                 -- Operator teams (id, name, lead_id)
team_members          -- Team rosters (id, team_id, user_id, role)
mitre_techniques      -- Cached MITRE data (id, technique_id, name, tactic)
adversaries           -- TTP profiles (id, name, description, known_techniques)
threat_intel          -- External threat data (id, source, indicator, severity)
```

**Schema Pattern:**
```python
campaigns: {
    id (PK),
    name TEXT,
    client TEXT,
    operator_team_id FK,
    start_date DATE,
    end_date DATE,
    objective TEXT,
    rules_of_engagement TEXT,
    status (PLANNING|ACTIVE|SUSPENDED|COMPLETE|ARCHIVED),
    classification (CLEAR|GREEN|AMBER|RED),
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    encrypted BOOLEAN,  # All sensitive fields encrypted
    hmac_signature BLOB # Row-level integrity
}
```

### Phase 1: Operational Intelligence (8 Tables)
**Evidence, Retention, Compliance**

```sql
evidence_items        -- File evidence (id, campaign_id, filename, sha256_hash, collected_by, timestamp)
evidence_metadata     -- Chain of custody (id, evidence_id, collection_method, source_host, encrypted)
retention_policies    -- Data lifecycle (id, campaign_id, entity_type, days_kept, action)
compliance_frameworks -- Standards (id, name, description, requirement_count)
audit_log_archive     -- Historical logs (id, campaign_id, original_log_id, archived_at)
```

### Phase 2: Advanced Runtime (18 Tables)
**Background Tasks, Webhooks, Approval Workflows, Anomaly Detection**

```sql
-- Runtime Task Execution
runtime_tasks         -- Background tasks (id, campaign_id, task_type, status, scheduled_at, next_run)
task_executors        -- 5 executor threads (id, executor_name, status, last_run, next_run)
scheduled_actions     -- Recurring tasks (id, campaign_id, action_type, frequency, enabled)

-- Integration & Webhooks
webhooks              -- Integration endpoints (id, campaign_id, endpoint_url, event_type, enabled)
webhook_deliveries    -- Delivery history (id, webhook_id, payload, status, timestamp, retry_count)
integration_events    -- Logged events (id, campaign_id, integration, event, timestamp)

-- Approval & Workflow
approval_workflows    -- Approval rules (id, campaign_id, entity_type, required_role, require_evidence)
approval_requests     -- Pending approvals (id, workflow_id, requester_id, entity_id, status, comment)
approval_audit        -- Decision history (id, approval_id, approver_id, decision, timestamp, reason)

-- Classification & Data Minimization
data_classification   -- TLP controls (id, campaign_id, level, redaction_rules)
client_safe_mode      -- Operator mode (id, campaign_id, enabled, restrictions)
sensitive_assets      -- Protected hosts (id, campaign_id, asset_id, sensitivity_level, justification)

-- Analysis & Detection
anomaly_events        -- Suspicious activity (id, campaign_id, event_type, severity, detected_at, details)
activity_patterns     -- Baseline patterns (id, campaign_id, pattern_type, baseline_count, anomaly_threshold)
```

## 3. Encryption & Cryptography

### Session Crypto Layer (PBKDF2 + Fernet)

**Key Derivation:**
```python
def derive_key(passphrase: str) -> bytes:
    """
    PBKDF2-SHA256: 480,000 iterations
    Input: User passphrase
    Salt: Persisted in vectorvue.salt (16 bytes)
    Output: 32-byte key suitable for Fernet
    """
    salt = load_salt_from_disk()
    key = PBKDF2(
        hash_func=SHA256,
        password=passphrase,
        salt=salt,
        iterations=480000,
        dklen=32
    )
    return key
```

**Encryption at Rest:**
```python
# All sensitive fields encrypted before insert:
finding.description = crypto.encrypt(plaintext_description)
credential.hash = crypto.encrypt(plaintext_hash)

# Decryption on retrieval:
plaintext = crypto.decrypt(finding.description)
```

**Row-Level Integrity:**
```python
# HMAC signature on every row:
row_data = json.dumps(row).encode()
hmac_sig = HMAC-SHA256(key, row_data)
# Stored in 'hmac_signature' column
# Verified on read to detect tampering
```

### Cipher Specification

| Property | Value |
|----------|-------|
| **Algorithm** | Fernet (AES-128-CBC with HMAC-SHA256) |
| **Key Derivation** | PBKDF2-SHA256, 480,000 iterations |
| **Salt** | 16 bytes, persisted in `vectorvue.salt` |
| **IV** | Generated fresh per encryption |
| **Integrity** | Row-level HMAC-SHA256 |
| **Authentication** | Token + session TTL (120 min) |

## 4. Database Orchestration (vv_core.py)

### Database Class Architecture
```python
class Database:
    """Manages both vectorvue.db and adversary.db with encrypted schema"""
    
    # Operational Database (encrypted)
    vectorvue.db: SQLite3
        - campaigns, findings, assets, credentials (41 tables)
        - All user input encrypted
        - All rows HMAC-signed
    
    # Intelligence Database (secondary)
    adversary.db: SQLite3
        - threat_intel, mitre_techniques, adversaries
        - Reference data (lower encryption priority)
    
    # Salt Storage
    vectorvue.salt: Binary
        - 16-byte PBKDF2 salt
        - Unique per deployment
        - **CRITICAL:** Backup immediately
```

### Campaign Isolation Pattern
Every query filters by `campaign_id`:

```python
def list_findings(campaign_id: str) -> List[Finding]:
    """Get findings only for specified campaign"""
    query = "SELECT * FROM findings WHERE campaign_id=? AND encrypted=1"
    results = self.execute(query, (campaign_id,))
    return [decrypt_and_verify_row(row) for row in results]

# This pattern enforces team isolation:
# OPERATOR@TeamA cannot see findings from OPERATOR@TeamB
# Even if database is compromised, campaign_id filter prevents leakage
```

### 150+ Database Methods (Phase 2 Complete)

**Finding Management (20+ methods):**
- `create_finding(campaign_id, title, description, impact, ...)`
- `update_finding(finding_id, changes)`
- `delete_finding(finding_id, reason)` [requires LEAD+ role]
- `get_findings_by_campaign(campaign_id)`
- `get_findings_by_status(campaign_id, status)`
- `get_findings_by_severity(campaign_id, severity)`
- `approve_finding(finding_id, approver_id, comment)`
- `reject_finding(finding_id, approver_id, reason)`

**Asset & Credential Management (20+ methods):**
- `create_asset(campaign_id, ip, hostname, os, ...)`
- `update_asset(asset_id, changes)`
- `create_credential(campaign_id, account, domain, hash, ...)`
- `verify_credential_integrity(credential_id)` [check hash still valid]
- `list_lateral_movement_paths(asset_id)` [reach analysis]

**Evidence & Chain of Custody (15+ methods):**
- `record_evidence(campaign_id, filename, sha256_hash, collected_by, ...)`
- `get_evidence_chain_of_custody(evidence_id)` [full audit trail]
- `verify_evidence_hash(evidence_id)` [SHA256 check]
- `archive_evidence(evidence_id, reason)` [secure deletion]

**MITRE Mapping (10+ methods):**
- `link_finding_to_technique(finding_id, technique_id)`
- `get_coverage_matrix(campaign_id)` [% techniques tested]
- `get_techniques_by_tactic(campaign_id, tactic)`
- `get_uncovered_techniques(campaign_id)` [gaps analysis]

**Approval Workflow (10+ methods):**
- `submit_for_approval(entity_id, entity_type, submitter_id)`
- `approve_entity(approval_id, approver_id, comment)`
- `request_changes(approval_id, approver_id, comment)`
- `get_pending_approvals(campaign_id, role=LEAD)` [LEAD's queue]
- `get_approval_history(entity_id)` [full decision chain]

**Background Task Management (15+ methods):**
- `create_scheduled_action(campaign_id, action_type, frequency)`
- `enqueue_task(task_type, campaign_id, params)`
- `get_pending_tasks(executor_type)` [tasks for Scheduler executor]
- `mark_task_complete(task_id, status, output)`
- `get_task_execution_history(task_id)` [retry tracking]

**Retention & Lifecycle (10+ methods):**
- `create_retention_policy(campaign_id, entity_type, days_kept)`
- `execute_retention_sweep(campaign_id)` [nightly purge]
- `archive_old_findings(campaign_id, days_threshold)`
- `secure_delete_evidence(evidence_id, reason)` [multi-pass wipe]

**Audit & Compliance (20+ methods):**
- `log_activity(campaign_id, operator_id, action, details)`
- `get_activity_log(campaign_id, filters={})`
- `get_user_access_log(user_id)` [who accessed what]
- `export_compliance_report(campaign_id, format)` [PDF/JSON]
- `verify_audit_integrity(campaign_id)` [check HMAC signatures]

## 5. File System Abstraction (vv_fs.py)

### Atomic Write Pattern
Crash-safe file operations for evidence and reports:

```python
@staticmethod
def atomic_write(path: Path, content: str) -> Tuple[bool, str]:
    """
    1. Write to temporary file (same filesystem)
    2. Call fsync() to ensure disk flush
    3. Atomic rename to target path
    4. Returns: (success, message)
    
    If process crashes during write, temp file remains but target untouched.
    """
    temp_file = path.parent / f"{path.name}.tmp"
    try:
        with open(temp_file, 'w') as f:
            f.write(content)
        os.fsync(f.fileno())  # Flush to disk
        temp_file.rename(path)  # Atomic on POSIX
        return True, f"Wrote {path.name}"
    except Exception as e:
        return False, f"Error: {str(e)}"
```

### Secure File Deletion
Multi-pass overwrite before deletion:

```python
@staticmethod
def secure_wipe(path: Path, passes: int = 3) -> Tuple[bool, str]:
    """
    1. Overwrite file with random bytes (3 passes: random, zeros, ones)
    2. Truncate file to zero length
    3. Delete file
    4. Logs all operations for audit
    """
    file_size = path.stat().st_size
    with open(path, 'r+b') as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(file_size))
        f.truncate(0)
    path.unlink()
    return True, "Secure deleted"
```

### File Operations

| Method | Purpose | Returns |
|--------|---------|---------|
| `atomic_write(path, content)` | Crash-safe write | (bool, message) |
| `read_file(path)` | Read with error handling | (bool, content, encoding) |
| `secure_wipe(path, passes)` | Multi-pass overwrite delete | (bool, message) |
| `calculate_file_hash(path)` | SHA256 hash | str (hex digest) |
| `ingest_c2_log(log_path)` | Parse C2 logs → markdown | (bool, formatted_md) |
| `validate_file_encoding(path)` | Check UTF-8/binary | (bool, encoding) |

## 6. Theme System (vv_theme.py)

### Phosphor Cyberpunk Palette
```python
PHOSPHOR_GREEN   = "#39FF14"  # Primary accent (findings, success)
ELECTRIC_CYAN    = "#00FFFF"  # Secondary accent (commands, UI)
RED_ALERT        = "#FF0000"  # Critical/destructive actions
DARK_SLATE       = "#1a1a2e"  # Background
NEUTRAL_GRAY     = "#888888"  # Disabled, secondary text
```

### CSS Variable Architecture
```css
/* theme.CYBER_CSS */
--primary-green: #39FF14;
--secondary-cyan: #00FFFF;
--alert-red: #FF0000;
--background: #1a1a2e;

button {
    background: var(--primary-green);
    color: black;
}

button:disabled {
    background: var(--neutral-gray);
}
```

## 7. Runtime Executor Architecture (Phase 2)

### Background Task Execution System

```
┌────────────────────────────────────────────────────┐
│         RuntimeExecutor (Main Thread)              │
│     (Spawns 5 Background Executor Threads)        │
├────────────────────────────────────────────────────┤
│  ┌──────────┬──────────┬──────────┬──────────┬────┐
│  │Scheduler │ Webhooks │ Sessions │Retention│Anom│
│  │Executor  │Executor  │Executor  │Executor │Exec│
│  └──────────┴──────────┴──────────┴──────────┴────┘
│     ↓         ↓         ↓         ↓         ↓
│  Every 30s   On Event  Every 60s  Nightly  Real-time
│  Execute    Deliver    TTL Check  Purge    Detect
└────────────────────────────────────────────────────┘
```

### 5 Executor Types

**1. Scheduler Executor (30-second interval)**
- Executes all scheduled actions from `scheduled_actions` table
- Updates `runtime_tasks` with status
- Logs all executions in `activity_log`

**2. Webhook Executor (event-driven)**
- Monitors `webhooks` table
- Delivers payloads on finding approval, report generation
- Retries failed deliveries (exponential backoff: 2s → 32s)
- Logs in `webhook_deliveries` and `integration_events`

**3. Session Executor (1-minute interval)**
- Checks `sessions.expires_at` against current time
- Auto-logs out expired sessions
- Logs session terminations with reason
- OPERATOR sees: "Your session expired" message

**4. Retention Executor (nightly, default 2 AM UTC)**
- Reads retention policies from `retention_policies` table
- Purges findings/credentials/audit logs per config
- Calls `FileSystemService.secure_wipe()` for evidence files
- Logs all purges with item count and reason

**5. Anomaly Executor (real-time processing)**
- Monitors `activity_log` for patterns
- Flags suspicious activities:
  - Login outside business hours (if configured)
  - Mass export (>100 items in 1 hour)
  - Sensitive host access (if flagged in `sensitive_assets`)
- Logs detections in `anomaly_events` table
- Alerts ADMIN if severity HIGH or CRITICAL

### RuntimeExecutor Data Structure
```python
class RuntimeExecutor:
    def __init__(self):
        self.executors = {
            'scheduler': SchedulerExecutor(interval=30),
            'webhooks': WebhookExecutor(event_driven=True),
            'sessions': SessionExecutor(interval=60),
            'retention': RetentionExecutor(time='02:00 UTC'),
            'anomaly': AnomalyExecutor(real_time=True),
        }
    
    async def start(self):
        """Launch all 5 executor threads"""
        for executor in self.executors.values():
            asyncio.create_task(executor.run())
    
    async def enqueue_task(self, task_type, campaign_id, params):
        """Queue task for executor"""
        task = {
            'id': secrets.token_hex(16),
            'type': task_type,
            'campaign_id': campaign_id,
            'params': params,
            'created_at': datetime.utcnow(),
            'status': 'PENDING'
        }
        await self.db.create_scheduled_action(task)
```

## 8. UI Architecture (vv.py)

### View Hierarchy
```
CyberTUI (Main Application)
├── LoginView / RegisterView
├── CampaignView (Primary - Ctrl+2)
├── SituationalAwarenessView (Ctrl+1)
├── MitreIntelligenceView (Ctrl+3)
├── FileManagerView (Ctrl+4)
├── TaskOrchestratorView (Ctrl+5)
├── SecurityHardeningView (Ctrl+6)
├── ApprovalQueueView (Phase 2)
├── AnomalyDetectionView (Phase 2)
├── ReportGeneratorView (Phase 2)
├── CollaborationView (Phase 2)
├── IntegrationView (Phase 2)
├── AuditTrailView (Phase 2)
├── DataClassificationView (Phase 2)
├── TeamManagementView (Phase 2)
└── ComplianceReportView (Phase 2)
```

### 30+ Keybindings
```python
BINDINGS = [
    # Navigation
    ("ctrl+1", "show_view('situational')", "Situational Awareness"),
    ("ctrl+2", "show_view('campaign')", "Campaign Management"),
    ("ctrl+3", "show_view('mitre')", "MITRE Intelligence"),
    ("ctrl+4", "show_view('file_manager')", "File Manager"),
    ("ctrl+5", "show_view('task_orchestrator')", "Task Orchestrator"),
    ("ctrl+6", "show_view('security')", "Security Hardening"),
    
    # Campaign Operations
    ("ctrl+k", "init_campaign()", "New Campaign"),
    ("ctrl+shift+k", "switch_campaign()", "Switch Campaign"),
    ("ctrl+shift+s", "change_status()", "Change Status"),
    
    # Finding Management
    ("ctrl+e", "edit_finding()", "Edit Finding"),
    ("ctrl+s", "save()", "Save"),
    ("ctrl+shift+a", "submit_approval()", "Submit for Approval"),
    ("ctrl+shift+r", "approve_reject()", "Approve/Reject"),
    
    # Advanced (30+ total)
    ("ctrl+shift+g", "generate_report()", "Generate Report"),
    ("ctrl+l", "logout()", "Logout"),
    # ... 15+ more
]
```

## 9. RBAC & Authorization

### Role Model
```python
class Role(Enum):
    VIEWER = 0       # Read-only access
    OPERATOR = 1     # Create findings
    LEAD = 2         # Approve, manage team
    ADMIN = 3        # System admin

def role_gte(user_role: Role, minimum_role: Role) -> bool:
    """Check if user meets minimum role requirement"""
    return user_role.value >= minimum_role.value

# Usage:
if role_gte(user.role, Role.LEAD):
    allow_delete_finding()
```

### Permission Matrix

| Operation | VIEWER | OPERATOR | LEAD | ADMIN |
|-----------|--------|----------|------|-------|
| View findings | ✅ | ✅ | ✅ | ✅ |
| Create finding | ❌ | ✅ | ✅ | ✅ |
| Approve finding | ❌ | ❌ | ✅ | ✅ |
| Delete finding | ❌ | ❌ | ✅ | ✅ |
| Generate report | ❌ | ❌ | ✅ | ✅ |
| Manage users | ❌ | ❌ | ❌ | ✅ |
| View audit logs | ❌ | ❌ | ❌ | ✅ |
| Manage policies | ❌ | ❌ | ❌ | ✅ |

## 10. Error Handling & Recovery

### Database Transactions
```python
def update_campaign_status(campaign_id, new_status):
    """Atomic multi-step operation"""
    with self.db.transaction():  # Context manager
        campaign = self.db.get_campaign(campaign_id)
        campaign.status = new_status
        campaign.updated_at = datetime.utcnow()
        self.db.update_campaign(campaign)
        self.db.log_activity(
            campaign_id,
            operator_id,
            f"Status changed: {campaign.status}",
            hmac_sign=True
        )
    # All or nothing: if error, automatic rollback
```

### Error Recovery Patterns
- **Database Locked:** Retry with exponential backoff
- **Encryption Failure:** Log to system, show user message, halt operation
- **File I/O Error:** Use FileSystemService methods (atomic_write guarantees)
- **Network Error (Webhooks):** Queue for retry in webhook_deliveries table

## 11. Deployment & Scalability

### Single-Machine Deployment
- SQLite3 on local disk (sufficient for 100,000+ findings)
- Python 3.10+ with Textual TUI
- No external dependencies (air-gap capable)

### Data Growth Estimates
| Metric | Size | Notes |
|--------|------|-------|
| Empty DB | 100 KB | Schema only |
| 100 findings | 500 KB | + evidence files |
| 1000 findings | 5 MB | Small campaign |
| 10,000 findings | 50 MB | Large campaign |

### Backup Strategy
```bash
# Daily backup (before operations)
tar czf vectorvue-backup-$(date +%Y%m%d).tar.gz \
    vectorvue.db adversary.db vectorvue.salt

# Restore
tar xzf vectorvue-backup-YYYYMMDD.tar.gz
```

## 12. Security Considerations

### Threat Model
- **Attacker Goal:** Exfiltrate encrypted findings, credentials, evidence
- **Assumption:** Disk access possible (physical security not assumed)
- **Mitigation:** AES-256 encryption at rest, HMAC integrity checks, secure deletion

### Cryptographic Assurance
- All sensitive fields encrypted before disk write
- Salt unique per deployment (in vectorvue.salt)
- PBKDF2 with 480k iterations slows brute-force attacks
- HMAC prevents tampering detection bypass

### Operational Security
- Client Safe Mode redacts sensitive details
- Sensitive Asset flagging prevents accidental disclosure
- Approval workflow ensures quality control
- Audit logging tracks all actions with operator attribution
- Retention policies auto-purge old data per compliance

---

**VectorVue v3.4** | Phase 2/8 Complete | Enterprise Architecture | Production Ready
