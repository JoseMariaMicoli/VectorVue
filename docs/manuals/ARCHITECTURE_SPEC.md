# VectorVue v3.7 Architecture Specification

![Version](https://img.shields.io/badge/Version-v3.7-39FF14) ![Phase](https://img.shields.io/badge/Phase-5/8_Complete-00FFFF) ![Tables](https://img.shields.io/badge/Database-72_Tables-FF00FF)

Complete technical architecture for VectorVue v3.7 - Red Team Campaign Management Platform. This specification details database schema, cryptography, background task execution, and system design patterns.

---

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         VectorVue v3.7                          │
│                    Red Team Campaign Manager                    │
└─────────────────────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────────────────────┐
│                    Textual TUI Framework                        │
│  (Terminal UI with 256-color + TrueColor support, UTF-8)       │
│                                                                 │
│  ├─ LoginView (Authentication)                                 │
│  ├─ RegisterView (User creation)                               │
│  ├─ CampaignView (Campaign + asset mgmt)                       │
│  ├─ FileManagerView (File CRUD)                                │
│  ├─ MitreIntelligenceView (T-number lookup)                    │
│  ├─ ThreatIntelligenceView (Phase 5: feeds, actors, IoCs)      │
│  ├─ ReportingView (Phase 3: evidence + export)                 │
│  ├─ TeamManagementView (Phase 4: multi-team coordination)      │
│  └─ [12+ additional views]                                     │
└─────────────────────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────────────────────┐
│                   SessionCrypto Layer                           │
│  AES-256-GCM encryption + PBKDF2 (480k iterations)             │
│  HMAC signing on all database rows                             │
│                                                                 │
│  ├─ derive_key(password) → 32-byte encryption key              │
│  ├─ encrypt(plaintext) → AES-256-GCM ciphertext                │
│  ├─ decrypt(ciphertext) → plaintext                            │
│  └─ sign(row_data) → HMAC-SHA256 signature                     │
└─────────────────────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────────────────────┐
│               Database Orchestration Layer                      │
│  SQLite with 72 tables across 5 operational phases              │
│                                                                 │
│  ├─ vectorvue.db: Main operational database                    │
│  ├─ vectorvue.salt: 256-bit PBKDF2 salt (persisted)            │
│  └─ Transactions: Multi-step operations wrapped in context mgr │
└─────────────────────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────────────────────┐
│                 Background Task Executor                        │
│  Async worker (separate thread) running after login             │
│                                                                 │
│  ├─ Task Scheduler (30-sec intervals)                          │
│  ├─ Webhook Delivery (async HTTP POST)                         │
│  ├─ Session Timeout (120-min inactivity)                       │
│  ├─ Retention Purge (delete old records)                       │
│  └─ Anomaly Detection (operator behavior analysis)             │
└─────────────────────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────────────────────┐
│                  File System Abstraction                        │
│  Safe atomic I/O with crash-proof writes                       │
│                                                                 │
│  ├─ atomic_write(path, content) → Temp + fsync + replace      │
│  ├─ secure_wipe(path) → Multi-pass overwrite                  │
│  ├─ calculate_file_hash(path) → SHA256 for integrity           │
│  └─ ingest_c2_log(path) → Parse logs to markdown               │
└─────────────────────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────────────────────┐
│              Theme & Color Management                           │
│  Centralized CSS injection with Phosphor Cyberpunk palette      │
│                                                                 │
│  ├─ Phosphor Green: #39FF14 (accent, highlights)               │
│  ├─ Electric Cyan: #00FFFF (active, selection)                 │
│  ├─ Red Alert: #FF0000 (errors, critical)                      │
│  └─ Amber Warning: #FFAA00 (warnings, cautions)                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Database Schema (72 Tables)

### Phase 0-1: Foundation & Authentication (12 Tables)

#### users
Primary user account table with role assignment.

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,          -- Argon2 hash
    email TEXT UNIQUE,
    role INTEGER DEFAULT 0,               -- 0=VIEWER, 1=OPERATOR, 2=LEAD, 3=ADMIN
    status TEXT DEFAULT 'active',         -- active, suspended, inactive
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    login_count INTEGER DEFAULT 0,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    force_password_change BOOLEAN DEFAULT 0,
    hmac_signature TEXT,                  -- HMAC-SHA256 for integrity
    is_deleted BOOLEAN DEFAULT 0
);
```

#### user_roles
Definition of available roles and their capabilities.

```sql
CREATE TABLE user_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name TEXT UNIQUE NOT NULL,       -- VIEWER, OPERATOR, LEAD, ADMIN
    role_level INTEGER NOT NULL,          -- 0, 1, 2, 3
    description TEXT,
    can_create_findings BOOLEAN,
    can_approve_findings BOOLEAN,
    can_delete_campaigns BOOLEAN,
    can_manage_teams BOOLEAN,
    can_manage_users BOOLEAN,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### user_preferences
Per-user UI settings and preferences.

```sql
CREATE TABLE user_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    theme TEXT DEFAULT 'phosphor',        -- phosphor, classic, dark
    default_view TEXT DEFAULT 'editor',   -- editor, dashboard, campaign
    auto_save BOOLEAN DEFAULT 1,
    vim_mode BOOLEAN DEFAULT 1,
    notifications_enabled BOOLEAN DEFAULT 1,
    color_scheme TEXT,                    -- json: {alert_color, ok_color}
    preferred_report_format TEXT,         -- pdf, html, markdown
    preferred_export_dir TEXT,            -- /path/to/05-Delivery/
    timezone TEXT DEFAULT 'UTC',
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

#### sessions
Active user sessions with timeout tracking.

```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,   -- encrypted token
    ip_address TEXT,
    user_agent TEXT,
    login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_activity DATETIME,
    expires_at DATETIME,
    is_active BOOLEAN DEFAULT 1,
    mfa_verified BOOLEAN DEFAULT 0,
    hmac_signature TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(user_id, is_active)            -- One active session per user
);
```

#### campaigns
Top-level engagement context.

```sql
CREATE TABLE campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    client TEXT,
    operator_team TEXT,
    start_date DATE,
    end_date DATE,
    rules_of_engagement TEXT,             -- Operational constraints
    objective TEXT,                       -- Campaign goal
    status TEXT DEFAULT 'planning',       -- planning, active, paused, concluded
    classification TEXT,                  -- UNCLASSIFIED, CONFIDENTIAL, SECRET
    budget_usd DECIMAL(10,2),
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME,
    is_deleted BOOLEAN DEFAULT 0,
    hmac_signature TEXT,
    FOREIGN KEY (created_by) REFERENCES users(id)
);
```

#### campaign_participants
Users assigned to specific campaigns (Phase 4).

```sql
CREATE TABLE campaign_participants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role_in_campaign TEXT,                -- operator, lead, observer
    assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    assigned_by INTEGER,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (assigned_by) REFERENCES users(id),
    UNIQUE(campaign_id, user_id)
);
```

#### campaign_audit_log
Audit trail for campaign-level changes.

```sql
CREATE TABLE campaign_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    action TEXT,                          -- created, updated, deleted, status_changed
    actor_id INTEGER,
    old_value TEXT,                       -- JSON: {field: old_value}
    new_value TEXT,                       -- JSON: {field: new_value}
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (actor_id) REFERENCES users(id)
);
```

#### roles
Master role definitions (separate from user_roles for flexibility).

```sql
CREATE TABLE roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_name TEXT UNIQUE NOT NULL,
    role_level INTEGER NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### permissions
Granular permission definitions.

```sql
CREATE TABLE permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    permission_name TEXT UNIQUE NOT NULL, -- create_finding, approve_finding, etc.
    description TEXT,
    category TEXT,                        -- finding, campaign, team, user, report
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### role_permissions
Many-to-many mapping of roles to permissions.

```sql
CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);
```

#### system_settings
Global configuration for VectorVue instance.

```sql
CREATE TABLE system_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key TEXT UNIQUE NOT NULL,
    setting_value TEXT,                   -- JSON for complex values
    data_type TEXT,                       -- string, int, boolean, json
    description TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER,
    FOREIGN KEY (updated_by) REFERENCES users(id)
);
```

#### audit_log
Master audit trail for all database modifications.

```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT,
    operation TEXT,                       -- INSERT, UPDATE, DELETE
    record_id INTEGER,
    actor_id INTEGER,
    action_description TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    campaign_id INTEGER,
    FOREIGN KEY (actor_id) REFERENCES users(id),
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);
```

---

### Phase 2: Operational Intelligence (15 Tables)

#### findings
Primary table for vulnerability/misconfiguration findings.

```sql
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,                     -- Markdown content
    severity TEXT,                        -- CRITICAL, HIGH, MEDIUM, LOW
    cvss_score DECIMAL(3,1),              -- 0.0 - 10.0
    cvss_vector TEXT,                     -- CVSS:3.1/AV:N/AC:L/...
    mitre_tactic TEXT,                    -- Reconnaissance, Initial Access, etc.
    mitre_technique TEXT,                 -- T1110, T1566, etc.
    mitre_subtechnique TEXT,              -- T1110.001, etc.
    status TEXT DEFAULT 'created',        -- created, reviewed, approved, exported, archived
    remediation TEXT,
    approval_status TEXT,                 -- pending, approved, rejected
    approved_by INTEGER,
    approved_at DATETIME,
    created_by INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER,
    updated_at DATETIME,
    is_deleted BOOLEAN DEFAULT 0,
    hmac_signature TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (approved_by) REFERENCES users(id),
    INDEX idx_campaign_severity (campaign_id, severity)
);
```

#### assets
Targets within campaigns (hosts, networks, services, accounts).

```sql
CREATE TABLE assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    name TEXT NOT NULL,                   -- 192.168.1.10 or hostname
    asset_type TEXT,                      -- host, network, service, account, database
    os TEXT,                              -- Windows 10, Ubuntu 20.04, etc.
    os_version TEXT,
    criticality TEXT,                     -- LOW, MEDIUM, HIGH, CRITICAL
    sensitivity_tags TEXT,                -- JSON: [prod, finance, healthcare]
    owner TEXT,
    status TEXT DEFAULT 'discovered',     -- discovered, targeting, compromised, remediated
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER,
    is_deleted BOOLEAN DEFAULT 0,
    hmac_signature TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    UNIQUE(campaign_id, name)
);
```

#### credentials
Harvested credentials (encrypted at rest).

```sql
CREATE TABLE credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    credential_type TEXT,                 -- password, hash, token, ssh_key, mfa_bypass
    username TEXT,                        -- Not encrypted (needed for audit)
    secret TEXT,                          -- AES-256-GCM encrypted
    source TEXT,                          -- T1110, T1566, phishing, dump_file, etc.
    strength TEXT,                        -- weak, normal, strong (entropy)
    harvested_at DATETIME,
    status TEXT DEFAULT 'active',         -- active, expired, rotated, invalidated
    created_by INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN DEFAULT 0,
    hmac_signature TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    INDEX idx_campaign_type (campaign_id, credential_type)
);
```

#### asset_credentials
Association between assets and credentials (access tracking).

```sql
CREATE TABLE asset_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    credential_id INTEGER NOT NULL,
    access_level TEXT,                    -- guest, user, admin, system
    access_type TEXT,                     -- local, domain, service
    linked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    linked_by INTEGER,
    FOREIGN KEY (asset_id) REFERENCES assets(id),
    FOREIGN KEY (credential_id) REFERENCES credentials(id),
    FOREIGN KEY (linked_by) REFERENCES users(id),
    UNIQUE(asset_id, credential_id)
);
```

#### commands
Executed commands during engagement (Phase 2a).

```sql
CREATE TABLE commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    session_id INTEGER,
    command_text TEXT NOT NULL,           -- `whoami`, `cat /etc/passwd`, etc.
    executed_on_asset INTEGER,            -- Asset ID where command executed
    executing_user TEXT,                  -- DOMAIN\username
    execution_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    exit_code INTEGER,
    status TEXT DEFAULT 'success',        -- success, failed, timeout
    duration_seconds DECIMAL(5,2),
    mitre_technique TEXT,                 -- T1033, T1087, etc.
    created_by INTEGER,
    is_deleted BOOLEAN DEFAULT 0,
    hmac_signature TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (session_id) REFERENCES sessions(id),
    FOREIGN KEY (executed_on_asset) REFERENCES assets(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);
```

#### command_output
Output from executed commands.

```sql
CREATE TABLE command_output (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id INTEGER NOT NULL,
    stdout TEXT,                          -- Command output
    stderr TEXT,                          -- Error output (if any)
    stored_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_redacted BOOLEAN DEFAULT 0,        -- Credentials redacted?
    FOREIGN KEY (command_id) REFERENCES commands(id)
);
```

#### command_artifacts
Files/artifacts resulting from command execution.

```sql
CREATE TABLE command_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id INTEGER NOT NULL,
    artifact_name TEXT,                   -- e.g., "SAM_dump.hive"
    artifact_hash TEXT,                   -- SHA256
    artifact_size_bytes INTEGER,
    storage_path TEXT,                    -- Where artifact stored
    mitre_technique TEXT,                 -- T1005, T1113, etc.
    FOREIGN KEY (command_id) REFERENCES commands(id)
);
```

#### sessions (Operational)
Reverse shells, meterpreter sessions, etc.

```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    session_type TEXT,                    -- meterpreter, reverse_shell, ssh, winrm
    target_asset INTEGER,
    target_ip TEXT,
    target_port INTEGER,
    executing_user TEXT,
    callback_ip TEXT,                     -- Attacker C2 IP
    callback_port INTEGER,
    opened_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_activity DATETIME,
    status TEXT DEFAULT 'active',         -- active, idle, dead, ended
    duration_minutes INTEGER,
    commands_executed INTEGER DEFAULT 0,
    created_by INTEGER,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (target_asset) REFERENCES assets(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);
```

#### persistence_mechanisms
Installed backdoors and persistence methods (Phase 2b).

```sql
CREATE TABLE persistence_mechanisms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    persistence_type TEXT,                -- registry_key, scheduled_task, cron_job, service, webshell, ssh_key, sudo_rule
    target_asset INTEGER NOT NULL,
    method_text TEXT,                     -- e.g., "HKLM\...\Run" or "/etc/cron.d/job"
    installation_method TEXT,             -- T-number, manual description
    installed_at DATETIME,
    status TEXT DEFAULT 'active',         -- active, disabled, detected, removed
    description TEXT,
    recovery TEXT,                        -- How to remove
    installed_by INTEGER,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (target_asset) REFERENCES assets(id),
    FOREIGN KEY (installed_by) REFERENCES users(id)
);
```

#### detections
Defensive detections during engagement (Phase 2b).

```sql
CREATE TABLE detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    detection_type TEXT,                  -- antivirus, ids, edr, siem, manual
    detector_product TEXT,                -- AVG, Defender, Snort, Splunk, etc.
    alert_id TEXT,                        -- From defensive system
    detected_at DATETIME,
    triggered_by TEXT,                    -- Description of what triggered alert
    mitre_technique TEXT,                 -- T1547, T1566, etc.
    severity TEXT,                        -- From defensive system
    detector_response TEXT,               -- What did defender do?
    operator_response TEXT,               -- How did attacker respond?
    detected_by INTEGER,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (detected_by) REFERENCES users(id)
);
```

#### objectives
Campaign objectives and progress tracking (Phase 2b).

```sql
CREATE TABLE objectives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    objective_text TEXT NOT NULL,         -- What needs to be achieved?
    evidence_required TEXT,               -- What proof is needed?
    priority TEXT,                        -- HIGH, MEDIUM, LOW
    status TEXT DEFAULT 'not_started',    -- not_started, in_progress, achieved, failed
    completion_percent INTEGER DEFAULT 0, -- 0-100
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    achieved_at DATETIME,
    achieved_by INTEGER,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (achieved_by) REFERENCES users(id)
);
```

#### campaign_metrics
Real-time metrics aggregated from findings/assets/credentials.

```sql
CREATE TABLE campaign_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL UNIQUE,
    total_findings INTEGER DEFAULT 0,
    critical_findings INTEGER DEFAULT 0,
    high_findings INTEGER DEFAULT 0,
    medium_findings INTEGER DEFAULT 0,
    low_findings INTEGER DEFAULT 0,
    total_assets INTEGER DEFAULT 0,
    compromised_assets INTEGER DEFAULT 0,
    total_credentials INTEGER DEFAULT 0,
    active_sessions INTEGER DEFAULT 0,
    persistence_count INTEGER DEFAULT 0,
    risk_score DECIMAL(3,1),              -- 0.0-10.0
    coverage_percent DECIMAL(5,2),        -- % of assets compromised
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);
```

#### finding_approvals
Approval workflow for findings (Phase 2).

```sql
CREATE TABLE finding_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    requested_by INTEGER,                 -- OPERATOR requesting approval
    approved_by INTEGER,                  -- LEAD+ approving
    status TEXT DEFAULT 'pending',        -- pending, approved, rejected
    rejection_reason TEXT,
    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    approved_at DATETIME,
    FOREIGN KEY (finding_id) REFERENCES findings(id),
    FOREIGN KEY (requested_by) REFERENCES users(id),
    FOREIGN KEY (approved_by) REFERENCES users(id)
);
```

#### activity_log
General activity log for user actions.

```sql
CREATE TABLE activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER,
    user_id INTEGER,
    action TEXT,                          -- finding_created, finding_approved, credential_harvested, etc.
    action_detail TEXT,                   -- JSON: {finding_id: 123, severity: HIGH}
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

#### scheduled_tasks
Tasks scheduled for background execution (Phase 2c).

```sql
CREATE TABLE scheduled_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_name TEXT NOT NULL,
    task_type TEXT,                       -- webhook, retention_purge, report_generate, anomaly_check
    campaign_id INTEGER,
    schedule TEXT,                        -- "0 2 * * *" cron format, or "one-time"
    next_run DATETIME,
    last_run DATETIME,
    last_result TEXT,                     -- success, failed
    error_message TEXT,
    is_enabled BOOLEAN DEFAULT 1,
    created_by INTEGER,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);
```

#### webhook_deliveries
Log of webhook payloads sent to external systems.

```sql
CREATE TABLE webhook_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER,
    webhook_url TEXT,
    trigger_event TEXT,                   -- finding.created, finding.approved, etc.
    payload TEXT,                         -- JSON
    http_status INTEGER,                  -- 200, 500, timeout, etc.
    response_body TEXT,
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    retry_count INTEGER DEFAULT 0,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);
```

---

### Phase 3: Reporting & Evidence Chain of Custody (8 Tables)

#### reports
Generated reports for delivery to client/stakeholders.

```sql
CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    report_type TEXT,                     -- technical, executive, compliance
    report_format TEXT,                   -- pdf, html, markdown
    title TEXT,
    executive_summary TEXT,
    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    generated_by INTEGER NOT NULL,
    approved_by INTEGER,                  -- LEAD+ approval before delivery
    approved_at DATETIME,
    file_path TEXT,                       -- Path to generated file
    file_hash TEXT,                       -- SHA256 of final report
    classification TEXT,                  -- UNCLASSIFIED, CONFIDENTIAL, SECRET
    is_delivered BOOLEAN DEFAULT 0,
    delivered_to TEXT,                    -- Client email
    delivered_at DATETIME,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (generated_by) REFERENCES users(id),
    FOREIGN KEY (approved_by) REFERENCES users(id)
);
```

#### report_sections
Sections within a report.

```sql
CREATE TABLE report_sections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    section_name TEXT,                    -- Executive Summary, Findings, Recommendations
    section_order INTEGER,
    content TEXT,
    page_number INTEGER,
    FOREIGN KEY (report_id) REFERENCES reports(id)
);
```

#### evidence_items
Individual evidence items collected during engagement (immutable).

```sql
CREATE TABLE evidence_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    collection_method TEXT,               -- T-number or custom method
    who_collected INTEGER NOT NULL,       -- User ID
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_host INTEGER,                  -- Asset ID
    file_hash TEXT,                       -- SHA256 (immutable proof)
    file_size_bytes INTEGER,
    classification TEXT,                  -- UNCLASSIFIED, CONFIDENTIAL, SECRET
    status TEXT DEFAULT 'collected',      -- collected, verified, approved, reported
    approved_by INTEGER,
    approved_at DATETIME,
    is_immutable BOOLEAN DEFAULT 1,       -- Cannot be edited after creation
    storage_location TEXT,                -- Where file stored (05-Delivery/)
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (who_collected) REFERENCES users(id),
    FOREIGN KEY (source_host) REFERENCES assets(id),
    FOREIGN KEY (approved_by) REFERENCES users(id)
);
```

#### evidence_artifacts
Files attached to evidence items.

```sql
CREATE TABLE evidence_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL,
    artifact_file_path TEXT,
    artifact_hash TEXT,                   -- SHA256
    artifact_size_bytes INTEGER,
    artifact_type TEXT,                   -- screenshot, memory_dump, registry_dump, etc.
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (evidence_id) REFERENCES evidence_items(id)
);
```

#### evidence_manifest
Summary of all evidence collected for a campaign.

```sql
CREATE TABLE evidence_manifest (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL UNIQUE,
    total_items INTEGER,
    total_size_bytes BIGINT,
    manifest_hash TEXT,                   -- Hash of manifest file
    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    generated_by INTEGER,
    manifest_file_path TEXT,              -- Path to manifest.txt
    is_verified BOOLEAN DEFAULT 0,
    verified_by INTEGER,
    verified_at DATETIME,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (generated_by) REFERENCES users(id),
    FOREIGN KEY (verified_by) REFERENCES users(id)
);
```

#### campaign_reports
Legacy: Association between campaigns and generated reports.

```sql
CREATE TABLE campaign_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    report_id INTEGER NOT NULL,
    PRIMARY KEY (campaign_id, report_id),
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (report_id) REFERENCES reports(id)
);
```

#### evidence_chains
Chain of custody tracking (who handled evidence, when, for what).

```sql
CREATE TABLE evidence_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL,
    handler_id INTEGER,                   -- User who handled evidence
    action TEXT,                          -- collected, verified, approved, exported
    action_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    notes TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence_items(id),
    FOREIGN KEY (handler_id) REFERENCES users(id)
);
```

#### compliance_mappings
Evidence mapped to compliance frameworks (PCI, HIPAA, SOC2, etc.).

```sql
CREATE TABLE compliance_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    framework TEXT,                       -- PCI-DSS, HIPAA, SOC2, GDPR, etc.
    control_id TEXT,                      -- PCI 1.1, HIPAA 164.308, etc.
    control_name TEXT,
    remediation_sla_days INTEGER,
    status TEXT,                          -- compliant, non_compliant, remediated
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);
```

---

### Phase 4: Team Federation & Coordination (16 Tables)

#### teams
Team definitions for multi-operator coordination.

```sql
CREATE TABLE teams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_name TEXT UNIQUE NOT NULL,
    description TEXT,
    budget_usd DECIMAL(10,2),
    team_lead INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active',         -- active, on_hold, disbanded
    color_tag TEXT,                       -- For UI organization
    FOREIGN KEY (team_lead) REFERENCES users(id)
);
```

#### team_members
Users assigned to teams.

```sql
CREATE TABLE team_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    team_role TEXT,                       -- team_member, team_lead, team_observer
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    joined_by INTEGER,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY (team_id) REFERENCES teams(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (joined_by) REFERENCES users(id),
    UNIQUE(team_id, user_id)
);
```

#### team_roles
Roles within a team (different from global roles).

```sql
CREATE TABLE team_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    role_name TEXT,                       -- team_member, team_lead, observer
    description TEXT,
    can_edit_findings BOOLEAN,
    can_approve_findings BOOLEAN,
    FOREIGN KEY (team_id) REFERENCES teams(id),
    UNIQUE(team_id, role_name)
);
```

#### team_permissions
Permissions assigned to team roles.

```sql
CREATE TABLE team_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_role_id INTEGER NOT NULL,
    permission TEXT,                      -- view_findings, edit_findings, etc.
    FOREIGN KEY (team_role_id) REFERENCES team_roles(id)
);
```

#### campaign_team_assignments
Campaigns assigned to teams.

```sql
CREATE TABLE campaign_team_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    team_id INTEGER NOT NULL,
    assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    assigned_by INTEGER,
    PRIMARY KEY (campaign_id, team_id),
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (team_id) REFERENCES teams(id),
    FOREIGN KEY (assigned_by) REFERENCES users(id)
);
```

#### data_sharing_policies
Policies controlling what team members can see/do.

```sql
CREATE TABLE data_sharing_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    policy_name TEXT,
    applies_to_role TEXT,                 -- team_member, team_lead, etc.
    can_view_findings BOOLEAN DEFAULT 1,
    can_view_credentials BOOLEAN DEFAULT 0,
    can_view_evidence BOOLEAN DEFAULT 1,
    can_export_data BOOLEAN DEFAULT 0,
    can_delete_findings BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES teams(id)
);
```

#### team_metrics
Performance metrics for teams.

```sql
CREATE TABLE team_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL UNIQUE,
    total_campaigns INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    findings_approved_ratio DECIMAL(3,2), -- 0.0-1.0
    average_finding_severity TEXT,
    total_credentials_harvested INTEGER DEFAULT 0,
    total_assets_compromised INTEGER DEFAULT 0,
    team_risk_score DECIMAL(3,1),
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES teams(id)
);
```

#### operator_performance
Per-operator metrics tracked across campaigns.

```sql
CREATE TABLE operator_performance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    team_id INTEGER,
    total_findings INTEGER DEFAULT 0,
    findings_approved_count INTEGER DEFAULT 0,
    findings_rejected_count INTEGER DEFAULT 0,
    average_finding_severity TEXT,
    total_commands_executed INTEGER DEFAULT 0,
    total_sessions_opened INTEGER DEFAULT 0,
    total_credentials_harvested INTEGER DEFAULT 0,
    campaigns_participated INTEGER DEFAULT 0,
    quality_score DECIMAL(3,2),           -- 0.0-1.0 based on approval ratio
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (team_id) REFERENCES teams(id)
);
```

#### team_intelligence_pools
Shared pools of findings/IoCs within teams (Phase 4).

```sql
CREATE TABLE team_intelligence_pools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    pool_name TEXT NOT NULL,
    description TEXT,
    pool_type TEXT,                       -- findings, credentials, iocs, techniques
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY (team_id) REFERENCES teams(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);
```

#### coordination_logs
Log of team coordination events.

```sql
CREATE TABLE coordination_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    event_type TEXT,                      -- member_joined, approval_requested, finding_shared
    actor_id INTEGER,
    event_detail TEXT,                    -- JSON
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES teams(id),
    FOREIGN KEY (actor_id) REFERENCES users(id)
);
```

#### team_approvals
Team-level approval workflow (Phase 4).

```sql
CREATE TABLE team_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    team_id INTEGER NOT NULL,
    requested_by INTEGER,
    approved_by INTEGER,
    status TEXT DEFAULT 'pending',        -- pending, approved, rejected
    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    approved_at DATETIME,
    FOREIGN KEY (finding_id) REFERENCES findings(id),
    FOREIGN KEY (team_id) REFERENCES teams(id),
    FOREIGN KEY (requested_by) REFERENCES users(id),
    FOREIGN KEY (approved_by) REFERENCES users(id)
);
```

#### team_audit_log
Audit trail for team-level changes.

```sql
CREATE TABLE team_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    action TEXT,
    actor_id INTEGER,
    action_detail TEXT,                   -- JSON
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES teams(id),
    FOREIGN KEY (actor_id) REFERENCES users(id)
);
```

#### intelligence_pool_findings
Association between intelligence pools and findings.

```sql
CREATE TABLE intelligence_pool_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pool_id INTEGER NOT NULL,
    finding_id INTEGER NOT NULL,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    added_by INTEGER,
    PRIMARY KEY (pool_id, finding_id),
    FOREIGN KEY (pool_id) REFERENCES team_intelligence_pools(id),
    FOREIGN KEY (finding_id) REFERENCES findings(id),
    FOREIGN KEY (added_by) REFERENCES users(id)
);
```

#### team_notifications
Notifications within team coordination.

```sql
CREATE TABLE team_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    recipient_id INTEGER,                 -- Null = broadcast to all
    notification_type TEXT,               -- finding_created, approval_needed, etc.
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    read_at DATETIME,
    FOREIGN KEY (team_id) REFERENCES teams(id),
    FOREIGN KEY (recipient_id) REFERENCES users(id)
);
```

#### capability_assessments
Team capability matrix tracking (Phase 4).

```sql
CREATE TABLE capability_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id INTEGER NOT NULL,
    capability_category TEXT,             -- reconnaissance, exploitation, persistence, etc.
    capability_level TEXT,                -- basic, intermediate, advanced, expert
    evidence_description TEXT,
    assessed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (team_id) REFERENCES teams(id)
);
```

#### remediation_tracking
Track remediation status of findings (Phase 4).

```sql
CREATE TABLE remediation_tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    assigned_to TEXT,                     -- Organization team
    remediation_deadline DATE,
    remediation_status TEXT,              -- assigned, in_progress, completed, deferred
    completion_date DATE,
    remediation_evidence TEXT,            -- Proof of remediation
    verified_by INTEGER,
    verified_at DATETIME,
    FOREIGN KEY (finding_id) REFERENCES findings(id),
    FOREIGN KEY (verified_by) REFERENCES users(id)
);
```

---

### Phase 5: Advanced Threat Intelligence (21 Tables)

#### threat_feeds
External threat intelligence feeds (VirusTotal, Shodan, OTX, MISP).

```sql
CREATE TABLE threat_feeds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_name TEXT UNIQUE NOT NULL,       -- "VirusTotal IP Reputation"
    feed_type TEXT,                       -- virustotal, shodan, otx, misp, custom
    feed_url TEXT,
    api_key TEXT,                         -- AES-256-GCM encrypted
    update_interval_hours INTEGER,        -- How often to refresh
    last_update DATETIME,
    next_update DATETIME,
    is_active BOOLEAN DEFAULT 1,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER,
    FOREIGN KEY (created_by) REFERENCES users(id)
);
```

#### threat_feed_refresh_log
Log of feed refresh operations.

```sql
CREATE TABLE threat_feed_refresh_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_id INTEGER NOT NULL,
    refresh_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT,                          -- success, failed, partial
    records_added INTEGER,
    records_updated INTEGER,
    error_message TEXT,
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(id)
);
```

#### threat_actors
Known threat actor profiles (APT groups, cybercriminal organizations).

```sql
CREATE TABLE threat_actors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_name TEXT UNIQUE NOT NULL,      -- "Lazarus Group"
    aliases TEXT,                         -- JSON: ["APT-C-39", "Hidden Cobra"]
    origin_country TEXT,                  -- "North Korea"
    organization TEXT,                    -- "RGB, DPRK"
    founded_year INTEGER,
    known_targets TEXT,                   -- JSON: ["Financial", "Cryptocurrency"]
    confidence_score DECIMAL(3,2),        -- 0.0-1.0
    description TEXT,
    public_references TEXT,               -- JSON: URLs
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER,
    FOREIGN KEY (created_by) REFERENCES users(id)
);
```

#### actor_aliases
Aliases for threat actors.

```sql
CREATE TABLE actor_aliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER NOT NULL,
    alias_name TEXT,
    source TEXT,                          -- Where alias came from (feed, researcher, etc.)
    FOREIGN KEY (actor_id) REFERENCES threat_actors(id),
    UNIQUE(actor_id, alias_name)
);
```

#### actor_ttps
Tactics, Techniques & Procedures used by threat actors.

```sql
CREATE TABLE actor_ttps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER NOT NULL,
    mitre_technique TEXT NOT NULL,        -- T1110, T1566, etc.
    how_used TEXT,                        -- Narrative of technique usage
    tools_used TEXT,                      -- JSON: ["PsExec", "Mimikatz"]
    first_observed DATETIME,
    last_observed DATETIME,
    confidence_score DECIMAL(3,2),        -- 0.0-1.0
    FOREIGN KEY (actor_id) REFERENCES threat_actors(id),
    UNIQUE(actor_id, mitre_technique)
);
```

#### indicators_of_compromise
IoCs: IPs, domains, hashes, emails, URLs (Phase 5).

```sql
CREATE TABLE indicators_of_compromise (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER,
    indicator_type TEXT,                  -- ipv4, ipv6, domain, file_hash, email, url
    indicator_value TEXT NOT NULL,        -- 192.168.1.100, malware.com, a1b2c3d4...
    threat_level TEXT,                    -- low, medium, high, critical
    source_feed INTEGER,                  -- Where did this come from? (threat_feeds.id)
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME,
    status TEXT DEFAULT 'active',         -- active, blocked, remediated, false_positive
    found_in_campaign BOOLEAN DEFAULT 0,  -- Was it found in our campaign?
    ioc_hash TEXT,                        -- For deduplication
    created_by INTEGER,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    FOREIGN KEY (source_feed) REFERENCES threat_feeds(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    UNIQUE(indicator_type, indicator_value),
    INDEX idx_indicator (indicator_type, indicator_value)
);
```

#### ioc_enrichment
Enrichment data for IoCs (VirusTotal verdicts, Shodan data, Whois, etc.).

```sql
CREATE TABLE ioc_enrichment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_id INTEGER NOT NULL,
    enrichment_source TEXT,               -- virustotal, shodan, whois, reverse_dns, etc.
    malicious_verdict TEXT,               -- malicious, suspicious, clean, unknown
    malware_families TEXT,                -- JSON: ["Emotet", "Dridex"]
    prevalence TEXT,                      -- How many orgs affected? (low, medium, high)
    last_analysis_date DATETIME,
    enrichment_data TEXT,                 -- JSON: {detailed enrichment}
    FOREIGN KEY (ioc_id) REFERENCES indicators_of_compromise(id)
);
```

#### threat_correlations
Correlations between findings, techniques, actors, and IoCs (Phase 5).

```sql
CREATE TABLE threat_correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type_1 TEXT,                   -- finding, technique, actor, ioc
    entity_id_1 INTEGER,
    entity_type_2 TEXT,
    entity_id_2 INTEGER,
    correlation_strength DECIMAL(3,2),    -- 0.0-1.0
    correlation_reason TEXT,              -- "Same technique T1110", "Both in campaign"
    correlation_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### risk_scores
Automated risk scores for findings (Phase 5).

```sql
CREATE TABLE risk_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL UNIQUE,
    base_cvss DECIMAL(3,1),               -- From CVSS vector
    exploitability_score DECIMAL(3,2),    -- Is public PoC available?
    prevalence_score DECIMAL(3,2),        -- How many orgs affected?
    ioc_count_factor DECIMAL(3,2),        -- Number of IoCs tied to finding
    temporal_score DECIMAL(3,1),          -- Time decay (older = lower)
    final_risk_score DECIMAL(3,1),        -- 0.0-10.0
    risk_level TEXT,                      -- CRITICAL, HIGH, MEDIUM, LOW
    calculated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);
```

#### risk_scoring_rules
Rules used to calculate risk scores (customizable per instance).

```sql
CREATE TABLE risk_scoring_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT UNIQUE NOT NULL,
    rule_description TEXT,
    cvss_weight DECIMAL(3,2),             -- e.g., 0.40 (40% weight)
    exploitability_weight DECIMAL(3,2),
    prevalence_weight DECIMAL(3,2),
    ioc_weight DECIMAL(3,2),
    temporal_weight DECIMAL(3,2),
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME,
    CONSTRAINT weights_sum_to_1 CHECK ((cvss_weight + exploitability_weight + prevalence_weight + ioc_weight + temporal_weight) = 1.0)
);
```

#### enrichment_data
Cache of enrichment data (to avoid re-querying threat feeds repeatedly).

```sql
CREATE TABLE enrichment_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data_type TEXT,                       -- virustotal_verdict, shodan_result, whois_record
    data_key TEXT,                        -- What was queried (IP, domain, hash)
    data_value TEXT,                      -- JSON result
    fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,                  -- When should this cache entry expire?
    UNIQUE(data_type, data_key)
);
```

#### threat_intelligence_archive
Historical threat intelligence records (for trend analysis).

```sql
CREATE TABLE threat_intelligence_archive (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    archive_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    threat_actor_count INTEGER,
    active_ioc_count INTEGER,
    threat_feeds_count INTEGER,
    average_risk_score DECIMAL(3,1),
    high_risk_findings INTEGER,
    critical_risk_findings INTEGER
);
```

#### behavioral_analytics
Operator behavior analysis for anomaly detection (Phase 5).

```sql
CREATE TABLE behavioral_analytics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    campaign_id INTEGER NOT NULL,
    behavior_pattern TEXT,                -- findings_per_hour, credentials_per_day, etc.
    baseline_value DECIMAL(8,2),          -- Historical average
    current_value DECIMAL(8,2),           -- Current measurement
    standard_deviation DECIMAL(8,2),      -- How far from norm?
    anomaly_probability DECIMAL(3,2),     -- 0.0-1.0
    is_anomalous BOOLEAN DEFAULT 0,
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);
```

#### anomaly_rules
Rules for behavioral anomaly detection.

```sql
CREATE TABLE anomaly_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT UNIQUE NOT NULL,
    metric TEXT,                          -- findings_per_hour, credentials_per_day
    threshold_sigma INTEGER,              -- How many std devs = anomaly? (default 3)
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

#### detected_anomalies
Anomalies detected in operator behavior.

```sql
CREATE TABLE detected_anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    campaign_id INTEGER NOT NULL,
    anomaly_type TEXT,                    -- excessive_findings, rapid_credential_harvest
    severity TEXT,                        -- warning, alert, critical
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    alert_sent BOOLEAN DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);
```

#### attack_patterns
Named attack patterns (combining multiple TTPs into known attack chains).

```sql
CREATE TABLE attack_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_name TEXT UNIQUE NOT NULL,    -- "Spear Phishing → C2 Callback → Lateral Movement"
    description TEXT,
    techniques TEXT,                      -- JSON: ["T1566", "T1071", "T1570"]
    threat_actors TEXT,                   -- JSON: [actor_ids]
    first_observed DATETIME,
    is_active BOOLEAN DEFAULT 1
);
```

#### attack_timeline
Chronological timeline of attack progression (Phase 5).

```sql
CREATE TABLE attack_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    event_time DATETIME,
    event_type TEXT,                      -- finding_created, detection, command_executed
    event_detail TEXT,                    -- JSON
    mitre_technique TEXT,
    detected_by_defender BOOLEAN DEFAULT 0,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
);
```

#### technique_coverage
MITRE ATT&CK technique coverage matrix (which techniques discovered per campaign).

```sql
CREATE TABLE technique_coverage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL,
    mitre_tactic TEXT,                    -- Reconnaissance, Initial Access, etc.
    mitre_technique TEXT,                 -- T1110, T1566, etc.
    coverage_count INTEGER DEFAULT 0,     -- How many findings for this technique?
    discovery_date DATETIME,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
    UNIQUE(campaign_id, mitre_technique)
);
```

#### intelligence_sharing
Control who can see which threat intelligence (Phase 5).

```sql
CREATE TABLE intelligence_sharing (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    intelligence_item_type TEXT,          -- threat_actor, ioc, attack_pattern
    intelligence_item_id INTEGER,
    shared_with_team INTEGER,
    shared_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    shared_by INTEGER,
    can_export BOOLEAN DEFAULT 0,         -- Can recipient export this data?
    FOREIGN KEY (shared_with_team) REFERENCES teams(id),
    FOREIGN KEY (shared_by) REFERENCES users(id)
);
```

#### feed_data_cache
Cached data from threat feeds (to reduce API calls).

```sql
CREATE TABLE feed_data_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_id INTEGER NOT NULL,
    cached_data TEXT,                     -- JSON: raw feed data
    cached_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    record_count INTEGER,
    FOREIGN KEY (feed_id) REFERENCES threat_feeds(id)
);
```

---

## Cryptography & Security

### Session Crypto Implementation

**Key Derivation (PBKDF2):**

```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives import hashes

password = "user_password"
salt = b'\x...'  # 32 bytes, stored in vectorvue.salt

kdf = PBKDF2(
    algorithm=hashes.SHA256(),
    length=32,                             # 256 bits
    iterations=480_000,                    # OWASP recommendation 2024
    salt=salt
)

key = kdf.derive(password.encode())        # 32-byte encryption key
```

**Encryption (AES-256-GCM):**

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

plaintext = "sensitive_data"
key = b'\x...'  # From PBKDF2 above (32 bytes)
nonce = os.urandom(12)                     # 96-bit random nonce

cipher = AESGCM(key)
ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)

# Storage: nonce + ciphertext (nonce is not secret)
stored = nonce + ciphertext
```

**Decryption:**

```python
nonce = stored[:12]
ciphertext = stored[12:]

cipher = AESGCM(key)
plaintext = cipher.decrypt(nonce, ciphertext, None).decode()
```

### Integrity Verification (HMAC)

**Signing (database rows):**

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC

row_data = "user=john,role=admin,campaign_id=1"
key = b'\x...'  # Encryption key

hmac = HMAC(key, hashes.SHA256())
hmac.update(row_data.encode())
signature = hmac.finalize()  # 32-byte signature

# Store signature with row in hmac_signature column
```

**Verification:**

```python
hmac = HMAC(key, hashes.SHA256())
hmac.update(row_data.encode())

try:
    hmac.verify(stored_signature)
    # ✓ Row is authentic
except:
    # ✗ Row has been tampered with
```

---

## Background Task Execution (Phase 2c)

VectorVue runs an async task executor after login:

```
┌────────────────────────────────┐
│   Background Task Executor     │
│  (Separate async thread)       │
└────────────────────────────────┘
        ↓ (30-sec interval)
┌────────────────────────────────┐
│ 1. Task Scheduler              │
│    - Check scheduled_tasks     │
│    - Execute if next_run due   │
│    - Update last_run timestamp │
└────────────────────────────────┘
        ↓
┌────────────────────────────────┐
│ 2. Webhook Delivery            │
│    - Query webhook_deliveries  │
│    - POST to external URLs     │
│    - Retry on failure          │
└────────────────────────────────┘
        ↓
┌────────────────────────────────┐
│ 3. Session Timeout             │
│    - Check sessions.last_activity
│    - Expire if > 120 minutes   │
│    - Auto-logout user          │
└────────────────────────────────┘
        ↓
┌────────────────────────────────┐
│ 4. Retention Policy            │
│    - Delete old findings       │
│    - Delete old credentials    │
│    - Delete old sessions       │
│    - Per system_settings       │
└────────────────────────────────┘
        ↓
┌────────────────────────────────┐
│ 5. Anomaly Detection           │
│    - Analyze operator behavior │
│    - Detect unusual patterns   │
│    - Alert on high probability │
└────────────────────────────────┘
```

---

## File System Abstraction (vv_fs.py)

All file I/O goes through `FileSystemService` for safety and auditability.

**Atomic Write Pattern (Crash-Safe):**

```python
import tempfile
import os

def atomic_write(path, content):
    # 1. Write to temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name
    
    # 2. Fsync to ensure on-disk write
    fd = os.open(tmp_path, os.O_RDONLY)
    os.fsync(fd)
    os.close(fd)
    
    # 3. Atomic replace
    os.replace(tmp_path, path)
```

**Secure Wipe (Multi-Pass Overwrite):**

```python
def secure_wipe(path, passes=3):
    size = os.path.getsize(path)
    
    for _ in range(passes):
        with open(path, 'wb') as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    
    os.remove(path)
```

**Hash Verification:**

```python
import hashlib

def calculate_file_hash(path):
    sha256 = hashlib.sha256()
    
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    
    return sha256.hexdigest()
```

---

## Database Transactions

**Pattern for multi-step operations:**

```python
with self.db.transaction():
    # All operations here are in a transaction
    finding = self.db.create_finding(...)
    evidence = self.db.create_evidence(...)
    self.db.link_finding_to_evidence(finding.id, evidence.id)
    
    # If any operation fails, entire transaction rolls back
```

---

**VectorVue v3.7** | Phase 5/8 Complete | 72 Tables | 200+ Methods
