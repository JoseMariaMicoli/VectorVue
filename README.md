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

# VectorVue v3.0-3.4 - Red Team Campaign Management Platform

![Status](https://img.shields.io/badge/Status-Operational-39FF14) ![Version](https://img.shields.io/badge/Version-3.4_Production-00FFFF) ![Build](https://img.shields.io/badge/Build-Enterprise_Grade-grey) ![License](https://img.shields.io/badge/License-Proprietary-FF0000) ![Phase](https://img.shields.io/badge/Phase-2/8_Complete-39FF14)

**VectorVue v3.0-3.4** is an enterprise-grade, terminal-based Red Team Campaign Management Platform engineered for offensive security operators. It transforms raw pentest findings into structured, auditable campaign evidence within a comprehensive operational security framework with advanced features for collaboration, analytics, compliance, and runtime task execution.

Designed for teams that demand precision, VectorVue integrates MITRE ATT&CK® mapping, approval workflows, evidence chain of custody, atomic database operations, multi-operator collaboration, behavioral analytics, real-time task scheduling, webhook delivery, session management, and retention policies—all within a unified, high-performance Text User Interface (TUI).

---

## 📋 VectorVue Evolution: Phase 0 → Phase 2 (Complete)

### ✅ Phase 0: Core Foundation (v3.0 - Initial Release)
**Status: COMPLETE** | Lines Added: 3,675 | Database Tables: 15

**Campaign Management:**
- Campaign isolation and lifecycle management (planning → active → finished → archived)
- Multi-campaign support with seamless switching
- Campaign metadata: client, operator team, rules of engagement, objectives, status

**Multi-User RBAC:**
- 4-level role hierarchy: VIEWER (0) < OPERATOR (1) < LEAD (2) < ADMIN (3)
- Role-based view/edit/delete permissions across all operations
- Session management with secure tokens
- Operator attribution on all audit events

**Evidence Chain of Custody:**
- Immutable evidence_items table with SHA256 integrity
- Evidence collection timestamps with operator tracking
- Collection method documentation (file upload, command output, screenshot, etc.)
- Evidence approval workflow

**Approval Workflow:**
- Finding state machine: pending → approved/rejected
- LEAD+ approval required before evidence export
- Audit trail of all approval decisions
- Rejection reasons and comments

**Activity Timeline & Audit:**
- Detailed activity_log with severity classification
- Operator attribution and timestamps
- Event categorization (CREATE_FINDING, APPROVE_EVIDENCE, DELETE_CAMPAIGN, etc.)
- Legacy audit_log backward compatibility

**Database Foundation:**
- 15 core tables: campaigns, findings, assets, credentials, actions, evidence_items, activity_log, users, groups, sessions, relations, loot, audit_log, approval_history, campaign_metadata
- AES-256 encryption (Fernet) for sensitive fields
- PBKDF2 key derivation (480k iterations)
- Row-level HMAC signing for integrity

**MITRE ATT&CK Integration:**
- Automated technique/tactic lookups from mitre_reference.txt
- Attack path narrative generation (grouped by tactic)
- Tactic/technique counting for campaign coverage matrix
- Visual evidence of attack progression

---

### ✅ Phase 1: Operational Intelligence Layer (v3.1 - Added)
**Status: COMPLETE** | Lines Added: 638 | Database Tables: +8 (Total: 23)

**Situational Awareness:**
- Command execution logging (command_logs table)
- Session tracking with open/close lifecycle
- Detection event recording (detections, alerts, severity)
- Objective progress monitoring

**Persistence Mechanisms:**
- Persistence techniques inventory (type, target, verify_method)
- Backdoor location tracking with hash verification
- Scheduled task persistence logging
- Lateral movement path documentation

**Operational State Tracking:**
- Current session status (active/detected/revived)
- Session backup and recovery mechanisms
- Detection handling with automated alerts
- Objective achievement milestones

**Database Additions:**
- command_logs: Executed commands with input/output
- operational_sessions: Open sessions per asset
- detection_events: Automated alerts triggered
- objectives: Campaign goals with progress
- persistence_mechanisms: Installed backdoors
- scheduled_tasks: Persistence timers
- backup_sessions: Session recovery
- threat_intel_items: Raw intelligence feeds

---

### ✅ Phase 2: Execution & Detection + Runtime Features (v3.2-3.3-3.4 Combined)
**Status: COMPLETE** | Lines Added: 1,678 | Database Tables: +18 (Total: 41) | Background Task Scheduler Added

#### Phase 2a: Execution & Detection (v3.2)
- 5 new tables for command execution logging, session lifecycle, detection tracking, objectives, persistence
- CommandExecutionLogView, SessionActivityView, DetectionTimelineView, ObjectiveProgressView, PersistenceInventoryView
- Keybindings: Ctrl+E, Ctrl+J, Ctrl+D, Ctrl+O, Ctrl+P

#### Phase 2b: Intelligence & Analysis (v3.3)
- 10 new tables for situational awareness, post-engagement analysis, threat intel, remediation, capability assessment
- SituationalAwarenessView, PostEngagementAnalysisView, ThreatIntelligenceView, RemediationTrackingView, CapabilityAssessmentView
- Keybindings: Ctrl+1 through Ctrl+5
- Dashboard with metrics, analysis heatmaps, remediation tracking

#### Phase 2c: Advanced Features & Security + Runtime Execution (v3.4)
- 13 new tables for collaboration, orchestration, analytics, integration, compliance, encryption/TLP, audit immutability, sessions, retention
- CollaborationEngineView, TaskOrchestrationView, BehavioralAnalyticsView, IntegrationGatewayView, ComplianceReportingView, SecurityHardeningView
- Keybindings: Alt+1 through Alt+6
- 30+ button handlers for all v3.4 features
- 4 default retention policies (findings 90d, credentials 180d, audit 365d, detection 30d)
- 4 default compliance frameworks (SOC 2, FedRAMP, ISO 27001, NIST CSF)

**Runtime Task Execution (New in v3.4):**
- **Background Task Scheduler:** `RuntimeExecutor` async class runs every 30 seconds
  - Retrieves and executes pending scheduled tasks
  - Logs task execution with start/end timestamps
  - Updates task status automatically
  
- **Webhook Delivery Engine:** 
  - Fetches active webhooks from integration_gateways table
  - Delivers webhook payloads to external endpoints
  - Simulates retry logic with HTTP status codes
  - Logs all delivery attempts
  
- **Session Timeout Monitor:**
  - Enforces 120-minute inactivity timeout
  - Expires inactive operational_sessions automatically
  - Closes sessions gracefully with end_time recording
  
- **Retention Policy Scheduler:**
  - Executes retention_policies table rules
  - Auto-purges findings, credentials, audit logs, detection events
  - Implements secure deletion (multi-pass) or archival per policy
  - Tracks purged records for compliance reporting
  
- **Anomaly Detection Hooks:**
  - Triggers behavioral_profile analysis on operations
  - Detects operation rate anomalies vs baseline
  - Records detection events with confidence scores
  - Enables predictive defense analytics

**Runtime Integration:**
- Started automatically on user login via `_post_login_setup()`
- Runs as `@work` async task (non-blocking TUI)
- Gracefully stops on logout or shutdown
- Silently handles errors without crashing application

---

## 🏗️ Complete Architecture: 41 Database Tables

### Phase 0 Tables (15)
campaigns, findings, assets, credentials, actions, evidence_items, activity_log, users, groups, sessions, relations, loot, audit_log, approval_history, campaign_metadata

### Phase 1 Tables (8)
command_logs, operational_sessions, detection_events, objectives, persistence_mechanisms, scheduled_tasks, backup_sessions, threat_intel_items

### Phase 2 Tables (18)
behavioral_profiles, defense_predictions, threat_profiles, post_analysis_items, remediation_tracking, capability_matrix, collaboration_sessions, operator_presence, collaborative_changes, task_templates, task_executions, webhooks, webhook_delivery_log, integration_config, tlp_classification, immutable_audit_log, session_management, retention_policies

---

## 🚀 Roadmap: Phases 3-8 (Planned)

### Phase 3: Reporting & Export Engine
**ETA: Q2 2026** | Estimated Lines: 400-500 | Status: `Not Started`

- Campaign reports (PDF/HTML with branding)
- Evidence chain of custody documents  
- Finding summaries with CVSS scores
- Compliance mapping reports (NIST/FedRAMP attestations)
- Executive summaries for clients
- Automated scheduling of recurring reports

**Key Features:**
- Multi-format export (PDF, HTML, JSON, CSV)
- Client-branded report templates
- Evidence appendix with hash verification
- Risk scoring summaries
- Metrics dashboards

### Phase 4: Multi-Team & Federation
**ETA: Q3 2026** | Estimated Lines: 350-450 | Status: `Not Started`

- Team management (create, assign operators, team budgets)
- Cross-team campaign coordination
- Data sharing policies (what teams see)
- Team metrics & operator performance tracking
- Shared intelligence across teams

**Key Features:**
- Team CRUD with operator assignment
- Permission matrix per team
- Shared campaign visibility
- Team-level metrics (findings/week, approval rate, etc.)
- Operator leaderboards

### Phase 5: Advanced Threat Intelligence
**ETA: Q3 2026** | Estimated Lines: 450-550 | Status: `Not Started`

- External feed ingestion (VirusTotal, Shodan, OTX)
- Correlation engine (link findings to external threats)
- Automated enrichment (IP geolocation, domain reputation)
- Threat scoring & severity auto-calculation

**Key Features:**
- Feed connector framework
- Threat actor profiles
- IoC management (IP, domain, hash, email)
- Risk scoring automation
- Automated enrichment on finding creation

### Phase 6: Deployment & Hardening
**ETA: Q4 2026** | Estimated Lines: 300-400 | Status: `Not Started`

- Docker containerization with multi-container compose
- systemd service setup & auto-restart
- TLS/mTLS for inter-service communication
- Hardware security module (HSM) integration
- Air-gap deployment support (no internet)

**Key Features:**
- Docker Compose with PostgreSQL backend
- systemd service templates
- TLS certificate generation
- Air-gap archive generation
- Deployment hardening guide

### Phase 7: Client Portal (Web UI)
**ETA: Q4 2026** | Estimated Lines: 800-1000 | Status: `Not Started`

- Read-only findings view for clients
- Real-time alerts on new findings
- Evidence & report downloads
- Risk scoring dashboard
- Remediation tracking

**Key Features:**
- React/Vue.js frontend
- WebSocket alerts
- PDF/HTML download
- Responsive design
- Client-specific filtering

### Phase 8: Advanced ML/Analytics (Optional)
**ETA: Q1 2027** | Estimated Lines: 500-700 | Status: `Not Started`

- Attack path prediction
- Behavioral anomaly learning
- Automated remediation suggestions
- Operator performance ML models
- Threat pattern recognition

**Key Features:**
- ML pipeline for anomaly detection
- Predictive attack modeling
- Remediation recommendation engine
- Performance analytics
- Pattern clustering

---

## 📊 Current Metrics (After Phase 2)

| Component | Lines | Status | Version |
|-----------|-------|--------|---------|
| vv.py (UI Controller) | 1,882 | ✅ Complete | v3.4 |
| vv_core.py (Database & Runtime) | 4,617 | ✅ Complete | v3.4 |
| vv_theme.py (Theme System) | 743 | ✅ Complete | v3.0 |
| vv_fs.py (Filesystem) | 126 | ✅ Complete | v3.0 |
| **Total** | **7,368** | ✅ Production Ready | **v3.4** |
| Database Tables | 41 | ✅ Complete | v3.4 |
| UI Views | 16 | ✅ Complete | v3.4 |
| Keybindings | 30+ | ✅ Complete | v3.4 |
| Background Tasks | 5 | ✅ Complete | v3.4 |

---

## 🔧 Database Schema (Complete)

### Phase 0 Core Tables (15 tables)
**Campaign & Evidence Management:**
- `campaigns` - Campaign metadata, status, client, ROE, objectives
- `findings` - Vulnerabilities with approval workflow (pending/approved/rejected)
- `assets` - Targets with first/last seen, tags, sensitivity
- `credentials` - Captured creds (encrypted), source, type
- `actions` - Operator actions, MITRE technique mapping, timestamps

**Audit & Integrity:**
- `evidence_items` - Immutable evidence with SHA256, collection method
- `activity_log` - Detailed audit trail (severity, event_type, operator)
- `audit_log` - Legacy backward compatibility
- `approval_history` - Evidence approval decisions with reasons
- `campaign_metadata` - Extended campaign attributes

**Access Control & Sessions:**
- `users` - Operators with role (VIEWER/OPERATOR/LEAD/ADMIN)
- `groups` - Team/group membership
- `sessions` - Session tokens, expiration, authentication state

**Intelligence & Relations:**
- `relations` - Attack graph edges (lateral movement paths)
- `loot` - File artifacts, trophies, binary hashes

### Phase 1 Operational Tables (8 tables)
- `command_logs` - Executed commands with input/output
- `operational_sessions` - Open sessions per asset (open/close/detected)
- `detection_events` - Automated alerts with severity, confidence
- `objectives` - Campaign goals with completion tracking
- `persistence_mechanisms` - Installed backdoors, C2 channels
- `scheduled_tasks` - Persistence timers, verification methods
- `backup_sessions` - Session recovery and revival
- `threat_intel_items` - Raw intelligence feeds

### Phase 2 Advanced Tables (18 tables)
**Intelligence & Analytics:**
- `behavioral_profiles` - Baseline operation patterns, anomaly thresholds
- `defense_predictions` - Predicted defensive responses
- `threat_profiles` - Threat actor characteristics
- `post_analysis_items` - Analysis findings
- `remediation_tracking` - Remediation status per finding
- `capability_matrix` - Capability assessment scores

**Collaboration & Orchestration:**
- `collaboration_sessions` - Multi-operator work sessions
- `operator_presence` - Real-time operator status
- `collaborative_changes` - Sync events between operators
- `task_templates` - Reusable task definitions
- `task_executions` - Task execution logs

**Integration & Delivery:**
- `webhooks` - External webhook endpoints
- `webhook_delivery_log` - Delivery attempts, status codes
- `integration_config` - API keys, endpoint configs

**Security & Compliance:**
- `tlp_classification` - Traffic Light Protocol labels
- `immutable_audit_log` - Append-only audit trail
- `session_management` - Session timeout, encryption keys
- `retention_policies` - Data lifecycle rules (90d/180d/365d)

---

## 📂 Project Structure

```text
VectorVue_Root/
├── .github/
│   ├── copilot-instructions.md         # AI agent development guide
│   └── dev-log/
│       ├── V3_DEPLOYMENT_READINESS.md  # Deployment checklist
│       ├── VV3_COMPLETE.md             # v3.0 completion status
│       ├── VV3_COMPLETION_SUMMARY.md   # v3.4 summary
│       ├── VV3_CORE_REFACTOR_LOG.md    # vv_core.py evolution
│       ├── VV3_INTEGRATION_GUIDE.md    # Multi-module integration
│       └── VV3_REFACTORING_INDEX.md    # Refactor timeline
├── docs/
│   ├── manuals/
│   │   ├── INDEX.md                    # Documentation index
│   │   ├── GETTING_STARTED.md          # Installation & first campaign
│   │   ├── OPERATOR_MANUAL.md          # Field usage & keybindings
│   │   ├── ARCHITECTURE_SPEC.md        # Technical deep dive
│   │   └── TROUBLESHOOTING_GUIDE.md    # Error diagnosis
│   └── dev-log/                        # Development logs
├── 05-Delivery/                        # Report/export directory
├── vv.py                               # Main TUI (1,882 lines, v3.4)
├── vv_core.py                          # Database & crypto (4,617 lines, v3.4)
├── vv_theme.py                         # Theme system (743 lines, v3.0)
├── vv_fs.py                            # Filesystem abstraction (126 lines, v3.0)
├── vv_file_manager.py                  # File manager UI
├── mitre_reference.txt                 # MITRE ATT&CK lookup
├── requirements.txt                    # Dependencies
├── vectorvue.db                        # SQLite3 (auto-created)
├── vectorvue.salt                      # Encryption salt (auto-created)
├── LICENSE                             # Proprietary
├── README.md                           # This file (Master Documentation)
└── ROADMAP.md                          # Detailed phase roadmap
```

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

# 4. Launch VectorVue v3.4
python3 vv.py

# 5. On first launch
# → Create admin user (ADMIN role)
# → Create or select campaign
# → Start documenting findings
# → Background tasks (scheduler, webhooks, retention) auto-start on login
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
* **[Architecture Spec](./docs/manuals/ARCHITECTURE_SPEC.md)** - v3.4 schema, crypto layer, RBAC design
* **[Troubleshooting](./docs/manuals/TROUBLESHOOTING_GUIDE.md)** - Common errors and fixes

### Phase Documentation
* **[Roadmap](./ROADMAP.md)** - Detailed phase 0-8 roadmap with timelines
* **[v3.4 Completion](./docs/dev-log/VV3_COMPLETION_SUMMARY.md)** - What's complete (phases 0-2)
* **[Deployment Readiness](./docs/dev-log/V3_DEPLOYMENT_READINESS.md)** - Production checklist

---

## 🔐 Security & Compliance

✅ **Evidence Integrity:** Immutable evidence_items with SHA256 hashing  
✅ **Audit Trail:** Complete activity_log with operator attribution and timestamps  
✅ **RBAC Enforcement:** 4-level role hierarchy (Viewer/Operator/Lead/Admin)  
✅ **Encryption:** AES-256 via Fernet on all sensitive fields  
✅ **Approval Workflow:** Findings require LEAD+ approval before export  
✅ **Campaign Isolation:** No cross-campaign data leakage  
✅ **Session Management:** 120-minute timeout enforcement (v3.4)  
✅ **Retention Policies:** Auto-purge/archive data per policy (v3.4)  
✅ **Webhook Delivery:** External integration with retry logic (v3.4)  
✅ **Anomaly Detection:** Behavioral analysis on operations (v3.4)  

---

## 🛠 Development

### Contributing

VectorVue follows strict architectural patterns documented in `.github/copilot-instructions.md`. Key patterns:

1. **Database Access:** Always use `Database` class methods, never direct SQL
2. **Campaign Context:** Every operation requires valid campaign_id
3. **Role Checks:** Enforce RBAC at controller (vv.py) AND database (vv_core.py) layers
4. **Audit Logging:** Call `db.log_audit_event()` for all mutations
5. **Cryptography:** Use `SessionCrypto` for all sensitive data
6. **Runtime Tasks:** Use `RuntimeExecutor` for background operations (v3.4)
7. **Retention:** Always check `retention_policies` before purging data

### Testing

```bash
# Verify syntax
python3 -m py_compile vv.py vv_core.py vv_theme.py vv_fs.py

# Test imports
python3 -c "import vv_core, vv_theme, vv_fs; print('✅ All modules OK')"

# Test runtime executor
python3 -c "from vv import RuntimeExecutor; from vv_core import Database; print('✅ RuntimeExecutor loaded')"

# Run VectorVue v3.4
python3 vv.py
```

---

## 📊 Production Metrics (Phase 0-2 Complete)

| Component | Lines | Status | Version |
|-----------|-------|--------|---------|
| vv.py (UI + Runtime) | 1,882 | ✅ Complete | v3.4 |
| vv_core.py (Database + Crypto + Runtime Methods) | 4,617 | ✅ Complete | v3.4 |
| vv_theme.py (Semantic Theme) | 743 | ✅ Complete | v3.0 |
| vv_fs.py (Filesystem Abstraction) | 126 | ✅ Complete | v3.0 |
| **Total Code** | **7,368** | ✅ Production Ready | **v3.4** |
| **Database Tables** | 41 | ✅ Complete | v3.4 |
| **UI Views** | 16 | ✅ Complete | v3.4 |
| **Background Tasks** | 5 | ✅ Complete | v3.4 |
| **Keybindings** | 30+ | ✅ Complete | v3.4 |
| **Database Methods** | 150+ | ✅ Complete | v3.4 |

---

## 📋 Version History

### v3.4 (Current - February 2026) - PRODUCTION READY ✅
**Phases 0-2 Complete | 7,368 Lines | 41 Database Tables**

**Phase 0: Core Foundation**
- ✅ Campaign management (isolation, multi-campaign, lifecycle)
- ✅ Multi-user RBAC (4-level role hierarchy)
- ✅ Approval workflow (pending → approved/rejected)
- ✅ Evidence chain of custody (SHA256, immutable)
- ✅ Activity timeline & audit trail (operator attribution)
- ✅ Atomic database transactions
- ✅ MITRE ATT&CK integration (attack path narrative)
- ✅ Semantic theme system (22 colors, 50+ CSS classes)
- ✅ Encryption (AES-256 via Fernet)

**Phase 1: Operational Intelligence**
- ✅ Command execution logging
- ✅ Session lifecycle tracking (open/close/detected)
- ✅ Detection events with severity/confidence
- ✅ Objective progress monitoring
- ✅ Persistence mechanisms inventory
- ✅ Scheduled task persistence logging
- ✅ Backup session recovery
- ✅ Threat intelligence feed ingestion

**Phase 2a: Execution & Detection (v3.2)**
- ✅ CommandExecutionLogView (Ctrl+E)
- ✅ SessionActivityView (Ctrl+J)
- ✅ DetectionTimelineView (Ctrl+D)
- ✅ ObjectiveProgressView (Ctrl+O)
- ✅ PersistenceInventoryView (Ctrl+P)

**Phase 2b: Intelligence & Analysis (v3.3)**
- ✅ SituationalAwarenessView (Ctrl+1)
- ✅ PostEngagementAnalysisView (Ctrl+2)
- ✅ ThreatIntelligenceView (Ctrl+3)
- ✅ RemediationTrackingView (Ctrl+4)
- ✅ CapabilityAssessmentView (Ctrl+5)

**Phase 2c: Advanced Features & Runtime (v3.4)**
- ✅ CollaborationEngineView (Alt+1) - Multi-operator sessions
- ✅ TaskOrchestrationView (Alt+2) - Task templates & scheduling
- ✅ BehavioralAnalyticsView (Alt+3) - Anomaly detection
- ✅ IntegrationGatewayView (Alt+4) - Webhook management
- ✅ ComplianceReportingView (Alt+5) - SOC 2, FedRAMP, ISO 27001, NIST CSF
- ✅ SecurityHardeningView (Alt+6) - TLP, audit immutability, retention
- ✅ RuntimeExecutor - Background task scheduler
- ✅ Session timeout enforcement (120 min inactivity)
- ✅ Webhook delivery engine with retry logic
- ✅ Retention policy auto-execution
- ✅ Anomaly detection hooks

### v3.0-3.3 (Previous) - LEGACY ✓
- Campaign management and RBAC (v3.0)
- Operational intelligence layer (v3.1)
- Execution & detection views (v3.2)
- Intelligence & analysis views (v3.3)

### v2.1 (Legacy - Deprecated)
- Pentest findings notebook
- Single-user operation
- Basic MITRE lookup
- Atomic file I/O

---

## ⚖️ License & Disclaimer

**VectorVue v3.0-3.4** is proprietary software developed for Offensive Security R&D. Unauthorized distribution or reverse engineering is strictly prohibited. The developers assume no liability for misuse or damage caused by this software in non-authorized environments.

For enterprise licensing inquiries, contact the Internal Engineering Lead.

---

**VectorVue v3.4** | *Red Team Campaign Management for Enterprise Operators*  
**Status:** Production Ready | **Phase Progress:** 2/8 Complete (25%) | **Last Updated:** February 16, 2026

---

```
