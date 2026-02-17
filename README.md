```
██▒   █▓▓█████  ▄████▄  ▄▄▄█████▓ ▒█████   ██▀███      ██▒   █▓ ██▓  ██▓ ▓█████ 
▓██░   █▒▓█   ▀ ▒██▀ ▀█  ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒    ▓██░   █▒▓██▒  ██▒ ▓█   ▀ 
 ▓██  █▒░▒███   ▒▓█    ▄ ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒     ▓██  █▒░▓██░  ██▒ ▒███   
  ▒██ █░░▒▓█  ▄ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄       ▒██ █░░▒██   ██░ ▒▓█  ▄ 
   ▒▀█░  ░▒████▒▒ ▓███▀ ░  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒      ▒▀█░  ░ ████▓▒░ ░▒████▒
   ░ ▐░  ░░ ▒░ ░░ ░▒ ▒  ░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░      ░ ▐░  ░ ▒░▒░▒░  ░░ ▒░ ░
   ░ ░░   ░ ░  ░  ░  ▒       ░      ░ ░ ▒░   ░▒ ░ ▒░      ░ ░░  ░ ░ ░▒░▒░   ░ ░  ░
   ░      ░    ░    ░          ░      ░ ░ ░ ▒    ░░   ░ ░      ░        ░ ░ ▒░     ░    
          ░  ░ ░                               ░               ░ ░ ░      ░  ░  
               >> RED TEAM CAMPAIGN MANAGEMENT PLATFORM <<
```

# VectorVue v3.7 - Advanced Red Team Campaign Management Platform

![Status](https://img.shields.io/badge/Status-Operational-39FF14) ![Version](https://img.shields.io/badge/Version-3.7_Production-00FFFF) ![Build](https://img.shields.io/badge/Build-Enterprise_Grade-grey) ![License](https://img.shields.io/badge/License-Proprietary-FF0000) ![Phase](https://img.shields.io/badge/Phase-5/8_Complete-62.5%-39FF14)

**VectorVue v3.7** is an enterprise-grade, terminal-based Red Team Campaign Management Platform engineered for offensive security operators. It transforms raw pentest findings into structured, auditable campaign evidence within a comprehensive operational security framework featuring:

- **Campaign Management:** Multi-campaign isolation with RBAC (4-level role hierarchy)
- **Evidence Chain of Custody:** Immutable SHA256-verified evidence with approval workflows
- **Operational Intelligence:** Real-time command execution, session tracking, detection logging
- **Runtime Execution:** Background task scheduler, webhook delivery, retention policies (30s cycle)
- **Multi-Team Federation:** Team isolation, cross-team coordination, performance leaderboards
- **Threat Intelligence:** Feed ingestion, actor profiles, IoC correlation, automated risk scoring
- **Reporting & Export:** PDF/HTML/JSON reports, compliance mapping (NIST/FedRAMP/ISO27001/SOC2)
- **MITRE ATT&CK Integration:** Automated technique/tactic mapping, attack coverage matrices
- **Encryption:** AES-256-GCM with PBKDF2 (480k iterations), row-level HMAC integrity
- **15+ Operational Views:** Command logs, sessions, detections, persistence, analytics, collaboration
- **Behavioral Analytics:** Operation baseline analysis, anomaly detection, defense prediction
- **Compliance:** Immutable audit logs, session timeouts, retention policies, TLP classification

**Platforms:** Linux/macOS (WSL2 on Windows) | **UI:** Terminal-based TUI (Textual framework) | **Database:** SQLite3 with dual-database support

---

## 📚 User Documentation

Complete documentation for operators, administrators, and developers:

- **[GETTING_STARTED.md](docs/manuals/GETTING_STARTED.md)** - Installation, Python environment setup, first campaign creation, authentication flows
- **[OPERATOR_MANUAL.md](docs/manuals/OPERATOR_MANUAL.md)** - Complete operational guide with 15+ view descriptions, keybindings, workflows, evidence tracking
- **[ARCHITECTURE_SPEC.md](docs/manuals/ARCHITECTURE_SPEC.md)** - Technical architecture, 50+ table schema, encryption/HMAC, API reference, database methods
- **[TROUBLESHOOTING_GUIDE.md](docs/manuals/TROUBLESHOOTING_GUIDE.md)** - Common errors, debugging, performance optimization, database recovery
- **[INDEX.md](docs/manuals/INDEX.md)** - Complete documentation index and cross-references

**Development & Roadmap:**
- [ROADMAP.md](docs/ROADMAP.md) - Comprehensive 8-phase roadmap with detailed specifications
- [dev-log/](docs/dev-log/) - Development journals, completion summaries, integration guides

---

## ⚡ Quick Start

### Requirements
- Python 3.10+
- SQLite 3.37+
- Terminal with 256-color support (xterm-256color)
- 50 MB disk space (initial)

### Installation

```bash
git clone https://github.com/yourorg/vectorvue.git
cd vectorvue
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python vv.py
```

**First Run:** Create admin user → Create initial campaign → Select campaign → Access main views

---

## 📊 Complete Feature Matrix: Phases 0-5 (62.5% Complete)

### ✅ PHASE 0: Core Foundation (3,675 lines | 15 tables)

**Campaign Lifecycle**
- Campaign creation with client, ROE, classification, objectives
- Status tracking: PLANNING → ACTIVE → FINISHED → ARCHIVED
- Campaign metadata storage and audit trail
- Multi-campaign support with seamless switching

**Multi-User RBAC**
- 4-level role hierarchy: VIEWER (0) < OPERATOR (1) < LEAD (2) < ADMIN (3)
- Role-based view/edit/delete permissions
- Session management with secure tokens
- Operator attribution on all operations (audit_log.who_acted)

**Evidence Chain of Custody**
- Immutable evidence_items table (SHA256 hashing)
- Evidence collection timestamps and operator tracking
- Collection method docs: file_upload, command_output, screenshot, log_ingestion
- Evidence state machine: pending → approved/rejected

**Approval Workflow**
- 2-step finding workflow: create → needs_approval → approved/rejected
- LEAD+ required for finding approval
- Rejection with comments and version history
- Audit trail of all approval decisions

**MITRE ATT&CK Framework**
- Automated technique lookup from mitre_reference.txt
- Attack narrative generation grouped by tactic
- Campaign coverage matrix (technique execution tracking)
- Tactic/technique finding linkage

**Database (15 Tables)**
```
campaigns, findings, assets, credentials, actions, 
evidence_items, activity_log, users, groups, sessions, 
relations, loot, audit_log, approval_history, campaign_metadata
```

**Security Foundation**
- AES-256 encryption (Fernet) for sensitive fields
- PBKDF2 key derivation (480k iterations)
- Row-level HMAC-SHA256 integrity verification
- SessionCrypto layer for all encrypted operations

**UI Components**
- LoginView / RegisterView (authentication)
- CampaignView (campaign CRUD and switching)
- MitreIntelligenceView (technique search and coverage)
- FileManagerView (atomic file operations)
- HeaderHUD (session/project display)

---

### ✅ PHASE 1: Operational Intelligence Layer (638 lines | +8 tables)

**Command Execution Logging**
- CommandExecutionLogView (Ctrl+E)
- Real-time command logging with input/output capture
- C2 operator log parsing and ingestion
- Command history per campaign with results tracking

**Session Lifecycle Management**
- SessionActivityView (Ctrl+J)
- Open/detected/revived session states
- Session backup and recovery mechanisms
- First/last activity timestamps

**Detection Event Recording**
- DetectionTimelineView (Ctrl+D)
- Severity classification: LOW/MEDIUM/HIGH/CRITICAL
- Automated alert generation on session detection
- Detection reason documentation and response logging

**Objective Progress Tracking**
- ObjectiveProgressView (Ctrl+O)
- Campaign objective CRUD with status
- Completion percentage calculation
- Linked findings per objective

**Persistence Mechanisms**
- PersistenceInventoryView (Ctrl+P)
- Backdoor type and location tracking
- Hash verification for integrity checking
- Verification method documentation

**Scheduled Task Persistence**
- Task scheduling with frequency (hourly/daily/weekly)
- Execution status and verification tracking
- Persistence persistence (cross-reboot reliability)

**Database (+8 Tables | 23 Total)**
```
command_logs, operational_sessions, detection_events, objectives,
persistence_mechanisms, scheduled_tasks, backup_sessions, threat_intel_items
```

---

### ✅ PHASE 2a: Execution & Detection (v3.2)

All Phase 1 views fully operational with enhanced:
- VimDataTable integration (j/k/g/G navigation)
- Campaign context requirement (must select campaign first)
- Timestamp formatting and sorting
- Operator attribution on all records

---

### ✅ PHASE 2b: Intelligence & Analysis (v3.3, +5 tables)

**Situational Awareness Dashboard**
- SituationalAwarenessView (Ctrl+1)
- Real-time metrics: assets, credentials, sessions, persistence
- Risk score aggregation
- Detection heat map visualization
- Pending alerts list

**Post-Engagement Analysis**
- PostEngagementAnalysisView (Ctrl+2)
- TTP effectiveness metrics
- Timeline replay capability
- Performance analytics aggregation
- Metric comparisons and trends

**Threat Intelligence**
- Threat actor profiles with confidence scoring
- Intelligence feed aggregation and parsing
- Indicator-to-finding correlation
- Risk scoring automation

**Remediation Tracking**
- RemediationTrackingView (Ctrl+4)
- Remediation action logging per finding
- Timeline tracking with status
- Impact score calculation
- Completion metrics

**Capability Assessment**
- CapabilityAssessmentView (Ctrl+5)
- Capability matrix display (technique × asset)
- Success rate aggregation
- Difficulty scoring
- Trend analysis (improving/stable/declining)

**Database (+5 Tables | 28 Total)**
```
behavioral_profiles, threat_profiles, post_analysis_items,
remediation_tracking, capability_matrix
```

---

### ✅ PHASE 2c: Advanced Runtime Features (v3.4, +18 tables)

**Real-Time Collaboration**
- CollaborationEngineView (Alt+1)
- Multi-operator session management
- Operator presence tracking (active/idle)
- Conflict detection on concurrent edits
- Collaborative changes logging
- Real-time sync capability

**Task Orchestration**
- TaskOrchestrationView (Alt+2)
- Template-based task creation
- Scheduled task execution (daily/weekly/monthly)
- Task execution status tracking
- Retry policy management
- Task history with result logging

**Behavioral Analytics**
- BehavioralAnalyticsView (Alt+3)
- Behavioral profile creation per operator
- Operation rate baselines (commands/hour, findings/day)
- Anomaly detection triggers (threshold exceeding)
- Defense prediction model training
- Confidence scoring

**Integration Gateway**
- IntegrationGatewayView (Alt+4)
- Webhook endpoint management
- HTTP delivery with retry logic
- Integration configuration (API keys, headers)
- Delivery log display with status codes
- Payload formatting options

**Compliance Reporting**
- ComplianceReportingView (Alt+5)
- Framework selection: SOC 2 Type II, FedRAMP, ISO 27001, NIST CSF
- Compliance status dashboards
- Audit report generation
- Control satisfaction tracking
- Evidence appendix generation

**Security Hardening**
- SecurityHardeningView (Alt+6)
- TLP classification application (WHITE/GREEN/AMBER/RED)
- Immutable audit log management
- Session timeout configuration (default 120 min)
- Retention policy enforcement
- Secure deletion verification (multi-pass)

**Background Task Execution System (NEW - RuntimeExecutor)**

The `RuntimeExecutor` class runs continuously as a background async task (30-second cycle):

**Task Scheduler**
- Retrieves pending tasks from task_executions table
- Executes tasks with logging
- Updates status on completion/failure
- Timestamp tracking for auditing

**Webhook Delivery Engine**
- Fetches active webhooks from integration_gateways
- Delivers payloads to external endpoints
- HTTP status code handling (200/retry/fail)
- Retry logic with exponential backoff simulation
- Delivery log entry for each attempt

**Session Timeout Monitor**
- Monitors operational_sessions for inactivity
- Enforces 120-minute timeout
- Auto-expires idle sessions
- Records end_time for audit trail
- Graceful session closure

**Retention Policy Scheduler**
- Executes retention_policies rules every 30 seconds
- Purges findings (90-day default)
- Purges credentials (180-day default)
- Purges audit logs (365-day default)
- Purges detection events (30-day default)
- Secure deletion (multi-pass overwrite) or archival per policy
- Tracks purged record counts for compliance

**Anomaly Detection Hooks**
- Analyzes behavioral_profiles per operator
- Detects operation rate anomalies vs baseline
- Records detection_events with confidence scores
- Enables predictive defense training
- Silent operation (doesn't block TUI)

**Database (+18 Tables | 46 Total)**
```
collaboration_sessions, operator_presence, collaborative_changes,
task_templates, task_executions, webhooks, webhook_delivery_log,
integration_config, tlp_classification, immutable_audit_log,
session_management, retention_policies, behavioral_profile,
anomaly_detection, defense_prediction, threat_profile,
post_analysis, remediation_tracking
```

**Seeded Defaults**
- 4 retention policies (findings 90d, credentials 180d, audit 365d, detections 30d)
- 4 compliance frameworks
- Default session timeout: 120 minutes
- Default encryption: AES-256-GCM

---

### ✅ PHASE 3: Reporting & Export Engine (1,250+ lines | +8 tables)

**Campaign Reporting**
- ReportingView (Ctrl+R)
- PDF generation with executive summary, technical findings, risk scoring
- HTML generation with cyberpunk styling and branding
- Executive summary editor with metrics dashboard

**Evidence Chain of Custody**
- Evidence manifest generation (SHA256 hashing)
- Chronological evidence listing
- Operator attribution and collection method per item
- Integrity verification with per-entry hashing
- Manifest verification button

**Finding Summaries**
- CVSS 3.1 vector parsing and scoring
- Severity classification (CRITICAL/HIGH/MEDIUM/LOW)
- Impact assessment with affected assets list
- Remediation recommendations storage
- Supporting evidence links

**Compliance Mapping Reports**
- NIST SP 800-171 attestation generation
- FedRAMP compliance statements
- ISO 27001 control mapping
- SOC 2 Type II compliance tracking
- Audit-ready documentation

**Client Reports**
- White-labeled branding in HTML output
- Campaign-scoped filtering (only findings from selected campaign)
- Executive overview metrics
- Risk dashboard with severity distribution

**Report Scheduling**
- Recurring report generation (daily/weekly/monthly)
- Email recipient list management
- Report archive management
- Version tracking with timestamps
- Modification history with operator attribution

**Database (+8 Tables | 54 Total)**
```
campaign_reports, evidence_manifests, evidence_manifest_entries,
finding_summaries, compliance_report_mappings, compliance_attestations,
client_reports, report_schedules
```

---

### ✅ PHASE 4: Multi-Team & Federation (650+ lines | +10 tables)

**Team Management**
- TeamManagementView (Ctrl+T)
- Team CRUD with lead operator, budget, status
- Team member assignment with role-based access
- Team-specific finding visibility
- Cross-team visibility with policies

**Cross-Team Coordination**
- Shared campaign visibility (campaign_team_assignments)
- Team-specific data filtering (all queries by team)
- Shared intelligence pools (team_intelligence_pools)
- Coordinated operations logging
- Coordination event tracking

**Data Sharing Policies**
- Team-level access control
- Finding visibility policies (read-only/read-write/admin)
- Evidence sharing rules
- Credential pool isolation per team
- Intelligence sharing with approval gates

**Operator Performance**
- Performance metrics per operator per team per period
- Findings created/approved counts
- Approval rate calculation
- CVSS score averaging
- Operator leaderboard by effectiveness score

**Database (+10 Tables | 64 Total)**
```
teams, team_members, team_roles, team_permissions,
campaign_team_assignments, data_sharing_policies,
team_metrics, operator_performance, team_intelligence_pools,
coordination_logs
```

---

### ✅ PHASE 5: Advanced Threat Intelligence (650+ lines | +8 tables)

**External Feed Ingestion**
- ThreatIntelligenceView (Ctrl+Shift+I)
- Threat feed registration (VirusTotal, Shodan, OTX, MISP)
- Feed status tracking and error logging
- Last updated timestamps per feed
- Multi-source aggregation

**Threat Actor Profiles**
- APT group, cyber gang, and individual profiles
- Actor metadata (aliases, origin, organization, targets)
- Attribution confidence scoring
- Campaign history association
- TTP documentation per actor (technique + frequency)

**Indicator Management**
- IoC ingestion: IP, Domain, File Hash, Email Address, C2
- Indicator type classification
- Threat level assignment (LOW/MEDIUM/HIGH/CRITICAL)
- Confidence scoring per indicator
- Source feed tracking

**Automated Enrichment**
- Multi-source enrichment (GeoIP, WHOIS, threat scores, file signatures)
- Confidence tracking per enrichment
- TTL/expiration support for cached data
- Enrichment type classification
- Automated lookup on IoC ingestion

**Correlation Engine**
- Finding-to-IoC correlation with confidence
- Threat actor linking (findings/assets/credentials to actors)
- Campaign clustering and pattern recognition
- Correlation timestamp tracking
- Evidence-based threat assessment

**Risk Scoring**
- Automated 0-10 risk calculation
- Formula: (threat×0.3 + likelihood×0.3 + impact×0.4)
- Risk levels: CRITICAL (≥8.0), HIGH (≥6.0), MEDIUM (≥4.0), LOW (<4.0)
- Trend analysis: rising (>6.0), stable (3.0-6.0), falling (<3.0)
- Per-finding scoring with linked IoCs

**Intelligence Archive**
- Long-term storage with classification (UNCLASSIFIED/CONFIDENTIAL/SECRET)
- Archive by type: TTPs, campaigns, profiles
- Tagging system for organization
- Audit trail with operator attribution

**Database (+8 Tables | 72 Total)**
```
threat_feeds, threat_actors, actor_ttps, indicators_of_compromise,
enrichment_data, threat_correlations, risk_scores, intelligence_archive
```

---

## 🏗️ Complete Database Architecture

**Total: 72 Tables across 5 Phases**

### Core Tables (Phase 0 - 15)
| Category | Tables |
|----------|--------|
| Campaign | campaigns, campaign_metadata |
| Users & Auth | users, groups, sessions |
| Findings | findings, findings_search_cache |
| Operations | assets, credentials, actions, relations, loot |
| Evidence | evidence_items, approval_history |
| Audit | activity_log, audit_log |

### Operational Intelligence (Phase 1 - 8)
command_logs, operational_sessions, detection_events, objectives, persistence_mechanisms, scheduled_tasks, backup_sessions, threat_intel_items

### Advanced Runtime (Phase 2 - 18)
behavioral_profiles, defense_predictions, threat_profiles, post_analysis_items, remediation_tracking, capability_matrix, collaboration_sessions, operator_presence, collaborative_changes, task_templates, task_executions, webhooks, webhook_delivery_log, integration_config, tlp_classification, immutable_audit_log, session_management, retention_policies

### Reporting (Phase 3 - 8)
campaign_reports, evidence_manifests, evidence_manifest_entries, finding_summaries, compliance_report_mappings, compliance_attestations, client_reports, report_schedules

### Team Federation (Phase 4 - 10)
teams, team_members, team_roles, team_permissions, campaign_team_assignments, data_sharing_policies, team_metrics, operator_performance, team_intelligence_pools, coordination_logs

### Threat Intelligence (Phase 5 - 8)
threat_feeds, threat_actors, actor_ttps, indicators_of_compromise, enrichment_data, threat_correlations, risk_scores, intelligence_archive

---

## 🔐 Security Architecture

**Encryption Layer**
- AES-256-GCM (Fernet symmetric encryption)
- PBKDF2-SHA256 key derivation (480,000 iterations)
- Salt persistence in vectorvue.salt
- Per-row encryption for sensitive fields

**Integrity Verification**
- HMAC-SHA256 on all encrypted data
- Evidence hash verification (SHA256)
- Report manifest integrity checks
- Audit log immutability enforcement

**Access Control**
- 4-level RBAC: VIEWER < OPERATOR < LEAD < ADMIN
- Campaign-level isolation (all queries filtered)
- Team-level isolation (team_id in all queries)
- Role-based view enabling/disabling

**Audit Trail**
- activity_log with severity classification
- Operator attribution (who_acted field)
- Event categorization (CREATE_FINDING, APPROVE_EVIDENCE, etc.)
- Timestamp recording (activity_timestamp)
- Immutable audit log (TLP enforcement)

---

## 🎮 Keybindings Reference

### Authentication & Core
| Key | Action |
|-----|--------|
| q | Quit Application |
| Escape | Return to Editor |
| Ctrl+L | Logout |
| Ctrl+S | Save Database |

### Campaign & Core Views
| Key | Action |
|-----|--------|
| Space | Toggle File Manager |
| Ctrl+M | Toggle MITRE DB |
| Ctrl+K | Toggle Campaign View |
| Ctrl+R | Toggle Reporting |

### Execution & Detection (Phase 1)
| Key | Action |
|-----|--------|
| Ctrl+E | Toggle Command Log |
| Ctrl+J | Toggle Sessions |
| Ctrl+D | Toggle Detections |
| Ctrl+O | Toggle Objectives |
| Ctrl+P | Toggle Persistence |

### Intelligence & Analysis (Phase 2b)
| Key | Action |
|-----|--------|
| Ctrl+1 | Toggle Dashboard |
| Ctrl+2 | Toggle Analysis |
| Ctrl+3 | Toggle Threat Intel (legacy) |
| Ctrl+4 | Toggle Remediation |
| Ctrl+5 | Toggle Capability |

### Advanced Features (Phase 2c)
| Key | Action |
|-----|--------|
| Alt+1 | Toggle Collaboration |
| Alt+2 | Toggle Task Orchestration |
| Alt+3 | Toggle Behavioral Analytics |
| Alt+4 | Toggle Integration Gateway |
| Alt+5 | Toggle Compliance |
| Alt+6 | Toggle Security Hardening |

### Team & Threat Intelligence (Phase 4-5)
| Key | Action |
|-----|--------|
| Ctrl+T | Toggle Team Management |
| Ctrl+Shift+I | Toggle Threat Intelligence |

### Data Table Navigation (VimDataTable)
| Key | Action |
|-----|--------|
| j | Cursor Down |
| k | Cursor Up |
| g | Scroll to Top |
| G | Scroll to Bottom |
| Enter | Select Row |

---

## 📈 Roadmap: Future Phases (Planned)

### Phase 6: Deployment & Hardening (Q4 2026)
- Docker containerization with docker-compose
- PostgreSQL backend option (scalability)
- TLS 1.3 enforcement with cert management
- HSM support for key storage
- Air-gap deployment capability

### Phase 7: Client Portal (Q1 2027)
- Web UI for read-only finding/report access
- Client team management
- Evidence download with access controls
- Report scheduling for automated delivery
- Audit log visibility for compliance

### Phase 8: ML/Analytics (Q2 2027)
- Attack prediction model training
- Anomaly detection with historical baselines
- Threat actor clustering analysis
- Defender capability prediction
- Automated finding deduplication

---

## 📝 License

**Proprietary** - VectorVue is proprietary software. Unauthorized access, copying, distribution, or modification is prohibited.

---

## 🤝 Support

For issues, questions, or feature requests:
- Check [TROUBLESHOOTING_GUIDE.md](docs/manuals/TROUBLESHOOTING_GUIDE.md)
- Review [OPERATOR_MANUAL.md](docs/manuals/OPERATOR_MANUAL.md)
- Consult [ARCHITECTURE_SPEC.md](docs/manuals/ARCHITECTURE_SPEC.md)
- Review development logs in [docs/dev-log/](docs/dev-log/)

---

**VectorVue v3.7** | Production Ready | 62.5% Roadmap Complete | 72 Database Tables | 200+ Methods | 10,000+ LOC
