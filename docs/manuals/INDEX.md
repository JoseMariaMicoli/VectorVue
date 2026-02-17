
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

# VectorVue v3.8 Documentation Index

![Version](https://img.shields.io/badge/Version-v3.8-39FF14) ![Phase](https://img.shields.io/badge/Phase-5.5_Complete-39FF14) ![Cognition](https://img.shields.io/badge/Cognition-Operational-00FF00) ![Docs](https://img.shields.io/badge/Documentation-Complete-00FF00)

Complete navigation guide for VectorVue v3.8 documentation with Phase 5.5 (Operational Cognition) now complete. This index organizes all manuals by topic and operational phase.

---

## Quick Start (5 minutes)

**New to VectorVue?** Start here:

1. **[GETTING_STARTED.md](./GETTING_STARTED.md)** (25 minutes)
   - System requirements & installation
   - First-time authentication setup
   - Creating your first campaign
   - Core UI navigation

2. **[OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md)** (45 minutes)
   - Complete operations reference
   - Phase-by-phase feature overview
   - Keybindings & workflows
   - Quick command reference

---

## Documentation by Phase

### Phase 0-1: Foundation & Core Authentication

**Files:**
- [GETTING_STARTED.md](./GETTING_STARTED.md) - Installation & first login
- [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md#phase-0) - Authentication workflows

**Topics:**
- ✅ User registration & role assignment (VIEWER/OPERATOR/LEAD/ADMIN)
- ✅ Mandatory authentication on every launch (no auto-login)
- ✅ Session management & timeout
- ✅ RBAC (Role-Based Access Control)
- ✅ Database initialization (vectorvue.db + vectorvue.salt)

---

### Phase 1: Campaign Management

**Files:**
- [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md#phase-1) - Campaign operations
- [GETTING_STARTED.md](./GETTING_STARTED.md#4️⃣-create-your-first-campaign) - Campaign creation
- [COMPLETE_FEATURES.md](./COMPLETE_FEATURES.md#phase-1) - Full feature reference

**Topics:**
- ✅ Creating & switching between campaigns
- ✅ Asset management (hosts, networks, services, accounts, databases)
- ✅ Credential harvesting & storage (AES-256-GCM encrypted)
- ✅ Asset-credential linking
- ✅ Campaign metrics & risk aggregation

**Key Commands:**
- `Ctrl+K` - Campaign view
- `Ctrl+K` → Assets - Add/manage campaign targets
- `Ctrl+K` → Credentials - Manage harvested credentials

---

### Phase 2: Operational Intelligence

**Files:**
- [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md#phase-2) - Full operations guide
- [COMPLETE_FEATURES.md](./COMPLETE_FEATURES.md#phase-2) - Detailed feature matrix

**Subphases:**

#### Phase 2a: Command Execution Logging
- Logging commands executed during engagement
- Output capture & storage
- MITRE ATT&CK technique mapping

**Key Commands:**
- `Ctrl+E` - Command execution log

#### Phase 2b: Session & Persistence Tracking
- Active session management (reverse shells, C2 callbacks, meterpreter)
- Persistence mechanism tracking (registry keys, cron jobs, scheduled tasks)
- Detection log (defensive responses observed)
- Objective tracking

**Key Commands:**
- `Ctrl+J` - Active sessions
- `Ctrl+P` - Persistence mechanisms
- `Ctrl+D` - Detection log
- `Ctrl+O` - Objectives

#### Phase 2c: Background Task Execution
- Automated task scheduler
- Webhook delivery to external systems
- Session timeout management
- Retention policy enforcement
- Anomaly detection (behavioral analytics)

**Key Commands:**
- `Alt+2` - Background task executor
- `Alt+3` - Analytics & anomalies

---

### Phase 3: Reporting & Evidence Chain of Custody

**Files:**
- [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md#phase-3) - Reporting workflows
- [ARCHITECTURE_SPEC.md](./ARCHITECTURE_SPEC.md#phase-3) - Database schema
- [COMPLETE_FEATURES.md](./COMPLETE_FEATURES.md#phase-3) - Evidence & reporting features

**Topics:**
- ✅ Evidence collection with immutable integrity (SHA256 hash)
- ✅ Chain of custody tracking (who handled evidence, when, how)
- ✅ Report generation (Technical, Executive, Compliance formats)
- ✅ Report delivery & approval workflow (LEAD+ approval required)
- ✅ Compliance mapping (PCI-DSS, HIPAA, SOC2, GDPR, etc.)
- ✅ PDF/HTML export with watermarking
- ✅ Evidence manifest generation

**Key Commands:**
- `Ctrl+R` - Reporting & evidence view
- `Ctrl+R` → Generate Report - Create deliverable
- `Ctrl+R` → Evidence - Collect/manage evidence items

---

### Phase 4: Team Federation & Coordination

**Files:**
- [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md#phase-4) - Team management
- [ARCHITECTURE_SPEC.md](./ARCHITECTURE_SPEC.md#phase-4) - 16 team tables
- [COMPLETE_FEATURES.md](./COMPLETE_FEATURES.md#phase-4) - Team features

**Topics:**
- ✅ Multi-operator team management
- ✅ Role-based team permissions (team_member, team_lead, observer)
- ✅ Data sharing policies & intelligence pools
- ✅ Campaign team assignments
- ✅ Operator performance metrics & quality scoring
- ✅ Team approval workflow
- ✅ Team audit logs & coordination events
- ✅ Capability assessment matrix
- ✅ Remediation tracking & verification

**Key Commands:**
- `Ctrl+T` - Team management

---

### Phase 5: Advanced Threat Intelligence

**Files:**
- [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md#phase-5) - Complete Phase 5 guide
- [ARCHITECTURE_SPEC.md](./ARCHITECTURE_SPEC.md#phase-5) - 21 threat intel tables
- [COMPLETE_FEATURES.md](./COMPLETE_FEATURES.md#phase-5) - Full feature matrix

**Topics:**
- ✅ Threat intelligence feed integration (VirusTotal, Shodan, OTX, MISP)
- ✅ Threat actor profiling & TTP (Tactics, Techniques & Procedures) mapping
- ✅ Indicators of Compromise (IoC) management & enrichment
- ✅ Automatic enrichment with VirusTotal verdicts, Shodan data, Whois, DNS
- ✅ Threat correlation engine (findings ↔ techniques ↔ actors ↔ IoCs)
- ✅ Automated risk scoring (CVSS + exploitability + prevalence + IoC correlation)
- ✅ Attack timeline & progression visualization
- ✅ MITRE ATT&CK coverage matrix (which techniques discovered)
- ✅ Behavioral anomaly detection (operator activity patterns)
- ✅ Intelligence sharing between teams

**Key Commands:**
- `Ctrl+Shift+I` - Threat Intelligence view (NEW in Phase 5)
- `Ctrl+Shift+I` → Add Feed - Integrate threat feeds
- `Ctrl+Shift+I` → Create Threat Actor - Profile known actors
- `Ctrl+Shift+I` → Ingest IoC - Add indicators of compromise
- `Ctrl+Shift+I` → Risk Scores - View automated risk calculations

---

### Phase 5.5: Operational Cognition & Decision Support

**Files:**
- [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md#phase-5.5) - Cognition workflows & recommendations
- [ARCHITECTURE_SPEC.md](./ARCHITECTURE_SPEC.md#phase-5.5) - 10 cognition modules & integration
- Supplementary: [Cognition Quick Reference](../../docs/dev-log/COGNITION_QUICK_REFERENCE.md)

**Topics:**
- ✅ Attack graph & compromise pathfinding (Dijkstra's shortest path)
- ✅ Objective distance calculation (steps to campaign goal)
- ✅ Recommendation scoring (risk-weighted action suggestions)
- ✅ Detection pressure tracking (0-100 defensive state scale)
- ✅ OpSec simulation (probability logging/detection prediction)
- ✅ Event replay (immutable campaign narrative timeline)
- ✅ Operator tempo analysis (action rate tracking & spike detection)
- ✅ Infrastructure burn tracking (C2 & tool exposure assessment)
- ✅ Confidence analysis (data completeness & observation scoring)
- ✅ Memory & pattern learning (technique success rate history)

**Core Principle:**
No autonomy. Every recommendation is explainable. Operator always decides via **Observe → Simulate → Execute → Evaluate → Adapt** workflow.

**Key Commands:**
- `Ctrl+Shift+C` - Cognition panel (recommendations & analysis)
- `Ctrl+Shift+G` - Attack graph & pathfinding
- `Ctrl+Shift+O` - Objective progress & distance
- `Ctrl+Shift+P` - Detection pressure & defensive trend

---

## Documentation by Phase

### Authentication & Security

- [GETTING_STARTED.md → Authentication](./GETTING_STARTED.md#3️⃣-first-launch--authentication)
- [OPERATOR_MANUAL.md → Authentication](./OPERATOR_MANUAL.md#authentication--session-management)
- [ARCHITECTURE_SPEC.md → Cryptography](./ARCHITECTURE_SPEC.md#cryptography--security)
- [TROUBLESHOOTING_GUIDE.md → Auth Issues](./TROUBLESHOOTING_GUIDE.md#auth)

**Key Concepts:**
- PBKDF2 key derivation (480,000 iterations)
- AES-256-GCM encryption at rest
- HMAC integrity verification
- RBAC with 4-level role hierarchy
- Session timeout after 120 minutes inactivity

### Campaign Management

- [GETTING_STARTED.md → First Campaign](./GETTING_STARTED.md#4️⃣-create-your-first-campaign)
- [OPERATOR_MANUAL.md → Campaign Ops](./OPERATOR_MANUAL.md#creating--switching-campaigns)
- [OPERATOR_MANUAL.md → Asset Management](./OPERATOR_MANUAL.md#asset-management)
- [OPERATOR_MANUAL.md → Credential Management](./OPERATOR_MANUAL.md#credential-management)
- [ARCHITECTURE_SPEC.md → Campaign Schema](./ARCHITECTURE_SPEC.md#campaigns)

**Key Concepts:**
- Campaign isolation (all findings belong to campaigns)
- Asset types & criticality tracking
- Sensitive host warnings (production, finance, healthcare)
- Credential encryption & type tracking
- Campaign metrics aggregation

### Evidence & Reporting

- [OPERATOR_MANUAL.md → Evidence Management](./OPERATOR_MANUAL.md#evidence-management)
- [OPERATOR_MANUAL.md → Report Generation](./OPERATOR_MANUAL.md#report-generation)
- [ARCHITECTURE_SPEC.md → Evidence Schema](./ARCHITECTURE_SPEC.md#phase-3-reporting--evidence-chain-of-custody-8-tables)
- [COMPLETE_FEATURES.md → Evidence & Reporting](./COMPLETE_FEATURES.md#evidence--reporting)

**Key Concepts:**
- Immutable evidence items (cannot be edited after creation)
- Chain of custody tracking (handler, timestamp, action)
- SHA256 integrity verification
- Multiple report formats (PDF, HTML, Markdown)
- Compliance framework mapping
- Evidence manifest generation

### Team Operations

- [OPERATOR_MANUAL.md → Team Management](./OPERATOR_MANUAL.md#team-management)
- [OPERATOR_MANUAL.md → Intelligence Sharing](./OPERATOR_MANUAL.md#intelligence-sharing-phase-4)
- [OPERATOR_MANUAL.md → Team Performance](./OPERATOR_MANUAL.md#operator-performance-tracking)
- [ARCHITECTURE_SPEC.md → Team Schema](./ARCHITECTURE_SPEC.md#phase-4-team-federation--coordination-16-tables)

**Key Concepts:**
- Multi-operator coordination
- Team role hierarchy (team_member, team_lead, observer)
- Data sharing policies & access control
- Intelligence pool sharing
- Operator performance metrics
- Approval workflows (team_lead required)

### Threat Intelligence

- [OPERATOR_MANUAL.md → Threat Feeds](./OPERATOR_MANUAL.md#threat-feeds)
- [OPERATOR_MANUAL.md → Threat Actors](./OPERATOR_MANUAL.md#threat-actor-profiles)
- [OPERATOR_MANUAL.md → IoC Management](./OPERATOR_MANUAL.md#indicators-of-compromise-ioc-management)
- [OPERATOR_MANUAL.md → Risk Scoring](./OPERATOR_MANUAL.md#risk-scoring-automated)
- [OPERATOR_MANUAL.md → Threat Correlation](./OPERATOR_MANUAL.md#threat-correlation-engine)
- [ARCHITECTURE_SPEC.md → Threat Intel Schema](./ARCHITECTURE_SPEC.md#phase-5-advanced-threat-intelligence-21-tables)
- [COMPLETE_FEATURES.md → Threat Intelligence](./COMPLETE_FEATURES.md#phase-5-advanced-threat-intelligence)

**Key Concepts:**
- External feed integration (VirusTotal, Shodan, OTX, MISP, Custom)
- Automatic enrichment with reputation data
- Threat actor profiles with TTP mapping
- IoC management (IP, domain, hash, email, URL)
- Automated risk scoring formula
- Attack progression timeline
- MITRE ATT&CK coverage matrix

### Background Tasks & Automation

- [OPERATOR_MANUAL.md → Background Task Execution](./OPERATOR_MANUAL.md#phase-2c-background-task-execution)
- [ARCHITECTURE_SPEC.md → Task Executor](./ARCHITECTURE_SPEC.md#background-task-execution-phase-2c)
- [TROUBLESHOOTING_GUIDE.md → Background Tasks](./TROUBLESHOOTING_GUIDE.md#background)

**Key Concepts:**
- Async task scheduler (30-second intervals)
- Webhook delivery to external systems
- Session timeout enforcement
- Retention policy automation
- Behavioral anomaly detection

---

## Documentation by Audience

### System Administrators

**Start with:**
1. [GETTING_STARTED.md](./GETTING_STARTED.md) - Installation & deployment
2. [ARCHITECTURE_SPEC.md](./ARCHITECTURE_SPEC.md) - System design & database schema
3. [TROUBLESHOOTING_GUIDE.md](./TROUBLESHOOTING_GUIDE.md) - Common issues & fixes

**Key sections:**
- Database schema (72 tables)
- Cryptography implementation
- File system abstraction layer
- Background task executor
- Audit logging & compliance

### Red Team Operators

**Start with:**
1. [GETTING_STARTED.md](./GETTING_STARTED.md) - First-time setup
2. [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md) - Complete operations guide
3. [COMPLETE_FEATURES.md](./COMPLETE_FEATURES.md) - Feature reference

**Key sections:**
- Campaign creation & asset management
- Finding documentation with MITRE mapping
- Credential tracking (Phase 1)
- Evidence collection (Phase 3)
- IoC management & risk scoring (Phase 5)

### Team Leads

**Start with:**
1. [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md#phase-4) - Team management
2. [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md#phase-1) - Campaign isolation & oversight
3. [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md#reporting--evidence-chain-of-custody) - Report generation & approval

**Key sections:**
- Team creation & member assignment
- Role-based permissions & approval workflows
- Campaign metrics & team performance tracking
- Intelligence sharing & data policies
- Report generation & delivery

### Compliance Officers

**Start with:**
1. [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md#evidence-management) - Evidence chain of custody
2. [ARCHITECTURE_SPEC.md](./ARCHITECTURE_SPEC.md#audit_log) - Audit logging
3. [TROUBLESHOOTING_GUIDE.md](./TROUBLESHOOTING_GUIDE.md) - Security verification

**Key sections:**
- Immutable evidence tracking
- Audit trail logging
- User authentication & session tracking
- Encryption & integrity verification
- Compliance framework mapping (PCI, HIPAA, SOC2)

---

## Feature Reference by View

| View | Keybinding | Purpose | Phase | Documentation |
|------|-----------|---------|-------|-----------------|
| Campaign | Ctrl+K | Create/switch campaigns, manage assets & credentials | 1 | [OPERATOR_MANUAL.md#phase-1](./OPERATOR_MANUAL.md#phase-1) |
| Editor | Default | Create findings with MITRE mapping | 2 | [OPERATOR_MANUAL.md#finding-management](./OPERATOR_MANUAL.md#finding-management) |
| Command Log | Ctrl+E | View executed commands | 2a | [OPERATOR_MANUAL.md#command-execution-logging-phase-2a](./OPERATOR_MANUAL.md#command-execution-logging-phase-2a) |
| Sessions | Ctrl+J | Track active shells & callbacks | 2b | [OPERATOR_MANUAL.md#session--persistence-tracking-phase-2b](./OPERATOR_MANUAL.md#session--persistence-tracking-phase-2b) |
| Detections | Ctrl+D | Log defensive responses | 2b | [OPERATOR_MANUAL.md#detection-log-ctrl-d](./OPERATOR_MANUAL.md#detection-log-ctrl-d) |
| Objectives | Ctrl+O | Track campaign goals | 2b | [OPERATOR_MANUAL.md#objective-tracking-ctrl-o](./OPERATOR_MANUAL.md#objective-tracking-ctrl-o) |
| Persistence | Ctrl+P | Document installed backdoors | 2b | [OPERATOR_MANUAL.md#persistence-tracking](./OPERATOR_MANUAL.md#persistence-tracking) |
| Dashboard | Ctrl+1 | Real-time metrics & risk score | 2b | [OPERATOR_MANUAL.md#dashboard-ctrl-1](./OPERATOR_MANUAL.md#dashboard-ctrl-1) |
| Background Tasks | Alt+2 | Monitor executor & scheduled tasks | 2c | [OPERATOR_MANUAL.md#background-task-execution-phase-2c](./OPERATOR_MANUAL.md#background-task-execution-phase-2c) |
| Reporting | Ctrl+R | Generate reports & manage evidence | 3 | [OPERATOR_MANUAL.md#reporting--evidence-chain-of-custody](./OPERATOR_MANUAL.md#reporting--evidence-chain-of-custody) |
| Teams | Ctrl+T | Multi-operator coordination | 4 | [OPERATOR_MANUAL.md#team-management](./OPERATOR_MANUAL.md#team-management) |
| Threat Intel | Ctrl+Shift+I | Feeds, threat actors, IoCs, risk scoring | 5 | [OPERATOR_MANUAL.md#threat-intelligence-view](./OPERATOR_MANUAL.md#threat-intelligence-view) |

---

## Database Tables by Phase

### Phase 0-1: Foundation (12 tables)
`users`, `user_roles`, `user_preferences`, `sessions`, `campaigns`, `campaign_participants`, `campaign_audit_log`, `roles`, `permissions`, `role_permissions`, `system_settings`, `audit_log`

See: [ARCHITECTURE_SPEC.md → Phase 0-1](./ARCHITECTURE_SPEC.md#phase-0-1-foundation--authentication-12-tables)

### Phase 2: Operations (15 tables)
`findings`, `assets`, `credentials`, `asset_credentials`, `commands`, `command_output`, `command_artifacts`, `sessions`, `persistence_mechanisms`, `detections`, `objectives`, `campaign_metrics`, `finding_approvals`, `activity_log`, `scheduled_tasks`, `webhook_deliveries`

See: [ARCHITECTURE_SPEC.md → Phase 2](./ARCHITECTURE_SPEC.md#phase-2-operational-intelligence-15-tables)

### Phase 3: Reporting (8 tables)
`reports`, `report_sections`, `evidence_items`, `evidence_artifacts`, `evidence_manifest`, `campaign_reports`, `evidence_chains`, `compliance_mappings`

See: [ARCHITECTURE_SPEC.md → Phase 3](./ARCHITECTURE_SPEC.md#phase-3-reporting--evidence-chain-of-custody-8-tables)

### Phase 4: Teams (16 tables)
`teams`, `team_members`, `team_roles`, `team_permissions`, `campaign_team_assignments`, `data_sharing_policies`, `team_metrics`, `operator_performance`, `team_intelligence_pools`, `coordination_logs`, `team_approvals`, `team_audit_log`, `intelligence_pool_findings`, `team_notifications`, `capability_assessments`, `remediation_tracking`

See: [ARCHITECTURE_SPEC.md → Phase 4](./ARCHITECTURE_SPEC.md#phase-4-team-federation--coordination-16-tables)

### Phase 5: Threat Intelligence (21 tables)
`threat_feeds`, `threat_feed_refresh_log`, `threat_actors`, `actor_aliases`, `actor_ttps`, `indicators_of_compromise`, `ioc_enrichment`, `threat_correlations`, `risk_scores`, `risk_scoring_rules`, `enrichment_data`, `threat_intelligence_archive`, `behavioral_analytics`, `anomaly_rules`, `detected_anomalies`, `attack_patterns`, `attack_timeline`, `technique_coverage`, `intelligence_sharing`, `feed_data_cache`

See: [ARCHITECTURE_SPEC.md → Phase 5](./ARCHITECTURE_SPEC.md#phase-5-advanced-threat-intelligence-21-tables)

---

## Keybindings Quick Reference

**Campaign & Intelligence:**
- `Ctrl+K` - Campaign management
- `Ctrl+E` - Command execution log
- `Ctrl+J` - Active sessions
- `Ctrl+D` - Detection log
- `Ctrl+O` - Objectives
- `Ctrl+P` - Persistence
- `Ctrl+Shift+I` - Threat Intelligence (Phase 5)

**Analytics:**
- `Ctrl+1` - Dashboard
- `Ctrl+2` - Analysis
- `Ctrl+3` - Intelligence (legacy)
- `Ctrl+4` - Remediation
- `Ctrl+5` - Capability

**Advanced:**
- `Ctrl+R` - Reporting
- `Ctrl+T` - Teams
- `Ctrl+M` - MITRE ATT&CK
- `Alt+1` - Collaboration
- `Alt+2` - Background Tasks
- `Alt+3` - Analytics
- `Alt+4` - Integrations
- `Alt+5` - Compliance
- `Alt+6` - Security

**General:**
- `Space` - File Manager
- `Ctrl+L` - Logout
- `Ctrl+Q` - Quit

See: [OPERATOR_MANUAL.md → Keybindings](./OPERATOR_MANUAL.md#keybindings-reference)

---

## Common Tasks

### Creating Your First Campaign
[GETTING_STARTED.md](./GETTING_STARTED.md#4️⃣-create-your-first-campaign) (5 minutes)

### Documenting a Finding
[OPERATOR_MANUAL.md → Finding Management](./OPERATOR_MANUAL.md#finding-management) (10 minutes)

### Harvesting Credentials
[OPERATOR_MANUAL.md → Credential Management](./OPERATOR_MANUAL.md#credential-management) (5 minutes)

### Collecting Evidence
[OPERATOR_MANUAL.md → Evidence Management](./OPERATOR_MANUAL.md#evidence-management) (10 minutes)

### Generating a Report
[OPERATOR_MANUAL.md → Report Generation](./OPERATOR_MANUAL.md#report-generation) (15 minutes)

### Setting Up a Team
[OPERATOR_MANUAL.md → Team Management](./OPERATOR_MANUAL.md#team-management) (10 minutes)

### Ingesting Threat Feeds
[OPERATOR_MANUAL.md → Threat Feeds](./OPERATOR_MANUAL.md#threat-feeds) (15 minutes)

### Analyzing Risk Scores
[OPERATOR_MANUAL.md → Risk Scoring](./OPERATOR_MANUAL.md#risk-scoring-automated) (10 minutes)

---

## Troubleshooting

**Having issues?** See [TROUBLESHOOTING_GUIDE.md](./TROUBLESHOOTING_GUIDE.md)

| Issue | Category | Link |
|-------|----------|------|
| Installation fails | Setup | [TROUBLESHOOTING_GUIDE.md → Installation](./TROUBLESHOOTING_GUIDE.md#installation) |
| Can't log in | Auth | [TROUBLESHOOTING_GUIDE.md → Auth](./TROUBLESHOOTING_GUIDE.md#auth) |
| Database locked | Storage | [TROUBLESHOOTING_GUIDE.md → Database](./TROUBLESHOOTING_GUIDE.md#database) |
| UI looks wrong | Display | [TROUBLESHOOTING_GUIDE.md → UI](./TROUBLESHOOTING_GUIDE.md#ui) |
| Can't find data | Campaigns | [TROUBLESHOOTING_GUIDE.md → Campaigns](./TROUBLESHOOTING_GUIDE.md#campaigns) |
| Reports not generating | Phase 3 | [TROUBLESHOOTING_GUIDE.md → Reporting](./TROUBLESHOOTING_GUIDE.md#phase3) |
| Teams not working | Phase 4 | [TROUBLESHOOTING_GUIDE.md → Teams](./TROUBLESHOOTING_GUIDE.md#phase4) |
| Threat feeds failing | Phase 5 | [TROUBLESHOOTING_GUIDE.md → Threat Intelligence](./TROUBLESHOOTING_GUIDE.md#phase5) |

---

## Roadmap & Versions

**Current Version:** v3.7

**Completed Phases:**
- ✅ Phase 0-1: Foundation (12 tables)
- ✅ Phase 2: Operations (15 tables)
- ✅ Phase 3: Reporting (8 tables)
- ✅ Phase 4: Teams (16 tables)
- ✅ Phase 5: Threat Intelligence (21 tables)

**Total:** 72 tables, 200+ methods, 16+ operational views

See: [ROADMAP.md](../ROADMAP.md) for complete roadmap through Phase 8 (85 tables target)

---

## Document Versions

| Document | Version | Last Updated | Status |
|----------|---------|--------------|--------|
| GETTING_STARTED.md | 3.7 | 2026-02-18 | ✅ Current |
| OPERATOR_MANUAL.md | 3.7 | 2026-02-18 | ✅ Current |
| ARCHITECTURE_SPEC.md | 3.7 | 2026-02-18 | ✅ Current |
| TROUBLESHOOTING_GUIDE.md | 3.7 | 2026-02-18 | ✅ Current |
| INDEX.md | 3.7 | 2026-02-18 | ✅ Current |
| COMPLETE_FEATURES.md | 3.7 | 2026-02-18 | ✅ Current |
| ROADMAP.md | 3.7 | 2026-01-20 | ✅ Current |

---

**VectorVue v3.7** | Complete Documentation | Phase 5/8 Complete (62.5%)
