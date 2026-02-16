# VectorVue v3.4 Documentation Index

![Docs](https://img.shields.io/badge/Docs-v3.4_Complete-39FF14?style=flat-square) ![Phase](https://img.shields.io/badge/Phase-2_Complete-39FF14?style=flat-square) ![Status](https://img.shields.io/badge/Status-Production_Ready-00FFFF)

Welcome to the VectorVue v3.4 Red Team Campaign Management Platform documentation suite. This index guides you through all available resources covering the complete Phase 0-2 implementation with background task execution, advanced analytics, and enterprise security controls.

## 📚 Core Documentation

### [Getting Started](./GETTING_STARTED.md)
**For new operators and deployment teams**
- v3.4 system requirements (Python 3.10+, Alacritty or equivalent)
- Installation and dependency setup (cryptography, textual)
- First launch & admin user creation
- Campaign initialization with classification & ROE
- Database initialization (41 tables, dual databases)
- Data backup and recovery procedures
- Background executor startup verification
- Post-installation security hardening checklist

### [Operator Manual](./OPERATOR_MANUAL.md)
**For daily operational use**
- Authentication, session management, role assignment (4 RBAC levels)
- Campaign management and status lifecycle (PLANNING → ARCHIVED)
- Six primary views (Ctrl+1 through Ctrl+6) with full keybinding reference
- Situational Awareness dashboard with real-time metrics
- Campaign Management (Assets, Credentials, Evidence tabs)
- MITRE ATT&CK Intelligence with technique mapping & coverage matrix
- File Manager with atomic I/O and secure deletion
- Task Orchestrator for background task monitoring (5 executor types)
- Security Hardening with encryption, policies, compliance controls
- Core workflows: Finding documentation, approval, evidence chain of custody
- Multi-operator collaboration and task assignment
- Background task execution (30-second scheduler, webhook delivery, retention)
- Report generation in 5 formats (PDF, DOCX, JSON, HTML, XLSX)
- Client Safe Mode and sensitive host flagging for OPSEC
- Complete 30+ keybinding reference with vim-mode navigation

### [Architecture Specification](./ARCHITECTURE_SPEC.md)
**For developers and architects**
- v3.4 Six Pillars architecture: UI, Runtime, Filesystem, Database, Crypto, Theme
- Complete database schema (41 tables across 3 phases)
- Phase 0 core: 15 tables, campaign/role/RBAC/operations
- Phase 1 operational intelligence: 8 tables, evidence/retention/compliance
- Phase 2 advanced runtime: 18 tables, background tasks/webhooks/approval/anomaly
- SessionCrypto layer (PBKDF2-SHA256, 480k iterations + Fernet AES-256)
- Row-level HMAC-SHA256 integrity verification
- Campaign isolation patterns (all queries scoped by campaign_id)
- 150+ database methods across 10 categories (findings, assets, credentials, evidence, MITRE, approval, runtime, retention, audit, compliance)
- Runtime Executor architecture with 5 background executors (Scheduler, Webhooks, Sessions, Retention, Anomaly)
- File system abstraction with atomic I/O patterns (temp + fsync + atomic rename)
- Secure file deletion (multi-pass overwrite before unlinking)
- Phosphor Cyberpunk theme system with CSS variables and 22-color palette
- 16 TUI views with tab navigation (no overlays)
- RBAC matrix (VIEWER/OPERATOR/LEAD/ADMIN with permission matrix)
- Error handling, transactions, and recovery patterns

### [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md)
**For problem diagnosis and recovery**
- Installation & startup issues (dependencies, terminal colors, permissions)
- Database issues (encryption, locking, schema migration, constraints)
- Authentication & session issues (login failures, timeouts, unexpected logouts)
- Finding & evidence issues (saving, hash mismatches, approvals, deletions)
- Background task & runtime issues (executor errors, report hangs, webhook failures)
- Encryption & security issues (decryption failures, crypto errors, sensitive data exposure)
- MITRE & technique mapping issues (empty views, linking problems)
- Performance & optimization (slow UI, large databases)
- Data recovery & backup (accidental deletion, backup corruption)
- Support information gathering (version, schema, system info, reproduction steps)

---

## � Quick Navigation by Task

### I want to...

**Deploy VectorVue v3.0** → [Getting Started](./GETTING_STARTED.md)

**Set up my first campaign** → [Getting Started](./GETTING_STARTED.md) → Creating Your First Campaign

**Log in and navigate the UI** → [Operator Manual](./OPERATOR_MANUAL.md) → Getting Around

**Create and track findings** → [Operator Manual](./OPERATOR_MANUAL.md) → Findings Workflow

**Collect and verify evidence** → [Operator Manual](./OPERATOR_MANUAL.md) → Evidence Chain of Custody

**Understand the database** → [Architecture Specification](./ARCHITECTURE_SPEC.md) → Database Schema

**Implement RBAC** → [Architecture Specification](./ARCHITECTURE_SPEC.md) → RBAC & Access Control

**Fix an error** → [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md)

---

## 📖 Reading Guide

### For New Users (First Time)
1. **Start:** [Getting Started](./GETTING_STARTED.md) - Full setup walkthrough
2. **Learn:** [Operator Manual](./OPERATOR_MANUAL.md) - Navigation and core workflows
3. **Deep Dive:** [Architecture Spec](./ARCHITECTURE_SPEC.md) - Optional technical details

### For Operators (Daily Use)
1. **Reference:** [Operator Manual](./OPERATOR_MANUAL.md) - Your main guide
2. **Troubleshoot:** [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md) - When issues arise
3. **Understand Design:** [Architecture Spec](./ARCHITECTURE_SPEC.md) - Why things work

### For Developers/Maintainers
1. **Essential:** [Architecture Specification](./ARCHITECTURE_SPEC.md) - Technical deep dive
2. **Code Patterns:** See `.github/copilot-instructions.md`
3. **Issue Resolution:** [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md)

---

## 🔑 Key Concepts in v3.4

### Campaign Management (Phase 0)
A **Campaign** is a complete offensive security engagement containing:
- **Status Lifecycle:** PLANNING → ACTIVE → SUSPENDED → COMPLETE → ARCHIVED
- **Classification:** TLP levels (CLEAR, GREEN, AMBER, RED)
- **Findings:** Vulnerabilities with approval workflows (PENDING → APPROVED/REJECTED)
- **Assets:** Target systems with sensitivity flagging
- **Credentials:** Captured authentication material (encrypted at rest)
- **Evidence:** Immutable artifacts with SHA256 verification and chain of custody
- **Actions:** Operator activities mapped to MITRE techniques
- **Activity Log:** Complete audit trail with HMAC signatures

### Role-Based Access Control (Phase 0)
- **VIEWER (0):** Read-only access (findings, reports, evidence)
- **OPERATOR (1):** Create findings, manage assets, upload evidence
- **LEAD (2):** Approve findings, manage team, generate reports
- **ADMIN (3):** System administration, encryption, policies, audit logs

### Background Task Execution (Phase 2)
Five executor types automatically running:
- **Scheduler:** Every 30 seconds, executes scheduled actions
- **Webhooks:** Delivers integration payloads (Slack, webhook endpoints)
- **Sessions:** Monitors 120-minute TTL, enforces auto-logout
- **Retention:** Nightly purge per configured policies, secure deletion
- **Anomaly:** Real-time detection of suspicious activity patterns

### Evidence Chain of Custody (Phase 1)
- **Immutable:** Cannot be edited after creation
- **Hashed:** SHA256 integrity verification
- **Signed:** HMAC signatures on every database row
- **Auditable:** Tracked in activity_log with operator + timestamp
- **Metadata:** Collection method, source host, encrypted status

### Approval Workflow (Phase 2)
Multi-stage quality control: PENDING → LEAD reviews → APPROVED (report) or REJECTED (deleted)

---

## 🚀 v3.4 Features

### Phase 0: Core Foundation (15 Tables)
- ✅ Campaign-centric architecture with global scope isolation
- ✅ Multi-user RBAC with 4-level role hierarchy
- ✅ AES-256-GCM encryption with PBKDF2 key derivation
- ✅ HMAC row-level integrity verification
- ✅ Evidence immutability and SHA256 chain of custody
- ✅ Activity timeline with operator attribution
- ✅ Team-based access control and scoping

### Phase 1: Operational Intelligence (8 Tables)
- ✅ Evidence chain of custody with metadata
- ✅ Retention policies with configurable lifecycle
- ✅ Compliance frameworks and standards tracking
- ✅ Audit log archival with immutable records
- ✅ Data minimization and classification levels

### Phase 2: Advanced Runtime (18 Tables)
- ✅ **Background Task Execution:** RuntimeExecutor with 5 async executors
- ✅ **Approval Workflows:** Multi-stage approval with decision audit trail
- ✅ **Webhook Integrations:** Slack, generic webhooks with retry logic
- ✅ **Anomaly Detection:** Real-time pattern analysis and alerting
- ✅ **Report Generation:** 5 formats (PDF, DOCX, JSON, HTML, XLSX)
- ✅ **Client Safe Mode:** Redaction and data minimization
- ✅ **Session Management:** Timeout enforcement, activity tracking
- ✅ **Retention Policies:** Automated purging with secure deletion
- ✅ **Collaborative Workflows:** Task assignment, conflict prevention
- ✅ **6 Primary Views:** Ctrl+1-6 with tab navigation
- ✅ **30+ Keybindings:** Vim-mode navigation, quick actions
- ✅ **MITRE Coverage Matrix:** Technique completion tracking

---

## 🛠 Technical Reference

| Component | Status | Details |
|-----------|--------|---------|
| **Framework:** | ✅ | Textual 0.90+ TUI |
| **Database:** | ✅ | SQLite3 with 41-table schema (Phases 0-2) |
| **Encryption:** | ✅ | AES-256-GCM + PBKDF2-SHA256 (480k iterations) |
| **Integrity:** | ✅ | HMAC-SHA256 row-level signing |
| **Executors:** | ✅ | 5 background task executors (async) |
| **Reports:** | ✅ | 5 formats (PDF, DOCX, JSON, HTML, XLSX) |
| **Version:** | ✅ | v3.4 (February 2026) |
| **Phase Status:** | ✅ | 2/8 Complete (25% of roadmap) |
| **Production:** | ✅ | Enterprise-ready security & OPSEC |
| **License:** | 🔒 | Proprietary |

---

## 📊 Statistics

| Metric | Count |
|--------|-------|
| **Total Lines of Code** | 7,368 |
| **Database Tables** | 41 |
| **UI Views** | 16 |
| **Keybindings** | 30+ |
| **Database Methods** | 150+ |
| **Background Executors** | 5 |
| **Report Formats** | 5 |
| **Documentation Files** | 6 |
| **Documentation Lines** | 2,068 |

---

## 🔍 Finding What You Need

| Goal | Start Here |
|------|-----------|
| **Deploy VectorVue for first time** | [Getting Started](./GETTING_STARTED.md) |
| **Learn UI and daily operations** | [Operator Manual](./OPERATOR_MANUAL.md) |
| **Understand system architecture** | [Architecture Spec](./ARCHITECTURE_SPEC.md) |
| **Fix a problem** | [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md) |
| **Learn database schema** | [Architecture Spec](./ARCHITECTURE_SPEC.md) → Section 2 |
| **Understand background tasks** | [Architecture Spec](./ARCHITECTURE_SPEC.md) → Section 7 |
| **Configure approval workflows** | [Operator Manual](./OPERATOR_MANUAL.md) → Section 6 |
| **Enable client safe mode** | [Operator Manual](./OPERATOR_MANUAL.md) → Section 7 |
| **Monitor task execution** | [Operator Manual](./OPERATOR_MANUAL.md) → Task Orchestrator (Ctrl+5) |
| **Export compliance report** | [Operator Manual](./OPERATOR_MANUAL.md) → Security Hardening (Ctrl+6) |

---

*For support inquiries, contact the Internal Engineering Lead.*
