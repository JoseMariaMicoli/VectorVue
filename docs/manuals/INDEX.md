# VectorVue v3.0 Documentation Index

![Docs](https://img.shields.io/badge/Docs-v3.0_Complete-39FF14?style=flat-square) ![Version](https://img.shields.io/badge/Version-3.0_RC1-00FFFF?style=flat-square)

Welcome to the VectorVue v3.0 Red Team Campaign Management Platform documentation suite. This index guides you through all available resources.

## 📚 Core Documentation

### [Getting Started](./GETTING_STARTED.md)
**For new operators and deployment teams**
- System requirements and environment setup
- Installation and initialization steps
- Creating your first campaign
- User roles and basic workflows
- Initial configuration steps

### [Operator Manual](./OPERATOR_MANUAL.md)
**For daily operational use**
- Keyboard shortcuts and navigation
- Campaign management workflows
- Evidence collection and chain of custody
- Finding creation and approval process
- Asset and credential management
- MITRE ATT&CK integration
- Timeline and activity logging
- Multi-operator collaboration

### [Architecture Specification](./ARCHITECTURE_SPEC.md)
**For developers and architects**
- v3.0 design principles (Five Pillars)
- Database schema and relationships
- SessionCrypto layer (PBKDF2 + Fernet AES-256)
- RBAC implementation and permission model
- Campaign isolation architecture
- Evidence immutability and HMAC signing
- File system abstraction (`vv_fs.py`)
- Atomic transaction patterns
- Theme system and CSS architecture

### [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md)
**For problem diagnosis and recovery**
- Authentication errors and session issues
- Database integrity and recovery
- Crypto key derivation problems
- File I/O and atomic write failures
- MITRE lookup failures
- Performance tuning
- Common edge cases and workarounds

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

## 🔑 Key Concepts in v3.0

### Campaign Management
A **Campaign** is a complete offensive security engagement containing:
- **Findings:** Vulnerabilities with approval workflows
- **Assets:** Target systems, users, services
- **Credentials:** Captured authentication material (encrypted)
- **Evidence:** Immutable artifacts with SHA256 verification
- **Actions:** Operator activities mapped to MITRE techniques
- **Activity Log:** Complete audit trail with attribution

### Role-Based Access Control
- **VIEWER:** Read-only access
- **OPERATOR:** Can create findings, collect evidence
- **LEAD:** Can approve findings, manage evidence
- **ADMIN:** Full control including user/campaign management

### Evidence Chain of Custody
- **Immutable:** Cannot be edited after creation
- **Hashed:** SHA256 integrity verification
- **Signed:** HMAC signatures on database records
- **Auditable:** Tracked in activity_log with operator + timestamp

### Approval Workflow
Findings progress: `PENDING` → `APPROVED` (LEAD+) or `REJECTED` (LEAD+)

---

## 🚀 v3.0 Features

### Core Campaign Management
- Campaign-centric architecture (all data scoped)
- Multi-user RBAC (4-level hierarchy)
- Approval workflows for findings
- Evidence chain of custody with immutability
- Activity timeline with severity classification

### Advanced Features
- Attack path narrative (MITRE-grouped timeline)
- Atomic transactions with rollback
- Dual-logging (activity_log + audit_log)
- Semantic theme system (22 colors, 50+ CSS classes)
- Campaign isolation (no cross-campaign leakage)

---

## 🛠 Technical Reference

| Component | Status | Details |
|-----------|--------|---------|
| **Framework:** | ✅ | Textual 0.90+ |
| **Database:** | ✅ | SQLite3 with v3.0 schema |
| **Crypto:** | ✅ | AES-256 Fernet + PBKDF2 |
| **Version:** | ✅ | 3.0-RC1 (February 2026) |
| **License:** | 🔒 | Proprietary |

---
*For support inquiries, contact the Internal Engineering Lead.*
