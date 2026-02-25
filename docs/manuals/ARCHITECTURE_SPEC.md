# VectorVue v3.0 Architecture Specification

![Type](https://img.shields.io/badge/Type-Technical_Deep_Dive-9945FF?style=flat-square) ![Version](https://img.shields.io/badge/Version-3.0-39FF14?style=flat-square) ![Status](https://img.shields.io/badge/Status-Production_Ready-00FFFF?style=flat-square)

Complete technical architecture for VectorVue v3.0 Red Team Campaign Management Platform. This document covers the Five Pillars design, database schema, RBAC implementation, cryptography, and system-level patterns.

## 1. Component Diagram

```text
[ USER INPUT ]
      │
      ▼
[ EVENT LOOP (Textual App) ] ───┬───> [ RENDERER (CSS/Widgets) ]
      │                         │
      │                         └───> [ FILE MANAGER VIEW ]
      │
      ▼
[ DATA CONTROLLER ] ────────────┐
      │                         │
      ▼                         ▼
[ INTELLIGENCE ENGINE ]    [ DATABASE MGR ]
(Memory Cache)             (SQLite3 Connection)
      │                         │
      ▼                         ▼
[ mitre_reference.txt ]    [ vectorvue.db ]
```

## 2. Database Schema (`vectorvue.db`)

The application maintains a lightweight, serverless SQLite database. The schema is designed for portability and simplicity.

**Table:** `findings`

| Column | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `id` | INTEGER PK | Auto | Unique record identifier. |
| `title` | TEXT | NULL | The headline of the vulnerability. |
| `description` | TEXT | NULL | The full Markdown body of the finding. |
| `cvss_score` | REAL | 0.0 | Numerical risk score (0.0-10.0). |
| `mitre_id` | TEXT | "" | Associated MITRE T-Code. |
| `tactic_id` | TEXT | "" | (Reserved for future use). |
| `status` | TEXT | "Open" | Workflow state of the finding. |
| `evidence` | TEXT | "" | Raw evidence logs/screenshots path. |
| `remediation` | TEXT | "" | Recommended mitigation steps. |

## 3. Atomic I/O Implementation

To prevent data corruption (partial writes) during unexpected terminations, the `FileSystemService` implements atomic write logic:

1.  **Staging:** Data is written to a `tempfile.NamedTemporaryFile` in the target directory.
2.  **Flushing:** `file.flush()` and `os.fsync(fd)` are called to force the OS to write buffers to the physical disk.
3.  **Swapping:** `os.replace(src, dst)` is called. On POSIX systems, this is an atomic operation that instantly swaps the inode pointers.

## 4. Phosphor Design System (Theme)

The UI is governed by a centralized theme file (`vv_theme.py`). It defines CSS variables for consistency.

**Color Tokens:**
*   `$p-green` (#39FF14): Primary Action, Success, Low Risk.
*   `$e-cyan` (#00FFFF): Information, Selection, File Context.
*   `$a-amber` (#FFBF00): Warning, High Risk, System Pending.
*   `$r-alert` (#FF0000): Critical Error, Destruction, Critical Risk.
*   `$bg-void` (#050505): Application background (High Contrast).

This palette is chosen to maximize readability in low-light environments typical of security operations centers.

---

## v3.0 New Architecture: Five Pillars

VectorVue v3.0 is built on five foundational components:

### 1. **SessionCrypto Layer** (vv_core.py)
- **PBKDF2 Key Derivation:** 480,000 iterations
- **Encryption Cipher:** Fernet AES-256 (symmetric)
- **Salt Persistence:** Stored in `vectorvue.salt`
- **Row-Level Integrity:** HMAC signing on all database records
- **Function:** All sensitive data encrypted before disk write

### 2. **Database Orchestration** (vv_core.py)
- **Dual-Database Strategy:**
  - `vectorvue.db`: Operational store
  - `adversary.db`: Intelligence secondary store
- **Schema Version:** v3.0 with migration support
- **Transaction Manager:** Atomic via `_TransactionContext`
- **Pattern:** Never plaintext to disk

### 3. **UI Controller** (vv.py)
- **Framework:** Textual 0.90+
- **Architecture:** Hard view-switching
- **RBAC:** Enforced at controller level
- **Audit:** Every mutation logged

### 4. **File System Abstraction** (vv_fs.py)
- **Atomic Writes:** Temp + fsync + replace
- **Secure Wipe:** Multi-pass overwrite
- **Hash Integrity:** SHA256 for evidence
- **C2 Ingestion:** Log parsing to markdown

### 5. **Theme System** (vv_theme.py)
- **Colors:** 22 Phosphor cyberpunk palette
- **CSS:** 50+ semantic classes
- **OPSEC:** Caution, evidence, audit, approval indicators

---

## RBAC & Access Control

**Role Hierarchy:**
- VIEWER (0) < OPERATOR (1) < LEAD (2) < ADMIN (3)

**Permission Matrix:**
- VIEWER: Read-only
- OPERATOR: Create findings, collect evidence
- LEAD: Approve findings, manage evidence
- ADMIN: User management, campaign deletion

---

## Campaign Isolation

**Pattern:** All data scoped to campaign_id. No global scope queries allowed.

---

## Evidence Chain of Custody

- **Immutable:** Cannot edit after creation
- **Hashed:** SHA256 verification
- **Signed:** HMAC signatures on records
- **Auditable:** Tracked in activity_log

---

## Approval Workflow

Findings: `PENDING` → `APPROVED` (LEAD+) or `REJECTED` (LEAD+)

---

## Activity Timeline

Complete audit log with:
- Operator attribution
- Timestamp (ISO 8601)
- Action type
- Target context
- Severity classification

---

## Security Safeguards

✅ No plaintext passwords (AES-256 encrypted)  
✅ Campaign isolation enforced  
✅ Immutable evidence items  
✅ HMAC-signed records  
✅ Approval required for reports  
✅ Sensitive host warnings  
✅ Session expiry (auto-logout)  
✅ Dual-logging (activity_log + audit_log)  

---

## Related Documentation

- [Getting Started](./GETTING_STARTED.md) - Deployment
- [Operator Manual](./OPERATOR_MANUAL.md) - Daily workflows
- [Troubleshooting](./TROUBLESHOOTING_GUIDE.md) - Error diagnosis

---

**VectorVue v3.0** | Red Team Campaign Management Platform | v3.0-RC1
