**Remediation Tracker**. This is a functional spreadsheet-style template designed to be delivered alongside your report. It allows the client's IT and Dev teams to track their progress, assign owners, and document their "Risk Acceptance" for items they cannot fix immediately.

---

## Post-Engagement Remediation Tracker

**Project:** [Client Name] - 2026 Security Assessment

**Date Issued:** January 10, 2026

| Finding ID | Title | Severity | Owner | Target Date | Status | Remediation Note / Risk Acceptance |
| --- | --- | --- | --- | --- | --- | --- |
| **FIND-001** | SQL Injection (Web A05) | **Critical** | DB Team | 2026-01-15 | 🟡 In Progress | Implementing Prepared Statements. |
| **FIND-002** | BOLA in API (API1) | **High** | API Devs | 2026-01-20 | 🔴 Open | Reviewing Auth logic in `/v1/orders`. |
| **FIND-003** | Kerberoasting (AD) | **High** | IT Admin | 2026-01-12 | 🟢 Fixed | Rotated SVC_Backup with 30-char pass. |
| **FIND-004** | Insecure Storage (M9) | **High** | Mobile Team | 2026-02-01 | 🔴 Open | Moving tokens to Android Keystore. |
| **FIND-005** | LLMNR Enabled (Net) | **Medium** | Net Ops | 2026-01-15 | 🟡 In Progress | Deploying GPO to disable across HQ. |
| **FIND-006** | Info Leak (Web A09) | **Low** | Web Team | 2026-03-01 | 🔵 Risk Accepted | Necessary for legacy debug logs. |

---
