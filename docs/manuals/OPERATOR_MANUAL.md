<!--
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
-->

# VectorVue Operator Manual

This manual is for delivery teams running security validation operations in VectorVue.

## 1. Operating Model

VectorVue workflow for operators:

1. Prepare campaign scope and rules of engagement
2. Execute and record activity evidence
3. Track findings and remediation
4. Validate defensive effectiveness through analytics
5. Deliver auditor-ready evidence and reports

## 2. Access and Roles

Minimum role guidance:

- Viewer: read-only access
- Operator: create and update operational records
- Lead: approvals and team coordination
- Admin: platform administration and user management

## 2.1 Guided Onboarding Paths

Use guided workflows to reduce operator error during setup:

1. CLI guided wizard:
   - `make wizard`
2. TUI guided onboarding (admin):
   - `make run-tui`
   - open with `Ctrl+Shift+W` or sidebar `ONBOARD WIZARD`
3. Use the wizard to set:
   - tenant id/name
   - portal host and company branding
   - tenant admin and client credentials

## 3. Daily Operator Procedure

### 3.1 Start-of-Day Checks

1. Confirm platform health:

```bash
make api-smoke
```

2. Confirm active campaign and tenant context.
3. Confirm evidence and reporting storage are available.

### 3.2 Campaign Execution

1. Open active campaign context.
2. Register operational events and observations.
3. Maintain finding records with severity and technical details.
4. Attach supporting evidence for each significant finding.

### 3.3 Detection and Response Tracking

1. Review detections and timeline indicators.
2. Mark remediation progress where applicable.
3. Escalate critical findings to lead for formal approval.

### 3.4 End-of-Day Closure

1. Verify no orphan findings remain without severity.
2. Verify critical findings have evidence and remediation owner.
3. Review analytics summary for posture shifts.
4. Prepare report artifacts for stakeholder review.

## 4. Quality Standards

Use these standards for commercial delivery:

- Every critical finding must include reproducible evidence.
- Every remediation task must have owner and status.
- Every report should map to current campaign window.
- All tenant data must remain isolated and scoped.

## 5. Multi-Tenant Safety Rules

- Never process or export data across tenants.
- Always confirm tenant identity before running bulk exports.
- Use tenant-scoped credentials and API tokens only.

## 6. Compliance-Aware Operations

Operator actions directly feed compliance evidence generation.

To maintain auditor-grade quality:

- Keep timestamps and object references accurate.
- Avoid manual edits to immutable evidence datasets.
- Ensure findings and remediation states are updated promptly.

## 7. Recommended Demo Walkthrough

1. Overview: current campaign and risk posture
2. Findings: focus critical/high severity
3. Remediation: verify accountability and progress
4. Reports: export executive artifacts
5. Compliance APIs: show signed framework report response

## 8. Incident and Escalation Guidance

Escalate to lead/admin when:

- unauthorized access is suspected
- tenant data scope appears inconsistent
- evidence integrity checks fail
- API responses show signature or hash mismatch

## 9. References

- [Client Portal Manual](./CLIENT_PORTAL_MANUAL.md)
- [Client API Manual](./CLIENT_API_MANUAL.md)
- [Compliance API Spec](../COMPLIANCE_API_SPEC.md)
- [Auditor Guide](../AUDITOR_GUIDE.md)
- [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md)
