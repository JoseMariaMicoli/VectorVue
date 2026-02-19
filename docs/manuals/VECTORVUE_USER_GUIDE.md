<sub>Copyright (c) 2026 Jose Maria Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue User Guide

Audience: security operators, client stakeholders, auditors, and platform teams.

This guide explains how VectorVue is used as a commercial security validation and assurance platform.

## 1. What VectorVue Delivers

- Security validation execution with tenant isolation
- Operational visibility into findings, remediation, and risk posture
- Explainable analytics for defensive effectiveness
- Continuous compliance evidence with cryptographic integrity

## 2. Product Workflows

### 2.1 Operator Workflow

1. Configure campaign scope and controls
2. Execute and record campaign observations
3. Produce findings and evidence
4. Track remediation outcomes
5. Publish reports and analytics updates

### 2.2 Client Workflow

1. Review portal overview and analytics
2. Prioritize findings by severity and exploitability
3. Track remediation ownership and completion
4. Download formal reports and evidence artifacts

### 2.3 Auditor Workflow

1. Select framework and time window
2. Retrieve signed compliance dataset
3. Verify checksums and hash chain
4. Recompute control effectiveness state
5. Validate framework score consistency

## 3. Platform Architecture Summary

- API layer: FastAPI
- Datastore: PostgreSQL
- Queue/workers: Redis + RQ workers
- Portal: Next.js
- Reverse proxy: nginx

Core design rules:

- tenant boundary enforcement
- append-only evidence records where required
- reproducible analytics outputs with version lineage
- no silent model promotion

## 4. Security and Privacy Baseline

- JWT-based tenant-scoped access
- signed compliance API responses
- immutable compliance event chain
- telemetry limited to security workflow behavior
- no marketing-style tracking data capture

## 5. Commercial Service Quality Checklist

- Documentation and workflows are role-based
- Reports are consistent and exportable
- Compliance evidence is independently verifiable
- Deployment procedures are repeatable
- Support teams can troubleshoot using published runbooks

## 6. Guided Onboarding (Standard Language)

Use guided workflows to reduce setup errors and keep operations consistent.

### 6.1 CLI Guided Wizard (Recommended)

```bash
make wizard
```

Use menu options:

- `1` full commercial deploy
- `2` isolated customer portal deploy (tenant + users + host mapping)
- `3` real tenant bootstrap without dummy campaigns
- `4` seed multi-tenant demo dataset
- `5` real scenario validation (Phase 7-9 smoke)

### 6.2 TUI Guided Onboarding Wizard (Admin)

1. Start TUI:

```bash
make run-tui
```

2. Login with admin role.
3. Open onboarding:
- `Ctrl+Shift+W`, or
- sidebar `ONBOARD WIZARD`.
4. Fill tenant and portal fields:
- tenant id and tenant name
- portal host and company name
- primary/accent branding colors
- tenant admin and client credentials
5. Submit `CREATE TENANT + USERS`.

## 7. Where to Go Next

- Day-one setup: [Getting Started](./GETTING_STARTED.md)
- Delivery operations: [Operator Manual](./OPERATOR_MANUAL.md)
- Client usage: [Client Portal Manual](./CLIENT_PORTAL_MANUAL.md)
- API integrations: [Client API Manual](./CLIENT_API_MANUAL.md)
- Compliance and audit: [Compliance API Spec](../COMPLIANCE_API_SPEC.md), [Auditor Guide](../AUDITOR_GUIDE.md)
