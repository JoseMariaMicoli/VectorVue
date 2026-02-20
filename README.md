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

# VectorVue

VectorVue is a multi-tenant security validation and assurance platform for enterprise security teams, service providers, and regulated organizations.

It combines adversary emulation telemetry, control effectiveness analytics, and auditor-verifiable evidence to support continuous security operations and compliance assurance.

## Product Positioning

VectorVue is designed for commercial security delivery.

- Security Validation: run and track structured adversary simulation campaigns.
- Security Intelligence: measure detection quality, remediation responsiveness, and risk trends.
- Security Assurance: produce cryptographically verifiable evidence for audits and regulatory reviews.

## Core Capabilities

- Multi-tenant isolation for campaigns, findings, analytics, and compliance evidence
- Client portal with executive and operational views
- Read-only client API for findings, risk, remediation, reports, and analytics
- Usage telemetry focused on security workflow behavior (not marketing tracking)
- Explainable ML outputs with model version lineage
- Continuous compliance scoring and signed evidence export packages

## Quick Start (Commercial Demo)

1. Guided setup (recommended):

```bash
make wizard
```

Use menu option:
- `1` for full commercial deploy
- `2` for isolated customer portal deploy
- `4` for demo seed data

2. Deploy platform stack (direct command path):

```bash
make deploy
```

3. Seed realistic demo data:

```bash
make seed-clients
```

Production-style tenant onboarding without dummy campaign data:

```bash
make tenant-bootstrap-real \
  TENANT_ID=30000000-0000-0000-0000-000000000003 \
  TENANT_NAME="RealCorp Manufacturing" \
  TENANT_ADMIN_USER=realcorp_admin \
  TENANT_ADMIN_PASS='RealCorpAdm1n!' \
  TENANT_CLIENT_USER=realcorp_viewer \
  TENANT_CLIENT_PASS='RealCorpView3r!'
```

Validate Phase 7-9 behavior in this real empty-state tenant:

```bash
make phase79-real-smoke \
  TENANT_ID=30000000-0000-0000-0000-000000000003 \
  TENANT_ADMIN_USER=realcorp_admin \
  TENANT_ADMIN_PASS='RealCorpAdm1n!'
```

One-command isolated client portal stack:

```bash
make customer-deploy-portal-isolated \
  CUSTOMER=realcorp \
  TENANT_ID=30000000-0000-0000-0000-000000000003 \
  TENANT_NAME="RealCorp Manufacturing" \
  TENANT_PORTAL_HOST=realcorp.vectorvue.local
```

4. Open tenant portals:

- `https://acme.vectorvue.local/login`
- `https://globex.vectorvue.local/login`

5. Validate API and service health:

```bash
make api-smoke
```

## Documentation

Start here: [Documentation Index](docs/manuals/INDEX.md)

Recommended paths by role:

- Security Operators: [Getting Started](docs/manuals/GETTING_STARTED.md), [Operator Manual](docs/manuals/OPERATOR_MANUAL.md)
- Client Users: [Client Portal Manual](docs/manuals/CLIENT_PORTAL_MANUAL.md)
- Integration Teams: [Client API Manual](docs/manuals/CLIENT_API_MANUAL.md)
- Auditors and Compliance Teams: [Compliance API Spec](docs/COMPLIANCE_API_SPEC.md), [Auditor Guide](docs/AUDITOR_GUIDE.md)
- Platform Engineering: [Deployment](docs/manuals/Deployment.md), [PostgreSQL Usage Guide](docs/manuals/POSTGRES_USAGE_GUIDE.md)

## TUI Onboarding Wizard

For admin users in the TUI:

1. Run TUI: `make run-tui`
2. Login as admin.
3. Open onboarding wizard:
- `Ctrl+Shift+W`, or
- Sidebar button `ONBOARD WIZARD`
4. Fill tenant, company, branding, and user fields.
5. Submit `CREATE TENANT + USERS`.

## Security and Privacy Principles

- Tenant-scoped access control and strict data isolation
- Immutable evidence chain for compliance events
- Signed API responses for compliance endpoints
- No IP or user-agent collection in client telemetry workflows
- Security workflow analytics only

## Release Status

- Version: `v4.1`
- Maturity: Production-ready commercial platform
- Delivery Scope: Campaign operations, client portal/API, explainable analytics, continuous compliance assurance

## Licensing

VectorVue is licensed under BSL 1.1 as defined in project metadata.
