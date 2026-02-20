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

# Getting Started with VectorVue

This guide brings a new environment from zero to a working commercial demo.

## Objective

By the end of this guide you will have:

- Full platform deployed
- Tenant demo data loaded
- Client portals accessible
- API and compliance endpoints validated

## Prerequisites

- Docker and Docker Compose installed
- `make` available
- Hosts entries for local tenant domains if required by your environment

Recommended local host mapping:

- `acme.vectorvue.local` -> `127.0.0.1`
- `globex.vectorvue.local` -> `127.0.0.1`

## Step 1: Deploy Services

Recommended guided flow:

```bash
make wizard
```

Select:
- `1` for full commercial deploy
- `4` for demo seeding

Direct command path:

```bash
make deploy
```

This starts API, portal, runtime services, workers, PostgreSQL, Redis, and nginx.

## Step 2: Seed Demo Data

```bash
make seed-clients
```

This creates multi-tenant demo content including campaigns, findings, reports, remediation tasks, analytics records, and compliance-ready activity data.

## Step 3: Access Portals

Open:

- `https://acme.vectorvue.local/login`
- `https://globex.vectorvue.local/login`

Use credentials from [Demo Access Matrix](./DEMO_ACCESS_MATRIX.md).

## Step 4: Validate API Health

```bash
make api-smoke
```

Expected result:

- API health check returns healthy
- OpenAPI responds successfully

## Step 5: Validate Compliance Endpoints

Call any tenant-authenticated endpoint, for example:

- `GET /compliance/frameworks`
- `GET /compliance/ISO27001/score`

Compliance API responses are signed and tenant scoped.

## Step 6: Validate Worker Health

```bash
docker compose ps
```

Confirm these services are up:

- `vectorvue_ml_worker`
- `vectorvue_compliance_observation_worker`
- `vectorvue_compliance_daily_worker`

## Optional: Real Tenant Onboarding (No Dummy Data)

Create a production-style tenant and users only:

```bash
make tenant-bootstrap-real \
  TENANT_ID=30000000-0000-0000-0000-000000000003 \
  TENANT_NAME="RealCorp Manufacturing" \
  TENANT_ADMIN_USER=realcorp_admin \
  TENANT_ADMIN_PASS='RealCorpAdm1n!' \
  TENANT_CLIENT_USER=realcorp_viewer \
  TENANT_CLIENT_PASS='RealCorpView3r!'
```

Validate Phase 7-9 endpoint behavior for that tenant:

```bash
make phase79-real-smoke \
  TENANT_ID=30000000-0000-0000-0000-000000000003 \
  TENANT_ADMIN_USER=realcorp_admin \
  TENANT_ADMIN_PASS='RealCorpAdm1n!'
```

Guided alternative:

```bash
make wizard
```

Select:
- `3` to bootstrap a real tenant
- `5` to run real scenario validation

## Optional: Fully Isolated Client Portal Stack

```bash
make customer-deploy-portal-isolated \
  CUSTOMER=realcorp \
  TENANT_ID=30000000-0000-0000-0000-000000000003 \
  TENANT_NAME="RealCorp Manufacturing" \
  TENANT_PORTAL_HOST=realcorp.vectorvue.local
```

Guided alternative:

```bash
make wizard
```

Select option `2`.

## Optional: TUI Onboarding Wizard (Admin)

Use this when you want an in-app onboarding flow.

1. Start TUI:

```bash
make run-tui
```

2. Login with an admin account.
3. Open onboarding wizard with `Ctrl+Shift+W` or `ONBOARD WIZARD` in sidebar.
4. Enter tenant and portal/company data:
- tenant id and name
- portal host
- company name + colors
- tenant admin and client credentials
5. Click `CREATE TENANT + USERS`.

## Recommended First Walkthrough

1. Client Portal: Overview -> Analytics -> Findings -> Remediation -> Reports -> Risk
2. API: login -> findings -> risk -> telemetry event -> ML endpoint
3. Compliance: frameworks -> controls -> score -> report

## Troubleshooting

If migration or seed errors appear:

1. Re-run `make deploy`
2. Re-run `make seed-clients`
3. Check logs:

```bash
docker compose logs --tail=100 vectorvue_app
docker compose logs --tail=100 vectorvue_postgres
```

For deeper troubleshooting use [Troubleshooting Guide](./TROUBLESHOOTING_GUIDE.md).
