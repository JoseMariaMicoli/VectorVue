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

# VectorVue Deployment Guide

This runbook deploys VectorVue for production-style environments.

## 1. Prerequisites

- Docker Engine and Docker Compose
- OpenSSL
- Linux host recommended for operations
- DNS/hosts mapping for tenant domains

## 2. Deploy Full Stack

Recommended guided flow:

```bash
make wizard
```

Select option `1`.

Direct command path:

```bash
make deploy
```

Expected services:

- `vectorvue_app`
- `vectorvue_runtime`
- `vectorvue_ml_worker`
- `vectorvue_compliance_observation_worker`
- `vectorvue_compliance_daily_worker`
- `vectorvue_portal`
- `vectorvue_nginx`
- `vectorvue_postgres`
- `vectorvue_redis`

## 3. Seed Demo or Acceptance Data

```bash
make seed-clients
```

Guided path: `make wizard` and select option `4`.

## 4. Validation

```bash
make api-smoke
docker compose ps
```

Confirm API health, OpenAPI availability, and worker uptime.

## 5. TLS Certificate Assets

Generate local cert assets when needed:

```bash
./deploy/scripts/generate_tls_certs.sh
```

## 6. Tenant-Isolated Deployment Pattern

To run a separate customer namespace:

```bash
make customer-deploy-isolated \
  CUSTOMER=acme \
  TENANT_NAME="ACME Industries" \
  HTTP_HOST_PORT=8081 \
  HTTPS_HOST_PORT=8444 \
  POSTGRES_HOST_PORT=5544
```

Default local docker host mapping for PostgreSQL is `55433` (override with
`POSTGRES_HOST_PORT` when needed).

For full isolated portal onboarding in one flow:

```bash
make wizard
```

Select option `2`.

## 7. Upgrade and Migration Sequence

Use this order:

1. `make deploy`
2. `make pg-schema-bootstrap`
3. `make phase65-migrate`
4. `make phase7e-migrate`
5. `make phase8-migrate`
6. `make phase9-migrate`
7. `make seed-clients` (if demo/non-production)

## 8. Operational Notes

- Do not expose PostgreSQL directly unless required for admin workflows.
- Keep compliance signing keys and JWT secrets managed securely per environment.
- Monitor worker logs for queue failures and migration drift.

## 9. Commercial Tenant Commands

- Demo-ready seeding:
  - `make seed-clients`
- Real tenant onboarding (no dummy campaigns):
  - `make tenant-bootstrap-real ...`
- Phase 7-9 no-dummy validation:
  - `make phase79-real-smoke ...`
- One-command isolated client portal stack:
  - `make customer-deploy-portal-isolated ...`
- Guided command menu:
  - `make wizard`

## 10. TUI Admin Onboarding Wizard

Use this flow to onboard tenant + portal metadata from the app UI.

1. Start TUI:
   - `make run-tui`
2. Login with admin role.
3. Open wizard:
   - hotkey `Ctrl+Shift+W`
   - or sidebar `ONBOARD WIZARD`
4. Fill tenant metadata, company branding, and credentials.
5. Run `CREATE TENANT + USERS`.
