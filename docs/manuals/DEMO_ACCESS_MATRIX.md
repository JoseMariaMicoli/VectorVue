<sub>Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}</sub>

# VectorVue v4.1 Demo Access Matrix

## Scope

This page documents the default demo identities provisioned by `make seed-clients`.
Use it as the fast reference for:
- who logs in where
- which credentials to use
- the recommended 10-minute demo flow

## Seeded Identity Model

`make seed-clients` provisions:

- Global Red Team accounts (shared TUI/operator accounts)
- Client Panel 1 tenant with two client portal users
- Client Panel 2 tenant with two client portal users
- Two campaigns per client tenant (4 total)
- portal telemetry schema for defensive analytics datasets

## Default Accounts

### Global Red Team

- `redteam_admin` / `RedTeamAdm1n!` (`ADMIN`)
- `rt_lead` / `LeadOperat0r!` (`LEAD`)
- `rt_operator` / `CoreOperat0r!` (`OPERATOR`)

### Client Panel 1

- Tenant name: `ACME Industries`
- Tenant ID: `10000000-0000-0000-0000-000000000001`
- Portal URL: `https://acme.vectorvue.local/login`
- `acme_viewer` / `AcmeView3r!` (`viewer`)
- `acme_operator` / `AcmeOperat0r!` (`operator`)

### Client Panel 2

- Tenant name: `Globex Corporation`
- Tenant ID: `20000000-0000-0000-0000-000000000002`
- Portal URL: `https://globex.vectorvue.local/login`
- `globex_viewer` / `GlobexView3r!` (`viewer`)
- `globex_operator` / `GlobexOperat0r!` (`operator`)

## Fast Demo Procedure (10 Minutes)

1. Run seed:
```bash
make seed-clients
```
2. Open `https://acme.vectorvue.local/login`.
3. Login as `acme_viewer`.
4. Walk through:
   - `Overview`
   - `Findings` (filter critical, open detail)
   - `Reports` (download one PDF)
   - `Remediation`
   - `Risk`
5. Logout and repeat on `https://globex.vectorvue.local/login` with `globex_viewer`.

Expected result:
- clear tenant isolation
- populated dashboards
- downloadable reports
- visible remediation state

## Makefile Overrides

All identities are configurable with make variables:

- Global: `GLOBAL_ADMIN_USER`, `GLOBAL_ADMIN_PASS`, `OPERATOR_LEAD_USER`, `OPERATOR_LEAD_PASS`, `OPERATOR_USER`, `OPERATOR_PASS`
- Panel 1: `PANEL1_TENANT_ID`, `PANEL1_TENANT_NAME`, `PANEL1_CLIENT_USER_1`, `PANEL1_CLIENT_PASS_1`, `PANEL1_CLIENT_ROLE_1`, `PANEL1_CLIENT_USER_2`, `PANEL1_CLIENT_PASS_2`, `PANEL1_CLIENT_ROLE_2`
- Panel 2: `PANEL2_TENANT_ID`, `PANEL2_TENANT_NAME`, `PANEL2_CLIENT_USER_1`, `PANEL2_CLIENT_PASS_1`, `PANEL2_CLIENT_ROLE_1`, `PANEL2_CLIENT_USER_2`, `PANEL2_CLIENT_PASS_2`, `PANEL2_CLIENT_ROLE_2`

Example:

```bash
make seed-clients \
  PANEL1_TENANT_NAME='Initech' \
  PANEL1_CLIENT_USER_1='initech_viewer' \
  PANEL2_TENANT_NAME='Umbrella Corp' \
  GLOBAL_ADMIN_PASS='ChangeMeNow!'
```

## Notes

- Login enforces explicit `user_tenant_access` mapping:
  - `redteam_admin` -> both tenants
  - `rt_lead` -> panel 1 tenant
  - `rt_operator` -> panel 2 tenant
  - client users -> their own tenant only
- Client users are authenticated through `/api/v1/client/auth/login` and receive tenant-scoped JWTs.
- Role controls for `viewer|operator|lead|admin` apply to TUI and backend permission checks.
